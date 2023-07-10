mod task;
mod utils;

use core::task::{Context, Poll};
use futures::{FutureExt, StreamExt};
use futures_timer::Delay;
use libp2p::core::transport::ListenerId;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, NetworkBehaviour, PollParameters,
};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, ExpiredListenAddr, NewListenAddr, THandler, THandlerInEvent,
    ToSwarm,
};
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::task::Waker;
use std::time::Duration;
use task::{ForwardingError, NatCommands, NatResult, NatType};

use std::collections::{HashMap, VecDeque};

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("Require tokio or async-std feature to be enabled");

#[derive(Debug)]
struct LocalListener {
    pub addrs: Vec<Multiaddr>,
    pub external_addrs: Vec<Multiaddr>,
    pub renewal: Option<Delay>,
}

#[allow(clippy::type_complexity)]
pub struct Behaviour {
    events: VecDeque<swarm::ToSwarm<<Self as NetworkBehaviour>::ToSwarm, THandlerInEvent<Self>>>,
    nat_sender: futures::channel::mpsc::UnboundedSender<NatCommands>,
    event_receiver: futures::channel::mpsc::Receiver<Result<NatResult, ForwardingError>>,
    local_listeners: HashMap<ListenerId, LocalListener>,
    disabled: bool,
    waker: Option<Waker>,
}

impl Default for Behaviour {
    fn default() -> Self {
        Self::with_duration(Duration::from_secs(2 * 60))
    }
}

impl Behaviour {
    pub fn with_duration(duration: Duration) -> Self {
        assert!(duration.as_secs() > 10);
        let renewal = duration / 2;

        let (nat_sender, result_rx) = task::port_forwarding_task(duration, renewal);
        Self {
            events: Default::default(),
            nat_sender,
            event_receiver: result_rx,
            local_listeners: Default::default(),
            disabled: false,
            waker: None,
        }
    }

    /// Enables port forwarding
    pub fn enable(&mut self) {
        self.disabled = false;
        for local_listener in self.local_listeners.values_mut() {
            local_listener.renewal = Some(Delay::new(Duration::from_secs(10)));
        }
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// Disable port forwarding
    /// Note: This does not remove the current lease but instead will not allow them to be renewed
    pub fn disable(&mut self) {
        if self.disabled {
            return;
        }

        self.disabled = true;

        // No need to continue if there are no external addresses
        if self.external_addr().is_empty() {
            return;
        }

        for (id, listener) in &mut self.local_listeners {
            for addr in &listener.addrs {
                let _ = self
                    .nat_sender
                    .clone()
                    .unbounded_send(NatCommands::DisableForwardPort(
                        *id,
                        addr.clone(),
                        NatType::Igd,
                    ));
            }

            // Notify swarm about the external addresses expiring
            // Regardless of if we successfully disable port forwarding in the background task
            for addr in listener.external_addrs.drain(..) {
                self.events.push_back(ToSwarm::ExternalAddrExpired(addr));
            }

            listener.renewal = None;
        }

        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }

    /// Gets external addresses
    pub fn external_addr(&self) -> Vec<Multiaddr> {
        self.local_listeners
            .values()
            .flat_map(|local| local.addrs.clone())
            .collect::<Vec<_>>()
    }
}

impl NetworkBehaviour for Behaviour {
    type ConnectionHandler = DummyConnectionHandler;
    type ToSwarm = void::Void;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(DummyConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        _: PeerId,
        _: &Multiaddr,
        _: Endpoint,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(DummyConnectionHandler)
    }

    fn on_connection_handler_event(
        &mut self,
        _: libp2p::PeerId,
        _: swarm::ConnectionId,
        _: swarm::THandlerOutEvent<Self>,
    ) {
    }

    fn on_swarm_event(&mut self, event: swarm::FromSwarm<Self::ConnectionHandler>) {
        match event {
            swarm::FromSwarm::NewListenAddr(NewListenAddr { listener_id, addr }) => {
                // Used to make sure we only obtain private ips
                if utils::multiaddr_to_socket_port(addr).is_none() {
                    return;
                }

                match self.local_listeners.entry(listener_id) {
                    Entry::Occupied(mut entry) => {
                        let listener = entry.get_mut();
                        if !listener.addrs.contains(addr) {
                            listener.addrs.push(addr.clone());
                        }
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(LocalListener {
                            addrs: vec![addr.clone()],
                            external_addrs: vec![],
                            renewal: None,
                        });
                    }
                };

                let _ = self
                    .nat_sender
                    .clone()
                    .unbounded_send(NatCommands::ForwardPort(listener_id, addr.clone()));
            }
            swarm::FromSwarm::NewExternalAddrCandidate(_) => {}
            swarm::FromSwarm::ExternalAddrExpired(_) => {}
            swarm::FromSwarm::ExpiredListenAddr(ExpiredListenAddr { listener_id, addr }) => {
                if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id) {
                    let listener = entry.get_mut();

                    let list = &mut listener.addrs;

                    if !list.contains(addr) {
                        return;
                    }

                    list.retain(|local_addr| local_addr != addr);

                    let _ =
                        self.nat_sender
                            .clone()
                            .unbounded_send(NatCommands::DisableForwardPort(
                                listener_id,
                                addr.clone(),
                                NatType::Igd,
                            ));

                    if list.is_empty() {
                        entry.remove();
                    }
                }
            }
            _ => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<swarm::ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        for (id, local_listener) in &mut self.local_listeners {
            if let Some(renewal) = local_listener.renewal.as_mut() {
                if let Poll::Ready(()) = renewal.poll_unpin(cx) {
                    for addr in &local_listener.addrs {
                        let _ = self
                            .nat_sender
                            .clone()
                            .unbounded_send(NatCommands::ForwardPort(*id, addr.clone()));
                    }
                    renewal.reset(Duration::from_secs(30));
                }
            }
        }

        loop {
            match self.event_receiver.poll_next_unpin(cx) {
                Poll::Ready(Some(result)) => match result {
                    Ok(NatResult::PortForwardingEnabled {
                        listener_id,
                        addr,
                        nat_type: _,
                        timer,
                    }) => {
                        if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id)
                        {
                            let listener = entry.get_mut();
                            if !listener.external_addrs.contains(&addr) {
                                log::info!("Discovered {addr} as an external address.");
                                listener.external_addrs.push(addr.clone());
                                self.events
                                    .push_back(ToSwarm::ExternalAddrConfirmed(addr.clone()));
                            }
                            listener.renewal = Some(timer);
                        }
                    }
                    Ok(NatResult::PortForwardingDisabled { listener_id }) => {
                        if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id)
                        {
                            let listener = entry.get_mut();
                            if !listener.external_addrs.is_empty() {
                                for addr in listener.external_addrs.drain(..) {
                                    self.events
                                        .push_back(ToSwarm::ExternalAddrExpired(addr.clone()));
                                }
                            }
                        }
                    }
                    Err(ForwardingError::InvalidAddress {
                        listener_id,
                        address,
                    }) => {
                        if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id)
                        {
                            let listener = entry.get_mut();
                            log::debug!("Removing {address} from local listeners");
                            listener.addrs.retain(|local_addr| local_addr != &address);
                            listener.renewal = Some(Delay::new(Duration::from_secs(30)));
                        }
                    }
                    Err(ForwardingError::PortForwardingFailed { listener_id }) => {
                        if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id)
                        {
                            log::error!("Failed performing port forwarding");
                            let listener = entry.get_mut();
                            listener.renewal = Some(Delay::new(Duration::from_secs(30)));
                        }
                    }
                    Err(ForwardingError::Any {
                        listener_id,
                        error: e,
                    }) => {
                        log::error!("Error: {e}");
                        if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id)
                        {
                            let listener = entry.get_mut();
                            listener.renewal = Some(Delay::new(Duration::from_secs(30)));
                        }
                    }
                },
                Poll::Ready(None) => unreachable!("Channels are owned"),
                Poll::Pending => break,
            }
        }

        Poll::Pending
    }
}
