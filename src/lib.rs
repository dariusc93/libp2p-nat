mod task;
mod utils;

use core::task::{Context, Poll};
use futures::channel::oneshot::{self, Canceled};
use futures::future::BoxFuture;
use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, NetworkBehaviour, PollParameters,
};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, ExpiredListenAddr, ExternalAddrExpired,
    NewExternalAddrCandidate, NewListenAddr, THandler, THandlerInEvent, ToSwarm,
};
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::pin::Pin;
use std::time::Duration;
use task::{ForwardingError, NatCommands, NatType};
use wasm_timer::Interval;

use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(not(any(feature = "tokio", feature = "async-std")))]
compile_error!("Require tokio or async-std feature to be enabled");

#[allow(clippy::type_complexity)]
pub struct Behaviour {
    events: VecDeque<swarm::ToSwarm<<Self as NetworkBehaviour>::ToSwarm, THandlerInEvent<Self>>>,
    nat_sender: futures::channel::mpsc::UnboundedSender<NatCommands>,
    futures: HashMap<
        ListenerId,
        FuturesOrdered<
            BoxFuture<'static, Result<Result<(Multiaddr, NatType), ForwardingError>, Canceled>>,
        >,
    >,
    disable_futures:
        FuturesUnordered<BoxFuture<'static, Result<Result<(), ForwardingError>, Canceled>>>,
    duration: Duration,
    renewal_interval: Interval,
    external_address: HashSet<Multiaddr>,
    pending_external_address: HashSet<Multiaddr>,
    local_listeners: HashMap<ListenerId, HashSet<Multiaddr>>,
    disabled: bool,
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
        let nat_sender = task::port_forwarding_task();
        Self {
            events: Default::default(),
            nat_sender,
            futures: Default::default(),
            disable_futures: FuturesUnordered::default(),
            duration,
            renewal_interval: Interval::new(renewal),
            local_listeners: Default::default(),
            external_address: Default::default(),
            pending_external_address: Default::default(),
            disabled: false,
        }
    }

    /// Enables port forwarding
    pub fn enable(&mut self) {
        self.disabled = false;
        self.disable_futures.clear();
    }

    /// Disable port forwarding
    /// Note: This does not remove the current lease but instead will not allow them to be renewed
    pub fn disable(&mut self) {
        if self.disabled {
            return;
        }

        self.disabled = true;

        // No need to continue if there are no external addresses
        if self.external_address.is_empty() {
            return;
        }

        for addr in self.local_listeners.values().flatten() {
            let (tx, rx) = oneshot::channel();

            let _ = self
                .nat_sender
                .clone()
                .unbounded_send(NatCommands::DisableForwardPort(
                    addr.clone(),
                    NatType::Igd,
                    tx,
                ));

            self.disable_futures.push(rx.boxed());
        }

        // Notify swarm about the external addresses expiring
        // Regardless of if we successfully disable port forwarding in the background task
        for addr in self.external_address.drain() {
            self.events.push_back(ToSwarm::ExternalAddrExpired(addr));
        }
    }

    /// Gets external addresses
    pub fn external_addr(&self) -> Vec<Multiaddr> {
        Vec::from_iter(self.external_address.iter().cloned())
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

                self.local_listeners
                    .entry(listener_id)
                    .or_default()
                    .insert(addr.clone());

                let (tx, rx) = oneshot::channel();

                let _ = self
                    .nat_sender
                    .clone()
                    .unbounded_send(NatCommands::ForwardPort(addr.clone(), self.duration, tx));

                self.futures
                    .entry(listener_id)
                    .or_default()
                    .push_back(rx.boxed())
            }
            swarm::FromSwarm::NewExternalAddrCandidate(NewExternalAddrCandidate { addr }) => {
                if !self.pending_external_address.remove(addr) {
                    return;
                }

                if self.disabled {
                    return;
                }

                if self.external_address.contains(addr) {
                    return;
                }

                self.external_address.insert(addr.clone());

                log::info!("Discovered {addr} as an external address.");

                self.events
                    .push_back(ToSwarm::ExternalAddrConfirmed(addr.clone()));
            }
            swarm::FromSwarm::ExternalAddrExpired(ExternalAddrExpired { addr }) => {
                if !self.external_address.contains(addr) {
                    return;
                }

                self.external_address.remove(addr);
            }
            swarm::FromSwarm::ExpiredListenAddr(ExpiredListenAddr { listener_id, addr }) => {
                if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id) {
                    let list = entry.get_mut();
                    list.remove(addr);

                    let (tx, rx) = oneshot::channel();

                    let _ =
                        self.nat_sender
                            .clone()
                            .unbounded_send(NatCommands::DisableForwardPort(
                                addr.clone(),
                                NatType::Igd,
                                tx,
                            ));

                    self.disable_futures.push(rx.boxed());

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

        loop {
            match self.disable_futures.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(Ok(_)))) => {}
                Poll::Ready(Some(Ok(Err(e)))) => {
                    log::error!("Error disabling port forwarding: {e}")
                }
                Poll::Ready(Some(Err(_))) => log::error!("Channel has dropped"),
                Poll::Ready(None) => break,
                Poll::Pending => break,
            }
        }

        if !self.disabled {
            let lids = self.futures.keys().copied().collect::<Vec<_>>();

            for id in lids {
                if let Entry::Occupied(mut entry) = self.futures.entry(id) {
                    let list = entry.get_mut();

                    match Pin::new(list).poll_next_unpin(cx) {
                        Poll::Ready(Some(result)) => match result {
                            Ok(Ok((address, _))) => {
                                if !self.external_address.contains(&address)
                                    && !self.pending_external_address.contains(&address)
                                {
                                    self.pending_external_address.insert(address.clone());
                                    self.events
                                        .push_back(ToSwarm::NewExternalAddrCandidate(address));
                                }
                            }
                            Ok(Err(ForwardingError::InvalidAddress { address })) => {
                                //Used as a filter for any invalid addresses
                                //TODO: Probably do a prefilter when listening but before attempting to perform a port forward
                                if let Entry::Occupied(mut le) = self.local_listeners.entry(id) {
                                    log::debug!("Removing {address} from local listeners");
                                    le.get_mut().remove(&address);
                                }
                            }
                            Ok(Err(ForwardingError::PortForwardingFailed)) => {
                                if !self.external_address.is_empty() {
                                    for addr in &self.external_address {
                                        self.events
                                            .push_back(ToSwarm::ExternalAddrExpired(addr.clone()));
                                    }
                                }
                            }
                            Ok(Err(e)) => log::error!("Error: {e}"),
                            Err(_) => {
                                log::error!("Channel has dropped");
                            }
                        },
                        Poll::Ready(None) => continue,
                        Poll::Pending => continue,
                    }

                    if entry.get().is_empty() {
                        let _ = entry.remove();
                    }
                }
            }

            while let Poll::Ready(Some(_)) = self.renewal_interval.poll_next_unpin(cx) {
                for (id, addrs) in self.local_listeners.iter() {
                    for addr in addrs {
                        let (tx, rx) = oneshot::channel();
                        let _ = self
                            .nat_sender
                            .clone()
                            .unbounded_send(NatCommands::ForwardPort(
                                addr.clone(),
                                self.duration,
                                tx,
                            ));

                        self.futures.entry(*id).or_default().push_back(rx.boxed())
                    }
                }
            }
        }

        Poll::Pending
    }
}
