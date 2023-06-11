mod task;
mod utils;

use core::task::{Context, Poll};
use futures::channel::oneshot::{self, Canceled};
use futures::future::BoxFuture;
use futures::stream::FuturesOrdered;
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::core::{Endpoint, Multiaddr};
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, NetworkBehaviour, PollParameters,
};
use libp2p::swarm::{
    ConnectionDenied, ConnectionId, ExpiredListenAddr, NewListenAddr, THandler, THandlerInEvent,
};
use libp2p::PeerId;
use std::collections::hash_map::Entry;
use std::pin::Pin;
use std::time::Duration;
use task::NatCommands;
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
        FuturesOrdered<BoxFuture<'static, Result<anyhow::Result<()>, Canceled>>>,
    >,
    duration: Duration,
    renewal_interval: Interval,
    local_listeners: HashMap<ListenerId, HashSet<Multiaddr>>,
    disabled: bool,
}

impl Behaviour {
    #[cfg(any(feature = "tokio", feature = "async-std"))]
    pub async fn new() -> anyhow::Result<Self> {
        Self::with_duration(Duration::from_secs(2 * 60)).await
    }

    #[cfg(any(feature = "tokio", feature = "async-std"))]
    pub async fn with_duration(duration: Duration) -> anyhow::Result<Self> {
        if duration.as_secs() < 60 {
            anyhow::bail!("Duration must be 60 seconds or more");
        }
        let renewal = duration / 2;
        let nat_sender = task::port_forwarding_task().await?;
        Ok(Self {
            events: Default::default(),
            nat_sender,
            futures: Default::default(),
            duration,
            renewal_interval: Interval::new(renewal),
            local_listeners: Default::default(),
            disabled: false,
        })
    }

    /// Enables port forwarding
    pub fn enable(&mut self) {
        self.disabled = false;
    }

    /// Disable port forwarding
    /// Note: This does not remove the current lease but instead will not allow them to be renewed
    pub fn disable(&mut self) {
        self.disabled = true;
    }

    /// Gets external address
    /// Note: This uses nat-pmp for fetching external address at this time.
    #[cfg(any(feature = "tokio", feature = "async-std"))]
    #[cfg(not(target_os = "ios"))]
    pub async fn external_addr(&self) -> anyhow::Result<std::net::IpAddr> {
        let (tx, rx) = oneshot::channel();
        let _ = self
            .nat_sender
            .clone()
            .unbounded_send(NatCommands::NatpmpExternalAddr(tx));
        rx.await?
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
                if let Some((_, _)) = utils::multiaddr_to_socket_port(addr) {
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
            }
            swarm::FromSwarm::ExpiredListenAddr(ExpiredListenAddr { listener_id, addr }) => {
                if let Entry::Occupied(mut entry) = self.local_listeners.entry(listener_id) {
                    let list = entry.get_mut();
                    list.remove(addr);
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

        if !self.disabled {
            let lids = self.futures.keys().copied().collect::<Vec<_>>();

            for id in lids {
                if let Entry::Occupied(mut entry) = self.futures.entry(id) {
                    let list = entry.get_mut();

                    match Pin::new(list).poll_next_unpin(cx) {
                        Poll::Ready(Some(result)) => match result {
                            Ok(Ok(_)) => {
                                log::debug!("Successful with port forwarding");
                            }
                            Ok(Err(e)) => {
                                log::error!("Error attempting to port forward: {e}");
                            }
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
