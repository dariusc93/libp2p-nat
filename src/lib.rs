mod task;
mod utils;

use core::task::{Context, Poll};
use futures::channel::oneshot::{self, Canceled};
use futures::future::BoxFuture;
use futures::{FutureExt, StreamExt};
use libp2p::core::transport::ListenerId;
use libp2p::core::Multiaddr;
use libp2p::swarm::ConnectionHandler;
use libp2p::swarm::{
    self, dummy::ConnectionHandler as DummyConnectionHandler, NetworkBehaviour, PollParameters,
};
use std::collections::hash_map::Entry;
use std::net::IpAddr;
use std::pin::Pin;
use std::time::Duration;
use task::NatCommands;
use wasm_timer::Interval;

use std::collections::{HashMap, VecDeque};

type NetworkBehaviourAction = swarm::NetworkBehaviourAction<
    <<Behaviour as NetworkBehaviour>::ConnectionHandler as ConnectionHandler>::OutEvent,
    <Behaviour as NetworkBehaviour>::ConnectionHandler,
>;

#[allow(clippy::type_complexity)]
pub struct Behaviour {
    events: VecDeque<NetworkBehaviourAction>,
    nat_sender: futures::channel::mpsc::UnboundedSender<NatCommands>,
    futures: HashMap<ListenerId, Vec<BoxFuture<'static, Result<anyhow::Result<()>, Canceled>>>>,
    duration: Duration,
    renewal_interval: Interval,
    local_listeners: HashMap<ListenerId, Vec<Multiaddr>>,
    disabled: bool,
}

impl Behaviour {
    pub async fn new() -> anyhow::Result<Self> {
        let duration = Duration::from_secs(2 * 60);
        let renewal = duration / 2;
        let nat_sender = task::port_forwarding_task().await?;
        Ok(Self {
            events: Default::default(),
            nat_sender,
            futures: Default::default(),
            duration: Duration::from_secs(60),
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
    pub async fn external_addr(&self) -> anyhow::Result<IpAddr> {
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
    type OutEvent = void::Void;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        DummyConnectionHandler
    }

    fn inject_new_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        // Used to make sure we only obtain private ips
        if let Some((_, _)) = utils::multiaddr_to_socket_port(addr) {
            self.local_listeners
                .entry(id)
                .or_default()
                .push(addr.clone());

            let (tx, rx) = oneshot::channel();

            let _ = self
                .nat_sender
                .clone()
                .unbounded_send(NatCommands::ForwardPort(addr.clone(), self.duration, tx));

            self.futures.entry(id).or_default().push(rx.boxed())
        }
    }

    fn inject_expired_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        if let Entry::Occupied(mut entry) = self.local_listeners.entry(id) {
            let list = entry.get_mut();
            if let Some(index) = list.iter().position(|inner_addr| inner_addr == addr) {
                list.remove(index);
            }
            if list.is_empty() {
                entry.remove();
            }
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
        _: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction> {
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(event);
        }

        if self.disabled {
            let lids = self.futures.keys().copied().collect::<Vec<_>>();

            for id in lids {
                if let Entry::Occupied(mut entry) = self.futures.entry(id) {
                    let mut for_removal = vec![];
                    for (index, fut) in entry.get_mut().iter_mut().enumerate() {
                        match Pin::new(fut).poll_unpin(cx) {
                            Poll::Ready(result) => {
                                for_removal.push(index);
                                match result {
                                    Ok(Ok(_)) => {
                                        log::debug!("Successful with port forwarding");
                                    }
                                    Ok(Err(e)) => {
                                        log::error!("Error attempting to port forward: {e}");
                                    }
                                    Err(_) => {
                                        log::error!("Channel has dropped");
                                    }
                                }
                            }
                            Poll::Pending => continue,
                        }
                    }
                    for index in for_removal {
                        entry.get_mut().remove(index);
                    }
                    if entry.get().is_empty() {
                        entry.remove();
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

                        self.futures.entry(*id).or_default().push(rx.boxed())
                    }
                }
            }
        }

        Poll::Pending
    }
}
