use std::{io, str::FromStr, time::Duration};

use clap::Parser;
use futures::{future::Either, StreamExt};
use libp2p::{
    autonat::Behaviour as Autonat,
    core::{
        muxing::StreamMuxerBox,
        transport::{timeout::TransportTimeout, Boxed, OrTransport},
        upgrade::Version,
    },
    dns::{DnsConfig, ResolverConfig},
    identify::{self, Behaviour as Identify, Info},
    identity::{self, Keypair},
    kad::{store::MemoryStore, Kademlia},
    noise::{self},
    ping::Behaviour as Ping,
    relay::client::Transport as ClientTransport,
    relay::client::{self, Behaviour as RelayClient},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp::{async_io::Transport as AsyncTcpTransport, Config as GenTcpConfig},
    yamux::Config as YamuxConfig,
    Multiaddr, PeerId, Transport,
};

use libp2p_quic::{async_std::Transport as AsyncQuicTransport, Config as QuicConfig};

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    relay_client: RelayClient,
    identify: Identify,
    notifier: ext_behaviour::Behaviour,
    autonat: Autonat,
    nat: libp2p_nat::Behaviour,
    ping: Ping,
    kad: Toggle<Kademlia<MemoryStore>>,
}

#[derive(Debug, Parser)]
#[clap(name = "libp2p client")]
struct Opts {
    /// Fixed value to generate deterministic peer id.
    #[clap(long)]
    secret_key_seed: Option<u8>,
}

#[allow(clippy::collapsible_match)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opts = Opts::parse();

    let local_keypair = match opts.secret_key_seed {
        Some(seed) => generate_ed25519(seed),
        None => Keypair::generate_ed25519(),
    };

    let local_peer_id = PeerId::from(local_keypair.public());

    println!("Local Node: {local_peer_id}");

    let (relay_transport, relay_client) = client::new(local_peer_id);

    let transport = build_transport(local_keypair.clone(), relay_transport)?;

    let behaviour = Behaviour {
        autonat: Autonat::new(local_peer_id, Default::default()),
        ping: Ping::new(Default::default()),
        identify: Identify::new({
            let mut config =
                identify::Config::new("/libp2p-nat/0.1.0".to_string(), local_keypair.public());
            config.push_listen_addr_updates = true;
            config
        }),
        nat: libp2p_nat::Behaviour::new().await?,
        relay_client,
        kad: Toggle::from(Some({
            let store = MemoryStore::new(local_peer_id);
            Kademlia::new(local_peer_id, store)
        })),
        notifier: ext_behaviour::Behaviour::default(),
    };

    let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

    let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
        for peer_id in [
            "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
            "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
            "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
            "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
        ]
        .iter()
        .filter_map(|p| p.parse().ok())
        {
            kad.add_address(&peer_id, bootaddr.clone());
        }
    }

    swarm
        .behaviour_mut()
        .kad
        .as_mut()
        .map(|kad| kad.bootstrap());

    for addr in [
        "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
        "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
    ] {
        swarm.listen_on(addr)?;
    }

    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info:
                    Info {
                        protocols,
                        listen_addrs,
                        ..
                    },
            })) => {
                if protocols
                    .iter()
                    .any(|p| libp2p::autonat::DEFAULT_PROTOCOL_NAME.eq(p))
                {
                    for addr in listen_addrs.clone() {
                        swarm
                            .behaviour_mut()
                            .autonat
                            .add_server(peer_id, Some(addr));
                    }
                }
            }
            e => {
                log::debug!("{e:?}");
            }
        }
    }
    Ok(())
}

pub fn build_transport(
    keypair: Keypair,
    relay: ClientTransport,
) -> io::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let noise_config = noise::Config::new(&keypair).unwrap();

    let multiplex_upgrade = YamuxConfig::default();

    let quic_transport = AsyncQuicTransport::new(QuicConfig::new(&keypair));

    let transport = AsyncTcpTransport::new(GenTcpConfig::default().nodelay(true).port_reuse(true));

    let transport_timeout = TransportTimeout::new(transport, Duration::from_secs(30));

    let transport = futures::executor::block_on(DnsConfig::custom(
        transport_timeout,
        ResolverConfig::cloudflare(),
        Default::default(),
    ))?;

    let transport = OrTransport::new(relay, transport)
        .upgrade(Version::V1)
        .authenticate(noise_config)
        .multiplex(multiplex_upgrade)
        .timeout(Duration::from_secs(30))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        .boxed();

    let transport = OrTransport::new(quic_transport, transport)
        .map(|either_output, _| match either_output {
            Either::Left((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
            Either::Right((peer_id, muxer)) => (peer_id, StreamMuxerBox::new(muxer)),
        })
        .boxed();

    Ok(transport)
}

fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;

    identity::Keypair::ed25519_from_bytes(bytes).unwrap()
}

// Behaviour to use for printing out external addresses due to `Swarm` not emitting such events directly
mod ext_behaviour {
    use std::{
        collections::{hash_map::Entry, HashMap, HashSet, VecDeque},
        task::{Context, Poll},
    };

    use libp2p::{
        core::Endpoint,
        swarm::{
            derive_prelude::{ExternalAddrConfirmed, ListenerId},
            dummy, ConnectionDenied, ConnectionId, ExpiredListenAddr, ExternalAddrExpired,
            FromSwarm, ListenerClosed, NetworkBehaviour, NewListenAddr, PollParameters, THandler,
            THandlerInEvent, THandlerOutEvent, ToSwarm,
        },
        Multiaddr, PeerId,
    };

    #[allow(clippy::type_complexity)]
    #[derive(Debug, Default)]
    pub struct Behaviour {
        events: VecDeque<ToSwarm<<Self as NetworkBehaviour>::ToSwarm, THandlerInEvent<Self>>>,
        listener: HashMap<ListenerId, Vec<Multiaddr>>,
        external: HashSet<Multiaddr>,
    }

    impl NetworkBehaviour for Behaviour {
        type ConnectionHandler = dummy::ConnectionHandler;
        type ToSwarm = void::Void;

        fn handle_established_inbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: &Multiaddr,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_established_outbound_connection(
            &mut self,
            _: ConnectionId,
            _: PeerId,
            _: &Multiaddr,
            _: Endpoint,
        ) -> Result<THandler<Self>, ConnectionDenied> {
            Ok(dummy::ConnectionHandler)
        }

        fn handle_pending_inbound_connection(
            &mut self,
            _connection_id: libp2p::swarm::ConnectionId,
            _local_addr: &libp2p::Multiaddr,
            _remote_addr: &libp2p::Multiaddr,
        ) -> Result<(), libp2p::swarm::ConnectionDenied> {
            Ok(())
        }

        fn handle_pending_outbound_connection(
            &mut self,
            _connection_id: libp2p::swarm::ConnectionId,
            _maybe_peer: Option<libp2p::PeerId>,
            _addresses: &[libp2p::Multiaddr],
            _effective_role: libp2p::core::Endpoint,
        ) -> Result<Vec<libp2p::Multiaddr>, libp2p::swarm::ConnectionDenied> {
            Ok(vec![])
        }

        fn on_connection_handler_event(
            &mut self,
            _: libp2p::PeerId,
            _: ConnectionId,
            _: THandlerOutEvent<Self>,
        ) {
        }

        fn on_swarm_event(&mut self, event: FromSwarm<Self::ConnectionHandler>) {
            match event {
                FromSwarm::NewListenAddr(NewListenAddr { addr, listener_id }) => {
                    match self.listener.entry(listener_id) {
                        Entry::Occupied(mut entry) => {
                            let list = entry.get_mut();
                            if !list.contains(addr) {
                                list.push(addr.clone());
                                println!("Listening on (l): {addr}");
                            }
                        }
                        Entry::Vacant(entry) => {
                            entry.insert(vec![addr.clone()]);
                            println!("Listening on (l): {addr}");
                        }
                    }
                }
                FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed { addr }) => {
                    if self.external.insert(addr.clone()) {
                        println!("Listening on (e): {addr}");
                    }
                }
                FromSwarm::ExternalAddrExpired(ExternalAddrExpired { addr }) => {
                    if self.external.remove(addr) {
                        println!("Stopped listening on (e): {addr}");
                    }
                }
                FromSwarm::ExpiredListenAddr(ExpiredListenAddr { addr, listener_id }) => {
                    if let Entry::Occupied(mut entry) = self.listener.entry(listener_id) {
                        let list = entry.get_mut();
                        if let Some(index) = list.iter().position(|inner| addr == inner) {
                            list.remove(index);
                            println!("Stopped listening on (l): {addr}");
                        }

                        if list.is_empty() {
                            entry.remove();
                        }
                    }
                }
                FromSwarm::ListenerClosed(ListenerClosed { listener_id, .. }) => {
                    if let Some(addrs) = self.listener.remove(&listener_id) {
                        for addr in addrs {
                            println!("Stopped listening on (l): {addr}");
                        }
                    }
                }
                _ => {}
            }
        }

        fn poll(
            &mut self,
            _: &mut Context,
            _: &mut impl PollParameters,
        ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
            if let Some(event) = self.events.pop_front() {
                return Poll::Ready(event);
            }
            Poll::Pending
        }
    }
}
