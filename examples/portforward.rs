use std::{io, str::FromStr, time::Duration};

use clap::Parser;
use futures::{future::Either, StreamExt};
use libp2p::{
    autonat::Behaviour as Autonat,
    core::{
        muxing::StreamMuxerBox,
        transport::{timeout::TransportTimeout, Boxed, OrTransport},
        upgrade::{SelectUpgrade, Version},
    },
    dns::{DnsConfig, ResolverConfig},
    identify::{self, Behaviour as Identify, Info},
    identity::{self, Keypair},
    kad::{store::MemoryStore, Kademlia},
    mplex::MplexConfig,
    noise::{self, NoiseConfig},
    ping::Behaviour as Ping,
    quic::async_std::Transport as AsyncQuicTransport,
    quic::Config as QuicConfig,
    relay::client::Transport as ClientTransport,
    relay::client::{self, Behaviour as RelayClient},
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, SwarmBuilder, SwarmEvent},
    tcp::{async_io::Transport as AsyncTcpTransport, Config as GenTcpConfig},
    yamux::YamuxConfig,
    Multiaddr, PeerId, Transport,
};

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    relay_client: RelayClient,
    identify: Identify,
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
    };

    let mut swarm = SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id).build();

    let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;
    for peer_id in [
        "QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
        "QmQCU2EcMqAqQPR2i9bChDtGNJchTbq5TbXJJ16u19uLTa",
        "QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
        "QmcZf59bWwK5XFi76CZX8cbJ4BhTzzA3gU1ZjYZcYW3dwt",
    ]
    .iter()
    .filter_map(|p| p.parse().ok())
    {
        if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
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

    if let Ok(ip_addr) = swarm.behaviour().nat.external_addr().await {
        println!("External Address: {ip_addr}");
    }

    while let Some(event) = swarm.next().await {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                println!("Listening on: {address}");
            }
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
                    .any(|p| p.as_bytes() == libp2p::kad::protocol::DEFAULT_PROTO_NAME)
                {
                    if let Some(kad) = swarm.behaviour_mut().kad.as_mut() {
                        for addr in &listen_addrs {
                            kad.add_address(&peer_id, addr.clone());
                        }
                    }
                }

                if protocols
                    .iter()
                    .any(|p| p.as_bytes() == libp2p::autonat::DEFAULT_PROTOCOL_NAME)
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
    let xx_keypair = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&keypair)
        .unwrap();
    let noise_config = NoiseConfig::xx(xx_keypair).into_authenticated();

    let multiplex_upgrade = SelectUpgrade::new(YamuxConfig::default(), MplexConfig::new());

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

    let secret_key = identity::ed25519::SecretKey::from_bytes(&mut bytes)
        .expect("this returns `Err` only if the length is wrong; the length is correct; qed");
    identity::Keypair::Ed25519(secret_key.into())
}
