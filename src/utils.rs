use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use igd_next::PortMappingProtocol;
use libp2p::{multiaddr::Protocol, Multiaddr};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum MappingProtocol {
    TCP,
    UDP,
}

#[cfg(not(target_os = "ios"))]
impl From<natpmp::Protocol> for MappingProtocol {
    fn from(protocol: natpmp::Protocol) -> Self {
        match protocol {
            natpmp::Protocol::TCP => MappingProtocol::TCP,
            natpmp::Protocol::UDP => MappingProtocol::UDP,
        }
    }
}

impl From<PortMappingProtocol> for MappingProtocol {
    fn from(protocol: PortMappingProtocol) -> Self {
        match protocol {
            PortMappingProtocol::TCP => MappingProtocol::TCP,
            PortMappingProtocol::UDP => MappingProtocol::UDP,
        }
    }
}

impl From<MappingProtocol> for PortMappingProtocol {
    fn from(protocol: MappingProtocol) -> Self {
        match protocol {
            MappingProtocol::TCP => PortMappingProtocol::TCP,
            MappingProtocol::UDP => PortMappingProtocol::UDP,
        }
    }
}

#[cfg(not(target_os = "ios"))]
impl From<MappingProtocol> for natpmp::Protocol {
    fn from(protocol: MappingProtocol) -> Self {
        match protocol {
            MappingProtocol::TCP => natpmp::Protocol::TCP,
            MappingProtocol::UDP => natpmp::Protocol::UDP,
        }
    }
}

pub fn multiaddr_to_socket_port(addr: &Multiaddr) -> Option<(SocketAddr, MappingProtocol)> {
    let mut iter = addr.iter();
    let Some(mut addr) = iter
        .next()
        .and_then(|proto| match proto {
            Protocol::Ip4(addr) if addr.is_private() => {
                Some(SocketAddr::V4(SocketAddrV4::new(addr, 0)))
            }
            Protocol::Ip6(addr)
                if !addr.is_loopback()
                    && (addr.segments()[0] & 0xffc0) != 0xfe80
                    && (addr.segments()[0] & 0xfe00) != 0xfc00 =>
            {
                Some(SocketAddr::V6(SocketAddrV6::new(addr, 0, 0, 0)))
            }
            _ => None,
        }) else { return None };

    let Some((protocol, port)) = iter
        .next()
        .and_then(|proto| match proto {
            Protocol::Tcp(port) => Some((MappingProtocol::TCP, port)),
            Protocol::Udp(port) => Some((MappingProtocol::UDP, port)),
            _ => None,
        }) else { return None; };

    addr.set_port(port);

    Some((addr, protocol))
}

pub enum IpOrSocket {
    Socket(SocketAddr),
    Ip(IpAddr)
}

impl From<SocketAddr> for IpOrSocket {
    fn from(socket: SocketAddr) -> Self {
        IpOrSocket::Socket(socket)
    }
}

impl From<IpAddr> for IpOrSocket {
    fn from(ip: IpAddr) -> Self {
        IpOrSocket::Ip(ip)
    }
}

pub fn to_multipaddr(addr: SocketAddr, proto: MappingProtocol) -> Multiaddr {
    let port = addr.port();
    let ip = addr.ip();
    let mut multiaddr = Multiaddr::empty();
    match ip {
        IpAddr::V4(ip) => multiaddr.push(Protocol::Ip4(ip)),
        IpAddr::V6(ip) => multiaddr.push(Protocol::Ip6(ip)),
    }

    match proto {
        MappingProtocol::TCP => multiaddr.push(Protocol::Tcp(port)),
        MappingProtocol::UDP => multiaddr.push(Protocol::Udp(port))
    }

    multiaddr
}
