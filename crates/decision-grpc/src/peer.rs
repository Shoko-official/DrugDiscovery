use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct DecisionGrpcPeerKey(IpAddr);

impl DecisionGrpcPeerKey {
    pub fn from_socket_addr(address: SocketAddr) -> Self {
        let peer = match address.ip() {
            IpAddr::V6(address) => address
                .to_ipv4_mapped()
                .map_or(IpAddr::V6(address), IpAddr::V4),
            address => address,
        };
        Self(peer)
    }
}

impl fmt::Debug for DecisionGrpcPeerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcPeerKey")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DecisionGrpcConnectInfo {
    peer: DecisionGrpcPeerKey,
}

impl DecisionGrpcConnectInfo {
    pub fn new(peer: DecisionGrpcPeerKey) -> Self {
        Self { peer }
    }

    pub fn peer(self) -> DecisionGrpcPeerKey {
        self.peer
    }
}

impl fmt::Debug for DecisionGrpcConnectInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DecisionGrpcConnectInfo")
    }
}
