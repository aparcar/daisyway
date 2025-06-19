use std::net::SocketAddr;

use tokio::net::TcpStream;

use super::ConnectionId;
use crate::internal::{daisyway::crypto::Key, osk::SetOskReason};

pub struct AcceptEvent {
    pub stream: TcpStream,
    pub addr: SocketAddr,
}

pub struct ExitEvent {
    pub connection_id: ConnectionId,
}

pub struct OskEvent {
    pub connection_id: ConnectionId,
    pub key: Key,
    pub reason: SetOskReason,
}

pub enum ConnectionHandlerEvent {
    Exit(ExitEvent),
    Osk(OskEvent),
}

pub enum StreamEvent {
    Accept(AcceptEvent),
    Exit(ExitEvent),
    Osk(OskEvent),
}

impl From<ConnectionHandlerEvent> for StreamEvent {
    fn from(value: ConnectionHandlerEvent) -> Self {
        use ConnectionHandlerEvent as C;
        use StreamEvent as S;
        match value {
            C::Exit(exit) => S::Exit(exit),
            C::Osk(osk) => S::Osk(osk),
        }
    }
}
