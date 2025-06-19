use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::net::ToSocketAddrs;

use super::{DaisywayTcpClient, DaisywayTcpServer};
use crate::internal::{
    daisyway::crypto::DaisywayProtocolParameters, etsi014::Etsi014Connection, osk::OskHandler,
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum DaisywayTcpParticipantConfig {
    Client { endpoint: String },
    Server { listen: String },
}

#[derive(Debug, Clone)]
pub enum DaisywayTcpParticipant<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    Client(DaisywayTcpClient<O, Addr>),
    Server(DaisywayTcpServer<O, Addr>),
}

impl<O> DaisywayTcpParticipant<O, String>
where
    O: OskHandler + Clone,
{
    pub fn from_config(
        protocol_params: DaisywayProtocolParameters,
        config: &DaisywayTcpParticipantConfig,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
        rekey_interval: u64,
    ) -> Self {
        match config {
            DaisywayTcpParticipantConfig::Client { endpoint } => {
                Self::Client(DaisywayTcpClient::new(
                    protocol_params.clone(),
                    endpoint.clone(),
                    etsi_client,
                    osk_handler,
                ))
            }
            DaisywayTcpParticipantConfig::Server { listen } => {
                Self::Server(DaisywayTcpServer::new(
                    protocol_params.clone(),
                    listen.clone(),
                    etsi_client,
                    osk_handler,
                    rekey_interval,
                ))
            }
        }
    }
}

impl<O, Addr> DaisywayTcpParticipant<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    pub async fn event_loop(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Client(c) => c.event_loop().await,
            Self::Server(s) => s.event_loop().await,
        }
    }
}
