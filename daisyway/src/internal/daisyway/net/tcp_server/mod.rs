use std::sync::Arc;

use anyhow::Result;
use tokio::net::{TcpListener, ToSocketAddrs};

use crate::internal::{
    daisyway::crypto::DaisywayProtocolParameters, etsi014::Etsi014Connection, osk::OskHandler,
};

mod abort_on_drop_handle;
mod connection_manager;
mod events;
mod fanout_connection_handler;
mod fanout_osk_handler;

const MAX_BUDDING_CONNECTIONS: usize = 2000;

type ConnectionId = usize;

#[derive(Debug, Clone)]
pub struct DaisywayTcpServer<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    pub protocol_params: DaisywayProtocolParameters,
    pub listen_addr: Addr,
    pub etsi_client: Arc<Etsi014Connection>,
    pub osk_handler: O,
    pub rekey_interval: u64,
}

impl<O, Addr> DaisywayTcpServer<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        listen_addr: Addr,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
        rekey_interval: u64,
    ) -> Self {
        Self {
            protocol_params,
            listen_addr,
            etsi_client,
            osk_handler,
            rekey_interval,
        }
    }

    pub async fn event_loop(&mut self) -> Result<()> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        let mut manager = connection_manager::ConnectionManager::new(
            self.protocol_params.clone(),
            self.etsi_client.clone(),
            self.osk_handler.clone(),
            listener,
            self.rekey_interval,
        );
        manager.event_loop().await
    }
}
