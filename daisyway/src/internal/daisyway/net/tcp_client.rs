use std::{sync::Arc, time::Duration};

use anyhow::Result;
use log::{debug, info, warn};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::internal::{
    daisyway::crypto::{DaisywayClientProtocol, DaisywayProtocolParameters},
    etsi014::Etsi014Connection,
    osk::OskHandler,
};

#[derive(Debug, Clone)]
pub struct DaisywayTcpClient<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    pub protocol_params: DaisywayProtocolParameters,
    pub endpoint: Addr,
    pub etsi_client: Arc<Etsi014Connection>,
    pub osk_handler: O,
}

impl<O, Addr> DaisywayTcpClient<O, Addr>
where
    O: OskHandler + Clone,
    Addr: ToSocketAddrs + std::fmt::Debug,
{
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        endpoint: Addr,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
    ) -> Self {
        Self {
            protocol_params,
            endpoint,
            etsi_client,
            osk_handler,
        }
    }

    pub async fn event_loop(&self) -> Result<()> {
        loop {
            let res = self.event_loop_without_error_handling().await;

            if let Err(err) = res {
                warn!("[CLIENT] Error on connection: {err}");
                debug!("[CLIENT] Error on connection (full error message): {err:?}");
            }

            info!(
                "[CLIENT] Retrying connection to peer at {:?}...",
                &self.endpoint
            );
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    pub async fn event_loop_without_error_handling(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.endpoint).await?;
        info!("[CLIENT] Connected to server {:?}", &self.endpoint);

        let mut handler = DaisywayClientProtocol::new(
            self.protocol_params.clone(),
            stream,
            self.etsi_client.clone(),
            self.osk_handler.clone(),
        );
        handler.event_loop().await
    }
}
