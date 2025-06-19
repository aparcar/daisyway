use std::sync::Arc;

use anyhow::Result;
use tokio::{net::TcpStream, spawn, sync::mpsc, task::JoinHandle};

use super::{
    events::{ConnectionHandlerEvent, ExitEvent},
    fanout_osk_handler::FanoutOskHandler,
    ConnectionId,
};
use crate::internal::{
    daisyway::crypto::{DaisywayProtocolParameters, DaisywayServerProtocol},
    etsi014::Etsi014Connection,
};

#[derive(Clone)]
pub struct FanoutConnectionHandler {
    protocol_params: DaisywayProtocolParameters,
    etsi_client: Arc<Etsi014Connection>,
    manager_notification_tx: mpsc::Sender<ConnectionHandlerEvent>,
    rekey_interval: u64,
}

impl FanoutConnectionHandler {
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        etsi_client: Arc<Etsi014Connection>,
        manager_notification_tx: mpsc::Sender<ConnectionHandlerEvent>,
        rekey_interval: u64,
    ) -> Self {
        Self {
            protocol_params,
            etsi_client,
            manager_notification_tx,
            rekey_interval,
        }
    }

    pub fn spawn(self, connection_id: ConnectionId, stream: TcpStream) -> JoinHandle<()> {
        spawn(async move { self.init_task(connection_id, stream).await })
    }

    async fn init_task(self, connection_id: ConnectionId, stream: TcpStream) {
        let Self {
            manager_notification_tx,
            ..
        } = self.clone();

        // Run the connection handler, handle any errors
        if let Err(err) = self.event_loop(connection_id, stream).await {
            log::warn!("[SERVER] Error in connection #{connection_id}: {err}");
            log::debug!(
                "[SERVER] Error in connection #{connection_id} (full error message): {err:?}"
            );
        }

        // Tell the connection manager that this particular connection is exiting
        let res = manager_notification_tx
            .send(ConnectionHandlerEvent::Exit(ExitEvent { connection_id }))
            .await;
        if let Err(err) = res {
            log::warn!("[SERVER] Failed to inform connection manager about exit of connection #{connection_id}: {err}");
            log::debug!("[SERVER] Failed to inform connection manager about exit of connection #{connection_id} (full error message): {err:?}");
        }
    }

    async fn event_loop(self, connection_id: ConnectionId, stream: TcpStream) -> Result<()> {
        let Self {
            protocol_params,
            etsi_client,
            manager_notification_tx,
            rekey_interval,
        } = self;

        let osk_handler = FanoutOskHandler::new(manager_notification_tx, connection_id);
        let mut protocol_handler = DaisywayServerProtocol::new(
            protocol_params.clone(),
            stream,
            etsi_client.clone(),
            osk_handler,
            rekey_interval,
        );

        protocol_handler.event_loop().await
    }
}
