use std::future::Future;

use anyhow::Result;
use tokio::sync::mpsc;

use super::{
    events::{ConnectionHandlerEvent, OskEvent},
    ConnectionId,
};
use crate::internal::{
    daisyway::crypto::Key,
    osk::{OskHandler, SetOskReason},
};

pub struct FanoutOskHandler {
    pub manager_notification_tx: mpsc::Sender<ConnectionHandlerEvent>,
    pub connection_id: ConnectionId,
}

impl FanoutOskHandler {
    pub fn new(
        manager_notification_tx: mpsc::Sender<ConnectionHandlerEvent>,
        connection_id: ConnectionId,
    ) -> Self {
        Self {
            manager_notification_tx,
            connection_id,
        }
    }

    async fn set_osk_impl(&self, key: Key, reason: SetOskReason) -> Result<()> {
        let Self { connection_id, .. } = *self;
        self.manager_notification_tx
            .send(ConnectionHandlerEvent::Osk(OskEvent {
                key,
                reason,
                connection_id,
            }))
            .await?;
        Ok(())
    }
}

impl OskHandler for FanoutOskHandler {
    fn set_osk(&self, key: Key, reason: SetOskReason) -> impl Future<Output = Result<()>> {
        self.set_osk_impl(key, reason)
    }
}
