use std::sync::Arc;

use anyhow::{Context, Result};
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;
use zerocopy::{FromZeros, IntoBytes};

use super::{derive_daisyway_key, DaisywayProtocolParameters, Key, RekeyReq};
use crate::internal::{daisyway::crypto::REKEY_ACK, etsi014::Etsi014Connection, osk::OskHandler};

pub struct DaisywayClientProtocol<O, Stream>
where
    O: OskHandler,
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    pub protocol_params: DaisywayProtocolParameters,
    pub stream: Stream,
    pub etsi_client: Arc<Etsi014Connection>,
    pub osk_handler: O,
}

impl<O, Stream> DaisywayClientProtocol<O, Stream>
where
    O: OskHandler,
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        stream: Stream,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
    ) -> Self {
        Self {
            protocol_params,
            stream,
            etsi_client,
            osk_handler,
        }
    }

    pub async fn event_loop(&mut self) -> Result<()> {
        loop {
            let key = self.wait_for_key_negotiation().await?;
            self.osk_handler.set_fresh_osk(key).await?;
        }
    }

    async fn wait_for_key_negotiation(&mut self) -> Result<Key> {
        let mut rekey_req = RekeyReq::new_zeroed();
        self.stream
            .read_exact(rekey_req.as_mut_bytes())
            .await
            .context("Failed to read rekey request message")?;

        let nonce = rekey_req.nonce;
        let key = self
            .etsi_client
            .fetch_specific_key(Uuid::from_bytes(rekey_req.qkd_key_id))
            .await
            .context("Failed to fetch key from QKD device")?;

        self.stream
            .write_all(REKEY_ACK.as_bytes())
            .await
            .context("Failed to send rekey acknowledgement message")?;

        debug!("[SERVER] Received QKD ID: {}", key.id);

        Ok(derive_daisyway_key(&self.protocol_params, nonce, key))
    }
}
