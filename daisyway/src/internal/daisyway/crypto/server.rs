use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use log::debug;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zerocopy::{FromZeros, IntoBytes};

use super::{derive_daisyway_key, DaisywayProtocolParameters, Key, RekeyReq};
use crate::internal::{daisyway::crypto::RekeyAck, etsi014::Etsi014Connection, osk::OskHandler};

pub struct DaisywayServerProtocol<O, Stream>
where
    O: OskHandler,
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    pub protocol_params: DaisywayProtocolParameters,
    pub stream: Stream,
    pub etsi_client: Arc<Etsi014Connection>,
    pub osk_handler: O,
    pub rekey_interval: u64,
}

impl<O, Stream> DaisywayServerProtocol<O, Stream>
where
    O: OskHandler,
    Stream: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        stream: Stream,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
        rekey_interval: u64,
    ) -> Self {
        Self {
            protocol_params,
            stream,
            etsi_client,
            osk_handler,
            rekey_interval,
        }
    }

    pub async fn event_loop(&mut self) -> Result<()> {
        loop {
            let key = self.negotiate_key().await?;
            self.osk_handler.set_fresh_osk(key).await?;
            tokio::time::sleep(Duration::from_secs(self.rekey_interval)).await;
        }
    }

    async fn negotiate_key(&mut self) -> Result<Key> {
        let key = self
            .etsi_client
            .fetch_any_key()
            .await
            .context("Failed to fetch a QKD key.")?;
        debug!("[CLIENT] Sending QKD ID: {:?}", key.id);

        let rekey_req = RekeyReq::new(key.id.as_bytes().to_owned());
        let nonce = rekey_req.nonce;
        self.stream
            .write_all(rekey_req.as_bytes())
            .await
            .context("Could not send QKD key and nonce to server")?;

        let mut ack = RekeyAck::new_zeroed();
        self.stream
            .read_exact(ack.as_mut_bytes())
            .await
            .map_err(|e| anyhow!(e))
            .and_then(|_| ack.validate())
            .context("Failed to receive rekey acknoledgement message")?;

        Ok(derive_daisyway_key(&self.protocol_params, nonce, key))
    }
}
