use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use zerocopy::FromZeros;

use crate::internal::{
    daisyway::{
        crypto::{DaisywayProtocolParameters, Key, REKEY_INTERVAL},
        net::{DaisywayTcpParticipant, DaisywayTcpParticipantConfig},
    },
    etsi014::{Etsi014Config, Etsi014Connection},
    osk::{OskDeadman, OskHandler, OutfileOskHandler},
    util::{base64_to_key, load_base64_key_file},
};

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct DaisywayConfig {
    pub etsi014: Etsi014Config,
    pub wireguard: WireGuardConfig,
    pub outfile: Option<OutfileConfig>,
    pub peer: PeerConfig,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WireGuardConfig {
    #[serde(rename = "self_public_key")]
    pub local_peer_id: String,
    #[serde(rename = "peer_public_key")]
    pub remote_peer_id: String,
    pub interface: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OutfileConfig {
    path: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PeerConfig {
    #[serde(flatten)]
    pub participant: DaisywayTcpParticipantConfig,
    pub psk_file: Option<PathBuf>,
}

pub struct Daisyway {
    pub participant: DaisywayTcpParticipant<OskDeadman, String>,
}

impl DaisywayConfig {
    pub async fn load_from_file<P: AsRef<std::path::Path> + std::fmt::Debug>(
        file_path: P,
    ) -> Result<Self> {
        let cfg = tokio::fs::read_to_string(file_path.as_ref())
            .await
            .with_context(|| format!("Failed to read config file {file_path:?}"))?;
        log::info!("CONFIG FILE: {cfg}");
        Ok(toml::from_str(&cfg)?)
    }
}

impl Daisyway {
    pub async fn from_config(cfg: &DaisywayConfig) -> Result<Self> {
        let rekey_interval = cfg.etsi014.interval_secs.unwrap_or(REKEY_INTERVAL);
        info!("Rekey interval: {rekey_interval}s");

        let psk = cfg
            .peer
            .psk_file
            .as_ref()
            .map(|file| {
                info!("Loading PSK file from {file:?}");
                load_base64_key_file(file).context("Could not load PSK file from {file:?}")
            })
            .unwrap_or_else(|| {
                info!("No PSK file supplied. Using zero PSK.");
                Ok(Key::new_zeroed())
            })?;

        let local_peer_id =
            base64_to_key(cfg.wireguard.local_peer_id.as_bytes()).with_context(|| {
                format!(
                    "Could not decode WireGuard local peer id {:?}",
                    cfg.wireguard.local_peer_id
                )
            })?;

        let remote_peer_id =
            base64_to_key(cfg.wireguard.remote_peer_id.as_bytes()).with_context(|| {
                format!(
                    "Could not decode WireGuard remote peer id {:?}",
                    cfg.wireguard.remote_peer_id
                )
            })?;

        let protocol_params = DaisywayProtocolParameters {
            psk,
            local_peer_id,
            remote_peer_id,
        };

        let etsi_client = Arc::new(Etsi014Connection::from_config(&cfg.etsi014)?);

        let osk_handler = match (&cfg.wireguard.interface, &cfg.outfile) {
            (None, None) => bail!("You need to specify either the wireguard.interface or outfile.path configuration option"),
            (Some(_), Some(_)) => bail!("You can not specify both the wireguard.interface and outfile.path configuration options"),
            (None, Some(OutfileConfig { path })) => {
                info!("Using Outfile as key handler, storing key in {path:?}",);
                start_deadman(OutfileOskHandler::new(path), rekey_interval)
            },
            #[cfg(not(target_os = "linux"))]
            (Some(_), None) => {
                bail!("Directly interfacing with WireGuard is only supported on Linux. Please use the outfile configuration option instead.");
            },
            #[cfg(target_os = "linux")]
            (Some(interface), None) => {
                let peer = &cfg.wireguard.remote_peer_id;
                info!(
                    "Using WireGuard as key handler injecting PSK into interface {interface} for peer {peer}",
                );
                start_deadman(
                    crate::internal::osk::WireGuardOskHandler::setup(peer, interface)
                        .context("Could start WireGuard key handler")?,
                    rekey_interval
                )
            },
        };

        let participant = DaisywayTcpParticipant::from_config(
            protocol_params,
            &cfg.peer.participant,
            etsi_client,
            osk_handler,
            rekey_interval,
        );

        Ok(Self { participant })
    }

    pub async fn event_loop(&mut self) -> Result<()> {
        self.participant.event_loop().await
    }
}

fn start_deadman<O>(o: O, rekey_interval: u64) -> OskDeadman
where
    O: OskHandler + std::fmt::Debug + Send + 'static,
{
    OskDeadman::start(Duration::from_secs(rekey_interval + 30), move || o)
}
