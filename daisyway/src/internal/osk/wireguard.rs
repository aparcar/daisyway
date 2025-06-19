use std::{
    future::Future,
    sync::{Arc, Mutex},
};

use anyhow::{ensure, Context, Result};
use log::{error, info};
#[cfg(target_os = "linux")]
use wireguard_uapi::{DeviceInterface, WgSocket};

use super::{OskHandler, SetOskReason};
use crate::internal::{daisyway::crypto::Key, util::base64_to_key};

#[derive(Clone)]
pub struct WireGuardOskHandler {
    pub socket: Arc<Mutex<WgSocket>>,
    pub interface: String,
    pub peer_id: Key,
}

impl WireGuardOskHandler {
    pub fn setup(peer_id: &str, interface: &str) -> Result<Self> {
        let peer_id_u8 = base64_to_key(peer_id.as_bytes()).expect("Invalid peer_id");

        #[cfg(target_os = "linux")]
        let socket = {
            let mut socket =
                WgSocket::connect().context("Failed to connect to WireGuard control socket.")?;

            let device = socket
                .get_device(DeviceInterface::from_name(interface.to_string()))
                .with_context(|| format!("Failed to access WireGuard interface {interface}"))?;
            ensure!(
                device.peers.iter().any(|p| p.public_key == peer_id_u8),
                "Could not find WireGuard peer {peer_id}"
            );

            Arc::new(Mutex::new(socket))
        };

        Ok(Self {
            socket,
            interface: interface.to_owned(),
            peer_id: peer_id_u8.to_owned(),
        })
    }

    async fn set_osk_impl(&self, key: Key, reason: SetOskReason) -> Result<()> {
        use SetOskReason as R;
        match reason {
            R::Fresh => info!(
                "Injecting fresh PSK into WireGuard interface {}",
                self.interface
            ),
            R::Stale => error!(
                "Erasing stale PSK in WireGuard interface {} by overwriting with a random key",
                self.interface
            ),
        };

        let mut set_peer = wireguard_uapi::set::Peer::from_public_key(&self.peer_id);
        set_peer
            .flags
            .push(wireguard_uapi::set::WgPeerF::UpdateOnly);
        set_peer.preshared_key = Some(&key);
        let mut set_dev = wireguard_uapi::set::Device::from_ifname(&self.interface);
        set_dev.peers.push(set_peer);

        self.socket.lock().unwrap().set_device(set_dev)?;

        Ok(())
    }
}

impl OskHandler for WireGuardOskHandler {
    fn set_osk(&self, key: Key, reason: SetOskReason) -> impl Future<Output = Result<()>> {
        self.set_osk_impl(key, reason)
    }
}

impl std::fmt::Debug for WireGuardOskHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardOskHandler")
            .field("socket", &"...")
            .field("interface", &self.interface)
            .field("peer_id", &self.peer_id)
            .finish()
    }
}
