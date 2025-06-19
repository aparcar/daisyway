use anyhow::{ensure, Result};
use rand::Rng;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use super::hash_domain::HashDomain;
use crate::internal::{
    etsi014::Etsi014Key,
    util::{CascadeExt, UuidBytes},
};

pub const KEY_LENGTH: usize = 32;
pub const KEY_LENGTH_B64: usize = KEY_LENGTH * 4 / 3 + 4;

pub const REKEY_INTERVAL: u64 = 120;

pub type Key = [u8; KEY_LENGTH];
pub type Nonce = Key;
pub type HashValue = Key;

enum ProtocolDomains {}

impl ProtocolDomains {
    const PROTOCOL_DOMAIN: &[u8] =
        b"Daisyway v1 by Paul Spooren & Karolin Varner, Feb-2025 with Shake256";

    pub fn root() -> HashDomain {
        HashDomain::zero().mix(Self::PROTOCOL_DOMAIN)
    }

    pub fn derive_key() -> HashDomain {
        Self::root().mix(b"derive key")
    }
}

/// WireGuard public key
pub type PublicKey = [u8; 32];

/// WireGuard peer id; i.e. a WireGuard public key
pub type PeerId = PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaisywayProtocolParameters {
    pub psk: Key,
    pub local_peer_id: PeerId,
    pub remote_peer_id: PeerId,
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, Clone, Copy)]
pub struct WireGuardConnectionId {
    first_peer: PeerId,
    second_peer: PeerId,
}

impl WireGuardConnectionId {
    pub fn new(self_public_key: PeerId, peer_public_key: PeerId) -> Self {
        let [first_peer, second_peer] = [self_public_key, peer_public_key].cas(|a| a.sort());
        Self {
            first_peer,
            second_peer,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable)]
#[allow(dead_code)] // Used through zerocopy conversion
struct KdfInput {
    psk: Key,                                       // +32 = 64
    nonce: Nonce,                                   // +32 = 96
    qkd_key: Key,                                   // +32 = 128
    qkd_key_id: UuidBytes,                          // +16 = 144
    wireguard_connection_id: WireGuardConnectionId, // +64 = 208
}

impl KdfInput {
    pub fn new(
        psk: Key,
        nonce: Key,
        qkd_key: Etsi014Key,
        wireguard_connection_id: WireGuardConnectionId,
    ) -> Self {
        let Etsi014Key {
            key: qkd_key,
            id: qkd_key_id,
        } = qkd_key;
        let qkd_key_id = qkd_key_id.to_bytes_le();
        Self {
            psk,
            nonce,
            qkd_key,
            qkd_key_id,
            wireguard_connection_id,
        }
    }
}

pub fn derive_daisyway_key(
    params: &DaisywayProtocolParameters,
    nonce: Nonce,
    key: Etsi014Key,
) -> Key {
    let conn_id = WireGuardConnectionId::new(params.local_peer_id, params.remote_peer_id);
    let kdf_input = KdfInput::new(params.psk, nonce, key, conn_id);
    ProtocolDomains::derive_key()
        .mix(kdf_input.as_bytes())
        .into_key()
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable)]
pub struct RekeyReq {
    pub qkd_key_id: UuidBytes,
    pub nonce: Nonce,
}

impl RekeyReq {
    pub fn new(qkd_key_id: UuidBytes) -> Self {
        let nonce: Nonce = rand::rng().random();
        Self { qkd_key_id, nonce }
    }
}

#[repr(C, packed)]
#[derive(Debug, FromBytes, IntoBytes, Immutable, Clone, Copy, PartialEq, Eq)]
pub struct RekeyAck {
    pub dummy_data: u8,
}

impl RekeyAck {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self == &REKEY_ACK,
            "Rekey acknowledgement is invalid: Expected {REKEY_ACK:?} but received {self:?}"
        );
        Ok(())
    }
}

pub const REKEY_ACK: RekeyAck = RekeyAck { dummy_data: 1 };
