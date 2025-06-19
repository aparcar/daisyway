//! Various handlers for the shared key produced by the daisyway protocol

use std::future::Future;

use anyhow::Result;
use rand::Rng;

use crate::internal::daisyway::crypto::Key;

mod deadman;
mod outfile;

pub use deadman::*;
pub use outfile::*;

#[cfg(target_os = "linux")]
mod wireguard;

#[cfg(target_os = "linux")]
pub use wireguard::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SetOskReason {
    /// This is a new, secure key
    Fresh,
    /// This is a randomly chosen, invalid key, used explicitly to erase the old key
    Stale,
}

pub trait OskHandler {
    fn set_osk(&self, key: Key, reason: SetOskReason) -> impl Future<Output = Result<()>>;
    fn set_fresh_osk(&self, key: Key) -> impl Future<Output = Result<()>> {
        self.set_osk(key, SetOskReason::Fresh)
    }
    fn erase_stale_osk(&self) -> impl Future<Output = Result<()>> {
        let key = rand::rng().random();
        self.set_osk(key, SetOskReason::Stale)
    }
}
