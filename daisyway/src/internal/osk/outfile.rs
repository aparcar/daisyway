use std::{
    fs::File,
    future::Future,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::Result;
use base64ct::{Base64, Encoding};
use log::{error, info};

use super::{OskHandler, SetOskReason};
use crate::internal::daisyway::crypto::{Key, KEY_LENGTH_B64};

#[derive(Debug)]
pub struct OutfileOskHandler {
    path: PathBuf,
}

impl OutfileOskHandler {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_owned(),
        }
    }

    async fn set_osk_impl(&self, key: Key, reason: SetOskReason) -> Result<()> {
        use SetOskReason as R;
        let why = match reason {
            R::Fresh => {
                info!("Writing fresh output key to {:?}", self.path);
                "exchanged"
            }
            R::Stale => {
                error!(
                    "Erasing stale key in {:?} by overwriting with a random key",
                    self.path
                );
                "stale"
            }
        };

        let mut buf = [0u8; KEY_LENGTH_B64];
        let key = Base64::encode(&key, &mut buf).unwrap();

        let path = Path::new(self.path.as_path());
        let mut file = File::create(path).expect("Failed to create file");

        file.write_all(key.as_bytes())
            .unwrap_or_else(|_| panic!("Failed to write PSK to file {}", &self.path.display()));

        println!("output-key {path:?} {why}");

        Ok(())
    }
}

impl OskHandler for OutfileOskHandler {
    fn set_osk(&self, key: Key, reason: SetOskReason) -> impl Future<Output = Result<()>> {
        self.set_osk_impl(key, reason)
    }
}
