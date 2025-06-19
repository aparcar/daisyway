use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};
use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};

use crate::internal::daisyway::crypto::Key;

pub type MixReader = <Shake256 as ExtendableOutput>::Reader;

// TODO: Use Rosenpass' secret memory facilities

// TODO: Integrate with Rosenpass' facilities
#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable)]
pub struct HashDomain {
    pub key: Key,
}

impl HashDomain {
    pub fn zero() -> Self {
        Self::new(Key::new_zeroed())
    }

    pub fn new(key: Key) -> Self {
        Self { key }
    }

    pub fn mix_begin_reader(self, data: &[u8]) -> MixReader {
        let mut hasher = Shake256::default();
        hasher.update(&self.key);
        hasher.update(data);

        hasher.finalize_xof()
    }

    pub fn mix_read_into<Out: IntoBytes + FromBytes + Immutable>(self, data: &[u8], out: &mut Out) {
        let mut reader = self.mix_begin_reader(data);
        reader.read(out.as_mut_bytes());
    }

    pub fn mix_read<Out: IntoBytes + FromBytes + Immutable + Default>(self, data: &[u8]) -> Out {
        let mut out = Out::default();
        self.mix_read_into(data, &mut out);
        out
    }

    pub fn mix(self, data: &[u8]) -> Self {
        Self {
            key: self.mix_read(data),
        }
    }

    pub fn mix_fork(self, data: &[u8]) -> (Self, Self) {
        #[repr(C, packed)]
        #[derive(Debug, FromBytes, IntoBytes, Immutable, Default)]
        struct TwoKeys(Key, Key);

        let TwoKeys(a, b) = self.mix_read(data);
        (Self::new(a), Self::new(b))
    }

    pub fn mix_trifork(self, data: &[u8]) -> (Self, Self, Self) {
        #[repr(C, packed)]
        #[derive(Debug, FromBytes, IntoBytes, Immutable, Default)]
        struct ThreeKeys(Key, Key, Key);

        let ThreeKeys(a, b, c) = self.mix_read(data);
        (Self::new(a), Self::new(b), Self::new(c))
    }

    pub fn into_key(self) -> Key {
        self.key
    }
}
