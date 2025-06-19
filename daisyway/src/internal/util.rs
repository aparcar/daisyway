use anyhow::Result;
use base64ct::{Base64, Encoding};
use zerocopy::FromZeros;

use crate::internal::daisyway::crypto::{Key, KEY_LENGTH_B64};

pub type UuidBytes = [u8; 16];
pub type ConnectionIdBytes = [u8; 64];

pub trait ReadExt: std::io::Read {
    fn read_to_end_up_to(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::ErrorKind as K;

        let mut red = 0usize;
        loop {
            let left = &mut buf[red..];
            if left.is_empty() {
                return Ok(red);
            }

            let cnt = match self.read(left) {
                Ok(0) => return Ok(red),
                Ok(v) => v,
                Err(e) if e.kind() == K::Interrupted => continue,
                Err(e) => return Err(e),
            };

            red += cnt;
        }
    }
}

impl<T: std::io::Read> ReadExt for T {}

pub fn run<R, F: FnOnce() -> R>(f: F) -> R {
    f()
}

pub async fn run_async<R, F: AsyncFnOnce() -> R>(f: F) -> R {
    f().await
}

pub fn base64_to_key(encoded_key: &[u8]) -> Result<Key> {
    let mut key = Key::new_zeroed();
    Base64::decode(encoded_key, &mut key).map_err(|e| anyhow::anyhow!(e))?;
    Ok(key)
}

pub fn load_base64_key_file(file: &std::path::Path) -> Result<Key> {
    let mut psk_b64 = [0u8; KEY_LENGTH_B64];
    let psk_b64_len = std::fs::File::open(file)?.read_to_end_up_to(&mut psk_b64)?;
    let psk_b64 = &psk_b64[..psk_b64_len];
    let psk_b64 = match psk_b64.last().copied().map(|b| b.into()) {
        Some('\n') => &psk_b64[..psk_b64.len() - 1], // Trim trailing newline
        _ => psk_b64,
    };
    base64_to_key(psk_b64)
}

// TODO: This can be replaced with the IoErrorKind trait in Rosenpass itself
// if an implementation for anyhow errors is added
pub fn io_error_kind(e: &anyhow::Error) -> Option<std::io::ErrorKind> {
    e.downcast_ref::<std::io::Error>()?.kind().some()
}

/// Extension trait for getting the length of types with constant length
pub trait ConstLenExt {
    const LEN: usize;
}

impl<T, const L: usize> ConstLenExt for [T; L] {
    const LEN: usize = L;
}

/// Trait for the ok operation, which provides a way to convert a value into a Result
/// # Examples
/// ```rust
/// # use daisyway::internal::util::OkExt;
/// let value: i32 = 42;
/// let result: Result<i32, &str> = value.ok();
///
/// assert_eq!(result, Ok(42));
///
/// let value = "hello";
/// let result: Result<&str, &str> = value.ok();
///
/// assert_eq!(result, Ok("hello"));
/// ```
// TODO: This has been copied from the Rosenpass repo. We should eventually just depend on
// rosenpass itself.
pub trait OkExt<E>: Sized {
    /// Wraps a value in a Result::Ok variant
    fn ok(self) -> Result<Self, E>;
}

impl<T, E> OkExt<E> for T {
    fn ok(self) -> Result<Self, E> {
        Ok(self)
    }
}

/// A helper trait for turning any type value into `Some(value)`.
///
/// # Examples
///
/// ```
/// use daisyway::internal::util::SomeExt;
///
/// let x = 42;
/// let y = x.some();
///
/// assert_eq!(y, Some(42));
/// ```
// TODO: This has been copied from the Rosenpass repo. We should eventually just depend on
// rosenpass itself.
pub trait SomeExt: Sized {
    /// Wraps the calling value in `Some()`.
    fn some(self) -> Option<Self> {
        Some(self)
    }
}

impl<T> SomeExt for T {}

pub trait CascadeExt: Sized {
    fn cas<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}

impl<T: Sized> CascadeExt for T {
    fn cas<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}

/// A trait that provides a method to discard a value without explicitly handling its results.
///
/// # Examples
///
/// ```rust
/// # use daisyway::internal::util::DiscardResultExt;
/// let result: () = (|| { return 42u32 })().discard_result(); // Just discard
/// ```
// TODO: This has been copied from the Rosenpass repo. We should eventually just depend on
// rosenpass itself.
pub trait DiscardResultExt {
    /// Consumes and discards a value without doing anything with it.
    fn discard_result(self);
}

impl<T> DiscardResultExt for T {
    fn discard_result(self) {}
}
