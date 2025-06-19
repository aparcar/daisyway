use tokio::task::{AbortHandle, JoinHandle};

pub struct AbortOnDropHandle(AbortHandle);

impl From<AbortHandle> for AbortOnDropHandle {
    fn from(value: AbortHandle) -> Self {
        Self(value)
    }
}

impl<T> From<JoinHandle<T>> for AbortOnDropHandle {
    fn from(value: JoinHandle<T>) -> Self {
        value.abort_handle().into()
    }
}

impl Drop for AbortOnDropHandle {
    fn drop(&mut self) {
        self.0.abort();
    }
}
