use std::{future::Future, time::Duration};

use anyhow::Result;
use tokio::{sync::mpsc, time::timeout_at};

use super::{OskHandler, SetOskReason};
use crate::internal::daisyway::crypto::Key;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum DeadmanRequest {
    SetOsk { key: Key, reason: SetOskReason },
}

/// [OskHandler] that automatically erases output keys.
///
/// Spawns a thread in the background which immediately erases the current output key.
/// Ever time [OskHandler::set_osk] is called, the background thread is asked to update
/// the output key to the specific value. If update request is received after the configured timeout,
/// then the OSK is automatically erased.
///
/// Cloning just creates a new reference to the underlying thread.
///
/// Once all [OskDeadman] instances have been dropped, the worker thread will automatically be
/// closed and the OSK will be erased.
#[derive(Debug, Clone)]
pub struct OskDeadman {
    client: mpsc::Sender<DeadmanRequest>,
}

impl OskDeadman {
    pub fn start<Broker, F>(erase_after: Duration, make_broker: F) -> Self
    where
        Broker: std::fmt::Debug + OskHandler + Send + 'static,
        F: FnOnce() -> Broker + Send + 'static,
    {
        let client = DeadmanWorker::start(erase_after, make_broker);
        Self { client }
    }

    async fn set_osk_impl(&self, key: Key, reason: SetOskReason) -> Result<()> {
        self.client
            .send(DeadmanRequest::SetOsk { key, reason })
            .await?;
        Ok(())
    }
}

impl OskHandler for OskDeadman {
    fn set_osk(&self, key: Key, reason: SetOskReason) -> impl Future<Output = Result<()>> {
        self.set_osk_impl(key, reason)
    }
}

#[derive(Debug)]
struct DeadmanWorker<Broker>
where
    Broker: std::fmt::Debug + OskHandler + Send + 'static,
{
    broker: Broker,
    erase_after: Duration,
    requests: mpsc::Receiver<DeadmanRequest>,
}

impl<Broker> DeadmanWorker<Broker>
where
    Broker: std::fmt::Debug + OskHandler + Send + 'static,
{
    fn start<F>(erase_after: Duration, make_broker: F) -> mpsc::Sender<DeadmanRequest>
    where
        F: FnOnce() -> Broker + Send + 'static,
    {
        let (request_tx, request_rx) = mpsc::channel(8);
        std::thread::spawn(move || {
            let worker = Self {
                erase_after,
                requests: request_rx,
                broker: make_broker(),
            };
            match worker.thread_run() {
                Err(e) => panic!("Error in output key worker thread: {e:?}"),
                Ok(()) => log::trace!("Output key worker thread exiting!"),
            }
        });
        request_tx
    }

    fn thread_run(mut self) -> Result<()> {
        log::trace!("enter: DeadmanWorker::thread_run({self:?})");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let res = runtime.block_on(self.event_loop());
        log::trace!("exit: DeadmanWorker::thread_run({self:?})");
        res
    }

    async fn event_loop(&mut self) -> Result<()> {
        log::trace!("Shutting down internal output key broker. Erasing output key.");
        self.broker.erase_stale_osk().await?;

        let mut next_erase;
        loop {
            next_erase = tokio::time::Instant::now() + self.erase_after;
            let req = timeout_at(next_erase, self.requests.recv()).await.ok();
            match req {
                Some(Some(DeadmanRequest::SetOsk { key, reason })) => {
                    log::debug!("Output key DeadmanWorker received SetOsk request – updating OSK.");
                    self.broker.set_osk(key, reason).await?;
                }
                Some(None) => {
                    log::info!("Shutting down internal output key broker. Erasing output key.");
                    self.broker.erase_stale_osk().await?;
                    return Ok(());
                }
                None => {
                    log::warn!("Output key lifetime ended – erasing key");
                    self.broker.erase_stale_osk().await?;
                }
            }
        }
    }
}
