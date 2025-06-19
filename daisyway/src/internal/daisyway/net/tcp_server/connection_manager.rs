use std::{collections::BTreeMap, sync::Arc};

use anyhow::{Context, Result};
use log::info;
use tokio::{net::TcpListener, sync::mpsc};

use super::{
    abort_on_drop_handle::AbortOnDropHandle,
    events::{AcceptEvent, ConnectionHandlerEvent, ExitEvent, OskEvent, StreamEvent},
    fanout_connection_handler::FanoutConnectionHandler,
    ConnectionId, MAX_BUDDING_CONNECTIONS,
};
use crate::internal::{
    daisyway::crypto::DaisywayProtocolParameters, etsi014::Etsi014Connection, osk::OskHandler,
};

pub struct ConnectionManager<O>
where
    O: OskHandler + Clone,
{
    listener: TcpListener,
    osk_handler: O,

    fanout_connection_handler: FanoutConnectionHandler,
    manager_notification_rx: mpsc::Receiver<ConnectionHandlerEvent>,

    next_connection_id: ConnectionId,
    active_connection: Option<(ConnectionId, AbortOnDropHandle)>,
    budding_connections: BTreeMap<ConnectionId, AbortOnDropHandle>,
}

impl<O> ConnectionManager<O>
where
    O: OskHandler + Clone,
{
    pub fn new(
        protocol_params: DaisywayProtocolParameters,
        etsi_client: Arc<Etsi014Connection>,
        osk_handler: O,
        listener: TcpListener,
        rekey_interval: u64,
    ) -> Self {
        let (manager_notification_tx, manager_notification_rx) = mpsc::channel(16);
        let fanout_connection_handler = FanoutConnectionHandler::new(
            protocol_params,
            etsi_client,
            manager_notification_tx,
            rekey_interval,
        );
        Self {
            listener,
            osk_handler,
            fanout_connection_handler,
            active_connection: None,
            budding_connections: BTreeMap::new(),
            next_connection_id: 0,
            manager_notification_rx,
        }
    }

    pub async fn event_loop(&mut self) -> Result<()> {
        loop {
            let ev = tokio::select! {
                accept_res = self.listener.accept() => {
                    let (stream, addr) = accept_res?;
                    StreamEvent::Accept(AcceptEvent { stream, addr })
                },
                maybe_notif = self.manager_notification_rx.recv() => {
                    maybe_notif
                        .context("OSK notification queue closed. This is a bug!")?
                        .into()
                },
            };

            self.on_event(ev).await?;
        }
    }

    async fn on_event(&mut self, ev: StreamEvent) -> Result<()> {
        use StreamEvent as E;
        match ev {
            E::Accept(ev) => self.on_accept(ev).await,
            E::Exit(ev) => self.on_exit(ev).await,
            E::Osk(ev) => self.on_osk(ev).await,
        }
    }

    async fn on_accept(&mut self, ev: AcceptEvent) -> Result<()> {
        let connection_id = self.allocate_connection_id();
        info!(
            "[SERVER] Accepted connection #{connection_id} from {:?}",
            ev.addr
        );

        // Make sure there is space in the budding connections
        if self.budding_connections.len() >= MAX_BUDDING_CONNECTIONS {
            let (pruned_id, _handle) = self.budding_connections.pop_first().expect(
                "Could not prune oldest budding connection to make space \
                    for a new one, because data structure returned None. \
                    This is a bug!",
            );
            log::info!(
                "Pruning oldest budding connection #{pruned_id} \
                to make space for new connection #{connection_id}"
            );
        }

        // Set up the protocol handler task
        let abort_handle = self
            .fanout_connection_handler
            .clone()
            .spawn(connection_id, ev.stream)
            .into();

        // Register the connection as a budding connection
        self.budding_connections.insert(connection_id, abort_handle);

        Ok(())
    }

    async fn on_exit(&mut self, ev: ExitEvent) -> Result<()> {
        let conn_id = ev.connection_id;

        if Some(conn_id) == self.active_connection_id() {
            log::info!(
                "The TCP connection currently used to negotiate keys (#{conn_id}) has exited."
            );
            self.active_connection.take();
        } else if self.budding_connections.remove(&ev.connection_id).is_some() {
            log::debug!("Budding connection #{conn_id} has exited.");
        } else {
            log::warn!("Received exit notification for non-existent connection #{conn_id}. This is likely a bug!");
        }

        Ok(())
    }

    async fn on_osk(&mut self, ev: OskEvent) -> Result<()> {
        use std::cmp::Ordering as Ord;

        let conn_id = ev.connection_id;
        let active_id = self.active_connection_id();
        let conn_lifecycle = active_id
            .map(|active| conn_id.cmp(&active))
            .unwrap_or(Ord::Greater);

        match conn_lifecycle {
            // This comes from a stale session that has already been superseded
            Ord::Less => self.on_osk_from_stale(ev).await,
            // This comes from the currently active session
            Ord::Equal => self.on_osk_from_active(ev).await,
            // This comes from a budding (not-yet active) session
            Ord::Greater => self.on_osk_from_budding(ev).await,
        }
    }

    async fn on_osk_from_stale(&mut self, ev: OskEvent) -> Result<()> {
        let conn_id = ev.connection_id;
        log::debug!("Received OSK event from stale session #{conn_id}; discarding.");
        Ok(())
    }

    async fn on_osk_from_active(&mut self, ev: OskEvent) -> Result<()> {
        let conn_id = ev.connection_id;
        log::debug!("Receiving OSK from active connection #{conn_id}; forwarding.");
        self.osk_handler.set_osk(ev.key, ev.reason).await
    }

    async fn on_osk_from_budding(&mut self, ev: OskEvent) -> Result<()> {
        let new_active_id = ev.connection_id;
        let old_active_id = self.active_connection_id();

        // Extract the handle to the new, budding connection id
        let new_active_handle = match self.budding_connections.remove(&new_active_id) {
            None => {
                log::warn!(
                    "Received ouput key from non exitstend connection #{new_active_id}. \
                    This is likely a bug! Ignoring."
                );
                return Ok(());
            }
            Some(handle) => handle,
        };

        // Drop all the now-stale budding connections
        let mut removed = self.budding_connections.split_off(&new_active_id);
        std::mem::swap(&mut removed, &mut self.budding_connections);

        // Debug print
        log::debug!(
            "Receiving OSK from budding connection #{new_active_id}: \
            Promoting connection #{new_active_id} to active, \
            replacing the previously active connection #{old_active_id:?} \
            while skipping over {} budding connections
            that never became active.",
            removed.len(),
        );

        // Promote the new connection to active
        self.active_connection = Some((new_active_id, new_active_handle));

        // Finally, propagate the event
        self.osk_handler.set_osk(ev.key, ev.reason).await
    }

    fn active_connection_id(&self) -> Option<ConnectionId> {
        self.active_connection
            .as_ref()
            .map(|(active_conn_id, _rec)| *active_conn_id)
    }

    fn allocate_connection_id(&mut self) -> ConnectionId {
        let r = self.next_connection_id;
        self.next_connection_id += 1;
        r
    }
}
