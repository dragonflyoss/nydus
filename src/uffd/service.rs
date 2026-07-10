use std::fs;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::unix::AsyncFd;
use tokio::net::UnixListener;
use tokio::sync::{mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info, warn};

use super::core::{read_uffd_msg, ResolvedRange, UffdCore, UffdMsg};
use super::proto::{FaultPolicy, ProtoConn, Request, VmaRegion};

pub struct UffdService {
    core: Arc<UffdCore>,
    socket_path: PathBuf,
    shutdown: watch::Sender<bool>,
}

struct HandshakeState {
    regions: Vec<VmaRegion>,
    policy: FaultPolicy,
    uffd: AsyncFd<OwnedFd>,
}

enum ConnectionEvent {
    Socket(Result<Option<Request>>),
    Uffd(UffdMsg),
}

struct UffdConn {
    core: Arc<UffdCore>,
    proto: ProtoConn,
    message_rx: mpsc::Receiver<Result<Option<Request>>>,
    state: Option<HandshakeState>,
    shutdown: watch::Receiver<bool>,
    _reader_task: TaskGuard,
}

struct TaskGuard(JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl UffdService {
    pub fn new(core: Arc<UffdCore>, socket_path: PathBuf) -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            core,
            socket_path,
            shutdown,
        }
    }

    pub fn stop(&self) {
        self.shutdown.send_replace(true);
    }

    pub async fn run(&self) -> Result<()> {
        let mut shutdown = self.shutdown.subscribe();
        if let Some(parent) = self.socket_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let _ = fs::remove_file(&self.socket_path);
        let listener = UnixListener::bind(&self.socket_path)
            .with_context(|| format!("failed to bind {}", self.socket_path.display()))?;
        info!(
            "lepton uffd service listening on {}",
            self.socket_path.display()
        );

        let mut connections = JoinSet::new();
        loop {
            if *shutdown.borrow() {
                break;
            }
            tokio::select! {
                biased;
                _ = shutdown.changed() => break,
                accepted = listener.accept() => {
                    let (stream, _) = accepted.context("failed to accept uffd connection")?;
                    let core = self.core.clone();
                    let conn_shutdown = self.shutdown.subscribe();
                    let stream = stream.into_std().context("failed to convert unix stream")?;
                    connections.spawn(async move {
                        match UffdConn::new(core, stream, conn_shutdown) {
                            Ok(connection) => connection.run().await,
                            Err(err) => Err(err),
                        }
                    });
                }
                result = connections.join_next(), if !connections.is_empty() => {
                    log_connection_exit(result.expect("non-empty connection set"));
                }
            }
        }

        info!(
            "lepton uffd service stopping, waiting for {} connection(s)",
            connections.len()
        );
        while let Some(result) = connections.join_next().await {
            log_connection_exit(result);
        }
        let _ = fs::remove_file(&self.socket_path);
        info!("lepton uffd service stopped");
        Ok(())
    }
}

impl UffdConn {
    fn new(
        core: Arc<UffdCore>,
        stream: StdUnixStream,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self> {
        let proto = ProtoConn::new(stream)?;
        let reader = proto.clone();
        let (message_tx, message_rx) = mpsc::channel(1);
        let mut reader_shutdown = shutdown.clone();
        let reader_task = TaskGuard(tokio::spawn(async move {
            loop {
                if *reader_shutdown.borrow() {
                    break;
                }
                let result = tokio::select! {
                    biased;
                    _ = reader_shutdown.changed() => break,
                    result = reader.recv() => result,
                };
                let terminal = !matches!(&result, Ok(Some(_)));
                if let Err(err) = message_tx.send(result).await {
                    drop(err.0);
                    break;
                }
                if terminal {
                    break;
                }
            }
        }));
        Ok(Self {
            core,
            proto,
            message_rx,
            state: None,
            shutdown,
            _reader_task: reader_task,
        })
    }

    async fn run(mut self) -> Result<()> {
        loop {
            if *self.shutdown.borrow() {
                break;
            }
            let event = if let Some(state) = self.state.as_ref() {
                tokio::select! {
                    biased;
                    _ = self.shutdown.changed() => break,
                    message = self.message_rx.recv() => {
                        ConnectionEvent::Socket(
                            message.ok_or_else(|| anyhow!("socket reader exited"))?
                        )
                    }
                    msg = read_next_uffd_msg(&state.uffd) => {
                        ConnectionEvent::Uffd(msg?)
                    }
                }
            } else {
                tokio::select! {
                    biased;
                    _ = self.shutdown.changed() => break,
                    message = self.message_rx.recv() => {
                        ConnectionEvent::Socket(
                            message.ok_or_else(|| anyhow!("socket reader exited"))?
                        )
                    }
                }
            };
            match event {
                ConnectionEvent::Socket(message) => self.dispatch_message(message).await?,
                ConnectionEvent::Uffd(msg) => self.handle_uffd_event(msg).await?,
            }
        }
        info!("lepton uffd connection stopped");
        Ok(())
    }

    async fn dispatch_message(&mut self, message: Result<Option<Request>>) -> Result<()> {
        let request = match message {
            Ok(None) => bail!("client disconnected"),
            Err(err) if is_client_disconnect(&err) => return Err(err),
            Err(err) => return Err(err).context("failed to receive uffd protocol message"),
            Ok(Some(request)) => request,
        };
        match request {
            Request::Handshake {
                policy,
                prefault,
                regions,
                uffd,
            } => {
                if self.state.is_some() {
                    bail!("duplicate UFFD handshake");
                }
                self.state = Some(
                    self.handle_handshake(policy, prefault, regions, uffd)
                        .await?,
                );
            }
            Request::Stat => {
                self.proto
                    .send_stat(self.core.total_size(), self.core.block_size(), 0)
                    .await?;
            }
            Request::Fetch(request) => {
                let core = self.core.clone();
                let ranges = tokio::task::spawn_blocking(move || {
                    core.fetch_ranges(request.offset, request.len)
                })
                .await
                .context("UFFD FETCH blocking task failed")??;
                self.send_ranges(None, &ranges).await?;
            }
            Request::Probe => {
                let ranges = self.core.probe_ranges()?;
                self.send_ranges(None, &ranges).await?;
            }
        }
        Ok(())
    }

    async fn handle_handshake(
        &self,
        policy: FaultPolicy,
        prefault: bool,
        regions: Vec<VmaRegion>,
        uffd: OwnedFd,
    ) -> Result<HandshakeState> {
        set_nonblocking(uffd.as_raw_fd())?;
        let async_uffd = AsyncFd::new(uffd).context("failed to register userfaultfd with tokio")?;

        info!(
            "lepton uffd handshake: regions={} policy={:?} prefault={}",
            regions.len(),
            policy,
            prefault
        );
        for (idx, region) in regions.iter().enumerate() {
            debug!(
                "lepton uffd region[{idx}]: base={:#x} size={:#x} offset={:#x} page_size={:#x} prot={} flags={}",
                region.base_host_virt_addr,
                region.size,
                region.offset,
                region.page_size,
                region.prot,
                region.flags
            );
        }

        // Keep prefault synchronous until ProtoConn guarantees serialized concurrent writes.
        if prefault && policy == FaultPolicy::Zerocopy {
            let ranges = self.core.prefault_ranges(&regions)?;
            self.send_ranges(Some(&regions), &ranges).await?;
        }

        Ok(HandshakeState {
            regions,
            policy,
            uffd: async_uffd,
        })
    }

    async fn handle_uffd_event(&self, msg: UffdMsg) -> Result<()> {
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| anyhow!("received UFFD event before handshake"))?;
        let uffd_fd = state.uffd.get_ref().as_raw_fd();
        let policy = state.policy;
        let regions = state.regions.clone();
        debug!(
            "lepton uffd event: event=0x{:02x} addr={:#x} flags={:#x}",
            msg.event, msg.pagefault.address, msg.pagefault.flags
        );
        let core = self.core.clone();
        let ranges = tokio::task::spawn_blocking(move || {
            core.resolve_page_fault(uffd_fd, &regions, policy, &msg)
        })
        .await
        .context("UFFD page-fault blocking task failed")??;
        debug!(
            "lepton uffd resolved fault: policy={:?} ranges={}",
            policy,
            ranges.len()
        );

        if policy == FaultPolicy::Zerocopy {
            self.send_ranges(Some(&state.regions), &ranges).await?;
        }
        Ok(())
    }

    async fn send_ranges(
        &self,
        regions: Option<&[VmaRegion]>,
        ranges: &[ResolvedRange],
    ) -> Result<()> {
        for range in ranges {
            if let Some(regions) = regions {
                if !regions.iter().any(|region| {
                    range.device_offset >= region.offset
                        && range.device_offset < region.offset.saturating_add(region.size)
                }) {
                    bail!("resolved range is outside registered regions");
                }
            }
        }
        self.proto.send_ranges(ranges).await?;
        Ok(())
    }
}

fn log_connection_exit(result: std::result::Result<Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) if is_client_disconnect(&err) => {
            debug!("lepton uffd connection closed: {err:#}");
        }
        Ok(Err(err)) => warn!("lepton uffd connection exited: {err:#}"),
        Err(err) => warn!("lepton uffd connection task failed: {err}"),
    }
}

fn is_client_disconnect(err: &anyhow::Error) -> bool {
    let text = format!("{err:#}");
    text.contains("client disconnected")
        || text.contains("peer closed")
        || text.contains("Connection reset")
        || text.contains("Broken pipe")
}

async fn read_next_uffd_msg(uffd: &AsyncFd<OwnedFd>) -> Result<UffdMsg> {
    loop {
        let mut guard = uffd
            .readable()
            .await
            .context("failed to wait for userfaultfd readability")?;
        match read_uffd_msg(uffd.get_ref().as_raw_fd()) {
            Ok(Some(msg)) => return Ok(msg),
            Ok(None) => guard.clear_ready(),
            Err(err) => return Err(err).context("failed to read userfaultfd message"),
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
