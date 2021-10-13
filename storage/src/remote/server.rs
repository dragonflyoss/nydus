// Copyright (C) 2021 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::io::Result;
use std::mem;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use vm_memory::ByteValued;

use crate::remote::client::Client;
use crate::remote::connection::{Endpoint, Listener};
use crate::remote::message::{
    FetchRangeReply, FetchRangeRequest, GetBlobReply, GetBlobRequest, MsgHeader, MsgValidator,
    RequestCode,
};

struct ClientState {
    conn: Mutex<Endpoint>,
    exiting: AtomicBool,
    id: u64,
    state: ServerState,
    token: AtomicU64,
    uds: UnixStream,
}

impl ClientState {
    fn new(server: ServerState, id: u64, sock: UnixStream) -> Result<Self> {
        let uds = sock.try_clone()?;

        Ok(Self {
            conn: Mutex::new(Endpoint::from_stream(sock)),
            exiting: AtomicBool::new(false),
            id,
            state: server,
            token: AtomicU64::new(1),
            uds,
        })
    }

    fn run(&self) -> Result<()> {
        loop {
            if self.exiting.load(Ordering::Acquire) {
                return Ok(());
            }

            let mut guard = self.conn.lock().unwrap();
            let (mut hdr, _files) = guard.recv_header().map_err(|e| eio!(format!("{}", e)))?;
            match hdr.get_code() {
                RequestCode::Noop => self.handle_noop(&mut hdr, guard)?,
                RequestCode::GetBlob => self.handle_get_blob(&mut hdr, guard)?,
                RequestCode::FetchRange => self.handle_fetch_range(&mut hdr, guard)?,
                cmd => {
                    let msg = format!("unknown request command {}", u32::from(cmd));
                    return Err(einval!(msg));
                }
            }
        }
    }

    fn close(&self) {
        if !self.exiting.swap(true, Ordering::AcqRel) {
            let _ = self.uds.shutdown(Shutdown::Both);
        }
    }

    fn handle_noop(&self, hdr: &mut MsgHeader, mut guard: MutexGuard<Endpoint>) -> Result<()> {
        let size = hdr.get_size() as usize;
        if !hdr.is_valid() || size != 0 {
            return Err(eio!("invalid noop request message"));
        }

        hdr.set_reply(true);
        guard.send_header(&hdr, None).map_err(|_e| eio!())
    }

    fn handle_get_blob(&self, hdr: &mut MsgHeader, mut guard: MutexGuard<Endpoint>) -> Result<()> {
        let size = hdr.get_size() as usize;
        if !hdr.is_valid() || size != mem::size_of::<GetBlobRequest>() {
            return Err(eio!("invalid get blob request message"));
        }

        let (sz, data) = guard.recv_data(size).map_err(|e| eio!(format!("{}", e)))?;
        if sz != size || data.len() != size {
            return Err(einval!("invalid get blob request message"));
        }
        drop(guard);

        let mut msg = GetBlobRequest::new("");
        msg.as_mut_slice().copy_from_slice(&data);

        // TODO
        let token = self.token.fetch_add(1, Ordering::AcqRel);
        let reply = GetBlobReply::new(token, 0, libc::ENOSYS as u32);

        let mut guard = self.conn.lock().unwrap();
        hdr.set_reply(true);
        guard.send_message(&hdr, &reply, None).map_err(|_e| eio!())
    }

    fn handle_fetch_range(
        &self,
        hdr: &mut MsgHeader,
        mut guard: MutexGuard<Endpoint>,
    ) -> Result<()> {
        let size = hdr.get_size() as usize;
        if !hdr.is_valid() || size != mem::size_of::<FetchRangeRequest>() {
            return Err(eio!("invalid fetch range request message"));
        }

        let (sz, data) = guard.recv_data(size).map_err(|e| eio!(format!("{}", e)))?;
        if sz != size || data.len() != size {
            return Err(einval!("invalid fetch range request message"));
        }
        drop(guard);

        // TODO
        let mut msg = FetchRangeRequest::new(0, 0, 0);
        msg.as_mut_slice().copy_from_slice(&data);

        let reply = FetchRangeReply::new(0, msg.count, 0);

        let mut guard = self.conn.lock().unwrap();
        hdr.set_reply(true);
        guard.send_message(&hdr, &reply, None).map_err(|_e| eio!())
    }
}

#[derive(Clone)]
struct ServerState {
    active_workers: Arc<AtomicU64>,
    clients: Arc<Mutex<HashMap<u64, Arc<ClientState>>>>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            active_workers: Arc::new(AtomicU64::new(0)),
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn add(&self, id: u64, client: Arc<ClientState>) {
        self.clients.lock().unwrap().insert(id, client);
    }

    fn remove(&self, id: u64) {
        self.clients.lock().unwrap().remove(&id);
    }
}

/// Struct to maintain state for a connection from clients.
pub struct Server {
    sock: String,
    next_id: AtomicU64,
    exiting: AtomicBool,
    listener: Listener,
    state: ServerState,
}

impl Server {
    /// Create a new instance of `Server` to serve blob managment requests from clients.
    pub fn new(sock: &str) -> Result<Self> {
        let listener = Listener::new(sock, true).map_err(|_e| eio!())?;

        Ok(Server {
            sock: sock.to_owned(),
            next_id: AtomicU64::new(1),
            exiting: AtomicBool::new(false),
            listener,
            state: ServerState::new(),
        })
    }

    /// Start the server to handle incoming connections.
    pub fn start(server: Arc<Server>) -> Result<()> {
        server
            .listener
            .set_nonblocking(false)
            .map_err(|_e| eio!())?;

        std::thread::spawn(move || {
            server.state.active_workers.fetch_add(1, Ordering::Acquire);

            'listen: loop {
                if server.exiting.load(Ordering::Acquire) {
                    break 'listen;
                }

                match server.listener.accept() {
                    Ok(Some(sock)) => {
                        let id = server.next_id.fetch_add(1, Ordering::AcqRel);
                        let client = match ClientState::new(server.state.clone(), id, sock) {
                            Ok(v) => v,
                            Err(e) => {
                                warn!("failed to duplicate unix domain socket, {}", e);
                                break 'listen;
                            }
                        };
                        let client = Arc::new(client);

                        client.state.add(id, client.clone());
                        std::thread::spawn(move || {
                            client.state.active_workers.fetch_add(1, Ordering::AcqRel);
                            if let Err(e) = client.run() {
                                warn!("failed to handle request, {}", e);
                            }
                            client.state.active_workers.fetch_sub(1, Ordering::AcqRel);
                            client.state.remove(client.id);
                            client.close();
                        });
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error!("failed to accept connection, {}", e);
                        break 'listen;
                    }
                }
            }

            server.state.active_workers.fetch_sub(1, Ordering::AcqRel);
        });

        Ok(())
    }

    /// Shutdown the listener and all active client connections.
    pub fn stop(&self) {
        if !self.exiting.swap(true, Ordering::AcqRel) {
            // Hacky way to wake up the listener threads from accept().
            let client = Client::new(&self.sock);
            let _ = client.connect();

            let mut guard = self.state.clients.lock().unwrap();
            for (_token, client) in guard.iter() {
                client.close();
            }
            guard.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use vmm_sys_util::tempdir::TempDir;

    #[test]
    fn test_new_server() {
        let tmpdir = TempDir::new().unwrap();
        let sock = tmpdir.as_path().to_str().unwrap().to_owned() + "/test_sock1";
        let server = Arc::new(Server::new(&sock).unwrap());

        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 0);
        Server::start(server.clone()).unwrap();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 1);

        let client = Client::new(&server.sock);
        client.connect().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 2);
        client.close();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 1);
        assert_eq!(server.state.clients.lock().unwrap().len(), 0);

        let client = Client::new(&server.sock);
        client.connect().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 2);
        let client = Arc::new(client);
        Client::start(client.clone()).unwrap();
        client.call_ping().unwrap();

        server.stop();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_reconnect() {
        let tmpdir = TempDir::new().unwrap();
        let sock = tmpdir.as_path().to_str().unwrap().to_owned() + "/test_sock1";

        let server = Arc::new(Server::new(&sock).unwrap());
        Server::start(server.clone()).unwrap();

        let client = Client::new(&server.sock);
        client.connect().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        let client = Arc::new(client);
        Client::start(client.clone()).unwrap();
        client.call_ping().unwrap();

        server.stop();
        std::thread::sleep(Duration::from_secs(1));
        assert_eq!(server.state.active_workers.load(Ordering::Relaxed), 0);
        drop(server);

        let server = Arc::new(Server::new(&sock).unwrap());
        Server::start(server).unwrap();
        client.call_ping().unwrap();
    }
}
