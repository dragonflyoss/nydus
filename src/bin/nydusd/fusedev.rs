// Copyright 2020 Ant Financial. All rights reserved.
// Copyright (C) 2020 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0 AND BSD-3-Clause)

use std::io::Result;
use std::path::Path;
use std::sync::{atomic::Ordering, Arc};
use std::thread;

use fuse_rs::api::{server::Server, Vfs};
use nydus_utils::{eio, FuseChannel, FuseSession};
use vmm_sys_util::eventfd::EventFd;

use crate::daemon;
use daemon::{Error, NydusDaemon};

use crate::EVENT_MANAGER_RUN;

struct FuseServer {
    server: Arc<Server<Arc<Vfs>>>,
    ch: FuseChannel,
    // read buffer for fuse requests
    buf: Vec<u8>,
    evtfd: EventFd,
}

impl FuseServer {
    fn new(server: Arc<Server<Arc<Vfs>>>, se: &FuseSession, evtfd: EventFd) -> Result<FuseServer> {
        Ok(FuseServer {
            server,
            ch: se.new_channel(evtfd.try_clone().unwrap())?,
            buf: Vec::with_capacity(se.bufsize()),
            evtfd,
        })
    }

    fn svc_loop(&mut self) -> Result<()> {
        // Safe because we have already reserved the capacity
        unsafe {
            self.buf.set_len(self.buf.capacity());
        }

        // Given error EBADF, it means kernel has shut down this session.
        let _ebadf = std::io::Error::from_raw_os_error(libc::EBADF);
        loop {
            if let Some(reader) = self.ch.get_reader(&mut self.buf)? {
                let writer = self.ch.get_writer()?;
                if let Err(e) = self.server.handle_message(reader, writer, None) {
                    match e {
                        fuse_rs::Error::EncodeMessage(_ebadf) => {
                            return Err(eio!("fuse session has been shut down: {:?}"));
                        }
                        _ => {
                            error!("Handling fuse message, {}", Error::ProcessQueue(e));
                            continue;
                        }
                    }
                }
            } else {
                info!("fuse server exits");
                break;
            }
        }
        Ok(())
    }
}

struct FusedevDaemon {
    server: Arc<Server<Arc<Vfs>>>,
    session: FuseSession,
    threads: Vec<Option<thread::JoinHandle<Result<()>>>>,
    event_fd: EventFd,
}

impl FusedevDaemon {
    fn kick_one_server(&mut self) -> Result<()> {
        let mut s = FuseServer::new(
            self.server.clone(),
            &self.session,
            // Clone event fd must succeed, otherwise fusedev daemon should not work.
            self.event_fd.try_clone().unwrap(),
        )?;

        let thread = thread::Builder::new()
            .name("fuse_server".to_string())
            .spawn(move || {
                let _ = s.svc_loop();
                EVENT_MANAGER_RUN.store(false, Ordering::Relaxed);
                s.evtfd.write(1)
            })
            .map_err(Error::ThreadSpawn)?;
        self.threads.push(Some(thread));
        Ok(())
    }
}

impl NydusDaemon for FusedevDaemon {
    fn start(&mut self, cnt: u32) -> Result<()> {
        for _ in 0..cnt {
            self.kick_one_server()?;
        }
        Ok(())
    }

    fn wait(&mut self) -> Result<()> {
        for t in &mut self.threads {
            if let Some(handle) = t.take() {
                handle.join().map_err(|_| Error::WaitDaemon)??;
            }
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.event_fd.write(1).expect("Stop fuse service loop");
        self.session.umount()
    }
}

pub fn create_nydus_daemon(
    mountpoint: &str,
    fs: Arc<Vfs>,
    evtfd: EventFd,
    readonly: bool,
) -> Result<Box<dyn NydusDaemon>> {
    Ok(Box::new(FusedevDaemon {
        session: FuseSession::new(Path::new(mountpoint), "nydusfs", "", readonly)?,
        server: Arc::new(Server::new(fs)),
        threads: Vec::new(),
        event_fd: evtfd,
    }))
}
