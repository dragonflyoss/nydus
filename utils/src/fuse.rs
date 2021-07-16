// Copyright 2020 Ant Group. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io;
use std::ops::Deref;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::path::{Path, PathBuf};

use libc::{c_int, sysconf, _SC_PAGESIZE};
use nix::errno::Errno;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::poll::{poll, PollFd, PollFlags};
use nix::unistd::{close, dup, getgid, getuid, read};
use nix::Error as nixError;

use epoll::{ControlOptions, Event, Events};
use nix::fcntl::{fcntl, FcntlArg, OFlag};

use fuse_rs::transport::{FuseBuf, Reader, Writer};
use vmm_sys_util::eventfd::EventFd;

/// These follows definition from libfuse
const FUSE_KERN_BUF_SIZE: usize = 256;
const FUSE_HEADER_SIZE: usize = 0x1000;

const FUSE_DEVICE: &str = "/dev/fuse";
const FUSE_FSTYPE: &str = "fuse";

/// A fuse session representation
pub struct FuseSession {
    mountpoint: PathBuf,
    fsname: String,
    subtype: String,
    file: Option<File>,
    bufsize: usize,
}

const EXIT_FUSE_SERVICE: u64 = 1;

impl FuseSession {
    pub fn new(mountpoint: &Path, fsname: &str, subtype: &str) -> io::Result<FuseSession> {
        let dest = mountpoint.canonicalize()?;
        if !dest.is_dir() {
            return Err(enotdir!());
        }

        Ok(FuseSession {
            mountpoint: dest,
            fsname: fsname.to_owned(),
            subtype: subtype.to_owned(),
            file: None,
            bufsize: FUSE_KERN_BUF_SIZE * pagesize() + FUSE_HEADER_SIZE,
        })
    }

    pub fn mount(&mut self) -> io::Result<()> {
        let flags =
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOATIME | MsFlags::MS_RDONLY;

        let file = fuse_kern_mount(&self.mountpoint, &self.fsname, &self.subtype, flags)?;
        fcntl(file.as_raw_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).map_err(|e| einval!(e))?;
        self.file = Some(file);

        Ok(())
    }

    pub fn get_fuse_fd(&mut self) -> Option<RawFd> {
        self.file.as_ref().map(|file| file.as_raw_fd())
    }

    pub fn set_fuse_fd(&mut self, fd: RawFd) {
        self.file = Some(unsafe { File::from_raw_fd(fd) });
    }

    /// destroy a fuse session
    pub fn umount(&mut self) -> io::Result<()> {
        if self.file.is_none() {
            return Ok(());
        }

        fuse_kern_umount(self.mountpoint.to_str().unwrap(), self.file.take().unwrap())
    }

    /// return the mountpoint
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// return the fsname
    pub fn fsname(&self) -> &str {
        &self.fsname
    }

    /// return the subtype
    pub fn subtype(&self) -> &str {
        &self.subtype
    }

    /// return the default buffer size
    pub fn bufsize(&self) -> usize {
        self.bufsize
    }

    /// create a new fuse message channel
    pub fn new_channel(&self, evtfd: EventFd) -> io::Result<FuseChannel> {
        if let Some(file) = &self.file {
            FuseChannel::new(file.as_raw_fd(), evtfd, self.bufsize)
        } else {
            Err(einval!("invalid fuse session"))
        }
    }
}

impl Drop for FuseSession {
    fn drop(&mut self) {
        let _ = self.umount();
    }
}

pub struct FuseChannel {
    fd: c_int,
    epoll_fd: RawFd,
    bufsize: usize,
    events: RefCell<Vec<Event>>,
    // XXX: Ideally we should have write buffer as well
    // write_buf: Vec<u8>,
}

fn register_event(epoll_fd: c_int, fd: RawFd, evt: Events, data: u64) -> io::Result<()> {
    let event = Event::new(evt, data);
    epoll::ctl(epoll_fd, ControlOptions::EPOLL_CTL_ADD, fd, event)
}

impl FuseChannel {
    fn new(fd: c_int, evtfd: EventFd, bufsize: usize) -> io::Result<Self> {
        const EPOLL_EVENTS_LEN: usize = 100;
        let epoll_fd = epoll::create(true)?;

        register_event(epoll_fd, fd, Events::EPOLLIN, 0)?;

        let exit_evtfd = evtfd.try_clone().unwrap();
        register_event(
            epoll_fd,
            exit_evtfd.as_raw_fd(),
            Events::EPOLLIN,
            EXIT_FUSE_SERVICE,
        )?;

        Ok(FuseChannel {
            fd: dup(fd).map_err(|e| last_error!(e))?,
            epoll_fd,
            bufsize,
            events: RefCell::new(vec![Event::new(Events::empty(), 0); EPOLL_EVENTS_LEN]),
        })
    }

    pub fn get_reader<'b>(&self, buf: &'b mut Vec<u8>) -> io::Result<Option<Reader<'b>>> {
        loop {
            let num_events = epoll::wait(self.epoll_fd, -1, &mut self.events.borrow_mut())?;

            for event in self.events.borrow().iter().take(num_events) {
                let evset = match epoll::Events::from_bits(event.events) {
                    Some(evset) => evset,
                    None => {
                        let evbits = event.events;
                        warn!("epoll: ignoring unknown event set: 0x{:x}", evbits);
                        continue;
                    }
                };

                match evset {
                    Events::EPOLLIN => {
                        if event.data == EXIT_FUSE_SERVICE {
                            // Directly return from here is reliable as we handle only one epoll event
                            // which is `Read` or `Exit` once this function is called.
                            // One more trick is we don't read the event fd so as to make all fuse threads exit.
                            // That is because we configure this event fd as LEVEL triggered.
                            info!("Will exit from fuse service");
                            return Ok(None);
                        }

                        match read(self.fd, buf.as_mut_slice()) {
                            Ok(len) => {
                                return Ok(Some(
                                    Reader::new(FuseBuf::new(&mut buf[..len]))
                                        .map_err(|e| eother!(e))?,
                                ));
                            }
                            Err(nixError::Sys(e)) => match e {
                                Errno::ENOENT => {
                                    // ENOENT means the operation was interrupted, it's safe
                                    // to restart
                                    trace!("restart reading");
                                    continue;
                                }
                                Errno::ENODEV => {
                                    info!("fuse filesystem umounted");
                                    return Ok(None);
                                }
                                Errno::EAGAIN => {
                                    continue;
                                }
                                e => {
                                    warn! {"read fuse dev failed on fd {}: {}", self.fd, e};
                                    return Err(io::Error::from_raw_os_error(e as i32));
                                }
                            },
                            Err(e) => {
                                return Err(eother!(e));
                            }
                        }
                    }
                    x if (Events::EPOLLERR | Events::EPOLLHUP).contains(x) => {
                        warn!("Seems file was already closed!");
                        return Err(eio!());
                    }
                    _ => {
                        // We should not step into this branch as other event is not registered.
                        continue;
                    }
                }
            }
        }
    }

    pub fn get_writer(&self) -> io::Result<Writer> {
        Ok(Writer::new(self.fd, self.bufsize).unwrap())
    }
}

impl Drop for FuseChannel {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

/// Safe wrapper for `sysconf(_SC_PAGESIZE)`.
#[inline(always)]
fn pagesize() -> usize {
    // Trivially safe
    unsafe { sysconf(_SC_PAGESIZE) as usize }
}

/// Mount a fuse file system
fn fuse_kern_mount(
    mountpoint: &Path,
    fsname: &str,
    subtype: &str,
    flags: MsFlags,
) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(false)
        .read(true)
        .write(true)
        .open(FUSE_DEVICE)
        .map_err(|e| {
            error!("FUSE failed to open. {}", e);
            e
        })?;

    let meta = mountpoint.metadata().map_err(|e| {
        error!("Can not get metadata from mount point. {}", e);
        e
    })?;

    let opts = format!(
        "default_permissions,allow_other,fd={},rootmode={:o},user_id={},group_id={}",
        file.as_raw_fd(),
        meta.permissions().mode() & libc::S_IFMT,
        getuid(),
        getgid(),
    );
    let mut fstype = String::from(FUSE_FSTYPE);
    if !subtype.is_empty() {
        fstype.push('.');
        fstype.push_str(subtype);
    }

    info!(
        "mount source {} dest {} with fstype {} opts {} fd {}",
        fsname,
        mountpoint.to_str().unwrap(),
        fstype,
        opts,
        file.as_raw_fd(),
    );
    mount(
        Some(fsname),
        mountpoint,
        Some(fstype.deref()),
        flags,
        Some(opts.deref()),
    )
    .map_err(|e| eother!(format!("mount failed: {:}", e)))?;
    Ok(file)
}

/// Umount a fuse file system
fn fuse_kern_umount(mountpoint: &str, file: File) -> io::Result<()> {
    let mut fds = [PollFd::new(file.as_raw_fd(), PollFlags::empty())];
    let res = poll(&mut fds, 0);

    // Drop to close fuse session fd, otherwise synchronous umount
    // can recurse into filesystem and deadlock.
    drop(file);

    if res.is_ok() {
        // POLLERR means the file system is already umounted,
        // or the connection was severed via /sys/fs/fuse/connections/NNN/abort
        if let Some(event) = fds[0].revents() {
            if event == PollFlags::POLLERR {
                return Ok(());
            }
        }
    }

    umount2(mountpoint, MntFlags::MNT_DETACH).map_err(|e| eother!(e))
}
