//! The kernel end of a FUSE session over a socketpair, for tests of
//! filesystems that must answer requests no mounted kernel sends them.

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;

const FUSE_ROOT_ID: u64 = 1;

/// The requests a test sends.
#[derive(Clone, Copy)]
#[repr(u32)]
pub(crate) enum Opcode {
    Lookup = 1,
    Getattr = 3,
    Readlink = 5,
    Open = 14,
    Read = 15,
    Statfs = 17,
    Release = 18,
    Getxattr = 22,
    Listxattr = 23,
    Opendir = 27,
    Readdir = 28,
    Access = 34,
}

/// The little-endian fields of a reply.
pub(crate) trait Fields {
    fn u32_at(&self, at: usize) -> u32;
    fn u64_at(&self, at: usize) -> u64;
}

impl Fields for [u8] {
    fn u32_at(&self, at: usize) -> u32 {
        u32::from_le_bytes(self[at..at + 4].try_into().unwrap())
    }

    fn u64_at(&self, at: usize) -> u64 {
        u64::from_le_bytes(self[at..at + 8].try_into().unwrap())
    }
}

/// It sends raw FUSE requests and returns each reply's errno and payload.
pub(crate) struct Kernel {
    stream: UnixStream,
    unique: u64,
}

impl Kernel {
    /// Serves `filesystem` to a kernel of protocol 7.31 that negotiated no
    /// flag: neither FUSE_NO_OPEN_SUPPORT, FUSE_NO_OPENDIR_SUPPORT nor
    /// readdirplus.
    pub(crate) fn serve<FS>(filesystem: FS) -> (fuser::BackgroundSession, Self)
    where
        FS: fuser::Filesystem + Send + Sync + 'static,
    {
        let (daemon, stream) = UnixStream::pair().unwrap();
        let session = fuser::Session::from_initialized_fd(
            filesystem,
            OwnedFd::from(daemon),
            fuser::SessionACL::All,
            fuser::Config::default(),
            fuser::InitState {
                proto_version: fuser::Version(7, 31),
                negotiated: fuser::InitFlags::empty(),
                kernel_capabilities: fuser::InitFlags::empty(),
            },
        )
        .unwrap()
        .spawn()
        .unwrap();
        (session, Self { stream, unique: 0 })
    }

    pub(crate) fn request(&mut self, opcode: Opcode, nodeid: u64, body: &[u8]) -> (i32, Vec<u8>) {
        self.unique += 1;
        let mut request = Vec::with_capacity(40 + body.len());
        request.extend_from_slice(&((40 + body.len()) as u32).to_le_bytes());
        request.extend_from_slice(&(opcode as u32).to_le_bytes());
        request.extend_from_slice(&self.unique.to_le_bytes());
        request.extend_from_slice(&nodeid.to_le_bytes());
        // uid, gid, pid and padding.
        request.extend_from_slice(&[0; 16]);
        request.extend_from_slice(body);
        self.stream.write_all(&request).unwrap();

        let (error, unique, payload) = self.message();
        assert_eq!(unique, self.unique);
        (error, payload)
    }

    /// The next message the daemon sent: a reply's errno, or a notification's
    /// code, then the request it answers (0 for a notification) and the
    /// payload.
    pub(crate) fn message(&mut self) -> (i32, u64, Vec<u8>) {
        let mut header = [0u8; 16];
        self.stream.read_exact(&mut header).unwrap();
        let mut payload = vec![0; header.u32_at(0) as usize - header.len()];
        self.stream.read_exact(&mut payload).unwrap();
        (header.u32_at(4) as i32, header.u64_at(8), payload)
    }

    /// Looks `name` up in the root and returns its node id and mode.
    pub(crate) fn lookup(&mut self, name: &str) -> (u64, u32) {
        let (error, entry) = self.request(
            Opcode::Lookup,
            FUSE_ROOT_ID,
            &[name.as_bytes(), b"\0"].concat(),
        );
        assert_eq!(error, 0, "{name}");
        (entry.u64_at(0), entry.u32_at(100))
    }

    pub(crate) fn open(&mut self, opcode: Opcode, nodeid: u64, flags: i32) -> (i32, Vec<u8>) {
        self.request(opcode, nodeid, &[flags.to_le_bytes(), [0; 4]].concat())
    }

    /// One READDIR of at most `size` bytes from `offset`: the entries as
    /// (name, d_type, ino, next offset).
    pub(crate) fn readdir(
        &mut self,
        nodeid: u64,
        offset: u64,
        size: u32,
    ) -> Vec<(String, u32, u64, u64)> {
        let mut body = vec![0u8; 40];
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..20].copy_from_slice(&size.to_le_bytes());
        let (error, mut reply) = self.request(Opcode::Readdir, nodeid, &body);
        assert_eq!(error, 0);
        assert!(reply.len() <= size as usize);
        let mut entries = Vec::new();
        while !reply.is_empty() {
            let (ino, next) = (reply.u64_at(0), reply.u64_at(8));
            let (name_len, kind) = (reply.u32_at(16) as usize, reply.u32_at(20));
            let name = String::from_utf8(reply[24..24 + name_len].to_vec()).unwrap();
            entries.push((name, kind, ino, next));
            reply.drain(..(24 + name_len).next_multiple_of(8));
        }
        entries
    }

    /// One READ of `size` bytes at `offset`.
    pub(crate) fn read(&mut self, nodeid: u64, offset: u64, size: u32) -> (i32, Vec<u8>) {
        let mut body = vec![0u8; 40];
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..20].copy_from_slice(&size.to_le_bytes());
        self.request(Opcode::Read, nodeid, &body)
    }
}
