//! Exercise the actual socket worker without needing /dev/nbd or a mount.
#![cfg(all(target_os = "linux", feature = "nbd"))]

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use nydus::build::{build_image, BuildImageOptions};
use nydus::nbd::{service::NbdWorker, NbdCore};
use nydus_config::Config;
use nydus_format::blob::BlobMetadataCompressor;

fn fixture() -> (tempfile::TempDir, Arc<NbdCore>, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("file"), vec![0x5a; 8192]).unwrap();
    let blob = dir.path().join("staging");
    let output = build_image(
        &BuildImageOptions::new(
            source,
            4096,
            BlobMetadataCompressor::None,
            HashSet::new(),
            true,
        )
        .unwrap(),
        fs::File::create(&blob).unwrap(),
    )
    .unwrap();
    fs::rename(blob, dir.path().join(hex::encode(output.full_blob_digest))).unwrap();
    let bootstrap = output.standalone_bootstrap.unwrap();
    let path = dir.path().join("image.boot");
    fs::write(&path, &bootstrap).unwrap();
    let config = Config::from_yaml(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}/cache\nprefetch:\n  scope: none\n",
        dir.path().display(), dir.path().display(),
    )).unwrap();
    let core = Arc::new(NbdCore::new(&path, config).unwrap());
    (dir, core, bootstrap)
}

fn worker(core: Arc<NbdCore>) -> (UnixStream, thread::JoinHandle<()>) {
    let (peer, server) = UnixStream::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    peer.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let worker = NbdWorker::new(
        core,
        Arc::new(AtomicBool::new(true)),
        peer.try_clone().unwrap(),
        server,
    );
    (peer, thread::spawn(move || worker.run()))
}

fn request(command: u32, offset: u64, len: u32) -> [u8; 28] {
    let mut bytes = [0; 28];
    bytes[..4].copy_from_slice(&0x25609513u32.to_be_bytes());
    bytes[4..8].copy_from_slice(&command.to_be_bytes());
    bytes[8..16].copy_from_slice(b"opaque42");
    bytes[16..24].copy_from_slice(&offset.to_be_bytes());
    bytes[24..28].copy_from_slice(&len.to_be_bytes());
    bytes
}

fn reply(peer: &mut UnixStream, expected_errno: u32) {
    let mut bytes = [0; 16];
    peer.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes[..4], &0x67446698u32.to_be_bytes());
    assert_eq!(&bytes[4..8], &expected_errno.to_be_bytes());
    assert_eq!(&bytes[8..], b"opaque42");
}

#[test]
fn invalid_requests_return_errno_without_desynchronizing_the_socket() {
    let (_dir, core, bootstrap) = fixture();
    let size = core.device_size();
    let (mut peer, handle) = worker(core);
    for (command, offset, length, errno) in [
        (0, 1, 4096, 22),
        (0, 0, 4095, 22),
        (0, 0, 4 * 1024 * 1024 + 4096, 22),
        (0, size, 4096, 5),
        (0, u64::MAX - 4095, 4096, 5),
        (3, 0, 0, 22),
    ] {
        peer.write_all(&request(command, offset, length)).unwrap();
        reply(&mut peer, errno);
        peer.write_all(&request(0, 0, 4096)).unwrap();
        reply(&mut peer, 0);
        let mut data = [0; 4096];
        peer.read_exact(&mut data).unwrap();
        assert_eq!(data.as_slice(), &bootstrap[..4096]);
    }
    peer.write_all(&request(2, 0, 0)).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0, "disconnect has no reply");
    handle.join().unwrap();
}

#[test]
fn malformed_magic_write_and_partial_header_eof_close_without_reply() {
    let (_dir, core, _) = fixture();
    let mut bad_magic = request(0, 0, 4096);
    bad_magic[0] ^= 1;
    for bytes in [
        bad_magic.to_vec(),
        request(1, 0, 4096).to_vec(),
        request(0, 0, 4096)[..13].to_vec(),
    ] {
        let (mut peer, handle) = worker(core.clone());
        peer.write_all(&bytes).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
        handle.join().unwrap();
    }
}
