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
use nydus::nbd::proto::{
    NBD_CMD_DISC, NBD_CMD_READ, NBD_CMD_WRITE, NBD_EINVAL, NBD_EIO, NBD_OK, NBD_REPLY_HEADER_SIZE,
    NBD_REPLY_MAGIC, NBD_REQUEST_HEADER_SIZE, NBD_REQUEST_MAGIC,
};
use nydus::nbd::{service::NbdWorker, NbdCore};
use nydus_config::Config;
use nydus_format::blob::BlobMetadataCompressor;
use tempfile::{tempdir, TempDir};

const NBD_CMD_FLUSH: u32 = 3;

const HANDLE: &[u8; 8] = b"opaque42";

fn build_nbd_core() -> (TempDir, Arc<NbdCore>, Vec<u8>) {
    let dir = tempdir().unwrap();
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
    let config = serde_yaml::from_str::<Config>(&format!(
        "backend:\n  type: local\n  config:\n    dir: {}\nstorage:\n  dir: {}/cache\nprefetch:\n  scope: none\n",
        dir.path().display(),
        dir.path().display(),
    ))
    .unwrap();
    let core = Arc::new(NbdCore::new(&path, config).unwrap());
    (dir, core, bootstrap)
}

fn spawn_worker(core: Arc<NbdCore>) -> (UnixStream, thread::JoinHandle<()>) {
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

fn request(command: u32, offset: u64, len: u32) -> [u8; NBD_REQUEST_HEADER_SIZE] {
    let mut request = [0; NBD_REQUEST_HEADER_SIZE];
    request[..4].copy_from_slice(&NBD_REQUEST_MAGIC.to_be_bytes());
    request[4..8].copy_from_slice(&command.to_be_bytes());
    request[8..16].copy_from_slice(HANDLE);
    request[16..24].copy_from_slice(&offset.to_be_bytes());
    request[24..28].copy_from_slice(&len.to_be_bytes());
    request
}

fn read_reply(peer: &mut UnixStream) -> u32 {
    let mut reply = [0; NBD_REPLY_HEADER_SIZE];
    peer.read_exact(&mut reply).unwrap();
    assert_eq!(reply[..4], NBD_REPLY_MAGIC.to_be_bytes());
    assert_eq!(&reply[8..], HANDLE);
    u32::from_be_bytes(reply[4..8].try_into().unwrap())
}

#[test]
fn run_replies_an_errno_to_invalid_requests_and_keeps_the_socket_in_sync() {
    let (_dir, core, bootstrap) = build_nbd_core();
    let device_size = core.device_size();
    let (mut peer, handle) = spawn_worker(core);
    let test_cases = vec![
        (NBD_CMD_READ, 1, 4096, NBD_EINVAL),
        (NBD_CMD_READ, 0, 4095, NBD_EINVAL),
        (NBD_CMD_READ, 0, 4 * 1024 * 1024 + 4096, NBD_EINVAL),
        (NBD_CMD_READ, device_size, 4096, NBD_EIO),
        (NBD_CMD_READ, u64::MAX - 4095, 4096, NBD_EIO),
        (NBD_CMD_FLUSH, 0, 0, NBD_EINVAL),
    ];

    for (command, offset, len, errno) in test_cases {
        peer.write_all(&request(command, offset, len)).unwrap();
        assert_eq!(read_reply(&mut peer), errno, "{command} {offset} {len}");

        let mut data = [0; 4096];
        peer.write_all(&request(NBD_CMD_READ, 0, 4096)).unwrap();
        assert_eq!(read_reply(&mut peer), NBD_OK);
        peer.read_exact(&mut data).unwrap();
        assert_eq!(data.as_slice(), &bootstrap[..4096]);
    }

    peer.write_all(&request(NBD_CMD_DISC, 0, 0)).unwrap();
    assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    handle.join().unwrap();
}

#[test]
fn run_closes_the_socket_without_a_reply_on_a_bad_magic_a_write_or_a_short_header() {
    let (_dir, core, _) = build_nbd_core();
    let mut bad_magic = request(NBD_CMD_READ, 0, 4096);
    bad_magic[0] ^= 1;
    let test_cases = vec![
        bad_magic.to_vec(),
        request(NBD_CMD_WRITE, 0, 4096).to_vec(),
        request(NBD_CMD_READ, 0, 4096)[..13].to_vec(),
    ];

    for bytes in test_cases {
        let (mut peer, handle) = spawn_worker(core.clone());
        peer.write_all(&bytes).unwrap();
        peer.shutdown(Shutdown::Write).unwrap();

        assert_eq!(peer.read(&mut [0]).unwrap(), 0, "{bytes:?}");
        handle.join().unwrap();
    }
}
