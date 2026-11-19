#![cfg(all(feature = "uffd", feature = "registry"))]

#[path = "../../nydus-core/tests/common/mod.rs"]
mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use common::Image;
use nydus::uffd::proto::{Header, HEADER_SIZE, MSG_PROBE_REQUEST, MSG_RANGE_RESPONSE};
use nydus::uffd::{UffdCore, UffdService};
use nydus_config::Config;

/// Serves the blobs of `blob_dir` in byte ranges like a registry, one request
/// per connection.
fn serve_blobs(blob_dir: PathBuf) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                if stream.read_exact(&mut byte).is_err() {
                    break;
                }
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            let Some(target) = request.split_whitespace().nth(1) else {
                continue;
            };
            let hex = target.rsplit("sha256:").next().unwrap();
            let blob = fs::read(blob_dir.join(hex)).unwrap();
            let range = request
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("range").then(|| value.trim())
                })
                .unwrap()
                .strip_prefix("bytes=")
                .unwrap();
            let (start, end) = range.split_once('-').unwrap();
            let (start, end) = if start.is_empty() {
                (blob.len() - end.parse::<usize>().unwrap(), blob.len() - 1)
            } else {
                (start.parse().unwrap(), end.parse().unwrap())
            };
            write!(
                stream,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n",
                end - start + 1,
                blob.len(),
            )
            .unwrap();
            stream.write_all(&blob[start..=end]).unwrap();
        }
    });
    addr
}

#[test]
fn probe_opens_a_cold_blob_cache_through_the_registry() {
    let image = Image::build();
    let addr = serve_blobs(image.blob_dir.clone());
    // No prefetch, so the probe is what opens the blob cache and reads the
    // blob meta from the registry.
    let config = serde_yaml::from_str::<Config>(&format!(
        "backend:\n  type: registry\n  config:\n    addr: http://{addr}\n    repository: test/image\n    http:\n      max_retries: 0\nstorage:\n  dir: {}\nprefetch:\n  scope: none\n",
        image.dir.path().join("cache").display(),
    ))
    .unwrap();
    let core = Arc::new(UffdCore::new(&image.bootstrap, config).unwrap());
    let socket = image.dir.path().join("uffd.sock");
    let service = Arc::new(UffdService::new(core, socket.clone()));
    let server = {
        let service = service.clone();
        thread::spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(service.run())
        })
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut client = loop {
        match UnixStream::connect(&socket) {
            Ok(client) => break client,
            Err(err) => assert!(Instant::now() < deadline, "{err}"),
        }
        thread::sleep(Duration::from_millis(10));
    };
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .write_all(&Header::new(MSG_PROBE_REQUEST, 0).to_bytes())
        .unwrap();
    let mut header = [0u8; HEADER_SIZE];
    client.read_exact(&mut header).unwrap();
    assert_eq!(Header::from_bytes(&header).msg_type, MSG_RANGE_RESPONSE);
    assert!(image.dir.path().join("cache").read_dir().unwrap().count() > 0);

    drop(client);
    service.stop();
    server.join().unwrap().unwrap();
}
