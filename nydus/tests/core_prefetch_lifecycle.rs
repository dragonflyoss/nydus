#![cfg(feature = "registry")]

#[path = "../../nydus-core/tests/common/mod.rs"]
mod common;

use std::fs;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use common::Image;
use nydus_config::Config;
use nydus_core::{
    CreateFileOptions, ErofsReader, IncrementalWriter, IncrementalWriterOptions, NydusCore,
};

struct Origin {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    retry_started: mpsc::Receiver<()>,
    release_retry: mpsc::Sender<()>,
    handle: thread::JoinHandle<usize>,
}

impl Origin {
    fn serve(target: String, blob: Vec<u8>, retry_succeeds: bool) -> Origin {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = stop.clone();
        let (retry_started_tx, retry_started) = mpsc::channel();
        let (release_retry, release_retry_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut requests = 0;
            let mut data_requests = 0;
            while !stopped.load(Ordering::Acquire) {
                assert!(Instant::now() < deadline);
                let mut stream = match listener.accept() {
                    Ok((stream, _)) => stream,
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(err) => panic!("{err}"),
                };
                let request = read_request(&mut stream);
                requests += 1;
                assert_eq!(request.split_whitespace().nth(1).unwrap(), target);

                let (start, end) = parse_range(&request, blob.len());
                let unavailable = if start == 0 {
                    data_requests += 1;
                    assert!(data_requests <= 2);
                    if data_requests == 2 {
                        retry_started_tx.send(()).unwrap();
                        release_retry_rx
                            .recv_timeout(Duration::from_secs(3))
                            .unwrap();
                    }
                    data_requests == 1 || !retry_succeeds
                } else {
                    false
                };
                if unavailable {
                    stream
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                        .unwrap();
                } else {
                    write!(
                        stream,
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n",
                        end - start + 1,
                        blob.len(),
                    )
                    .unwrap();
                    stream.write_all(&blob[start..=end]).unwrap();
                }
            }
            assert_eq!(data_requests, 2);
            requests
        });

        Origin {
            addr,
            stop,
            retry_started,
            release_retry,
            handle,
        }
    }

    fn shutdown(self) -> usize {
        self.stop.store(true, Ordering::Release);
        self.handle.join().unwrap()
    }
}

fn read_request(stream: &mut TcpStream) -> String {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        assert!(request.len() < 16384);
    }
    String::from_utf8(request).unwrap()
}

fn parse_range(request: &str, len: usize) -> (usize, usize) {
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
    if start.is_empty() {
        (len - end.parse::<usize>().unwrap(), len - 1)
    } else {
        (start.parse().unwrap(), end.parse().unwrap())
    }
}

#[test]
fn drop_during_a_prefetch_retry_releases_the_image_without_starting_another_blob() {
    let test_cases = vec![true, false];

    for retry_succeeds in test_cases {
        let image = Image::build();
        let output = image.dir.path().join("child");
        let mut writer = IncrementalWriter::open_metadata_only(
            &image.bootstrap,
            IncrementalWriterOptions::new(output.clone()),
        )
        .unwrap();
        writer
            .create_file(Path::new("created"), 4096, CreateFileOptions::default())
            .unwrap()
            .write_at(0, &[0x5a; 4096])
            .unwrap();
        writer.commit().unwrap();
        let bootstrap = output.join("image.boot");
        let reader = ErofsReader::open_metadata_only(&bootstrap).unwrap();
        let blobs = reader.blob_infos().unwrap();
        assert_eq!(blobs.len(), 2);
        let upper_blob_id = hex::encode(blobs[1].blob_id);
        let origin = Origin::serve(
            format!("/v2/test/image/blobs/sha256:{upper_blob_id}"),
            fs::read(output.join(&upper_blob_id)).unwrap(),
            retry_succeeds,
        );
        let config = Config::from_yaml(&format!(
            "backend:\n  type: registry\n  config:\n    addr: http://{}\n    repository: test/image\n    http:\n      request_timeout: 2s\n      max_retries: 0\nstorage:\n  dir: {}\nprefetch:\n  scope: all\n  concurrent_blob_count: 1\n  retry_interval: 50ms\n  request_timeout: 2s\n",
            origin.addr,
            image.dir.path().join("cache").display(),
        ))
        .unwrap();
        let core = NydusCore::new(&bootstrap, config, None).unwrap();
        let metrics = Arc::downgrade(core.metrics());
        let ondemand_recorder = Arc::downgrade(core.ondemand_recorder());
        origin
            .retry_started
            .recv_timeout(Duration::from_secs(5))
            .unwrap();

        let dropped = Instant::now();
        drop(core);

        assert!(
            dropped.elapsed() < Duration::from_secs(1),
            "{retry_succeeds}"
        );
        assert!(metrics.upgrade().is_some(), "{retry_succeeds}");
        origin.release_retry.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while metrics.upgrade().is_some() || ondemand_recorder.upgrade().is_some() {
            assert!(Instant::now() < deadline, "{retry_succeeds}");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(origin.shutdown(), 4, "{retry_succeeds}");
    }
}
