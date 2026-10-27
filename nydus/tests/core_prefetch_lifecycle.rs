//! Drop a real core while its registry prefetch is retrying HTTP 503. The
//! in-flight operation may settle, but no second blob may start, and all
//! detached workers must release image telemetry/tracing within a bound.
#![cfg(feature = "registry")]

#[path = "../../nydus-core/tests/common/mod.rs"]
mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nydus_config::Config;
use nydus_core::{
    CreateFileOptions, ErofsReader, IncrementalWriter, IncrementalWriterOptions, NydusCore,
};

#[test]
fn dropping_core_during_http_retry_bounds_worker_lifetime_and_starts_no_new_blob() {
    for retry_succeeds in [true, false] {
        exercise_drop(retry_succeeds);
    }
}

fn exercise_drop(retry_succeeds: bool) {
    let image = common::Image::build();
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
    let upper_id = hex::encode(blobs[1].blob_id);
    let blob = fs::read(output.join(&upper_id)).unwrap();
    drop(reader);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = requests.clone();
    let (retry_started, retry_seen) = mpsc::channel();
    let (release_retry, retry_release) = mpsc::channel();
    let expected_id = upper_id.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut data_requests = 0;
        while !stopped.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "HTTP fixture exceeded lifetime bound"
            );
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("HTTP accept: {error}"),
            };
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
            let request = String::from_utf8(request).unwrap();
            let target = request.split_whitespace().nth(1).unwrap().to_owned();
            observed.lock().unwrap().push(target.clone());
            assert_eq!(
                target,
                format!("/v2/test/image/blobs/sha256:{expected_id}"),
                "drop must prevent opening another blob"
            );
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
                (
                    start.parse::<usize>().unwrap(),
                    end.parse::<usize>().unwrap(),
                )
            };
            let mut unavailable = false;
            if start == 0 {
                data_requests += 1;
                assert!(data_requests <= 2, "HTTP retries must be bounded");
                if data_requests == 1 {
                    unavailable = true;
                } else {
                    retry_started.send(()).unwrap();
                    retry_release.recv_timeout(Duration::from_secs(3)).unwrap();
                    unavailable = !retry_succeeds;
                }
            }
            if unavailable {
                stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ).unwrap();
            } else {
                write!(stream,
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                    end - start + 1, start, end, blob.len(),
                ).unwrap();
                stream.write_all(&blob[start..=end]).unwrap();
            }
        }
        assert_eq!(data_requests, 2, "exercise a real prefetch retry");
    });
    let config = Config::from_yaml(&format!(
        "backend:\n  type: registry\n  config:\n    addr: http://{address}\n    repository: test/image\n    http:\n      request_timeout: 2s\n      max_retries: 0\nstorage:\n  dir: {}\nprefetch:\n  scope: all\n  concurrent_blob_count: 1\n  retry_interval: 50ms\n  request_timeout: 2s\n",
        image.dir.path().join("cache").display(),
    )).unwrap();
    let core = NydusCore::new(&bootstrap, config, None).unwrap();
    let metrics = Arc::downgrade(core.metrics());
    let trace = Arc::downgrade(core.ondemand_recorder());
    retry_seen
        .recv_timeout(Duration::from_secs(5))
        .expect("prefetch never retried HTTP 503");
    let dropped = Instant::now();
    drop(core);
    assert!(
        dropped.elapsed() < Duration::from_secs(1),
        "core drop blocked on HTTP"
    );
    assert!(
        metrics.upgrade().is_some(),
        "retry must still own the backend"
    );
    release_retry.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while metrics.upgrade().is_some() || trace.upgrade().is_some() {
        assert!(
            Instant::now() < deadline,
            "detached prefetch retained the image"
        );
        thread::sleep(Duration::from_millis(1));
    }
    stop.store(true, Ordering::Release);
    server.join().unwrap();
    // Footer + metadata + initial data request + its one retry, all upper.
    assert_eq!(requests.lock().unwrap().len(), 4);
}
