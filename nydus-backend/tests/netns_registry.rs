//! A real HTTP registry reachable only inside the configured namespace.
//! Set NYDUS_TEST_REQUIRE_NETNS=1 on privileged runners to forbid skips.
#![cfg(all(target_os = "linux", feature = "registry"))]

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nydus_backend::{Backend, Netns};
use nydus_config::{BackendConfig, PrefetchConfig};
use nydus_telemetry::metrics::Metrics;
use nydus_test_utils::{blob::FullBlob, metadata::single_chunk_group};

fn current_netns() -> Netns {
    Netns::new(fs::File::open("/proc/thread-self/ns/net").unwrap().into()).unwrap()
}

#[test]
fn metadata_ondemand_and_prefetch_reach_only_the_configured_namespace() {
    let caller = current_netns().id();
    let isolated = thread::spawn(|| -> io::Result<_> {
        if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let output = Command::new("ip")
            .args(["link", "set", "lo", "up"])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other(format!(
                "ip link set lo up: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok((current_netns(), TcpListener::bind("127.0.0.1:0")?))
    })
    .join()
    .unwrap();
    let (netns, listener) = match isolated {
        Ok(value) => value,
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
            ) =>
        {
            assert!(
                std::env::var_os("NYDUS_TEST_REQUIRE_NETNS").is_none(),
                "required netns precondition failed: {error}"
            );
            eprintln!("SKIP: netns needs CAP_SYS_ADMIN/CAP_NET_ADMIN and iproute2: {error}");
            return;
        }
        Err(error) => panic!("create isolated registry namespace: {error}"),
    };
    assert_ne!(netns.id(), caller);
    netns.probe().unwrap();
    assert_eq!(current_netns().id(), caller);
    exercise_http(Some(netns), listener);
}

#[test]
fn registry_metadata_ondemand_and_prefetch_retry_work_over_real_http() {
    exercise_http(None, TcpListener::bind("127.0.0.1:0").unwrap());
}

fn exercise_http(netns: Option<Netns>, listener: TcpListener) {
    let caller = current_netns().id();
    let addr = listener.local_addr().unwrap();
    // Occupy the same address in the caller namespace. Any escaped request
    // connects here instead and cannot obtain a successful HTTP response.
    let sentinel = netns.as_ref().map(|_| {
        let listener = TcpListener::bind(addr).unwrap();
        listener.set_nonblocking(true).unwrap();
        listener
    });

    let dir = tempfile::tempdir().unwrap();
    let payload = vec![0x9a; 4096];
    let metadata = single_chunk_group(&payload);
    let id = FullBlob::new(&payload)
        .with_blob_metadata(&metadata)
        .save_in(dir.path());
    let blob = fs::read(dir.path().join(hex::encode(id))).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut requests = Vec::new();
        // Footer+table twice, two data reads, and one prefetch 503 retry.
        while requests.len() < 7 {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "registry did not receive all requests"
                    );
                    thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(error) => panic!("registry accept: {error}"),
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
            assert!(request.starts_with(&format!(
                "GET /v2/test/image/blobs/sha256:{} ",
                hex::encode(id)
            )));
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
            let body = &blob[start..=end];
            if requests.len() == 3 {
                stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                ).unwrap();
                requests.push((start, end));
                continue;
            }
            write!(
                stream,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                body.len(), start, end, blob.len()
            ).unwrap();
            stream.write_all(body).unwrap();
            requests.push((start, end));
        }
        requests
    });
    let config: BackendConfig = serde_yaml::from_str(&format!(
        "type: registry\nconfig:\n  addr: http://{addr}\n  repository: test/image\n  http:\n    request_timeout: 2s\n    max_retries: 0\n"
    ))
    .unwrap();
    let backend = <dyn Backend>::new(
        &config,
        &PrefetchConfig {
            retry_interval: Duration::from_millis(50),
            ..PrefetchConfig::default()
        },
        netns,
        Arc::new(Metrics::new()),
    )
    .unwrap();
    assert_eq!(
        backend.read_blob_metadata(&id).unwrap().chunk_group_count(),
        1
    );
    assert_eq!(current_netns().id(), caller);
    let mut data = [0; 16];
    backend.read_range_into(&id, 17, &mut data).unwrap();
    assert_eq!(data, [0x9a; 16]);
    assert_eq!(current_netns().id(), caller);
    assert_eq!(
        backend
            .prefetch_blob_metadata(&id)
            .unwrap()
            .chunk_group_count(),
        1
    );
    backend.prefetch_range_into(&id, 31, &mut data).unwrap();
    assert_eq!(data, [0x9a; 16]);
    assert_eq!(current_netns().id(), caller);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 7);
    assert_eq!(
        requests[3], requests[4],
        "prefetch must retry the failed range"
    );
    if let Some(sentinel) = sentinel {
        assert_eq!(
            sentinel.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}
