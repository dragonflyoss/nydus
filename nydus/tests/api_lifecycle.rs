//! Regress the server-thread startup/stop notification race. Process-level
//! HTTP isolation and socket lifecycle are covered by the Go E2E suite.
#![cfg(feature = "api-server")]

use std::sync::{mpsc, Arc};
use std::time::Duration;

use nydus::api_server::ApiServer;
use nydus_core::{Metrics, OndemandRecorder};

fn stop(server: ApiServer) {
    let (send, done) = mpsc::channel();
    std::thread::spawn(move || {
        server.stop();
        send.send(()).unwrap();
    });
    done.recv_timeout(Duration::from_secs(3))
        .expect("API shutdown must be bounded");
}

#[test]
fn stop_immediately_after_start_never_loses_shutdown_notification() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("api.sock");
    for _ in 0..32 {
        let server = ApiServer::start(
            &format!("unix://{}", path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
        )
        .unwrap();
        stop(server);
        assert!(!path.exists());
    }
}
