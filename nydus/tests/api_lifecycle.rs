#![cfg(feature = "api-server")]

use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

use nydus::api_server::ApiServer;
use nydus_core::{Metrics, OndemandRecorder};
use tempfile::tempdir;

#[test]
fn stop_immediately_after_start_never_loses_the_shutdown_notification() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("api.sock");

    for _ in 0..32 {
        let server = ApiServer::start(
            &format!("unix://{}", path.display()),
            Arc::new(Metrics::new()),
            Arc::new(OndemandRecorder::default()),
        )
        .unwrap();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            server.stop();
            tx.send(()).unwrap();
        });

        rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(!path.exists());
    }
}
