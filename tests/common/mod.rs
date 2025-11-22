#![cfg(windows)]

use std::net::TcpListener as StdTcpListener;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;

use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tracing::error;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:0";

pub struct TestServer {
    address: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
    lock_guard: Option<MutexGuard<'static, ()>>,
}

impl TestServer {
    pub fn spawn() -> Self {
        let lock_guard = acquire_server_lock();

        let listener = StdTcpListener::bind(DEFAULT_BIND_ADDR)
            .expect("Failed to bind temporary test server address");
        let address = listener
            .local_addr()
            .expect("Failed to obtain listener address")
            .to_string();

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = thread::spawn(move || {
            let runtime = Runtime::new().expect("Failed to create test tokio runtime");
            let shutdown_future = async move {
                let _ = shutdown_rx.await;
            };

            if let Err(err) = runtime.block_on(joybug2::server::run_server_with_std_listener(
                listener,
                shutdown_future,
            )) {
                error!(?err, "Test server exited with error");
            }
        });

        Self {
            address,
            shutdown_tx: Some(shutdown_tx),
            join_handle: Some(handle),
            lock_guard: Some(lock_guard),
        }
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        if let Some(handle) = self.join_handle.take() {
            if let Err(err) = handle.join() {
                error!(?err, "Test server thread panicked");
            }
        }

        // Drop the lock guard after the server thread has been joined
        let _ = self.lock_guard.take();
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn acquire_server_lock() -> MutexGuard<'static, ()> {
    static SERVER_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    SERVER_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("Failed to lock test server mutex")
}

