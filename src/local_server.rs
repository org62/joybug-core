//! Local debug server that runs in a separate thread with its own tokio runtime.

use std::net::TcpListener as StdTcpListener;
use std::thread::JoinHandle;
use tokio::sync::oneshot;
use tracing::{error, info};

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:0";

/// Handle for managing a local joybug2 debug server running in a background thread.
pub struct LocalServer {
    port: u16,
    address: String,
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread_handle: Option<JoinHandle<()>>,
}

impl LocalServer {
    /// Start a local debug server on a dynamically allocated port.
    /// Panics on failure. For a non-panicking version, use `start()`.
    pub fn spawn() -> Self {
        Self::start().expect("Failed to start local debug server")
    }

    /// Start a local debug server on a dynamically allocated port.
    pub fn start() -> Result<Self, String> {
        let listener = StdTcpListener::bind(DEFAULT_BIND_ADDR)
            .map_err(|e| format!("Failed to bind listener: {}", e))?;

        let local_addr = listener.local_addr()
            .map_err(|e| format!("Failed to get local address: {}", e))?;
        let port = local_addr.port();
        let address = local_addr.to_string();

        info!(port, "Starting local debug server");

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

        let thread_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime");
            rt.block_on(async move {
                let shutdown_future = async { let _ = shutdown_rx.await; };
                if let Err(e) = crate::server::run_server_with_std_listener(
                    listener,
                    shutdown_future,
                ).await {
                    error!("Local server error: {}", e);
                }
            });
        });

        Ok(Self {
            port,
            address,
            shutdown_tx: Some(shutdown_tx),
            thread_handle: Some(thread_handle),
        })
    }

    /// Returns the port the server is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the full address (e.g., "127.0.0.1:12345").
    pub fn address(&self) -> &str {
        &self.address
    }

    /// Stop the server and wait for the thread to finish.
    pub fn stop(&mut self) {
        info!(port = self.port, "Stopping local debug server");
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop();
    }
}
