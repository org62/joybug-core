//! Framed stream for sending and receiving length-prefixed bincode messages.
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::debug;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

// Global timing stats
static SERIALIZE_US: AtomicU64 = AtomicU64::new(0);
static DESERIALIZE_US: AtomicU64 = AtomicU64::new(0);
static SEND_BYTES: AtomicU64 = AtomicU64::new(0);
static RECV_BYTES: AtomicU64 = AtomicU64::new(0);
static SEND_COUNT: AtomicUsize = AtomicUsize::new(0);
static RECV_COUNT: AtomicUsize = AtomicUsize::new(0);
static NET_SEND_US: AtomicU64 = AtomicU64::new(0);
static NET_RECV_US: AtomicU64 = AtomicU64::new(0);

pub fn print_serialization_stats() {
    let ser = SERIALIZE_US.load(Ordering::Relaxed) as f64 / 1000.0;
    let deser = DESERIALIZE_US.load(Ordering::Relaxed) as f64 / 1000.0;
    let send_bytes = SEND_BYTES.load(Ordering::Relaxed);
    let recv_bytes = RECV_BYTES.load(Ordering::Relaxed);
    let send_count = SEND_COUNT.load(Ordering::Relaxed);
    let recv_count = RECV_COUNT.load(Ordering::Relaxed);
    let net_send = NET_SEND_US.load(Ordering::Relaxed) as f64 / 1000.0;
    let net_recv = NET_RECV_US.load(Ordering::Relaxed) as f64 / 1000.0;
    eprintln!("=== SERIALIZATION STATS (bincode) ===");
    eprintln!("  Serialize:   {:>8.2} ms ({} calls, {} bytes)", ser, send_count, send_bytes);
    eprintln!("  Deserialize: {:>8.2} ms ({} calls, {} bytes)", deser, recv_count, recv_bytes);
    eprintln!("  Net send:    {:>8.2} ms", net_send);
    eprintln!("  Net recv:    {:>8.2} ms", net_recv);
    eprintln!("=====================================");
}

pub fn reset_serialization_stats() {
    SERIALIZE_US.store(0, Ordering::Relaxed);
    DESERIALIZE_US.store(0, Ordering::Relaxed);
    SEND_BYTES.store(0, Ordering::Relaxed);
    RECV_BYTES.store(0, Ordering::Relaxed);
    SEND_COUNT.store(0, Ordering::Relaxed);
    RECV_COUNT.store(0, Ordering::Relaxed);
    NET_SEND_US.store(0, Ordering::Relaxed);
    NET_RECV_US.store(0, Ordering::Relaxed);
}

pub struct FramedJsonStream {
    stream: TcpStream,
    read_buffer: Vec<u8>,
}

impl FramedJsonStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buffer: Vec::with_capacity(4096),
        }
    }

    pub fn send<T: Serialize>(&mut self, message: &T) -> anyhow::Result<()> {
        // Serialize with bincode
        let start = Instant::now();
        let data = bincode::serde::encode_to_vec(message, BINCODE_CONFIG)?;
        SERIALIZE_US.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);
        SEND_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
        SEND_COUNT.fetch_add(1, Ordering::Relaxed);

        // Send: 8 bytes length + data
        let net_start = Instant::now();
        let len_bytes = (data.len() as u64).to_le_bytes();
        self.stream.write_all(&len_bytes)?;
        self.stream.write_all(&data)?;
        NET_SEND_US.fetch_add(net_start.elapsed().as_micros() as u64, Ordering::Relaxed);

        debug!("Sent message: {:?}", std::any::type_name::<T>());
        Ok(())
    }

    pub fn receive<T: DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        // Receive header: 8 bytes length
        let net_start = Instant::now();
        let mut len_bytes = [0u8; 8];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        self.read_buffer.resize(len, 0);
        self.stream.read_exact(&mut self.read_buffer)?;
        NET_RECV_US.fetch_add(net_start.elapsed().as_micros() as u64, Ordering::Relaxed);
        RECV_BYTES.fetch_add(len as u64, Ordering::Relaxed);
        RECV_COUNT.fetch_add(1, Ordering::Relaxed);

        // Deserialize with bincode
        let start = Instant::now();
        let (message, _): (T, _) = bincode::serde::decode_from_slice(&self.read_buffer, BINCODE_CONFIG)
            .map_err(|e| {
                eprintln!("bincode decode error for {}: {}", std::any::type_name::<T>(), e);
                e
            })?;
        DESERIALIZE_US.fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);

        debug!("Received message: {:?}", std::any::type_name::<T>());
        Ok(message)
    }
}
