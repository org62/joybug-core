//! Framed stream for sending and receiving length-prefixed bincode messages.
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Instant;
use tracing::debug;

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

/// What one `send` or `receive` cost, for the caller's perf span.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameStats {
    /// Payload size on the wire.
    pub bytes: u64,
    /// Encode (send) or decode (receive) time.
    pub codec_us: u64,
    /// Socket write time, or the time blocked in the read — which for a
    /// client is the server's whole handling time.
    pub io_us: u64,
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

    /// Set the read timeout on the underlying socket (see
    /// `TcpStream::set_read_timeout`). A timed-out read leaves the frame stream
    /// desynchronized, so callers must discard the connection on timeout.
    pub fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(dur)
    }

    pub fn send<T: Serialize>(&mut self, message: &T) -> anyhow::Result<()> {
        self.send_timed(message).map(|_| ())
    }

    pub fn send_timed<T: Serialize>(&mut self, message: &T) -> anyhow::Result<FrameStats> {
        // Serialize with bincode
        let start = Instant::now();
        let data = bincode::serde::encode_to_vec(message, BINCODE_CONFIG)?;
        let codec_us = start.elapsed().as_micros() as u64;

        // Send: 8 bytes length + data
        let net_start = Instant::now();
        let len_bytes = (data.len() as u64).to_le_bytes();
        self.stream.write_all(&len_bytes)?;
        self.stream.write_all(&data)?;
        let io_us = net_start.elapsed().as_micros() as u64;

        debug!("Sent message: {:?}", std::any::type_name::<T>());
        Ok(FrameStats { bytes: data.len() as u64, codec_us, io_us })
    }

    pub fn receive<T: DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        self.receive_timed().map(|(message, _)| message)
    }

    pub fn receive_timed<T: DeserializeOwned>(&mut self) -> anyhow::Result<(T, FrameStats)> {
        // Receive header: 8 bytes length
        let net_start = Instant::now();
        let mut len_bytes = [0u8; 8];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        self.read_buffer.resize(len, 0);
        self.stream.read_exact(&mut self.read_buffer)?;
        let io_us = net_start.elapsed().as_micros() as u64;

        // Deserialize with bincode
        let start = Instant::now();
        let (message, _): (T, _) = bincode::serde::decode_from_slice(&self.read_buffer, BINCODE_CONFIG)
            .map_err(|e| {
                tracing::error!("bincode decode error for {}: {}", std::any::type_name::<T>(), e);
                e
            })?;
        let codec_us = start.elapsed().as_micros() as u64;

        debug!("Received message: {:?}", std::any::type_name::<T>());
        Ok((message, FrameStats { bytes: len as u64, codec_us, io_us }))
    }
}
