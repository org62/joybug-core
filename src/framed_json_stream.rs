//! Framed JSON stream for sending and receiving length-prefixed JSON messages.
use serde::{de::DeserializeOwned, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;
use tracing::debug;

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
        let data = serde_json::to_vec(message)?;
        let len_bytes = (data.len() as u64).to_le_bytes();
        self.stream.write_all(&len_bytes)?;
        self.stream.write_all(&data)?;
        debug!("Sent message: {:?}", std::any::type_name::<T>());
        Ok(())
    }

    pub fn receive<T: DeserializeOwned>(&mut self) -> anyhow::Result<T> {
        let mut len_bytes = [0u8; 8];
        self.stream.read_exact(&mut len_bytes)?;
        let len = u64::from_le_bytes(len_bytes) as usize;

        self.read_buffer.resize(len, 0);
        self.stream.read_exact(&mut self.read_buffer)?;

        let message: T = serde_json::from_slice(&self.read_buffer)?;
        debug!("Received message: {:?}", std::any::type_name::<T>());
        Ok(message)
    }
}