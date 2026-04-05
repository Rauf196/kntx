use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::pool::buffer::BufferPool;
use crate::util::monotonic_millis;

use super::{Direction, ForwardResult, ProxyError};

/// forward bytes bidirectionally using pooled userspace buffers.
///
/// two concurrent futures (one per direction), each doing read -> write in a
/// loop with a buffer borrowed from the pool. when one direction sees EOF,
/// the write side shuts down to propagate the close,
/// then wait for the other direction to drain.
pub async fn forward(
    client: TcpStream,
    server: TcpStream,
    buffer_pool: &BufferPool,
    last_activity: &AtomicU64,
) -> Result<ForwardResult, ProxyError> {
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();

    let c2b_buf = buffer_pool.get();
    let b2c_buf = buffer_pool.get();

    let (c2b_buf, b2c_buf) = match (c2b_buf, b2c_buf) {
        (Some(a), Some(b)) => (a, b),
        _ => return Err(ProxyError::BufferPoolExhausted),
    };

    let (c2b_result, b2c_result) = tokio::join!(
        copy_one_direction(client_read, server_write, c2b_buf, last_activity),
        copy_one_direction(server_read, client_write, b2c_buf, last_activity),
    );

    let client_to_backend = c2b_result.map_err(|source| ProxyError::Forward {
        direction: Direction::ClientToBackend,
        source,
    })?;

    let backend_to_client = b2c_result.map_err(|source| ProxyError::Forward {
        direction: Direction::BackendToClient,
        source,
    })?;

    Ok(ForwardResult {
        client_to_backend,
        backend_to_client,
    })
}

/// copy bytes from reader to writer using the provided buffer.
/// returns total bytes transferred. shuts down the writer on EOF.
async fn copy_one_direction(
    mut reader: tokio::net::tcp::OwnedReadHalf,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    mut buf: crate::pool::buffer::BufferGuard,
    last_activity: &AtomicU64,
) -> std::io::Result<u64> {
    let mut total = 0u64;

    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            // EOF  - shutdown write side so the peer sees EOF too
            let _ = writer.shutdown().await;
            return Ok(total);
        }

        writer.write_all(&buf[..n]).await?;
        last_activity.store(monotonic_millis(), Ordering::Relaxed);
        total += n as u64;
    }
}
