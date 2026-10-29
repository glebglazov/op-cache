use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Get { key: String },
    Set { key: String, value: String },
    Ping,
    ClearCache,
    GetStats,
    Shutdown,
    /// Like `Get`, but a cold key comes back `Claimed` to one client at a time
    /// and a recent failure comes back `Failed`. The claimant reports with `Set`
    /// or `Fail` on the same connection; closing it gives the claim up.
    Lookup { key: String },
    Fail { key: String, error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Response {
    Hit { value: String },
    Miss,
    Stored,
    Pong,
    CacheCleared,
    Stats(CacheStats),
    ShuttingDown,
    Failed { error: String },
    Claimed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

/// Wire format: [4-byte length (big-endian)][MessagePack payload]
pub async fn write_message<W, T>(writer: &mut W, msg: &T) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
    T: Serialize,
{
    let payload = rmp_serde::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    let len = payload.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_message<R, T>(reader: &mut R) -> std::io::Result<T>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Sanity check to prevent OOM
    if len > 10 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "message too large",
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;

    rmp_serde::from_slice(&payload)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
