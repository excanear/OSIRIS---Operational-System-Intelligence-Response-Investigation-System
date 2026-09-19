use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest compressed frame accepted (bytes on the wire).
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;
/// Largest decompressed payload accepted (zip-bomb bound).
pub const MAX_DECOMPRESSED_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    TooLarge(usize),
    #[error("frame did not decompress within {MAX_DECOMPRESSED_LEN} bytes")]
    Decompress,
    #[error("frame payload is not valid: {0}")]
    Payload(#[from] serde_json::Error),
    #[error("connection closed")]
    Closed,
}

/// `[u32 BE length][zstd(JSON)]`.
pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    message: &T,
) -> Result<(), FrameError> {
    let json = serde_json::to_vec(message)?;
    let compressed = zstd::bulk::compress(&json, 3)?;
    if compressed.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(compressed.len()));
    }
    writer
        .write_all(&(compressed.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(&compressed).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads one frame. A clean EOF before the length prefix is `Closed`.
pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
) -> Result<T, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut compressed = vec![0u8; len];
    reader.read_exact(&mut compressed).await?;
    // Stream-decode with a hard cap so an attacker-declared content size never
    // drives a large up-front allocation.
    let mut decoder =
        zstd::stream::read::Decoder::new(&compressed[..]).map_err(|_| FrameError::Decompress)?;
    let mut json = Vec::new();
    std::io::Read::read_to_end(
        &mut std::io::Read::take(&mut decoder, MAX_DECOMPRESSED_LEN as u64 + 1),
        &mut json,
    )
    .map_err(|_| FrameError::Decompress)?;
    if json.len() > MAX_DECOMPRESSED_LEN {
        return Err(FrameError::Decompress);
    }
    Ok(serde_json::from_slice(&json)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ServerMsg;

    #[tokio::test]
    async fn a_frame_round_trips() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        let sent = ServerMsg::Nack {
            seq: 7,
            reason: "x".into(),
            permanent: true,
        };
        write_frame(&mut a, &sent).await.unwrap();
        let got: ServerMsg = read_frame(&mut b).await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn an_oversized_length_prefix_is_rejected_before_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
        let err = read_frame::<_, ServerMsg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }

    #[tokio::test]
    async fn a_closed_stream_is_reported_as_closed() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        let err = read_frame::<_, ServerMsg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Closed));
    }

    #[tokio::test]
    async fn a_decompression_bomb_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let bomb = zstd::bulk::compress(&vec![0u8; MAX_DECOMPRESSED_LEN + 1024], 3).unwrap();
        a.write_all(&(bomb.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&bomb).await.unwrap();
        let err = read_frame::<_, ServerMsg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Decompress));
    }

    #[test]
    fn limits_fit_agent_batches_but_stay_small() {
        assert_eq!(MAX_FRAME_LEN, 8 * 1024 * 1024);
        assert_eq!(MAX_DECOMPRESSED_LEN, 16 * 1024 * 1024);
    }

    #[tokio::test]
    async fn garbage_that_is_not_zstd_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&4u32.to_be_bytes()).await.unwrap();
        a.write_all(b"nope").await.unwrap();
        let err = read_frame::<_, ServerMsg>(&mut b).await.unwrap_err();
        assert!(matches!(err, FrameError::Decompress));
    }
}
