//! Newline-delimited framing with a hard size cap.
//!
//! `AsyncBufReadExt::read_line` grows its buffer without bound, which would
//! let a misbehaving peer exhaust memory with a single endless line.

use std::io;

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, PartialEq)]
pub enum Frame {
    /// One message without its trailing `\n` / `\r\n`.
    Line(Vec<u8>),
    /// A line longer than the limit; its bytes were consumed and discarded.
    TooLong,
}

/// Reads the next frame, or `None` at end of input. A final line without a
/// trailing newline is still returned.
pub async fn read_frame<R>(reader: &mut R, max_len: usize) -> io::Result<Option<Frame>>
where
    R: AsyncBufRead + Unpin,
{
    let mut line = Vec::new();
    let mut too_long = false;
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(match (too_long, line.is_empty()) {
                (true, _) => Some(Frame::TooLong),
                (false, true) => None,
                (false, false) => Some(finish(line)),
            });
        }
        let newline = buf.iter().position(|&b| b == b'\n');
        let chunk = &buf[..newline.unwrap_or(buf.len())];
        if !too_long {
            if line.len() + chunk.len() > max_len {
                too_long = true;
                line = Vec::new();
            } else {
                line.extend_from_slice(chunk);
            }
        }
        let consumed = chunk.len() + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            return Ok(Some(if too_long {
                Frame::TooLong
            } else {
                finish(line)
            }));
        }
    }
}

fn finish(mut line: Vec<u8>) -> Frame {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    Frame::Line(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn frames(input: &[u8], max_len: usize) -> Vec<Frame> {
        // A tiny buffer forces lines to span several fill_buf calls.
        let mut reader = tokio::io::BufReader::with_capacity(4, input);
        let mut out = Vec::new();
        while let Some(frame) = read_frame(&mut reader, max_len).await.unwrap() {
            out.push(frame);
        }
        out
    }

    #[tokio::test]
    async fn splits_lines_and_strips_crlf() {
        let got = frames(b"{\"a\":1}\r\n{\"b\":2}\nlast", 64).await;
        assert_eq!(
            got,
            vec![
                Frame::Line(b"{\"a\":1}".to_vec()),
                Frame::Line(b"{\"b\":2}".to_vec()),
                Frame::Line(b"last".to_vec()),
            ]
        );
    }

    #[tokio::test]
    async fn oversized_line_is_skipped_and_stream_recovers() {
        let got = frames(b"0123456789abcdef\nok\n", 8).await;
        assert_eq!(got, vec![Frame::TooLong, Frame::Line(b"ok".to_vec())]);
    }
}
