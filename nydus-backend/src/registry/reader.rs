//! The reader of a blob range a registry read streams.

use std::io::{self, BufRead, Read};

use bytes::{Buf, Bytes};
use tokio::sync::mpsc;

/// Reads a blob range from the chunks its read task sends.
pub(crate) struct StreamReader {
    /// The chunks the read task sends, an error ending them.
    rx: mpsc::Receiver<io::Result<Bytes>>,

    /// The rest of the chunk being read.
    chunk: Bytes,
}

/// Implements the stream reader.
impl StreamReader {
    /// The buffer size for the chunks sent through the channel.
    const CHANNEL_BUFFER_SIZE: usize = 4;

    /// Creates a reader and the sender its read task sends the chunks through.
    pub(crate) fn channel() -> (mpsc::Sender<io::Result<Bytes>>, Self) {
        let (tx, rx) = mpsc::channel(Self::CHANNEL_BUFFER_SIZE);
        (
            tx,
            Self {
                rx,
                chunk: Bytes::new(),
            },
        )
    }
}

/// Implements [Read] by copying out of the chunks.
impl Read for StreamReader {
    /// Copies the next bytes into `buf`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.fill_buf()?.read(buf)?;
        self.consume(len);
        Ok(len)
    }
}

/// Implements [BufRead] over the chunks, borrowing each in place.
impl BufRead for StreamReader {
    /// Returns the rest of the current chunk, waiting for the next one when
    /// it is used up.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        while self.chunk.is_empty() {
            let Some(chunk) = self.rx.blocking_recv() else {
                break;
            };
            self.chunk = chunk?;
        }

        Ok(&self.chunk)
    }

    /// Marks `amt` bytes of the current chunk read.
    fn consume(&mut self, amt: usize) {
        self.chunk.advance(amt);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::type_complexity)]

    use super::*;

    #[test]
    fn fill_buf_hands_out_the_chunks_until_an_error_or_the_end() {
        let test_cases: Vec<(Vec<io::Result<Bytes>>, fn(io::Result<Vec<u8>>))> = vec![
            (
                vec![Ok(Bytes::from_static(b"ab")), Ok(Bytes::from_static(b"cd"))],
                |result| assert_eq!(result.unwrap(), b"abcd"),
            ),
            (
                vec![Ok(Bytes::new()), Ok(Bytes::from_static(b"ab"))],
                |result| assert_eq!(result.unwrap(), b"ab"),
            ),
            (
                vec![
                    Ok(Bytes::from_static(b"ab")),
                    Err(io::Error::other("reset")),
                ],
                |result| assert_eq!(result.unwrap_err().to_string(), "reset"),
            ),
            (vec![], |result| assert!(result.unwrap().is_empty())),
        ];

        for (chunks, expect) in test_cases {
            let (tx, mut reader) = StreamReader::channel();
            let sender = std::thread::spawn(move || {
                for chunk in chunks {
                    tx.blocking_send(chunk).unwrap();
                }
            });

            let mut bytes = Vec::new();
            let result = reader.read_to_end(&mut bytes).map(|_| bytes);
            sender.join().unwrap();

            expect(result);
        }
    }

    #[test]
    fn fill_buf_borrows_the_chunk_in_place() {
        let chunk = Bytes::from_static(b"abcd");
        let (tx, mut reader) = StreamReader::channel();
        tx.blocking_send(Ok(chunk.clone())).unwrap();
        drop(tx);

        assert_eq!(reader.fill_buf().unwrap().as_ptr(), chunk.as_ptr());
        reader.consume(2);
        assert_eq!(reader.fill_buf().unwrap(), b"cd");
    }
}
