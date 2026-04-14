use std::io::{self, BufRead};

// Copied from the standard library with modification
// to support searching for two bytes.
// https://github.com/rust-lang/rust/blob/e35a56d96f7d9d4422f2b7b00bf0bf282b2ec782/library/std/src/io/mod.rs#L2067
pub(crate) fn read_until2<R: BufRead + ?Sized>(
    r: &mut R,
    delim1: u8,
    delim2: u8,
    buf: &mut Vec<u8>,
) -> io::Result<usize> {
    let mut read = 0;
    loop {
        let (done, used) = {
            let available = match r.fill_buf() {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            if let Some(i) = memchr::memchr2(delim1, delim2, available) {
                buf.extend_from_slice(&available[..=i]);
                (true, i + 1)
            } else {
                buf.extend_from_slice(available);
                (false, available.len())
            }
        };
        r.consume(used);
        read += used;
        if done || used == 0 {
            return Ok(read);
        }
    }
}
