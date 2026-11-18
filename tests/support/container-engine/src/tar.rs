// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Reads the file out of the tar archive `cp <container>:<path> -` writes.

use testkit::{Error, Result};

const BLOCK: usize = 512;
const SIZE: std::ops::Range<usize> = 124..136;
const TYPE_FLAG: usize = 156;

/// The contents of the first regular file in `archive`. Extended headers,
/// such as the PAX records Podman writes, are skipped.
pub(crate) fn first_file(archive: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0;
    while offset + BLOCK <= archive.len() {
        let header = &archive[offset..offset + BLOCK];
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let size = entry_size(header)?;
        let data = offset + BLOCK;
        testkit::ensure!(
            data + size <= archive.len(),
            "the tar entry at byte {offset} claims {size} bytes, past the end of the archive"
        );
        if matches!(header[TYPE_FLAG], b'0' | 0) {
            return Ok(archive[data..data + size].to_vec());
        }
        offset = data + size.div_ceil(BLOCK) * BLOCK;
    }
    Err(Error::msg("the tar archive holds no regular file"))
}

fn entry_size(header: &[u8]) -> Result<usize> {
    let field = &header[SIZE];
    let digits = std::str::from_utf8(field)
        .ok()
        .map(|text| text.trim_matches(|c: char| c == '\0' || c == ' '))
        .ok_or_else(|| Error::msg(format!("unreadable tar size field {field:?}")))?;
    usize::from_str_radix(digits, 8)
        .map_err(|_| Error::msg(format!("unreadable tar size field {digits:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(type_flag: u8, data: &[u8]) -> Vec<u8> {
        let mut header = vec![0; BLOCK];
        header[SIZE.start..SIZE.end - 1].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[TYPE_FLAG] = type_flag;
        let mut entry = header;
        entry.extend_from_slice(data);
        entry.resize(entry.len().div_ceil(BLOCK) * BLOCK, 0);
        entry
    }

    #[test]
    fn reads_the_file_after_a_pax_header() {
        let mut archive = entry(b'x', b"30 mtime=1795155617.832000000\n");
        archive.extend(entry(b'0', b"header.payload.signature"));
        archive.extend(vec![0; 2 * BLOCK]);
        assert_eq!(first_file(&archive).unwrap(), b"header.payload.signature");
    }

    #[test]
    fn reads_an_empty_file() {
        let mut archive = entry(b'0', b"");
        archive.extend(vec![0; 2 * BLOCK]);
        assert_eq!(first_file(&archive).unwrap(), b"");
    }

    #[test]
    fn rejects_an_archive_without_a_file() {
        let mut archive = entry(b'5', b"");
        archive.extend(vec![0; 2 * BLOCK]);
        assert!(first_file(&archive).is_err());
    }

    #[test]
    fn rejects_a_truncated_entry() {
        let mut archive = entry(b'0', &[b'a'; 600]);
        archive.truncate(BLOCK + 100);
        assert!(first_file(&archive).is_err());
    }
}
