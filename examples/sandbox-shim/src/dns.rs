// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Minimal DNS wire encoding for the proxy's mediated name lookups.
use anyhow::{Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

pub fn query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>> {
    let name = name.trim_end_matches('.');
    ensure!(!name.is_empty() && name.len() <= 253, "invalid DNS name");
    let mut message = Vec::with_capacity(18 + name.len());
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid DNS label"
        );
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    Ok(message)
}

fn skip_name(message: &[u8], mut offset: usize) -> Result<usize> {
    loop {
        let Some(&length) = message.get(offset) else {
            bail!("truncated DNS name");
        };
        match length {
            0 => return Ok(offset + 1),
            l if l & 0xC0 == 0xC0 => return Ok(offset + 2),
            l => offset += 1 + l as usize,
        }
    }
}

fn u16_at(message: &[u8], offset: usize) -> Result<u16> {
    match message.get(offset..offset + 2) {
        Some(bytes) => Ok(u16::from_be_bytes([bytes[0], bytes[1]])),
        None => bail!("truncated DNS message"),
    }
}

/// Addresses in the answer section of a response to query `id`.
pub fn answers(message: &[u8], id: u16) -> Result<Vec<IpAddr>> {
    ensure!(u16_at(message, 0)? == id, "DNS response ID mismatch");
    let flags = u16_at(message, 2)?;
    ensure!(flags & 0x8000 != 0, "not a DNS response");
    let rcode = flags & 0x000F;
    ensure!(rcode == 0, "DNS response code {rcode}");
    let questions = u16_at(message, 4)?;
    let answers = u16_at(message, 6)?;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)? + 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        let rtype = u16_at(message, offset)?;
        let length = u16_at(message, offset + 8)? as usize;
        let data = message
            .get(offset + 10..offset + 10 + length)
            .ok_or_else(|| anyhow::anyhow!("truncated DNS record"))?;
        match (rtype, length) {
            (TYPE_A, 4) => addresses.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, 16) => {
                let bytes: [u8; 16] = data.try_into().expect("length checked");
                addresses.push(IpAddr::V6(Ipv6Addr::from(bytes)));
            }
            _ => {}
        }
        offset += 10 + length;
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_record() {
        let mut response = query(7, "example.com", TYPE_A).unwrap();
        response[2] = 0x81;
        response[3] = 0x80;
        response[7] = 1; // one answer
        response.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
        assert_eq!(
            answers(&response, 7).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))]
        );
    }

    #[test]
    fn rejects_errors_and_bad_names() {
        let mut response = query(9, "example.com", TYPE_A).unwrap();
        response[2] = 0x81;
        response[3] = 0x83; // NXDOMAIN
        assert!(answers(&response, 9).is_err());
        assert!(query(1, "bad name", TYPE_A).is_err());
        assert!(query(1, "", TYPE_A).is_err());
    }
}
