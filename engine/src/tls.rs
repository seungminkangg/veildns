//! Bounded ClientHello inspection. TLS is never decrypted or terminated here.
//! Splitting records preserves handshake bytes; TCP packet boundaries are not guaranteed.

use crate::config::normalize_domain;

pub const MAX_INSPECTION_BYTES: usize = 128 * 1024;
const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
const MAX_RECORDS: usize = 64;
const MAX_RECORD_BYTES: usize = 16 * 1024 + 2048;

#[derive(Debug, PartialEq, Eq)]
pub enum Inspection {
    NeedMore,
    Passthrough,
    ClientHello {
        server_name: String,
        record_start: usize,
        split_offset: usize,
    },
}

pub fn inspect(data: &[u8]) -> Inspection {
    if data.len() > MAX_INSPECTION_BYTES {
        return Inspection::Passthrough;
    }
    if data.first().is_some_and(|b| *b != 22) {
        return Inspection::Passthrough;
    }
    let mut offset = 0;
    let mut handshake = Vec::new();
    let mut records = Vec::new();
    for _ in 0..MAX_RECORDS {
        if data.len() < offset + 5 {
            return Inspection::NeedMore;
        }
        if data[offset] != 22 || data[offset + 1] != 3 || data[offset + 2] > 4 {
            return Inspection::Passthrough;
        }
        let length = usize::from(u16::from_be_bytes([data[offset + 3], data[offset + 4]]));
        if length == 0 || length > MAX_RECORD_BYTES {
            return Inspection::Passthrough;
        }
        if data.len() < offset + 5 + length {
            return Inspection::NeedMore;
        }
        records.push((offset, handshake.len(), length));
        handshake.extend_from_slice(&data[offset + 5..offset + 5 + length]);
        if handshake.len() >= 4 {
            let expected = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            if handshake[0] != 1 || expected > MAX_HANDSHAKE_BYTES {
                return Inspection::Passthrough;
            }
            if handshake.len() >= expected + 4 {
                let Some((server_name, start, length)) = parse_hello(&handshake[..expected + 4])
                else {
                    return Inspection::Passthrough;
                };
                let preferred = start + length / 2;
                // Find a split strictly inside both the hostname and a TLS record.
                // A one-byte-per-record hostname is already fragmented: leave it intact.
                for (record_start, handshake_start, record_length) in records {
                    let lower = (start + 1).max(handshake_start + 1);
                    let upper = (start + length - 1).min(handshake_start + record_length - 1);
                    if lower <= upper {
                        return Inspection::ClientHello {
                            server_name,
                            record_start,
                            split_offset: preferred.clamp(lower, upper) - handshake_start,
                        };
                    }
                }
                return Inspection::Passthrough;
            }
        }
        offset += 5 + length;
    }
    Inspection::Passthrough
}

/// Return two wire chunks with one original record replaced by two valid records.
pub fn split_record(
    data: &[u8],
    record_start: usize,
    split_offset: usize,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let header = data.get(record_start..record_start.checked_add(5)?)?;
    let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if split_offset == 0 || split_offset >= length || data.len() < record_start + 5 + length {
        return None;
    }
    let mut first = data[..record_start].to_vec();
    first.extend_from_slice(&header[..3]);
    first.extend_from_slice(&(split_offset as u16).to_be_bytes());
    first.extend_from_slice(&data[record_start + 5..record_start + 5 + split_offset]);
    let mut second = header[..3].to_vec();
    second.extend_from_slice(&((length - split_offset) as u16).to_be_bytes());
    second.extend_from_slice(&data[record_start + 5 + split_offset..]);
    Some((first, second))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let bytes = self
            .bytes
            .get(self.offset..self.offset.checked_add(count)?)?;
        self.offset += count;
        Some(bytes)
    }
    fn u8(&mut self) -> Option<usize> {
        Some(usize::from(*self.take(1)?.first()?))
    }
    fn u16(&mut self) -> Option<usize> {
        let bytes = self.take(2)?;
        Some(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }
    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()?;
        self.take(n)
    }
    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()?;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn parse_hello(bytes: &[u8]) -> Option<(String, usize, usize)> {
    let mut c = Cursor { bytes, offset: 4 };
    c.take(34)?; // legacy version and random
    if c.vec8()?.len() > 32 {
        return None;
    }
    let suites = c.vec16()?;
    if suites.is_empty() || suites.len() % 2 != 0 {
        return None;
    }
    if c.vec8()?.is_empty() {
        return None;
    }
    let extensions = c.vec16()?;
    if !c.done() {
        return None;
    }
    let base = bytes.len() - extensions.len();
    let mut e = Cursor {
        bytes: extensions,
        offset: 0,
    };
    let mut found = None;
    while !e.done() {
        let kind = e.u16()?;
        let value = e.vec16()?;
        if kind != 0 {
            continue;
        }
        if found.is_some() {
            return None;
        }
        let value_base = base + e.offset - value.len();
        let mut v = Cursor {
            bytes: value,
            offset: 0,
        };
        let names = v.vec16()?;
        if !v.done() {
            return None;
        }
        let mut n = Cursor {
            bytes: names,
            offset: 0,
        };
        while !n.done() {
            let name_type = n.u8()?;
            let name = n.vec16()?;
            if name_type == 0 {
                if found.is_some() || name.len() < 2 {
                    return None;
                }
                let normalized = normalize_domain(std::str::from_utf8(name).ok()?).ok()?;
                found = Some((
                    normalized,
                    value_base + 2 + n.offset - name.len(),
                    name.len(),
                ));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(name: &str) -> Vec<u8> {
        let mut payload = vec![3, 3];
        payload.extend_from_slice(&[0; 32]);
        payload.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        payload.extend_from_slice(&((name.len() + 9) as u16).to_be_bytes());
        payload.extend_from_slice(&[0, 0]);
        payload.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        payload.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        payload.push(0);
        payload.extend_from_slice(&(name.len() as u16).to_be_bytes());
        payload.extend_from_slice(name.as_bytes());
        let mut handshake = vec![1, 0];
        handshake.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        handshake.extend(payload);
        handshake
    }

    fn record(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![22, 3, 1];
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    fn payloads(wire: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut p = 0;
        while p < wire.len() {
            let n = usize::from(u16::from_be_bytes([wire[p + 3], wire[p + 4]]));
            out.extend_from_slice(&wire[p + 5..p + 5 + n]);
            p += 5 + n;
        }
        out
    }

    #[test]
    fn preserves_handshake_across_original_record_boundaries_and_every_tcp_prefix() {
        let handshake = hello("www.example.com");
        for boundary in 1..handshake.len() {
            let wire = [
                record(&handshake[..boundary]),
                record(&handshake[boundary..]),
            ]
            .concat();
            for prefix in 0..wire.len() {
                assert_eq!(inspect(&wire[..prefix]), Inspection::NeedMore);
            }
            let Inspection::ClientHello {
                server_name,
                record_start,
                split_offset,
            } = inspect(&wire)
            else {
                panic!("boundary {boundary}")
            };
            assert_eq!(server_name, "www.example.com");
            let (a, b) = split_record(&wire, record_start, split_offset).unwrap();
            assert_eq!(payloads(&[a, b].concat()), handshake);
        }
    }

    #[test]
    fn preserves_following_records_and_handshake_messages() {
        let mut handshake = hello("example.com");
        handshake.extend_from_slice(&[11, 0, 0, 1, 42]);
        let mut wire = record(&handshake);
        wire.extend_from_slice(&[23, 3, 3, 0, 2, 7, 9]);
        let Inspection::ClientHello {
            record_start,
            split_offset,
            ..
        } = inspect(&wire)
        else {
            panic!()
        };
        let (a, b) = split_record(&wire, record_start, split_offset).unwrap();
        assert_eq!(payloads(&[a, b].concat()), [handshake, vec![7, 9]].concat());
    }

    #[test]
    fn malformed_unbounded_or_non_tls_inputs_are_not_modified() {
        assert_eq!(inspect(b"GET / HTTP/1.1\r\n"), Inspection::Passthrough);
        assert_eq!(inspect(&[22, 3, 3, 255, 255]), Inspection::Passthrough);
        assert_eq!(
            inspect(&record(&[1, 255, 255, 255])),
            Inspection::Passthrough
        );
        assert_eq!(
            inspect(&record(&hello("bad..example"))),
            Inspection::Passthrough
        );
        assert_eq!(
            inspect(&vec![22; MAX_INSPECTION_BYTES + 1]),
            Inspection::Passthrough
        );
        for i in 0..4096usize {
            let data: Vec<_> = (0..(i % 257))
                .map(|j| ((i * 37 + j * 131) % 256) as u8)
                .collect();
            let _ = inspect(&data); // malformed-input regression: no panic
        }
    }
}
