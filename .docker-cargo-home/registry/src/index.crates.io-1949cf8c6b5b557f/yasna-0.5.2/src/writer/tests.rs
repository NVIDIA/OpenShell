// Copyright 2016 Masaki Hara
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use alloc::vec;

#[cfg(feature = "num-bigint")]
use num_bigint::{BigUint, BigInt};

use super::super::Tag;
use super::*;

#[test]
fn test_der_write_bool() {
    let tests : &[(bool, &[u8])] = &[
        (false, &[1, 1, 0]),
        (true, &[1, 1, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_bool(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_i64() {
    let tests : &[(i64, &[u8])] = &[
        (-9223372036854775808, &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_i64(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_u64() {
    let tests : &[(u64, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
        (18446744073709551615,
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_u64(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_i32() {
    let tests : &[(i32, &[u8])] = &[
        (-2147483648, &[2, 4, 128, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (2147483647, &[2, 4, 127, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_i32(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_u32() {
    let tests : &[(u32, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (2147483647, &[2, 4, 127, 255, 255, 255]),
        (4294967295, &[2, 5, 0, 255, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_u32(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_i16() {
    let tests : &[(i16, &[u8])] = &[
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_i16(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_u16() {
    let tests : &[(u16, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_u16(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_i8() {
    let tests : &[(i8, &[u8])] = &[
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_i8(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_u8() {
    let tests : &[(u8, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (255, &[2, 2, 0, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_u8(value)
        });
        assert_eq!(data, edata);
    }
}


#[test]
fn test_der_write_bigint_bytes() {
    let tests: &[(_, &[_], &[_])] = &[
        // First group: identical to test_der_write_bigint
        (false, &(-9223372036854775808_i64).to_be_bytes(), &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0]),
        (false, &(-65537_i32).to_be_bytes(), &[2, 3, 254, 255, 255]),
        (false, &(-65536_i32).to_be_bytes(), &[2, 3, 255, 0, 0]),
        (false, &(-32769_i32).to_be_bytes(), &[2, 3, 255, 127, 255]),
        (false, &(-32768_i32).to_be_bytes(), &[2, 2, 128, 0]),
        (false, &(-129_i16).to_be_bytes(), &[2, 2, 255, 127]),
        (false, &(-128_i16).to_be_bytes(), &[2, 1, 128]),
        (false, &(-1_i16).to_be_bytes(), &[2, 1, 255]),
        (false, &[0], &[2, 1, 0]),
        (true, &[1], &[2, 1, 1]),
        (true, &127_i16.to_be_bytes(), &[2, 1, 127]),
        (true, &128_i16.to_be_bytes(), &[2, 2, 0, 128]),
        (true, &32767_u16.to_be_bytes(), &[2, 2, 127, 255]),
        (true, &32768_u16.to_be_bytes(), &[2, 3, 0, 128, 0]),
        (true, &65535_u16.to_be_bytes(), &[2, 3, 0, 255, 255]),
        (true, &65536_u32.to_be_bytes(), &[2, 3, 1, 0, 0]),
        (true, &9223372036854775807_u64.to_be_bytes(), &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
        // Second group: more special tests
        // Leading zeros are stripped:
        (true, &[0, 1, 2, 3], &[2, 3, 1, 2, 3]),
        (true, &[0, 0, 1, 2, 3], &[2, 3, 1, 2, 3]),
        (true, &[0, 0, 0, 1, 2, 3], &[2, 3, 1, 2, 3]),
        // [255, 0] is a fixpoint of normalization (it encodes -256):
        (false, &[255, 0], &[2, 2, 255, 0]),
    ];
    for &(is_nonnegative, ref value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_bigint_bytes(*value, is_nonnegative)
        });
        assert_eq!(data, edata);
    }
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_write_bigint() {
    use num_traits::FromPrimitive;
    let tests : &[(i64, &[u8])] = &[
        (-9223372036854775808, &[2, 8, 128, 0, 0, 0, 0, 0, 0, 0]),
        (-65537, &[2, 3, 254, 255, 255]),
        (-65536, &[2, 3, 255, 0, 0]),
        (-32769, &[2, 3, 255, 127, 255]),
        (-32768, &[2, 2, 128, 0]),
        (-129, &[2, 2, 255, 127]),
        (-128, &[2, 1, 128]),
        (-1, &[2, 1, 255]),
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_bigint(&BigInt::from_i64(value).unwrap())
        });
        assert_eq!(data, edata);
    }

    let tests : &[(BigInt, &[u8])] = &[
        (BigInt::parse_bytes(
            b"1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 3, 160, 201, 32, 117, 192, 219,
            243, 184, 172, 188, 95, 150, 206, 63, 10, 210]),
        (BigInt::parse_bytes(
            b"-1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 252, 95, 54, 223, 138, 63, 36,
            12, 71, 83, 67, 160, 105, 49, 192, 245, 46]),
    ];
    for &(ref value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_bigint(value)
        });
        assert_eq!(data, edata);
    }
}

#[cfg(feature = "num-bigint")]
#[test]
fn test_der_write_biguint() {
    use num_traits::FromPrimitive;
    let tests : &[(u64, &[u8])] = &[
        (0, &[2, 1, 0]),
        (1, &[2, 1, 1]),
        (127, &[2, 1, 127]),
        (128, &[2, 2, 0, 128]),
        (32767, &[2, 2, 127, 255]),
        (32768, &[2, 3, 0, 128, 0]),
        (65535, &[2, 3, 0, 255, 255]),
        (65536, &[2, 3, 1, 0, 0]),
        (9223372036854775807, &[2, 8, 127, 255, 255, 255, 255, 255, 255, 255]),
        (18446744073709551615,
            &[2, 9, 0, 255, 255, 255, 255, 255, 255, 255, 255]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_biguint(&BigUint::from_u64(value).unwrap())
        });
        assert_eq!(data, edata);
    }

    let tests : &[(BigUint, &[u8])] = &[
        (BigUint::parse_bytes(
            b"1234567890123456789012345678901234567890", 10).unwrap(),
            &[2, 17, 3, 160, 201, 32, 117, 192, 219,
            243, 184, 172, 188, 95, 150, 206, 63, 10, 210]),
    ];
    for &(ref value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_biguint(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_bytes() {
    let tests : &[(&[u8], &[u8])] = &[
        (&[1, 0, 100, 255], &[4, 4, 1, 0, 100, 255]),
        (&[], &[4, 0]),
        (&[4, 4, 4, 4], &[4, 4, 4, 4, 4, 4]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_bytes(value)
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_null() {
    let data = construct_der(|writer| {
        writer.write_null()
    });
    assert_eq!(data, vec![5, 0]);
}

#[test]
fn test_der_write_sequence_small() {
    let data = construct_der(|writer| {
        writer.write_sequence(|_| {})
    });
    assert_eq!(data, vec![48, 0]);

    let data = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bytes(&vec![91; 20]);
        })
    });
    assert_eq!(data, vec![
        48, 22, 4, 20, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91, 91,
        91, 91, 91, 91, 91, 91]);

    let data = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bytes(&vec![91; 200]);
        })
    });
    assert_eq!(data[0..9].to_vec(),
        vec![48, 129, 203, 4, 129, 200, 91, 91, 91]);
    assert_eq!(data.len(), 206);

    let data = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bytes(&vec![91; 2000]);
        })
    });
    assert_eq!(data[0..11].to_vec(),
        vec![48, 130, 7, 212, 4, 130, 7, 208, 91, 91, 91]);
    assert_eq!(data.len(), 2008);
}

#[test]
fn test_der_write_sequence_medium() {
    let data = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bytes(&vec![91; 200000]);
        })
    });
    assert_eq!(data[0..13].to_vec(),
        vec![48, 131, 3, 13, 69, 4, 131, 3, 13, 64, 91, 91, 91]);
    assert_eq!(data.len(), 200010);
}

#[test]
#[ignore]
fn test_der_write_sequence_large() {
    let data = construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_bytes(&vec![91; 20000000]);
        })
    });
    assert_eq!(data[0..15].to_vec(),
        vec![48, 132, 1, 49, 45, 6, 4, 132, 1, 49, 45, 0, 91, 91, 91]);
    assert_eq!(data.len(), 20000012);
}

#[test]
fn test_der_write_set() {
    let data = construct_der(|writer| {
        writer.write_set(|writer| {
            writer.next().write_tagged_implicit(Tag::context(28), |writer| {
                writer.write_i64(456789)
            });
            writer.next().write_tagged(Tag::context(345678), |writer| {
                writer.write_bytes(b"Foo")
            });
            writer.next().write_tagged(Tag::context(27), |writer| {
                writer.write_i64(456790)
            });
            writer.next().write_tagged(Tag::context(345677), |writer| {
                writer.write_bytes(b"Bar")
            });
        })
    });
    assert_eq!(data, vec![
        49, 32, 187, 5, 2, 3, 6, 248, 86, 156, 3, 6, 248, 85, 191, 149, 140,
        77, 5, 4, 3, 66, 97, 114, 191, 149, 140, 78, 5, 4, 3, 70, 111, 111]);
}

#[test]
fn test_der_write_set_of() {
    let tests : &[(&[i64], &[u8])] = &[
        (&[-129, -128, 127, 128], &[
            49, 14, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127]),
        (&[-128, 127, 128], &[
            49, 10, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128]),
        (&[-129, -128, 127, 128, 32768], &[
            49, 19, 2, 1, 127, 2, 1, 128, 2, 2, 0, 128, 2, 2, 255, 127,
            2, 3, 0, 128, 0]),
    ];
    for &(value, edata) in tests {
        let data = construct_der(|writer| {
            writer.write_set_of(|writer| {
                for &x in value {
                    writer.next().write_i64(x);
                }
            })
        });
        assert_eq!(data, edata);
    }
}

#[test]
fn test_der_write_tagged() {
    let data = construct_der(|writer| {
        writer.write_tagged(Tag::context(3), |writer| {
            writer.write_i64(10)
        })
    });
    assert_eq!(data, vec![163, 3, 2, 1, 10]);
}

#[test]
fn test_der_write_tagged_implicit() {
    let data = construct_der(|writer| {
        writer.write_tagged_implicit(Tag::context(3), |writer| {
            writer.write_i64(10)
        })
    });
    assert_eq!(data, vec![131, 1, 10]);
}
