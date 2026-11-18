// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

const MAX_BINARY: &[u8] = b"9223372036854775807";

/// Exact decimal coefficient and exponent for a nonnegative container resource
/// quantity. Keep the exponent separate so even large exponents take bounded space.
fn decimal(value: &str) -> Option<(Vec<u8>, i64)> {
    let negative = value.starts_with('-');
    let value = value.strip_prefix(['+', '-']).unwrap_or(value);
    let end = value
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(end);
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    let mut digits = whole.bytes().chain(fraction.bytes()).collect::<Vec<_>>();
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }

    let mut exponent = -i64::try_from(fraction.len()).ok()?;
    let binary_power = ["Ki", "Mi", "Gi", "Ti", "Pi", "Ei"]
        .iter()
        .position(|s| *s == suffix);
    if let Some(power) = binary_power {
        // Scale the decimal digits by the binary suffix without a floating-point conversion.
        let factor = 1_u64 << (10 * (power + 1));
        let mut carry = 0;
        digits.reverse();
        for digit in &mut digits {
            let product = u64::from(*digit - b'0') * factor + carry;
            *digit = b'0' + (product % 10) as u8;
            carry = product / 10;
        }
        while carry != 0 {
            digits.push(b'0' + (carry % 10) as u8);
            carry /= 10;
        }
        digits.reverse();
    } else {
        exponent += match suffix {
            "" => 0,
            "n" => -9,
            "u" => -6,
            "m" => -3,
            "k" => 3,
            "M" => 6,
            "G" => 9,
            "T" => 12,
            "P" => 15,
            "E" => 18,
            other => i64::from(other.strip_prefix(['e', 'E'])?.parse::<i32>().ok()?),
        };
    }
    let Some(first) = digits.iter().position(|d| *d != b'0') else {
        return Some((Vec::new(), 0));
    };
    if negative {
        return None;
    }
    digits.drain(..first);
    // Kubernetes rounds nonzero quantities away from zero at nano precision.
    if exponent < -9 {
        let keep = digits
            .len()
            .saturating_sub(usize::try_from(-9 - exponent).unwrap_or(usize::MAX));
        let round_up = digits[keep..].iter().any(|digit| *digit != b'0');
        digits.truncate(keep);
        if round_up {
            if let Some(index) = digits.iter().rposition(|digit| *digit != b'9') {
                digits[index] += 1;
                digits[index + 1..].fill(b'0');
            } else {
                digits.fill(b'0');
                digits.insert(0, b'1');
            }
        }
        exponent = -9;
    }
    // BinarySI saturates at i64::MAX. Compare at most its 19 integer digits.
    if binary_power.is_some() {
        let integer_digits = i64::try_from(digits.len()).ok()? + exponent;
        if integer_digits > 19 || (integer_digits == 19 && digits.as_slice() > MAX_BINARY) {
            return Some((MAX_BINARY.to_vec(), 0));
        }
    }
    while digits.last() == Some(&b'0') {
        digits.pop();
        exponent += 1;
    }
    Some((digits, exponent))
}

pub(super) fn equivalent(expected: &serde_json::Value, actual: &serde_json::Value) -> bool {
    // The raw Pod template can use JSON numbers. Kubernetes emits Quantity as a string.
    let parse = |value: &serde_json::Value| match value {
        serde_json::Value::String(value) => decimal(value),
        serde_json::Value::Number(value) => decimal(&value.to_string()),
        _ => None,
    };
    parse(expected).is_some_and(|value| Some(value) == parse(actual))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_at_kubernetes_precision() {
        for (left, right) in [
            ("0.5", "500m"),
            ("1.5Gi", "1536Mi"),
            ("+1E+3", "1k"),
            ("1e-99", "1n"),
            ("0.00000001901", "20n"),
            ("9.9999999999", "10"),
            (".00000000001Ki", "11n"),
            ("8Ei", "9223372036854775807"),
            ("-0", "0n"),
            ("9007199254740993", "9007199254740993000m"),
        ] {
            assert!(
                equivalent(&left.into(), &right.into()),
                "{left} and {right}"
            );
        }
        for (left, right) in [
            ("1G", "1Gi"),
            ("1M", "1m"),
            ("1e", "1"),
            ("0.5.0", "500m"),
            ("1ki", "1Ki"),
            ("9007199254740993", "9007199254740992"),
        ] {
            assert!(
                !equivalent(&left.into(), &right.into()),
                "{left} and {right}"
            );
        }
    }
}
