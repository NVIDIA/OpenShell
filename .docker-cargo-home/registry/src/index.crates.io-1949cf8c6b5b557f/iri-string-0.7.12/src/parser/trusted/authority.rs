//! Parsers for trusted `authority` string.

use crate::components::AuthorityComponents;
use crate::parser::str::{find_split_hole, rfind_split2};

/// Decomposes the authority into `(userinfo, host, port)`.
///
/// The leading `:` is truncated.
///
/// # Precondition
///
/// The given string must be a valid IRI reference.
#[inline]
#[must_use]
pub(crate) fn decompose_authority(authority: &str) -> AuthorityComponents<'_> {
    let i = authority;
    let (i, host_start) = match find_split_hole(i, b'@') {
        Some((userinfo, rest)) => (rest, userinfo.len() + 1),
        None => (authority, 0),
    };
    let colon_port_len = match rfind_split2(i, b':', b']') {
        Some((_, suffix)) if suffix.starts_with(':') => suffix.len(),
        _ => 0,
    };
    let host_end = authority.len() - colon_port_len;

    AuthorityComponents {
        authority,
        host_start,
        host_end,
    }
}

/// Returns `true` if the given valid host matches [`reg-name`] (or [`ireg-name`]) production rule.
///
/// # Precondition
///
/// This function expects that the parameter `host` is a valid `host` (or
/// `ihost`). When this is not satisfied, the function may panic or return a
/// meaningless value. However, it won't cause any undefined behavior, so this
/// function is safe.
///
/// [`reg-name`]: https://www.rfc-editor.org/rfc/rfc3986.html#page-21
/// [`ireg-name`]: https://www.rfc-editor.org/rfc/rfc3987.html#page-8
#[must_use]
pub(crate) fn is_host_reg_name(host: &str) -> bool {
    if host.starts_with('[') {
        // `IP-literal`.
        debug_assert!(host.ends_with(']'), "the host {host:?} must be IP-literal");
        return false;
    }

    /// Minimum length of an IPv4 address.
    const IPV4_MIN_LEN: usize = "0.0.0.0".len();
    /// Maximum length of an IPv4 address.
    const IPV4_MAX_LEN: usize = "255.255.255.255".len();

    if !(IPV4_MIN_LEN..=IPV4_MAX_LEN).contains(&host.len()) {
        // Not a IPv4 address, and already confirmed not to be `IP-literal`.
        return true;
    }

    let mut rest = host;
    let mut octets: [&str; 4] = Default::default();

    (octets[0], rest) = match find_split_hole(rest, b'.') {
        Some(v) => v,
        None => return true,
    };
    (octets[1], rest) = match find_split_hole(rest, b'.') {
        Some(v) => v,
        None => return true,
    };
    (octets[2], octets[3]) = match find_split_hole(rest, b'.') {
        Some(v) => v,
        None => return true,
    };

    let is_ipv4_addr = octets
        .into_iter()
        .all(|s| is_decimal_repr_of_octet(s.as_bytes()));
    !is_ipv4_addr
}

/// Returns `true` if the given decimal string is inside `0..=255`.
#[must_use]
const fn is_decimal_repr_of_octet(digits: &[u8]) -> bool {
    matches!(
        digits,
        [b'0'..=b'9']
            | [b'1'..=b'9', b'0'..=b'9']
            | [b'1', b'0'..=b'9', b'0'..=b'9']
            | [b'2', b'0'..=b'4', b'0'..=b'9']
            | [b'2', b'5', b'0'..=b'5']
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn is_host_reg_name() {
        const REG_NAMES: &[&str] = &[
            "www.example.com",
            "example.com",
            "localhost",
            "a",
            "",
            "255.255.255.256",
            "127.0.00.1",
            "127.0.0.01",
        ];
        const NON_REG_NAMES: &[&str] = &[
            "0.0.0.0",
            "127.0.0.1",
            "255.255.255.255",
            "[::1]",
            "[v999.zzz:zzz:zzz:zzz]",
        ];

        for reg_name in REG_NAMES {
            debug_assert!(super::is_host_reg_name(reg_name), "reg_name={reg_name:?}");
        }
        for non_reg_name in NON_REG_NAMES {
            debug_assert!(
                !super::is_host_reg_name(non_reg_name),
                "non_reg_name={non_reg_name:?}"
            );
        }
    }
}
