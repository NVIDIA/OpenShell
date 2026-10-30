// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sanitizers for free-form text that lands in OCSF events.

/// Sanitize a free-form reviewer-typed string before it lands in the OCSF
/// audit surface. Callers keep the raw text for their own consumers; this is
/// audit-side defense only.
///
/// Strips control characters (except space) and caps the length, marking
/// truncation with an ellipsis.
#[must_use]
pub fn sanitize_reason_for_audit(raw: &str) -> String {
    const MAX_CHARS: usize = 200;
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_control() || *c == ' ')
        .take(MAX_CHARS)
        .collect();
    if raw.chars().count() > MAX_CHARS {
        format!("{cleaned}…")
    } else {
        cleaned
    }
}

/// Most arguments rendered by [`sanitize_cmd_line_for_audit`].
const MAX_CMD_LINE_ARGS: usize = 64;
/// Most characters rendered by [`sanitize_cmd_line_for_audit`].
const MAX_CMD_LINE_CHARS: usize = 1024;
/// Most `name=` or `name:` prefixes examined in one argument.
const MAX_NAME_VALUE_DEPTH: usize = 4;
const REDACTED: &str = "[REDACTED]";

/// Name fragments, compared without case or separators, whose value is secret.
const SENSITIVE_NAME_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "cookie",
    "authorization",
    "bearer",
    "apikey",
    "accesskey",
    "privatekey",
    "sessionkey",
    "signature",
];

/// Whole words, between separators, whose value is secret.
const SENSITIVE_NAME_WORDS: &[&str] = &["pwd", "pass", "auth"];

/// Options whose value is `user:password`.
const USER_FLAGS: &[&str] = &["-u", "--user", "--proxy-user"];

/// Prefixes of well-known credential formats.
const SECRET_PREFIXES: &[&str] = &[
    "sk-",
    "sk_live_",
    "rk_live_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxs-",
    "xapp-",
    "AKIA",
    "ASIA",
    "AIza",
    "ya29.",
    "nvapi-",
    "hf_",
    "gsk_",
    "npm_",
    "pypi-",
    "shpat_",
    "dop_v1_",
];

/// What the argument after the current one holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Plain,
    Secret,
    UserPassword,
}

/// Render a command and its arguments as one line for the OCSF audit surface.
///
/// Redaction is a best-effort denylist and cannot catch a secret passed as a
/// plain positional argument. It covers values of options and `NAME=value` or
/// `Header: value` arguments whose name looks secret, the argument after a bare
/// secret-named option, `user:password` values, well-known credential formats,
/// and URL userinfo, query, and fragment. Arguments with whitespace, quotes, or
/// control characters are double-quoted with escapes, so one argument never
/// splits or forges a log line. At most 64 arguments and 1024 characters are
/// kept, and truncation is marked with an ellipsis.
#[must_use]
pub fn sanitize_cmd_line_for_audit<'a>(command: impl IntoIterator<Item = &'a str>) -> String {
    let mut words = command.into_iter();
    let argv: Vec<&str> = words.by_ref().take(MAX_CMD_LINE_ARGS).collect();
    let mut truncated = words.next().is_some();
    let mut out = String::new();
    let mut chars = 0;
    let mut next = Next::Plain;
    for arg in argv {
        let (text, following) = match next {
            Next::Secret => (REDACTED.to_string(), Next::Plain),
            Next::UserPassword => redact_user_password(arg)
                .map_or_else(|| redact_arg(arg), |text| (text, Next::Plain)),
            Next::Plain => redact_arg(arg),
        };
        next = following;
        let rendered = quote_arg(&text);
        if !out.is_empty() {
            out.push(' ');
            chars += 1;
        }
        chars += rendered.chars().count();
        out.push_str(&rendered);
        if chars > MAX_CMD_LINE_CHARS {
            truncated = true;
            break;
        }
    }
    if chars > MAX_CMD_LINE_CHARS {
        out = out.chars().take(MAX_CMD_LINE_CHARS).collect();
    }
    if truncated {
        out.push('…');
    }
    out
}

/// The text to log for `arg`, and what the next argument holds.
///
/// Peels up to `MAX_NAME_VALUE_DEPTH` `name=` or `name:` prefixes, so that
/// `--env=TOKEN=x` and `--header=Authorization: x` are caught. When the limit
/// is reached, a remainder that mentions a secret name is redacted whole.
fn redact_arg(arg: &str) -> (String, Next) {
    let mut out = String::new();
    let mut rest = arg;
    for depth in 0..=MAX_NAME_VALUE_DEPTH {
        if is_secret_shaped(rest) {
            out.push_str(REDACTED);
            return (out, Next::Plain);
        }
        let Some((name, sep, value)) = split_name_value(rest) else {
            break;
        };
        if depth == MAX_NAME_VALUE_DEPTH {
            if is_sensitive_name(rest) {
                out.push_str(REDACTED);
                return (out, Next::Plain);
            }
            break;
        }
        out.push_str(name);
        out.push(sep);
        if is_sensitive_name(name) {
            out.push_str(REDACTED);
            return (out, Next::Plain);
        }
        if sep == '=' && USER_FLAGS.contains(&name) {
            out.push_str(&redact_user_password(value).unwrap_or_else(|| value.to_string()));
            return (out, Next::Plain);
        }
        rest = value;
    }
    if out.is_empty() && USER_FLAGS.contains(&arg) {
        return (arg.to_string(), Next::UserPassword);
    }
    if out.is_empty() && takes_secret_value(arg) {
        return (arg.to_string(), Next::Secret);
    }
    out.push_str(&redact_urls(rest));
    (out, Next::Plain)
}

/// Split `arg` at its first `=` or `:`, except for the `:` of a URL scheme.
fn split_name_value(arg: &str) -> Option<(&str, char, &str)> {
    let index = arg.find(['=', ':'])?;
    if arg[index..].starts_with("://") {
        return None;
    }
    let sep = arg[index..].chars().next()?;
    Some((&arg[..index], sep, &arg[index + 1..]))
}

fn is_sensitive_name(name: &str) -> bool {
    let collapsed: String = name
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    SENSITIVE_NAME_PARTS
        .iter()
        .any(|part| collapsed.contains(part))
        || name
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| {
                SENSITIVE_NAME_WORDS
                    .iter()
                    .any(|w| word.eq_ignore_ascii_case(w))
            })
}

/// Whether the bare option `flag` takes a secret as its next argument. A flag
/// that only switches a mode or names a file or limit does not.
fn takes_secret_value(flag: &str) -> bool {
    let name = flag.trim_start_matches('-').to_ascii_lowercase();
    flag.starts_with('-')
        && is_sensitive_name(&name)
        && !["no-", "no_", "max"].iter().any(|p| name.starts_with(p))
        && !["stdin", "file", "path"].iter().any(|s| name.ends_with(s))
}

/// `user:[REDACTED]` for a `user:password` value, or `None` when `arg` has no
/// password. A `uid:gid` pair is not a password.
fn redact_user_password(arg: &str) -> Option<String> {
    let (user, password) = arg.split_once(':')?;
    let digits = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_digit());
    (!(digits(user) && digits(password))).then(|| format!("{user}:{REDACTED}"))
}

fn is_secret_shaped(text: &str) -> bool {
    let text = text.trim();
    let has_prefix = text.len() >= 20 && SECRET_PREFIXES.iter().any(|p| text.starts_with(p));
    let is_jwt = text.starts_with("eyJ") && text.matches('.').count() == 2;
    let is_auth_value = ["bearer ", "basic "].iter().any(|scheme| {
        text.get(..scheme.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(scheme))
    });
    has_prefix || is_jwt || is_auth_value
}

/// Replace the userinfo of every URL in `text`, and drop their queries and
/// fragments. A URL ends at whitespace.
fn redact_urls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(index) = rest.find("://") {
        let (head, after) = rest.split_at(index + 3);
        out.push_str(head);
        let (url, tail) = after.split_at(after.find(char::is_whitespace).unwrap_or(after.len()));
        let (authority, path) = url.split_at(url.find(['/', '?', '#']).unwrap_or(url.len()));
        match authority.rsplit_once('@') {
            Some((_, host)) => {
                out.push_str(REDACTED);
                out.push('@');
                out.push_str(host);
            }
            None => out.push_str(authority),
        }
        match path.find(['?', '#']) {
            Some(index) => {
                out.push_str(&path[..index]);
                out.push_str("?[REDACTED]");
            }
            None => out.push_str(path),
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Characters that hide or reorder text without being control characters.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{200b}'..='\u{200f}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2069}'
            | '\u{feff}'
    )
}

/// Double-quote `arg` when it is empty or has whitespace, quotes, backslashes,
/// or characters that need escaping, and escape them.
fn quote_arg(arg: &str) -> String {
    let plain = !arg.is_empty()
        && !arg.chars().any(|c| {
            c.is_whitespace() || c.is_control() || is_invisible_format(c) || c == '"' || c == '\\'
        });
    if plain {
        return arg.to_string();
    }
    let mut quoted = String::with_capacity(arg.len() + 2);
    quoted.push('"');
    for c in arg.chars() {
        match c {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            c if c.is_control() || is_invisible_format(c) => {
                use std::fmt::Write as _;
                let _ = write!(quoted, "\\u{{{:x}}}", u32::from(c));
            }
            c => quoted.push(c),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::{sanitize_cmd_line_for_audit, sanitize_reason_for_audit};

    fn cmd_line(argv: &[&str]) -> String {
        sanitize_cmd_line_for_audit(argv.iter().copied())
    }

    #[test]
    fn sanitize_reason_for_audit_strips_control_chars_and_caps_length() {
        // Tabs and newlines are stripped; ordinary printable chars survive;
        // multi-byte characters count as one char in the cap.
        let raw = "line one\nline\ttwo\u{0001}\u{0007}";
        let cleaned = sanitize_reason_for_audit(raw);
        assert!(!cleaned.contains('\n'));
        assert!(!cleaned.contains('\t'));
        assert!(!cleaned.contains('\u{0001}'));
        assert!(cleaned.contains("line one"));
        assert!(cleaned.contains("linetwo"));

        // Length cap with ellipsis marker so a downstream reader can tell
        // the audit string is truncated.
        let long: String = "x".repeat(500);
        let capped = sanitize_reason_for_audit(&long);
        assert!(capped.chars().count() <= 201);
        assert!(capped.ends_with('…'));

        // Empty input maps to empty output (caller renders "(no guidance)").
        assert_eq!(sanitize_reason_for_audit(""), "");
    }

    #[test]
    fn cmd_line_keeps_plain_arguments() {
        assert_eq!(
            cmd_line(&["python3", "/app/main.py", "--port", "8080", "hello"]),
            "python3 /app/main.py --port 8080 hello"
        );
        assert_eq!(cmd_line(&[]), "");
    }

    #[test]
    fn cmd_line_quotes_and_escapes_arguments() {
        assert_eq!(
            cmd_line(&["sh", "-c", "echo hi\nfake [log]\u{1b}", ""]),
            r#"sh -c "echo hi\nfake [log]\u{1b}" """#
        );
        assert_eq!(cmd_line(&["say", "a \"b\" c\\"]), r#"say "a \"b\" c\\""#);
    }

    #[test]
    fn cmd_line_redacts_sensitive_arguments() {
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln";
        let github = format!("ghp_{}", "a".repeat(36));
        let cases: &[(&[&str], &str)] = &[
            (&["app", "--token=s3cret"], "app --token=[REDACTED]"),
            (
                &["app", "--api-key", "s3cret", "-v"],
                "app --api-key [REDACTED] -v",
            ),
            (
                &["env", "DB_PASSWORD=s3cret", "app"],
                "env DB_PASSWORD=[REDACTED] app",
            ),
            (
                &["curl", "-H", "Authorization: Bearer s3cret"],
                "curl -H Authorization:[REDACTED]",
            ),
            (
                &["app", "--cfg=sk-aaaaaaaaaaaaaaaaaaaaaaaa"],
                "app --cfg=[REDACTED]",
            ),
            (&["app", jwt], "app [REDACTED]"),
            (&["app", &github], "app [REDACTED]"),
            (
                &["curl", "https://user:s3cret@example.com/a?k=s3cret#s3cret"],
                "curl https://[REDACTED]@example.com/a?[REDACTED]",
            ),
            (
                &["app", "--url=https://example.com?k=s3cret"],
                "app --url=https://example.com?[REDACTED]",
            ),
            (&["app", "--env=TOKEN=s3cret"], "app --env=TOKEN=[REDACTED]"),
            (
                &["curl", "--header=X-Auth-Token: s3cret"],
                "curl --header=X-Auth-Token:[REDACTED]",
            ),
            (
                &["app", "--cfg=sk-aaaaaaaaaaaaaaaaaaaaaaaa:s3cret"],
                "app --cfg=[REDACTED]",
            ),
            (
                &["curl", "-u", "admin:s3cret", "https://example.com"],
                "curl -u admin:[REDACTED] https://example.com",
            ),
            (
                &["curl", "--user=admin:s3cret"],
                "curl --user=admin:[REDACTED]",
            ),
            (
                &["openssl", "enc", "-pass", "pass:s3cret"],
                "openssl enc -pass [REDACTED]",
            ),
            (
                &["app", "--key=nvapi-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "app --key=[REDACTED]",
            ),
        ];
        for (argv, expected) in cases {
            let rendered = cmd_line(argv);
            assert_eq!(&rendered, expected);
            assert!(!rendered.contains("s3cret"), "{rendered}");
            assert!(!rendered.contains(jwt) && !rendered.contains(&github));
        }
    }

    #[test]
    fn cmd_line_redacts_secrets_inside_compound_arguments() {
        for argv in [
            &["sh", "-c", "export A=1 B=2 C=3 D=4 E=5 TOKEN=s3cret; run"][..],
            &["curl", "-d", "a=1&b=2&c=3&d=4&e=5&client_secret=s3cret"],
            &[
                "sh",
                "-c",
                "curl https://a.example/x https://u:s3cret@b.example/y?k=s3cret",
            ],
        ] {
            let rendered = cmd_line(argv);
            assert!(rendered.contains(super::REDACTED), "{rendered}");
            assert!(!rendered.contains("s3cret"), "{rendered}");
        }
    }

    #[test]
    fn cmd_line_keeps_non_secret_options_and_urls() {
        for argv in [
            &[
                "curl",
                "--output=/tmp/out",
                "localhost:8080",
                "https://github.com/x",
            ][..],
            &["docker", "run", "-u", "1000:1000", "--user=nobody", "image"],
            &["docker", "login", "--password-stdin", "registry.example"],
            &["llm", "--max-tokens", "4096", "--token-file", "/run/key"],
        ] {
            assert_eq!(cmd_line(argv), argv.join(" "));
        }
    }

    #[test]
    fn cmd_line_escapes_invisible_format_characters() {
        assert_eq!(
            cmd_line(&["a\u{202e}b\u{200b}c"]),
            r#""a\u{202e}b\u{200b}c""#
        );
    }

    #[test]
    fn cmd_line_caps_argument_count_and_length() {
        let many = vec!["x"; 100];
        let rendered = cmd_line(&many);
        assert_eq!(rendered, format!("{}…", vec!["x"; 64].join(" ")));

        let long = "y".repeat(5000);
        let rendered = cmd_line(&["app", &long]);
        assert_eq!(rendered.chars().count(), 1025);
        assert!(rendered.starts_with("app yyy") && rendered.ends_with('…'));

        let rendered = cmd_line(&["app", &format!("--token={long}")]);
        assert_eq!(rendered, "app --token=[REDACTED]");
    }

    #[test]
    fn cmd_line_bounds_work_on_pathological_arguments() {
        let separators = "=:".repeat(500_000);
        let rendered = cmd_line(&["app", &separators]);
        assert_eq!(rendered.chars().count(), 1025);
    }
}
