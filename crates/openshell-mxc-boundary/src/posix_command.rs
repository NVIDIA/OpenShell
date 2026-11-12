// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Recover argv from the POSIX command strings that reach a Windows boundary.
//!
//! The gateway and SSH server deliver `exec` requests as one POSIX shell
//! command string built by `shell_escape`: an optional `cd <dir> &&` prefix,
//! `KEY=<value>` assignments, then the escaped argv. Windows has no POSIX
//! shell, and handing that string to `cmd.exe` would mangle its quoting. This
//! module parses exactly that form back into structured parts so the boundary
//! can spawn the program directly with the caller's original arguments.
//! Strings that use any other shell syntax are not parsed; the caller runs them
//! through `cmd.exe` instead.

/// A command string reduced to the pieces the boundary spawns directly.
#[derive(Debug, PartialEq, Eq)]
pub struct PosixCommand {
    pub workdir: Option<String>,
    pub env: Vec<(String, String)>,
    pub argv: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Token {
    Word { text: String, quoted: bool },
    And,
}

/// Parse `[cd <word> &&] [NAME=<word>]... <word>...`.
///
/// Returns `None` when the string uses shell syntax beyond that form
/// (pipes, redirection, variables, globbing, or command separators), or when
/// no program word remains.
pub fn parse(command: &str) -> Option<PosixCommand> {
    let mut tokens = tokenize(command)?.into_iter().peekable();
    let workdir = if matches!(tokens.peek(), Some(Token::Word { text, quoted: false }) if text == "cd")
    {
        tokens.next();
        let Some(Token::Word { text, .. }) = tokens.next() else {
            return None;
        };
        if tokens.next() != Some(Token::And) {
            return None;
        }
        Some(text)
    } else {
        None
    };

    let mut env = Vec::new();
    let mut argv = Vec::new();
    for token in tokens {
        let Token::Word { text, quoted } = token else {
            return None;
        };
        if argv.is_empty()
            && !quoted
            && let Some((name, value)) = assignment(&text)
        {
            env.push((name, value));
            continue;
        }
        argv.push(text);
    }
    if argv.is_empty() {
        return None;
    }
    Some(PosixCommand { workdir, env, argv })
}

/// An unquoted leading `NAME=` makes the word an environment assignment.
fn assignment(word: &str) -> Option<(String, String)> {
    let (name, value) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first == '_' || first.is_ascii_alphabetic())
        || !chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((name.to_string(), value.to_string()))
}

/// Split on unquoted whitespace. A word's `quoted` flag records whether quoting
/// began before its first `=`, which keeps a quoted `'A=b'` an argument.
fn tokenize(command: &str) -> Option<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut chars = command.chars().peekable();
    loop {
        while chars.peek().is_some_and(char::is_ascii_whitespace) {
            chars.next();
        }
        let Some(&first) = chars.peek() else {
            return Some(tokens);
        };
        if first == '&' {
            chars.next();
            if chars.next() != Some('&') {
                return None;
            }
            tokens.push(Token::And);
            continue;
        }

        let mut text = String::new();
        let mut quote_before_equals = false;
        while let Some(&c) = chars.peek() {
            if c.is_ascii_whitespace() {
                break;
            }
            chars.next();
            match c {
                '\'' => {
                    quote_before_equals |= !text.contains('=');
                    loop {
                        match chars.next()? {
                            '\'' => break,
                            other => text.push(other),
                        }
                    }
                }
                '"' => {
                    quote_before_equals |= !text.contains('=');
                    loop {
                        match chars.next()? {
                            '"' => break,
                            '\\' => match chars.next()? {
                                escaped @ ('"' | '\\') => text.push(escaped),
                                other => {
                                    text.push('\\');
                                    text.push(other);
                                }
                            },
                            '$' | '`' => return None,
                            other => text.push(other),
                        }
                    }
                }
                '\\' => text.push(chars.next()?),
                '|' | '&' | ';' | '<' | '>' | '(' | ')' | '$' | '`' | '*' | '?' | '[' | '{'
                | '}' | '~' | '#' => return None,
                other => text.push(other),
            }
        }
        tokens.push(Token::Word {
            text,
            quoted: quote_before_equals,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn plain_arguments_round_trip() {
        let parsed = parse("cmd.exe /d /c echo hello").expect("parsed");
        assert_eq!(parsed.argv, argv(&["cmd.exe", "/d", "/c", "echo", "hello"]));
        assert_eq!(parsed.workdir, None);
        assert!(parsed.env.is_empty());
    }

    #[test]
    fn gateway_escaping_is_reversed() {
        // shell_escape("it's a C:\\path") and an empty argument.
        let parsed = parse(r#"'C:\Program Files\x.exe' 'it'"'"'s' '' plain"#).expect("parsed");
        assert_eq!(
            parsed.argv,
            argv(&[r"C:\Program Files\x.exe", "it's", "", "plain"])
        );
    }

    #[test]
    fn workdir_and_environment_prefixes_are_extracted() {
        let parsed =
            parse(r"cd 'C:\work dir' && A=1 B='two words' tool.exe --flag").expect("parsed");
        assert_eq!(parsed.workdir.as_deref(), Some(r"C:\work dir"));
        assert_eq!(
            parsed.env,
            vec![
                ("A".to_string(), "1".to_string()),
                ("B".to_string(), "two words".to_string())
            ]
        );
        assert_eq!(parsed.argv, argv(&["tool.exe", "--flag"]));
    }

    #[test]
    fn quoted_assignment_is_an_argument() {
        let parsed = parse("'A=1' tool").expect("parsed");
        assert!(parsed.env.is_empty());
        assert_eq!(parsed.argv, argv(&["A=1", "tool"]));
    }

    #[test]
    fn assignment_after_program_is_an_argument() {
        let parsed = parse("tool A=1").expect("parsed");
        assert_eq!(parsed.argv, argv(&["tool", "A=1"]));
    }

    #[test]
    fn shell_syntax_is_not_parsed() {
        for command in [
            "echo a | more",
            "echo a > out.txt",
            "echo a; echo b",
            "echo $HOME",
            "echo *.txt",
            "echo a && echo b",
            "'unterminated",
            "A=1",
            "",
        ] {
            assert_eq!(parse(command), None, "{command}");
        }
    }
}
