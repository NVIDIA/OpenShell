#![doc = include_str!("../README.md")]

/// possible stream sources
#[derive(Clone, Copy, Debug)]
pub enum Stream {
    Stdout,
    Stderr,
}

fn is_a_tty(stream: Stream) -> bool {
    use std::io::IsTerminal;
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// Returns true if `stream` is a TTY or the current terminal
/// [supports_unicode].
pub fn on(stream: Stream) -> bool {
    if !is_a_tty(stream) {
        // If we're just piping out, it's fine to spit out unicode! :)
        true
    } else {
        supports_unicode()
    }
}

/// Returns true if the current terminal, detected through various environment
/// variables, is known to support unicode rendering.
pub fn supports_unicode() -> bool {
    if std::env::consts::OS == "windows" {
        // Just a handful of things!
        std::env::var("CI").is_ok()
        || std::env::var("WT_SESSION").is_ok() // Windows Terminal
        || std::env::var("ConEmuTask") == Ok("{cmd:Cmder}".into()) // ConEmu and cmder
        || std::env::var("TERM_PROGRAM") == Ok("vscode".into())
        || std::env::var("TERM") == Ok("xterm-256color".into())
        || std::env::var("TERM") == Ok("alacritty".into())
    } else if std::env::var("TERM") == Ok("linux".into()) {
        // Linux kernel console. Maybe redundant with the below?...
        false
    } else {
        // From https://github.com/iarna/has-unicode/blob/master/index.js
        let ctype = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_CTYPE"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_else(|_| "".into())
            .to_uppercase();
        ctype.ends_with("UTF8") || ctype.ends_with("UTF-8")
    }
}
