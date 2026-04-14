#![doc = include_str!("../README.md")]

/// possible stream sources
#[derive(Clone, Copy, Debug)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// Returns true if the current terminal, detected through various environment
/// variables, is known to support hyperlink rendering.
pub fn supports_hyperlinks() -> bool {
    // Hyperlinks can be forced through this env var.
    if let Ok(arg) = std::env::var("FORCE_HYPERLINK") {
        return arg.trim() != "0";
    }

    if std::env::var("DOMTERM").is_ok() {
        // DomTerm
        return true;
    }

    if let Ok(version) = std::env::var("VTE_VERSION") {
        // VTE-based terminals above v0.50 (Gnome Terminal, Guake, ROXTerm, etc)
        if version.parse().unwrap_or(0) >= 5000 {
            return true;
        }
    }

    if let Ok(program) = std::env::var("TERM_PROGRAM") {
        if matches!(
            &program[..],
            "Hyper" | "iTerm.app" | "terminology" | "WezTerm" | "vscode" | "ghostty" | "zed"
        ) {
            return true;
        }
    }

    if let Ok(term) = std::env::var("TERM") {
        if matches!(&term[..], "xterm-kitty" | "alacritty" | "alacritty-direct") {
            return true;
        }
    }

    if let Ok(term) = std::env::var("COLORTERM") {
        if matches!(&term[..], "xfce4-terminal") {
            return true;
        }
    }

    // Windows Terminal and Konsole
    std::env::var("WT_SESSION").is_ok() || std::env::var("KONSOLE_VERSION").is_ok()
}

fn is_a_tty(stream: Stream) -> bool {
    use std::io::IsTerminal;
    match stream {
        Stream::Stdout => std::io::stdout().is_terminal(),
        Stream::Stderr => std::io::stderr().is_terminal(),
    }
}

/// Returns true if `stream` is a TTY, and the current terminal
/// [supports_hyperlinks].
pub fn on(stream: Stream) -> bool {
    (std::env::var("FORCE_HYPERLINK").is_ok() || is_a_tty(stream)) && supports_hyperlinks()
}
