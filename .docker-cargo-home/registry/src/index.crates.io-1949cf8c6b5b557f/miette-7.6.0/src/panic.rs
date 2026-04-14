use std::{error::Error, fmt::Display};

use backtrace::Backtrace;

use crate::{Context, Diagnostic, Result};

/// Tells miette to render panics using its rendering engine.
pub fn set_panic_hook() {
    std::panic::set_hook(Box::new(move |info| {
        let mut message = "Something went wrong".to_string();
        let payload = info.payload();
        if let Some(msg) = payload.downcast_ref::<&str>() {
            message = msg.to_string();
        }
        if let Some(msg) = payload.downcast_ref::<String>() {
            message.clone_from(msg);
        }
        let mut report: Result<()> = Err(Panic(message).into());
        if let Some(loc) = info.location() {
            report = report
                .with_context(|| format!("at {}:{}:{}", loc.file(), loc.line(), loc.column()));
        }
        if let Err(err) = report.with_context(|| "Main thread panicked.".to_string()) {
            eprintln!("Error: {:?}", err);
        }
    }));
}

#[derive(Debug)]
struct Panic(String);

impl Display for Panic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = &self.0;
        let panic = Panic::backtrace();
        write!(f, "{msg}{panic}")
    }
}

impl Error for Panic {}

impl Diagnostic for Panic {
    fn help<'a>(&'a self) -> Option<Box<dyn Display + 'a>> {
        Some(Box::new(
            "set the `RUST_BACKTRACE=1` environment variable to display a backtrace.",
        ))
    }
}

impl Panic {
    fn backtrace() -> String {
        use std::fmt::Write;
        if let Ok(var) = std::env::var("RUST_BACKTRACE") {
            if !var.is_empty() && var != "0" {
                const HEX_WIDTH: usize = std::mem::size_of::<usize>() + 2;
                // Padding for next lines after frame's address
                const NEXT_SYMBOL_PADDING: usize = HEX_WIDTH + 6;
                let mut backtrace = String::new();
                let trace = Backtrace::new();
                let frames = backtrace_ext::short_frames_strict(&trace).enumerate();
                for (idx, (frame, sub_frames)) in frames {
                    let ip = frame.ip();
                    let _ = write!(backtrace, "\n{:4}: {:2$?}", idx, ip, HEX_WIDTH);

                    let symbols = frame.symbols();
                    if symbols.is_empty() {
                        let _ = write!(backtrace, " - <unresolved>");
                        continue;
                    }

                    for (idx, symbol) in symbols[sub_frames].iter().enumerate() {
                        // Print symbols from this address,
                        // if there are several addresses
                        // we need to put it on next line
                        if idx != 0 {
                            let _ = write!(backtrace, "\n{:1$}", "", NEXT_SYMBOL_PADDING);
                        }

                        if let Some(name) = symbol.name() {
                            let _ = write!(backtrace, " - {}", name);
                        } else {
                            let _ = write!(backtrace, " - <unknown>");
                        }

                        // See if there is debug information with file name and line
                        if let (Some(file), Some(line)) = (symbol.filename(), symbol.lineno()) {
                            let _ = write!(
                                backtrace,
                                "\n{:3$}at {}:{}",
                                "",
                                file.display(),
                                line,
                                NEXT_SYMBOL_PADDING
                            );
                        }
                    }
                }
                return backtrace;
            }
        }
        "".into()
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn panic() {
        let panic = Panic("ruh roh raggy".to_owned());

        assert_eq!(panic.to_string(), "ruh roh raggy");
        assert!(panic.source().is_none());
        assert!(panic.code().is_none());
        assert!(panic.severity().is_none());
        assert_eq!(
            panic.help().map(|h| h.to_string()),
            Some(
                "set the `RUST_BACKTRACE=1` environment variable to display a backtrace."
                    .to_owned()
            )
        );
        assert!(panic.url().is_none());
        assert!(panic.source_code().is_none());
        assert!(panic.labels().is_none());
        assert!(panic.related().is_none());
        assert!(panic.diagnostic_source().is_none());
    }
}
