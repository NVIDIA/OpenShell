use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

// Define a custom error type
#[derive(Debug)]
pub(crate) enum MyError {
    IoError(std::io::Error),
    Other(String),
}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MyError::IoError(e) => write!(f, "I/O Error: {}", e),
            MyError::Other(s) => write!(f, "Error: {}", s),
        }
    }
}

impl Error for MyError {}

impl From<std::io::Error> for MyError {
    fn from(error: std::io::Error) -> Self {
        MyError::IoError(error)
    }
}

pub(crate) struct Output {
    pub(crate) success: bool,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

pub(crate) fn run(
    compiled: &str,
    unsafe_main: unsafe fn(
        stdin: &mut dyn Read,
        stdout: &mut dyn Write,
    ) -> Result<(), MyError>,
    input: &Path,
) -> Output {
    if cfg!(miri) {
        let mut input = File::open(input).unwrap();
        let mut stdout = Vec::new();
        let result = unsafe { unsafe_main(&mut input, &mut stdout) };

        Output {
            success: result.is_ok(),
            stdout,
            stderr: match result {
                Ok(_) => Vec::new(),
                Err(e) => e.to_string().into_bytes(),
            },
        }
    } else {
        let output = Command::new(compiled)
            .arg(input)
            .stdin(Stdio::null())
            .output()
            .unwrap();

        Output {
            success: output.status.success(),
            stdout: output.stdout,
            stderr: output.stderr,
        }
    }
}
