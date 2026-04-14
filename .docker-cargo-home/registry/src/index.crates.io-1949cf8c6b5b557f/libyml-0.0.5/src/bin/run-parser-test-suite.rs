//! A YAML parser and formatter using the libyml library.
//!
//! This program reads YAML files, parses them using the libyml library,
//! and outputs a formatted representation of the YAML structure.

#![allow(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::items_after_statements,
    clippy::let_underscore_untyped,
    clippy::missing_errors_doc,
    clippy::missing_safety_doc,
    clippy::too_many_lines,
    clippy::uninlined_format_args
)]

mod cstr;

use self::cstr::CStr;
use anyhow::{bail, Error, Result};
use libyml::{
    yaml_event_delete, yaml_parser_delete, yaml_parser_initialize,
    yaml_parser_parse, yaml_parser_set_input, YamlAliasEvent,
    YamlDocumentEndEvent, YamlDocumentStartEvent,
    YamlDoubleQuotedScalarStyle, YamlEventT, YamlEventTypeT,
    YamlFoldedScalarStyle, YamlLiteralScalarStyle, YamlMappingEndEvent,
    YamlMappingStartEvent, YamlNoEvent, YamlParserT,
    YamlPlainScalarStyle, YamlScalarEvent, YamlSequenceEndEvent,
    YamlSequenceStartEvent, YamlSingleQuotedScalarStyle,
    YamlStreamEndEvent, YamlStreamStartEvent,
};
use std::env;
use std::ffi::c_void;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::MaybeUninit;
use std::path::Path;
use std::process::ExitCode;
use std::ptr::addr_of_mut;
use std::slice;

/// The main parsing function that processes YAML input and writes formatted output.
///
/// # Safety
///
/// This function is unsafe because it deals with raw pointers and FFI.
/// Callers must ensure that the provided `stdin` and `stdout` are valid
/// and that the FFI calls are used correctly.
///
/// # Arguments
///
/// * `stdin` - A mutable reference to a type that implements `Read`, from which YAML will be read.
/// * `stdout` - A mutable reference to a type that implements `Write`, to which formatted output will be written.
///
/// # Returns
///
/// Returns `Ok(())` if parsing and formatting succeed, or an `Error` if any issues occur.
pub(crate) unsafe fn unsafe_main(
    mut stdin: &mut dyn Read,
    stdout: &mut dyn Write,
) -> Result<()> {
    let mut parser = MaybeUninit::<YamlParserT>::uninit();
    let parser = parser.as_mut_ptr();
    if yaml_parser_initialize(parser).fail {
        bail!("Could not initialize the parser object");
    }

    /// Callback function for reading input from stdio.
    ///
    /// This function is called by the YAML parser to read input data.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it deals with raw pointers.
    /// It assumes that `data` is a valid pointer to a `Read` trait object.
    unsafe fn read_from_stdio(
        data: *mut c_void,
        buffer: *mut u8,
        size: u64,
        size_read: *mut u64,
    ) -> i32 {
        let stdin: *mut &mut dyn Read = data.cast();
        let slice =
            slice::from_raw_parts_mut(buffer.cast(), size as usize);
        match (*stdin).read(slice) {
            Ok(n) => {
                *size_read = n as u64;
                1
            }
            Err(_) => 0,
        }
    }

    yaml_parser_set_input(
        parser,
        read_from_stdio,
        addr_of_mut!(stdin).cast(),
    );

    let mut event = MaybeUninit::<YamlEventT>::uninit();
    let event = event.as_mut_ptr();
    loop {
        if yaml_parser_parse(parser, event).fail {
            let error = format!(
                "Parse error: {}",
                CStr::from_ptr((*parser).problem)
            );
            let error = if (*parser).problem_mark.line != 0
                || (*parser).problem_mark.column != 0
            {
                format!(
                    "{}\nLine: {} Column: {}",
                    error,
                    ((*parser).problem_mark.line).wrapping_add(1),
                    ((*parser).problem_mark.column).wrapping_add(1),
                )
            } else {
                error
            };
            yaml_parser_delete(parser);
            return Err(Error::msg(error));
        }

        let type_: YamlEventTypeT = (*event).type_;
        match type_ {
            YamlNoEvent => writeln!(stdout, "???")?,
            YamlStreamStartEvent => writeln!(stdout, "+STR")?,
            YamlStreamEndEvent => writeln!(stdout, "-STR")?,
            YamlDocumentStartEvent => {
                write!(stdout, "+DOC")?;
                if !(*event).data.document_start.implicit {
                    write!(stdout, " ---")?;
                }
                writeln!(stdout)?;
            }
            YamlDocumentEndEvent => {
                write!(stdout, "-DOC")?;
                if !(*event).data.document_end.implicit {
                    write!(stdout, " ...")?;
                }
                writeln!(stdout)?;
            }
            YamlMappingStartEvent => {
                write!(stdout, "+MAP")?;
                if !(*event).data.mapping_start.anchor.is_null() {
                    write!(
                        stdout,
                        " &{}",
                        CStr::from_ptr(
                            (*event).data.mapping_start.anchor
                                as *const i8
                        ),
                    )?;
                }
                if !(*event).data.mapping_start.tag.is_null() {
                    write!(
                        stdout,
                        " <{}>",
                        CStr::from_ptr(
                            (*event).data.mapping_start.tag
                                as *const i8
                        ),
                    )?;
                }
                writeln!(stdout)?;
            }
            YamlMappingEndEvent => writeln!(stdout, "-MAP")?,
            YamlSequenceStartEvent => {
                write!(stdout, "+SEQ")?;
                if !(*event).data.sequence_start.anchor.is_null() {
                    write!(
                        stdout,
                        " &{}",
                        CStr::from_ptr(
                            (*event).data.sequence_start.anchor
                                as *const i8
                        ),
                    )?;
                }
                if !(*event).data.sequence_start.tag.is_null() {
                    write!(
                        stdout,
                        " <{}>",
                        CStr::from_ptr(
                            (*event).data.sequence_start.tag
                                as *const i8
                        ),
                    )?;
                }
                writeln!(stdout)?;
            }
            YamlSequenceEndEvent => writeln!(stdout, "-SEQ")?,
            YamlScalarEvent => {
                write!(stdout, "=VAL")?;
                if !(*event).data.scalar.anchor.is_null() {
                    write!(
                        stdout,
                        " &{}",
                        CStr::from_ptr(
                            (*event).data.scalar.anchor as *const i8
                        ),
                    )?;
                }
                if !(*event).data.scalar.tag.is_null() {
                    write!(
                        stdout,
                        " <{}>",
                        CStr::from_ptr(
                            (*event).data.scalar.tag as *const i8
                        ),
                    )?;
                }
                stdout.write_all(match (*event).data.scalar.style {
                    YamlPlainScalarStyle => b" :",
                    YamlSingleQuotedScalarStyle => b" '",
                    YamlDoubleQuotedScalarStyle => b" \"",
                    YamlLiteralScalarStyle => b" |",
                    YamlFoldedScalarStyle => b" >",
                    _ => {
                        return Err(Error::msg("Unknown scalar style"))
                    }
                })?;
                print_escaped(
                    stdout,
                    (*event).data.scalar.value,
                    (*event).data.scalar.length,
                )?;
                writeln!(stdout)?;
            }
            YamlAliasEvent => writeln!(
                stdout,
                "=ALI *{}",
                CStr::from_ptr((*event).data.alias.anchor as *const i8),
            )?,
            _ => return Err(Error::msg("Unknown event type")),
        }

        yaml_event_delete(event);
        if type_ == YamlStreamEndEvent {
            break;
        }
    }
    yaml_parser_delete(parser);
    Ok(())
}

/// Writes an escaped version of a byte slice to the given output.
///
/// This function handles proper escaping of special characters and
/// preserves UTF-8 encoded characters.
///
/// # Safety
///
/// This function is unsafe because it works with raw pointers.
/// The caller must ensure that `str` points to a valid memory location
/// containing at least `length` bytes.
///
/// # Arguments
///
/// * `stdout` - A mutable reference to a type that implements `Write`, to which the escaped output will be written.
/// * `str` - A raw pointer to the start of the byte slice to be escaped.
/// * `length` - The length of the byte slice.
///
/// # Returns
///
/// Returns `Ok(())` if writing succeeds, or an `io::Error` if any issues occur during writing.
unsafe fn print_escaped(
    stdout: &mut dyn Write,
    str: *const u8,
    length: u64,
) -> io::Result<()> {
    let slice = slice::from_raw_parts(str, length as usize);
    let mut chars = slice.iter().peekable();

    while let Some(&byte) = chars.next() {
        if byte >= 128 {
            // Start of a UTF-8 sequence
            stdout.write_all(slice::from_ref(&byte))?;
            while let Some(&&next_byte) = chars.peek() {
                if !(128..192).contains(&next_byte) {
                    break;
                }
                stdout.write_all(slice::from_ref(&next_byte))?;
                let _ = chars.next();
            }
        } else {
            let repr = match byte {
                b'\\' => "\\\\",
                b'\0' => "\\0",
                b'\x08' => "\\b",
                b'\n' => "\\n",
                b'\r' => "\\r",
                b'\t' => "\\t",
                _ if byte.is_ascii_graphic() || byte == b' ' => {
                    stdout.write_all(slice::from_ref(&byte))?;
                    continue;
                }
                _ => {
                    write!(stdout, "\\x{:02x}", byte)?;
                    continue;
                }
            };
            stdout.write_all(repr.as_bytes())?;
        }
    }
    Ok(())
}

/// The entry point of the program.
///
/// This function processes command-line arguments, reads YAML files,
/// and calls the parsing function for each file.
///
/// # Returns
///
/// Returns `ExitCode::SUCCESS` if all files are processed successfully,
/// or `ExitCode::FAILURE` if any errors occur.
fn main() -> ExitCode {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.is_empty() {
        eprintln!("Error: No input files provided.");
        eprintln!(
            "Usage: {} <in.yaml>...",
            env::args().next().unwrap_or_default()
        );
        eprintln!("Please provide one or more YAML files to parse.");
        return ExitCode::FAILURE;
    }

    for arg in args {
        let path = Path::new(&arg);
        if !path.exists() {
            eprintln!("Error: File {:?} does not exist.", path);
            return ExitCode::FAILURE;
        }
        if !path.is_file() {
            eprintln!("Error: {:?} is not a file.", path);
            return ExitCode::FAILURE;
        }

        match File::open(path) {
            Ok(mut file) => {
                let mut stdout = io::stdout();
                eprintln!("Processing file: {:?}", path);
                match unsafe { unsafe_main(&mut file, &mut stdout) } {
                    Ok(()) => eprintln!(
                        "Successfully processed file: {:?}",
                        path
                    ),
                    Err(err) => {
                        eprintln!(
                            "Error processing file {:?}: {}",
                            path, err
                        );
                        eprintln!("The parser encountered an error. Please check if the file contains valid YAML.");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Err(err) => {
                eprintln!("Error opening file {:?}: {}", path, err);
                eprintln!("Please check if you have the necessary permissions to read the file.");
                return ExitCode::FAILURE;
            }
        }
    }

    eprintln!("All files processed successfully.");
    ExitCode::SUCCESS
}
