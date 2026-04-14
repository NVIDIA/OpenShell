use crate::io::{read_until2, TermReader};
use crate::quirks::{terminal_quirks_from_env, TerminalQuirks};
use crate::{Color, ColorPalette, Error, QueryOptions, Result};
use std::io::{self, BufRead, BufReader, Write as _};
use std::time::Duration;
use terminal_trx::{terminal, RawModeGuard};

const QUERY_FG: &[u8] = b"\x1b]10;?";
const FG_RESPONSE_PREFIX: &[u8] = b"\x1b]10;";
const QUERY_BG: &[u8] = b"\x1b]11;?";
const BG_RESPONSE_PREFIX: &[u8] = b"\x1b]11;";

pub(crate) fn foreground_color(options: QueryOptions) -> Result<Color> {
    let quirks = terminal_quirks_from_env();
    let response = query(
        &options,
        quirks,
        |w| write_query(w, quirks, QUERY_FG),
        read_color_response,
    )
    .map_err(map_timed_out_err(options.timeout))?;
    parse_response(response, FG_RESPONSE_PREFIX)
}

pub(crate) fn background_color(options: QueryOptions) -> Result<Color> {
    let quirks = terminal_quirks_from_env();
    let response = query(
        &options,
        quirks,
        |w| write_query(w, quirks, QUERY_BG),
        read_color_response,
    )
    .map_err(map_timed_out_err(options.timeout))?;
    parse_response(response, BG_RESPONSE_PREFIX)
}

pub(crate) fn color_palette(options: QueryOptions) -> Result<ColorPalette> {
    let quirks = terminal_quirks_from_env();
    let (fg_response, bg_response) = query(
        &options,
        quirks,
        |w| write_query(w, quirks, QUERY_FG).and_then(|_| write_query(w, quirks, QUERY_BG)),
        |r| Ok((read_color_response(r)?, read_color_response(r)?)),
    )
    .map_err(map_timed_out_err(options.timeout))?;
    let foreground = parse_response(fg_response, FG_RESPONSE_PREFIX)?;
    let background = parse_response(bg_response, BG_RESPONSE_PREFIX)?;
    Ok(ColorPalette {
        foreground,
        background,
    })
}

fn write_query(w: &mut dyn io::Write, quirks: TerminalQuirks, query: &[u8]) -> io::Result<()> {
    quirks.write_all(w, query)?;
    quirks.write_string_terminator(w)?;
    Ok(())
}

fn map_timed_out_err(timeout: Duration) -> impl Fn(Error) -> Error {
    move |e| match e {
        Error::Io(io) if io.kind() == io::ErrorKind::TimedOut => Error::Timeout(timeout),
        e => e,
    }
}

const ST: &[u8] = b"\x1b\\";
const DA1: &[u8] = b"\x1b[c";
const ESC: u8 = 0x1b;
const BEL: u8 = 0x07;

fn parse_response(response: Vec<u8>, prefix: &[u8]) -> Result<Color> {
    response
        .strip_prefix(prefix)
        .and_then(|r| r.strip_suffix(ST).or(r.strip_suffix(&[BEL])))
        .and_then(xparsecolor)
        .ok_or(Error::Parse(response))
}

fn xparsecolor(input: &[u8]) -> Option<Color> {
    let xterm_color::Color {
        red: r,
        green: g,
        blue: b,
        ..
    } = xterm_color::Color::parse(input).ok()?;
    Some(Color { r, g, b })
}

type Reader<'a> = BufReader<TermReader<RawModeGuard<'a>>>;

// We detect terminals that don't support the color query in quite a smart way:
// First, we send the color query and then a query that we know is well-supported (DA1).
// Since queries are answered sequentially, if a terminal answers to DA1 first, we know that
// it does not support querying for colors.
//
// Source: https://gitlab.freedesktop.org/terminal-wg/specifications/-/issues/8#note_151381
fn query<T>(
    options: &QueryOptions,
    quirks: TerminalQuirks,
    write_query: impl FnOnce(&mut dyn io::Write) -> io::Result<()>,
    read_response: impl FnOnce(&mut Reader<'_>) -> Result<T>,
) -> Result<T> {
    if quirks.is_known_unsupported() {
        return Err(Error::unsupported());
    }

    let mut tty = terminal()?;

    // All standard I/O streams being redirected is a good
    // hint to us that we should not query the terminal.
    if !tty.has_connected_stdio_stream() {
        return Err(Error::unsupported());
    }

    let mut tty = tty.lock();
    let mut tty = tty.enable_raw_mode()?;

    write_query(&mut tty)?;
    quirks.write_all(&mut tty, DA1)?;
    tty.flush()?;

    let mut reader = BufReader::with_capacity(32, TermReader::new(tty, options.timeout));

    let response = read_response(&mut reader)?;

    // We still need to consume the response to DA1
    // Let's ignore errors, they are not that important.
    _ = consume_da1_response(&mut reader, true);

    Ok(response)
}

fn read_color_response(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.read_until(ESC, &mut buf)?; // Both responses start with ESC

    // If we get the response for DA1 back first, then we know that
    // the terminal does not recocgnize the color query.
    if !r.buffer().starts_with(b"]") {
        _ = consume_da1_response(r, false);
        return Err(Error::unsupported());
    }

    // Some terminals always respond with BEL (see terminal survey).
    read_until2(r, BEL, ESC, &mut buf)?;
    if buf.last() == Some(&ESC) {
        r.read_until(b'\\', &mut buf)?;
    }

    Ok(buf)
}

fn consume_da1_response(r: &mut impl BufRead, consume_esc: bool) -> io::Result<()> {
    let mut buf = Vec::new();
    if consume_esc {
        r.read_until(ESC, &mut buf)?;
    }
    r.read_until(b'[', &mut buf)?;
    r.read_until(b'c', &mut buf)?;
    Ok(())
}
