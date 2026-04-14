#![allow(clippy::unwrap_used)]

use super::*;
use pty_utils::pty_pair;
use std::env;
use std::io::Write;

#[test]
fn ttyname_r_returns_successfully() {
    let pty = pty_pair().unwrap();
    let name = ttyname_r(pty.user.as_fd()).unwrap();
    let name_as_str = name.to_str().unwrap();
    assert!(!name_as_str.is_empty());
    assert!(name_as_str.starts_with("/dev/"));
}

#[test]
fn reopened_tty_can_be_written_to() {
    let pty = pty_pair().unwrap();
    let mut tty = reopen_tty(pty.user.as_fd()).unwrap();
    tty.write_all(b"foo").unwrap();
}

#[test]
fn is_read_write_returns_true_for_read_write_fd() {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .unwrap();
    assert!(is_read_write(file.as_fd()).unwrap());
}

#[test]
fn is_read_write_returns_false_for_read_only_fd() {
    let file = OpenOptions::new().read(true).open("/dev/null").unwrap();
    assert!(!is_read_write(file.as_fd()).unwrap());
}

#[test]
fn is_read_write_returns_false_for_write_only_fd() {
    let file = OpenOptions::new().write(true).open("/dev/null").unwrap();
    assert!(!is_read_write(file.as_fd()).unwrap());
}

#[test]
fn is_same_file_with_same_fd() {
    let file = stdin();
    let fd = file.as_fd();
    assert!(is_same_file(fd, fd).unwrap());
}

#[test]
fn is_same_file_with_different_fd_but_same_underlying_file() {
    let file_1 = OpenOptions::new().read(true).open("/dev/null").unwrap();
    let file_2 = OpenOptions::new().read(true).open("/dev/null").unwrap();
    assert!(file_1.as_raw_fd() != file_2.as_raw_fd());
    assert!(is_same_file(file_1.as_fd(), file_2.as_fd()).unwrap());
}

#[test]
fn is_not_same_file_with_different_underlying_file() {
    let file_1 = OpenOptions::new()
        .read(true)
        .open(env::args().next().unwrap())
        .unwrap();
    let file_2 = OpenOptions::new().read(true).open("/dev/null").unwrap();
    assert!(!is_same_file(file_1.as_fd(), file_2.as_fd()).unwrap());
}
