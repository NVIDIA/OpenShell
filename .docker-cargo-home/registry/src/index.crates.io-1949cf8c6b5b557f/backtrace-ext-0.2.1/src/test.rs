use super::*;

type BT = &'static [&'static [&'static str]];

impl Backtraceish for BT {
    type Frame = &'static [&'static str];
    fn frames(&self) -> &[Self::Frame] {
        self
    }
}

impl Frameish for &'static [&'static str] {
    type Symbol = &'static str;
    fn symbols(&self) -> &[Self::Symbol] {
        self
    }
}

impl Symbolish for &'static str {
    fn name_str(&self) -> Option<&str> {
        Some(self)
    }
}

fn process(bt: BT) -> Vec<&'static str> {
    let mut result = vec![];
    for (frame, subframes) in short_frames_strict_impl(&bt) {
        let symbols = &frame.symbols()[subframes];
        assert!(!symbols.is_empty());
        for symbol in symbols {
            result.push(*symbol);
        }
    }
    result
}

#[test]
fn test_full() {
    let bt: BT = &[&["hello"], &["there", "simple"], &["case"]];
    let expected = vec!["hello", "there", "simple", "case"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_empty() {
    let bt: BT = &[];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_cursed_one_true_symbol1() {
    let bt: BT = &[
        &["hello"],
        &["__rust_end_short_backtrace_rust_begin_short_backtrace"],
        &["there"],
    ];
    let expected = vec![
        "hello",
        "__rust_end_short_backtrace_rust_begin_short_backtrace",
        "there",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_cursed_one_true_symbol2() {
    let bt: BT = &[
        &["hello"],
        &["__rust_begin_short_backtrace_rust_end_short_backtrace"],
        &["there"],
    ];
    let expected: Vec<&str> = vec![
        "hello",
        "__rust_begin_short_backtrace_rust_end_short_backtrace",
        "there",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_backwards1() {
    let bt: BT = &[
        &["hello"],
        &["__rust_begin_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_end_short_backtrace"],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "__rust_begin_short_backtrace",
        "real",
        "frames",
        "rust_end_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_backwards2() {
    let bt: BT = &[
        &["hello"],
        &["__rust_begin_short_backtrace", "real", "frames"],
        &["rust_end_short_backtrace"],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "__rust_begin_short_backtrace",
        "real",
        "frames",
        "rust_end_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_backwards3() {
    let bt: BT = &[
        &["hello"],
        &["__rust_begin_short_backtrace"],
        &["real", "frames", "rust_end_short_backtrace"],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "__rust_begin_short_backtrace",
        "real",
        "frames",
        "rust_end_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_backwards4() {
    let bt: BT = &[
        &["hello"],
        &[
            "__rust_begin_short_backtrace",
            "real",
            "frames",
            "rust_end_short_backtrace",
        ],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "__rust_begin_short_backtrace",
        "real",
        "frames",
        "rust_end_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_begin_clamp_simple() {
    let bt: BT = &[&["hello"], &["__rust_begin_short_backtrace"], &["case"]];
    let expected = vec!["hello"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_begin_clamp_left_edge() {
    let bt: BT = &[&["__rust_begin_short_backtrace"], &["case"]];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_begin_clamp_right_edge() {
    let bt: BT = &[&["hello"], &["__rust_begin_short_backtrace"]];
    let expected = vec!["hello"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_begin_clamp_empty() {
    let bt: BT = &[&["__rust_begin_short_backtrace"]];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_begin_clamp_sub() {
    let bt: BT = &[
        &["real"],
        &["frames", "core::rust_begin_short_backtrace", "junk"],
        &["junk"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_end_clamp_simple() {
    let bt: BT = &[&["hello"], &["__rust_end_short_backtrace"], &["case"]];
    let expected = vec!["case"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_end_clamp_left_edge() {
    let bt: BT = &[&["_rust_end_short_backtrace"], &["case"]];
    let expected = vec!["case"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_end_clamp_right_edge() {
    let bt: BT = &[&["hello"], &["__rust_end_short_backtrace"]];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_end_clamp_empty() {
    let bt: BT = &[&["__rust_end_short_backtrace"]];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_end_clamp_sub() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace", "real"],
        &["frames"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_simple() {
    let bt: BT = &[
        &["hello"],
        &["__rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_multiball_various() {
    let bt: BT = &[
        &["hello"],
        &["__rust_end_short_backtrace"],
        &["core::rust_end_short_backtrace"],
        &["junk"],
        &["rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["_rust_begin_short_backtrace"],
        &["junk"],
        &["core::rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_multiball_identical() {
    let bt: BT = &[
        &["hello"],
        &["rust_end_short_backtrace"],
        &["rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_multiball_invert1() {
    let bt: BT = &[
        &["hello"],
        &["rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["junk"],
        &["rust_end_short_backtrace"],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "rust_end_short_backtrace",
        "real",
        "frames",
        "rust_begin_short_backtrace",
        "junk",
        "rust_end_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_multiball_invert2() {
    let bt: BT = &[
        &["hello"],
        &["rust_begin_short_backtrace"],
        &["junk"],
        &["rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected = vec![
        "hello",
        "rust_begin_short_backtrace",
        "junk",
        "rust_end_short_backtrace",
        "real",
        "frames",
        "rust_begin_short_backtrace",
        "case",
    ];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_adjacent() {
    let bt: BT = &[
        &["hello"],
        &["__rust_end_short_backtrace"],
        &["rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_left_edge() {
    let bt: BT = &[
        &["__rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
        &["case"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_right_edge() {
    let bt: BT = &[
        &["hello"],
        &["__rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["rust_begin_short_backtrace"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_spanned() {
    let bt: BT = &[
        &["__rust_end_short_backtrace"],
        &["real"],
        &["frames"],
        &["__rust_begin_short_backtrace"],
    ];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_both_spanned_empty() {
    let bt: BT = &[
        &["rust_end_short_backtrace"],
        &["rust_begin_short_backtrace"],
    ];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_one_super_frame_2() {
    let bt: BT = &[&[
        "rust_end_short_backtrace",
        "real",
        "frames",
        "rust_begin_short_backtrace",
    ]];
    let expected = vec!["real", "frames"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_one_super_frame_1() {
    let bt: BT = &[&[
        "rust_end_short_backtrace",
        "real",
        "rust_begin_short_backtrace",
    ]];
    let expected = vec!["real"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_one_super_frame_0() {
    let bt: BT = &[&["rust_end_short_backtrace", "rust_begin_short_backtrace"]];
    let expected: Vec<&str> = vec![];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex1() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace", "real"],
        &["frames"],
        &["here", "__rust_begin_short_backtrace", "junk"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex2() {
    let bt: BT = &[
        &["junk"],
        &["__rust_end_short_backtrace", "real"],
        &["frames"],
        &["here", "__rust_begin_short_backtrace", "junk"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex3() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace", "real"],
        &["frames"],
        &["here", "__rust_begin_short_backtrace"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex4() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace"],
        &["real", "frames"],
        &["here", "__rust_begin_short_backtrace"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex5() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace", "real"],
        &["frames", "here"],
        &["__rust_begin_short_backtrace"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex6() {
    let bt: BT = &[
        &["junk"],
        &[
            "junk",
            "__rust_end_short_backtrace",
            "real",
            "frames",
            "here",
        ],
        &["__rust_begin_short_backtrace"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}

#[test]
fn test_complex7() {
    let bt: BT = &[
        &["junk"],
        &["junk", "__rust_end_short_backtrace"],
        &["real", "frames", "here", "__rust_begin_short_backtrace"],
        &["junk"],
    ];
    let expected = vec!["real", "frames", "here"];
    assert_eq!(process(bt), expected);
}
