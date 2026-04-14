use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use std::fs;
use unicode_segmentation::UnicodeSegmentation;

const FILES: &[&str] = &[
    "log", //"arabic",
    "english",
    //"hindi",
    "japanese",
    //"korean",
    //"mandarin",
    //"russian",
    //"source_code",
];

#[inline(always)]
fn grapheme(text: &str) {
    for w in text.unicode_word_indices() {
        black_box(w);
    }
}

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("unicode_word_indices");

    for file in FILES {
        let input = fs::read_to_string(format!("benches/texts/{file}.txt")).unwrap();
        group.throughput(criterion::Throughput::Bytes(input.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(file), &input, |b, content| {
            b.iter(|| grapheme(content))
        });
    }
}

criterion_group!(benches, bench_all);
criterion_main!(benches);
