#![feature(test)]

extern crate petgraph;
extern crate test;

use petgraph::graph6::ToGraph6;
use test::Bencher;

#[allow(dead_code)]
mod common;
use common::ungraph;

#[bench]
fn graph6_string_praust_bench(bench: &mut Bencher) {
    let a = ungraph().praust_a();
    let b = ungraph().praust_b();

    bench.iter(|| (a.graph6_string(), b.graph6_string()));
}

#[bench]
fn graph6_string_full_bench(bench: &mut Bencher) {
    let a = ungraph().full_a();
    let b = ungraph().full_b();

    bench.iter(|| (a.graph6_string(), b.graph6_string()));
}

#[bench]
fn graph6_string_petersen_bench(bench: &mut Bencher) {
    let a = ungraph().petersen_a();
    let b = ungraph().petersen_b();

    bench.iter(|| (a.graph6_string(), b.graph6_string()));
}
