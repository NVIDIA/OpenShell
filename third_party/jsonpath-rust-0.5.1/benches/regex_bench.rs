use criterion::{black_box, criterion_group, criterion_main, Criterion};
use jsonpath_rust::path::config::cache::{DefaultRegexCacheInst, RegexCache};
use jsonpath_rust::path::config::JsonPathConfig;
use jsonpath_rust::{JsonPathFinder, JsonPathInst, JsonPathQuery};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::str::FromStr;

fn regex_perf_test_with_cache(cfg: JsonPathConfig) {
    let json = Box::new(json!({
        "author":"abcd(Rees)",
    }));

    let _v = (json, cfg)
        .path("$.[?(@.author ~= '.*(?i)d\\(Rees\\)')]")
        .expect("the path is correct");
}

fn regex_perf_test_without_cache() {
    let json = Box::new(json!({
        "author":"abcd(Rees)",
    }));

    let _v = json
        .path("$.[?(@.author ~= '.*(?i)d\\(Rees\\)')]")
        .expect("the path is correct");
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let cfg = JsonPathConfig::new(RegexCache::Implemented(DefaultRegexCacheInst::default()));
    c.bench_function("regex bench without cache", |b| {
        b.iter(|| regex_perf_test_without_cache())
    });
    c.bench_function("regex bench with cache", |b| {
        b.iter(|| regex_perf_test_with_cache(cfg.clone()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
