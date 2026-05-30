//! Criterion benchmark for the Levenshtein typosquat primitive — the hottest
//! inner loop when a large `popular_packages` list is configured.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use depaudit_core::typosquat::levenshtein;

fn bench_levenshtein(c: &mut Criterion) {
    c.bench_function("levenshtein_short", |b| {
        b.iter(|| levenshtein(black_box("requests"), black_box("requets")))
    });
    c.bench_function("levenshtein_long", |b| {
        b.iter(|| {
            levenshtein(
                black_box("react-router-dom-helpers"),
                black_box("react-router-dom-helper"),
            )
        })
    });
}

criterion_group!(benches, bench_levenshtein);
criterion_main!(benches);
