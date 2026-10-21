use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use magnetar_constraint::{Field, F2_128, F61};

fn field_benchmarks(c: &mut Criterion) {
    let a = F2_128::from(0x0123_4567_89ab_cdefu64);
    let b = F2_128::from(0xfedc_ba98_7654_3210u64);

    c.bench_function("f2_128_mul", |bench| {
        bench.iter(|| black_box(black_box(a) * black_box(b)))
    });
    c.bench_function("f2_128_inv", |bench| bench.iter(|| black_box(a).inv()));

    let p = F61::from(1_234_567_891u64);
    let q = F61::from(9_876_543_211u64);
    c.bench_function("f61_mul", |bench| {
        bench.iter(|| black_box(black_box(p) * black_box(q)))
    });
    c.bench_function("f61_inv", |bench| bench.iter(|| black_box(p).inv()));
}

criterion_group!(benches, field_benchmarks);
criterion_main!(benches);
