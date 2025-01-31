use criterion::{black_box, criterion_group, criterion_main, Criterion};
use huginn::{validation::sanitize_input, SecurityConfig};
use std::time::Duration;

fn bench_sanitization(c: &mut Criterion) {
    let config = SecurityConfig::default();
    let binding = "AAAA".repeat(1000);

    let mut group = c.benchmark_group("Sanitization");
    group.sample_size(500);
    group.warm_up_time(Duration::from_secs(5));
    group.measurement_time(Duration::from_secs(10));
    group.noise_threshold(0.05);

    group.bench_function("sanitize 1KB input", |b| {
        b.iter(|| sanitize_input(black_box(binding.as_str()), &config))
    });

    group.finish();
}

criterion_group!(benches, bench_sanitization);
criterion_main!(benches);
