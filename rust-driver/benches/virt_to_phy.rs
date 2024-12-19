use blue_rdma_driver::bench_wrappers::virt_to_phy_bench_wrapper;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn benchmark_virt_to_phy_batch(c: &mut Criterion) {
    let data: Vec<Vec<u8>> = (0..100).map(|_| vec![0u8; 4096]).collect();
    let addrs: Vec<*const u8> = data.iter().map(|v| v.as_ptr()).collect();

    c.bench_function("virt_to_phy 100 addresses", |b| {
        b.iter(|| virt_to_phy_bench_wrapper(black_box(addrs.clone())))
    });
}

fn benchmark_virt_to_phy_single(c: &mut Criterion) {
    let data: Vec<u8> = vec![0u8; 4096];
    let addr: *const u8 = data.as_ptr();

    c.bench_function("virt_to_phy 1 address", |b| {
        b.iter(|| virt_to_phy_bench_wrapper(black_box(Some(addr))))
    });
}

criterion_group!(
    benches,
    benchmark_virt_to_phy_batch,
    benchmark_virt_to_phy_single
);
criterion_main!(benches);
