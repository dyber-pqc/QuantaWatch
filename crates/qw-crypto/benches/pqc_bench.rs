use criterion::{criterion_group, criterion_main, Criterion, black_box};
use qw_crypto::{SigningKeyPair, KemKeyPair, sha3_256, MerkleTree};

// ---------------------------------------------------------------------------
// ML-DSA-65 benchmarks
// ---------------------------------------------------------------------------

fn bench_ml_dsa_65(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-dsa-65");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            black_box(SigningKeyPair::generate().unwrap());
        });
    });

    // Sign a 1 KB message
    let kp = SigningKeyPair::generate().unwrap();
    let message_1kb = vec![0xABu8; 1024];

    group.bench_function("sign-1kb", |b| {
        b.iter(|| {
            black_box(kp.sign(black_box(&message_1kb)).unwrap());
        });
    });

    // Verify a signature
    let signature = kp.sign(&message_1kb).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(
                kp.verify(black_box(&message_1kb), black_box(&signature))
                    .unwrap(),
            );
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// ML-KEM-768 benchmarks
// ---------------------------------------------------------------------------

fn bench_ml_kem_768(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml-kem-768");

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            black_box(KemKeyPair::generate().unwrap());
        });
    });

    // Encapsulate
    let kp = KemKeyPair::generate().unwrap();

    group.bench_function("encapsulate", |b| {
        b.iter(|| {
            black_box(kp.encapsulate().unwrap());
        });
    });

    // Decapsulate
    let (ciphertext, _shared_secret) = kp.encapsulate().unwrap();

    group.bench_function("decapsulate", |b| {
        b.iter(|| {
            black_box(kp.decapsulate(black_box(&ciphertext)).unwrap());
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// SHA3-256 benchmarks
// ---------------------------------------------------------------------------

fn bench_sha3_256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha3-256");

    let data_1kb = vec![0xCDu8; 1_024];
    let data_10kb = vec![0xCDu8; 10_240];
    let data_100kb = vec![0xCDu8; 102_400];

    group.bench_function("hash-1kb", |b| {
        b.iter(|| {
            black_box(sha3_256(black_box(&data_1kb)));
        });
    });

    group.bench_function("hash-10kb", |b| {
        b.iter(|| {
            black_box(sha3_256(black_box(&data_10kb)));
        });
    });

    group.bench_function("hash-100kb", |b| {
        b.iter(|| {
            black_box(sha3_256(black_box(&data_100kb)));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Merkle tree benchmarks
// ---------------------------------------------------------------------------

fn bench_merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle-tree");

    // Build a set of leaf hashes
    let leaves_100: Vec<[u8; 32]> = (0..100)
        .map(|i| sha3_256(format!("leaf-{i}").as_bytes()))
        .collect();

    let leaves_1000: Vec<[u8; 32]> = (0..1_000)
        .map(|i| sha3_256(format!("leaf-{i}").as_bytes()))
        .collect();

    group.bench_function("build-100-leaves", |b| {
        b.iter(|| {
            black_box(MerkleTree::compute_root(black_box(&leaves_100)));
        });
    });

    group.bench_function("build-1000-leaves", |b| {
        b.iter(|| {
            black_box(MerkleTree::compute_root(black_box(&leaves_1000)));
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    bench_ml_dsa_65,
    bench_ml_kem_768,
    bench_sha3_256,
    bench_merkle_tree,
);
criterion_main!(benches);
