use criterion::{black_box, criterion_group, criterion_main, Criterion};
use katana_similarity::fingerprint::fingerprint_url;
use katana_similarity::pathtrie::PathTrie;
use katana_similarity::simhash::{hamming_distance, simhash64};

fn bench_simhash(c: &mut Criterion) {
    let text = "<html><body><h1>Hello World</h1><p>Testing simhash calculation on web pages</p></body></html>";
    c.bench_function("simhash64_html", |b| {
        b.iter(|| simhash64(black_box(text.split_whitespace())))
    });

    c.bench_function("hamming_distance", |b| {
        let h1: u64 = 0x123456789abcdef0;
        let h2: u64 = 0x123456789abcdeff;
        b.iter(|| hamming_distance(black_box(h1), black_box(h2)))
    });
}

fn bench_fingerprinting(c: &mut Criterion) {
    let target_url = "https://example.com/api/v1/users/12345/posts/98765/comments?page=2&sort=desc";

    c.bench_function("fingerprint_url_static", |b| {
        b.iter(|| fingerprint_url(black_box(target_url), None))
    });

    let trie = PathTrie::new(10);
    c.bench_function("fingerprint_url_adaptive_trie", |b| {
        b.iter(|| fingerprint_url(black_box(target_url), Some(&trie)))
    });
}

criterion_group!(benches, bench_simhash, bench_fingerprinting);
criterion_main!(benches);
