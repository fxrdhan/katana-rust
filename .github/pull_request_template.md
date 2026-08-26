## 🎯 Summary
<!-- Provide a clear, concise summary of the changes introduced in this PR. -->

## 🔗 Upstream Parity & References
<!-- Reference relevant sections in KATANA_ARCHITECTURE_CORPUS.md or ProjectDiscovery Go implementation -->
- **Architecture Corpus Section**: 
- **Upstream Go Reference**: 
- **Closes / Relates to**: #

---

## 🛠️ Type of Change
<!-- Mark with an 'x' that applies -->
- [ ] 🚀 **Feature** (new capability or parity feature)
- [ ] 🐛 **Bug Fix** (fixing unexpected behavior or parser divergence)
- [ ] ⚡ **Performance** (throughput, memory reduction, zero-alloc scanning)
- [ ] ♻️ **Refactor** (code cleanup without behavior changes)
- [ ] 🧪 **Tests** (unit tests, integration tests, fuzzing)
- [ ] 📝 **Documentation** (architecture docs, README, crate docs)

---

## 📦 Affected Crates
<!-- Mark the crates modified by this PR -->
- [ ] `katana-core`
- [ ] `katana-similarity`
- [ ] `katana-parser`
- [ ] `katana-engine`
- [ ] `katana-cli`

---

## 🧪 Testing & Verification
<!-- Describe the tests and verification steps you performed -->
- [ ] `cargo check --workspace`
- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace -- -D warnings`
- [ ] `cargo fmt --check`
- [ ] Manual / live crawl test against testbed

```bash
# Command used for testing:
cargo test -p <crate-name>
```

---

## 📋 Checklist
- [ ] My code adheres to the project's formatting and clippy guidelines.
- [ ] I have added tests that prove my fix is effective or that my feature works.
- [ ] Parity with ProjectDiscovery Katana behavior was verified against the Go reference.
- [ ] Documentation / architecture notes have been updated accordingly.
