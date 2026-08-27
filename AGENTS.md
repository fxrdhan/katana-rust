# Repository Guidelines for Antigravity & Coding Agents

This repository contains **Katana-Rust**, a high-performance Rust port of ProjectDiscovery's Katana crawler, organized as a multi-crate Cargo workspace.

---

## 1. Commit Policy: Atomic & Granular Commits

To ensure clean git history, easy code reviews, and deterministic bisecting:

- **Never create bulky or monolithic commits**: Do not group unrelated features, refactors, docs, or multi-crate changes into a single commit.
- **Commit per crate or logical concern**: When modifying multiple crates (e.g. `katana-core` and `katana-parser`), stage and commit changes to each crate or functional unit separately.
- **Strict Conventional Commits**: Follow `<type>(<scope>): <subject>` format.
  - Allowed types: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `chore`, `ci`.
  - Allowed scopes: `core`, `similarity`, `parser`, `engine`, `cli`, `headless`, `hybrid`, `scope`, `deps`.
- **Each commit must be buildable**: Every single commit should compile cleanly (`cargo check`) and pass existing unit tests (`cargo test`).
- **No emojis**: Keep all commit subjects, bodies, and documentation free of emojis.

---

## 2. Code Quality & Pre-Commit Verification

Before staging or committing any code changes:

1. **Format Code**: Run `cargo fmt --all` to comply with [rustfmt.toml](./rustfmt.toml).
2. **Lint Code**: Run `cargo clippy --workspace --all-targets --all-features -- -D warnings` and fix all warnings.
3. **Run Test Suite**: Run `cargo test --workspace --all-targets` and ensure 100% test pass rate.
4. **Doc Check**: Verify documentation builds without warnings via `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`.

---

## 3. Architecture & Parity Ground Truth

- **Authoritative Blueprint**: Always consult [KATANA_ARCHITECTURE_CORPUS.md](./KATANA_ARCHITECTURE_CORPUS.md) when implementing or refining algorithms (e.g. 3-layer deduplication, adaptive PathTrie promotion, Enqueue validation order, scope manager).
- **Upstream Reference**: The Go reference repository is located at `../katana-go` (`https://github.com/projectdiscovery/katana.git`). Use it for cross-verification, behavioral comparisons, and golden-vector testing.

---

## 4. Pull Request Standards

- Follow the template in [`.github/pull_request_template.md`](./.github/pull_request_template.md).
- Ensure all CI workflow checks pass (`.github/workflows/ci.yml`).
