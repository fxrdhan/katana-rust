<h1 align="center">
  Katana (Rust)
</h1>

<p align="center">
  <strong>A fast, memory-safe, asynchronous web crawler for offensive-security automation.</strong>
</p>

<p align="center">
  <em>High-performance Rust rewrite and 1:1 feature-parity port of <a href="https://github.com/projectdiscovery/katana">ProjectDiscovery's Katana</a>.</em>
</p>

---

## 📖 Attribution & Acknowledgements

**Katana-Rust** is an independent, 1:1 feature-parity Rust port of **[ProjectDiscovery Katana](https://github.com/projectdiscovery/katana)** (originally written in Go). 

All original crawling methodologies, heuristic pipelines, and architectural concepts were pioneered by the **[ProjectDiscovery](https://projectdiscovery.io)** team and open-source contributors. This project aims to bring memory-safety, zero-cost abstractions, deterministic concurrency, and raw throughput improvements of the Rust ecosystem to the Katana crawler.

---

## 🏛️ Architecture & Crate Layout

The project is structured as a modular Cargo Workspace:

```
katana-rust/
├── KATANA_ARCHITECTURE_CORPUS.md  # Authoritative architecture specification & ground truth
├── crates/
│   ├── katana-core/               # Core data structures: Request, Response, Result, Options, Scope, Filters
│   ├── katana-similarity/         # 3-Layer Deduplication: Charikar SimHash (FNV-1a), PathTrie, URL Fingerprinting
│   ├── katana-parser/             # HTML/DOM selector parsers, JS regex scrapers, JSLuice AST, Form extractors
│   ├── katana-engine/             # Trait Engine, Standard HTTP engine (Reqwest/Tokio), Hybrid/Headless (CDP)
│   └── katana-cli/                # Main CLI binary, command-line flags (clap), Runner, Output formats
```

For the comprehensive technical specification, refer to [KATANA_ARCHITECTURE_CORPUS.md](./KATANA_ARCHITECTURE_CORPUS.md).

---

## 🚀 Getting Started

### Prerequisites
* Rust 1.80+ (MSRV)
* Cargo

### Building from Source
```bash
# Clone the repository
git clone https://github.com/fxrdhan/katana-rust.git
cd katana-rust

# Build the workspace
cargo build --release

# Run CLI
./target/release/katana --help
```

---

## 📄 License
Licensed under the [MIT License](./LICENSE.md).
