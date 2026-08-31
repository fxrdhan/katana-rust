# Katana (Rust)

A fast, memory-safe, asynchronous web crawler for offensive-security automation — high-performance Rust port of [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana).

---

## Attribution & Acknowledgements

All original crawling methodologies, heuristic pipelines, and architectural concepts were pioneered by the **[ProjectDiscovery](https://projectdiscovery.io)** team and open-source contributors. This project brings memory safety, zero-cost abstractions, deterministic concurrency, and raw throughput improvements of the Rust ecosystem to the Katana crawler.

---

## Highlights & Capabilities

* **Standard HTTP Engine**: Asynchronous non-blocking HTTP crawling via `reqwest` & `tokio` with 10-step `enqueue()` validation funnel, adaptive host backoff, and cycle detection.
* **JSLuice Semantic AST Parser**: High-accuracy JavaScript AST parsing for extracting API endpoints (`fetch`, `axios`, `$.ajax`, `open`, `WebSocket`), object properties, and template literals while filtering 100+ standard vendor libraries.
* **Headless & Hybrid Browser Engines**: State-Graph navigation with DOM normalization/stripping, SimHash tolerance comparison ($\le 2$), and browser profile management.
* **3-Layer Deduplication**: Structural URL fingerprinting, adaptive 2-tier promotion `PathTrie` (with LRU host eviction), and 64-bit Charikar SimHash (FNV-1a).
* **Knowledge Base & Secret Scanner**: Automated API paradigm classification (REST, GraphQL, SOAP, WebSocket, XHR) and regular expression secret detection scanner for exposed credentials (AWS, GitHub, Google, Slack, Stripe, JWT).
* **Cross-Platform**: First-class support for Linux, macOS, and Windows with comprehensive automated CI test coverage.

---

## Architecture Overview

```
katana-rust/
├── ARCHITECTURE.md                # Authoritative architecture specification & ground truth
├── crates/
│   ├── katana-core/               # Request/Response models, ScopeManager, Filters, Knowledge Base & Secret Scanner
│   ├── katana-similarity/         # 3-Layer Deduplication: SimHash 64-bit, Adaptive PathTrie, URL Fingerprinting
│   ├── katana-parser/             # HTML/DOM selector parsers, JS regex scrapers, JSLuice AST, Form extractors
│   ├── katana-engine/             # Standard HTTP engine, Headless & Hybrid browser engines, HostBackoffManager
│   └── katana-cli/                # Main CLI binary, command-line flags (clap), OutputWriter, and E2E harness
```

For the comprehensive technical specification, refer to [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Feature Parity Matrix

| Feature Category | Capability / Flag | Status in Katana-Rust |
|---|---|:---:|
| **Engines** | Standard HTTP Engine | Supported |
| | Headless Engine (`-hl`) | Supported |
| | Hybrid Engine (`-hb`, `--hybrid`) | Supported |
| | Adaptive Host Backoff (429/503) | Supported |
| **Parsing & Scraping** | HTML/DOM Link Extraction | Supported |
| | JavaScript Regex Scraping (`-jc`) | Supported |
| | JSLuice Semantic AST (`-jsl`) | Supported |
| | Form Parsing & Extraction (`-f`) | Supported |
| | Robots.txt & Sitemap.xml Seeding | Supported |
| | Location Header Redirect Tracking | Supported |
| **Deduplication** | URL Structural Fingerprinting | Supported |
| | Adaptive PathTrie (`--filter-similar`) | Supported |
| | Charikar SimHash 64-bit Hashing | Supported |
| | DOM Normalization (`strip_dom`) | Supported |
| **Scope & Filters** | In-Scope / Out-of-Scope Regex | Supported |
| | Field Scope (`rdn`, `dn`, `fqdn`) | Supported |
| | Ignore Query Params (`-iqp`) | Supported |
| | Path-Climbing Navigation (`-pc`) | Supported |
| | Cycle & Logout Detection | Supported |
| **Intelligence** | API Protocol Classifier | Supported |
| | Secret & Token Scanner (`--scan-secrets`) | Supported |

---

## Installation & Usage

### Prerequisites
* Rust 1.80+ (MSRV)
* Cargo

### Build from Source
```bash
git clone https://github.com/fxrdhan/katana-rust.git
cd katana-rust
cargo build --release
```

The compiled binary will be located at `target/release/katana`.

---

## CLI Reference & Examples

### Basic Crawl
```bash
./target/release/katana -u https://example.com
```

### Crawl with JSLuice AST Analysis & Form Extraction
```bash
./target/release/katana -u https://example.com -jsl -f
```

### Crawl with Secret Detection & JSONL Output
```bash
./target/release/katana -u https://example.com --scan-secrets --jsonl
```

### Headless Hybrid Crawling
```bash
./target/release/katana -u https://example.com --headless-hybrid -d 3 -c 20
```

### Structural Deduplication & Path Climbing
```bash
./target/release/katana -u https://example.com --filter-similar -pc -iqp
```

---

## Benchmarks & Testing

### Running Tests
```bash
# Run all unit and integration tests across the workspace
cargo test --workspace

# Run end-to-end integration tests
cargo test --test e2e_crawler
```

### Running Performance Benchmarks
```bash
cargo bench --workspace
```

---

## License

Licensed under the [MIT License](./LICENSE.md).
