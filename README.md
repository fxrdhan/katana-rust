# Katana (Rust)

A fast, memory-safe, asynchronous web crawler for offensive-security automation — high-performance Rust port of [ProjectDiscovery Katana](https://github.com/projectdiscovery/katana).

---

## Attribution & Acknowledgements

All original crawling methodologies, heuristic pipelines, and architectural concepts were pioneered by the **[ProjectDiscovery](https://projectdiscovery.io)** team and open-source contributors. This project brings memory safety, zero-cost abstractions, deterministic concurrency, and raw throughput improvements of the Rust ecosystem to the Katana crawler.

---

## Highlights & Capabilities

* **Standard HTTP Engine**: Asynchronous non-blocking HTTP crawling via `reqwest` & `tokio` with 10-step `enqueue()` validation funnel, adaptive host backoff, and cycle detection.
* **JSLuice Semantic AST Parser**: High-accuracy JavaScript AST parsing for extracting API endpoints (`fetch`, `axios`, `$.ajax`, `open`, `WebSocket`), object properties, and template literals while filtering 100+ standard vendor libraries.
* **Headless & Hybrid Browser Engines**: State-Graph navigation with DOM normalization/stripping, SimHash tolerance comparison ($\le 2$), anti-bot stealth injection, and automated form filling (`-aff`).
* **3-Layer Deduplication**: Structural URL fingerprinting, adaptive 2-tier promotion `PathTrie` (with LRU host eviction), and 64-bit Charikar SimHash (FNV-1a).
* **Intelligence & Secret Scanner**: Automated API paradigm classification (REST, GraphQL, SOAP, WebSocket, XHR) and regular expression secret detection scanner for exposed credentials (AWS, GitHub, Google, Slack, Stripe, JWT).
* **Custom Field Extraction (YAML DSL)**: Extract specific fields from response headers, bodies, or combined payloads using regex capture groups.
* **Response Disk Storage & File Streaming**: Save raw HTTP responses to disk (`-sr`) and stream discovered endpoints directly to files (`-o`).
* **Raw Request & Resume Checkpointing**: Seed crawling directly from RFC 7230 raw HTTP request files (`-r`) and pause/resume large crawl jobs via JSON checkpoints (`-resume`).
* **CAPTCHA Detection & Solver Framework**: Automatic identification of reCAPTCHA v2/v3/Enterprise, Cloudflare Turnstile, and hCaptcha with automated DOM token injection scripts.
* **Cross-Platform & Release Automation**: Automated multi-platform compilation matrix covering Linux (GNU/musl), macOS (Apple Silicon / Intel), and Windows.

---

## Architecture Overview

```
katana-rust/
├── ARCHITECTURE.md                # Authoritative architecture specification & ground truth
├── crates/
│   ├── katana-core/               # Primitives, ScopeManager, Filters, Knowledge Base, Custom Fields, Raw HTTP & Resume
│   ├── katana-similarity/         # 3-Layer Deduplication: SimHash 64-bit, Adaptive PathTrie, URL Fingerprinting
│   ├── katana-parser/             # HTML/DOM selector parsers, JS regex scrapers, JSLuice AST, Form extractors
│   ├── katana-engine/             # Standard HTTP engine, Headless & Hybrid browser engines, Browser Launcher & Captcha
│   └── katana-cli/                # Main CLI binary, command-line flags (clap), OutputWriter, and E2E harness
```

For the comprehensive technical specification, refer to [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Feature Parity Matrix (100% Complete)

| Feature Category | Capability / Flag | Status in Katana-Rust |
|---|---|:---:|
| **Engines** | Standard HTTP Engine | Supported |
| | Headless Engine (`-hl`) | Supported |
| | Hybrid Engine (`-hb`, `--hybrid`) | Supported |
| | Adaptive Host Backoff (429/503) | Supported |
| | Browser Process Launcher & Discovery | Supported |
| | Anti-Bot Stealth Injection | Supported |
| | Form Auto-Fill Simulation (`-aff`) | Supported |
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
| **Custom Fields & Storage**| YAML Custom Field Extractor (`-config`, `-fields`) | Supported |
| | Output File Streaming (`-o`) | Supported |
| | Response Disk Storage (`-sr`, `-srd`) | Supported |
| **Input & State** | Stdin Asynchronous Pipe Streaming | Supported |
| | Raw HTTP Request Parsing (`-r`) | Supported |
| | Checkpoint State Resume (`-resume`) | Supported |
| **CAPTCHA** | Identification (reCAPTCHA, Turnstile, hCaptcha) | Supported |
| | Automated DOM Token Injection | Supported |
| | Capsolver Provider Framework | Supported |

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
katana -u https://example.com
```

### Crawl with JSLuice AST Analysis & Form Extraction
```bash
katana -u https://example.com -jsl -f
```

### Stdin Pipeline Streaming
```bash
cat urls.txt | katana -c 20 -d 3 -o discovered_urls.txt
```

### Crawl from Raw HTTP Request File
```bash
katana -r burp_request.txt -jsl --scan-secrets
```

### Headless Crawl with Form Auto-Fill
```bash
katana -u https://example.com -hl -aff --show-browser
```

### Store HTTP Responses & Custom Field Extraction
```bash
katana -u https://example.com -config fields.yaml -fields email,phone -sr -srd responses/
```

---

## Performance Benchmarking

Benchmark suites are implemented using Criterion (`katana-similarity` and `katana-parser`).

```bash
cargo bench --workspace
```
