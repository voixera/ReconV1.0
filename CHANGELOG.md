# Changelog

All notable changes to VXRecon are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **HTML `<title>` parsing on malformed markup.** `html.parser` treats
  `<title>` as CDATA, so an unclosed title could swallow following markup into
  the title text, and the chunking differed across Python versions/platforms
  (failing CI on Linux and Python 3.13). Title capture now strips leaked markup
  deterministically.
- **Missing `vxrecon/cases` package and over-broad `.gitignore`.** The `cases/`
  ignore rule also matched the source package `vxrecon/cases/`, so it was never
  committed and `pip install -e .` failed with "package directory ... does not
  exist". Workspace ignores are now anchored to the repository root.
- **CI network-gateway guard** no longer false-positives on `urllib.parse`
  (pure URL string handling, not a network capability).
- **CLI error reporting.** Module errors/notes are now shown even when a module
  produced no findings; invalid targets fail fast with a clear message and exit
  code 3 instead of a misleading PARTIAL scan; domain actions reject IP targets
  with an explanation.
- DNS honours the configured `--timeout`; availability conditions (CT/RDAP
  down, per-record DNS timeouts) are informational findings rather than scan
  failures; `--offline` marks network-dependent analyzers as SKIPPED.

### Notes

- Verified end-to-end on GitHub Actions: all 11 CI jobs pass across
  Ubuntu/Windows/macOS × Python 3.11/3.12/3.13.

## [1.0.0] - VXRecon 1.0

### Added

- **Extended tooling.**
  - Config file support (`--config`, JSON/TOML) with precedence
    CLI > env (`VXRECON_*`) > config > defaults (`core/config.py`).
  - Database utilities: `db targets|relationships|dns|certs|export|vacuum`.
  - Data export (`utils/export.py`): CSV and JSON writers.
  - Markdown report (`report.md`) and SARIF 2.1.0 report (`report.sarif`).
  - `case report <name>`: aggregate all case targets into one HTML report.
  - `completions` action (PowerShell / bash / zsh).
  - `--no-banner` global flag.
  - GitHub Actions CI: test matrix (3 OS x 3 Python), lint/compile job, and a
    job that verifies the single-network-gateway invariant.

### Changed

- Global flag defaults are now resolved centrally, enabling config/env
  precedence without changing CLI behaviour.

### Tests

- Added config, export and report-format tests. 135 tests total.

## [0.4.0] - Phases 4-9

### Added

- **Phase 4: Passive discovery and code intelligence.**
  - CT subdomain collector (crt.sh) with retry/backoff; no API key.
  - Subdomain analyzer (evidence-backed names).
  - JavaScript collector (same-origin `<script src>` only) and endpoint
    intelligence analyzer (URLs/paths/domains; discovered endpoints never
    contacted).
  - Source Map awareness analyzer (read-only availability check).
  - Public file exposure collector + analyzer (robots.txt, declared sitemaps).
  - Certificate Relationship Explorer correlator (cert -> issuer/SAN graph).
  - `subdomains` action.
- **Phase 5: Metadata and image intelligence.**
  - `utils/image_fingerprint.py`: SHA-256, MD5, dimensions, aHash/dHash,
    Hamming distance; graceful without Pillow.
  - Favicon collector + analyzer with evidence integrity.
  - Local file metadata analyzer (EXIF, GPS, magic-byte type, hashes).
  - `image` and `metadata` actions.
- **Phase 6: Change intelligence.**
  - Snapshot diff correlator (added/removed/changed).
  - Read-side repo helpers (snapshots, timeline, targets).
  - `diff` and `timeline` actions.
- **Phase 7: Correlation.**
  - Artifact correlation correlator.
  - Infrastructure Similarity Engine with a "shared indicators, not ownership"
    disclaimer.
  - Real `compare`, `correlate` and `graph` actions.
- **Phase 8: Reporting.**
  - Self-contained HTML report (findings, graph, evidence integrity, escaped).
  - Interactive SVG graph export (`graph.html`).
  - Timeline HTML export (`timeline.html`).
- **Phase 9: Documentation** (`docs/MODULES.md`, `docs/DATA_FLOW.md`).

## [0.3.0] - Phase 3

### Added

- **Phase 3: HTTP behaviour, Website DNA and the Technology Confidence Engine.**
- HTTP collector: single polite GET with manual redirect-chain capture, headers,
  cookies, content type/size, HTTP version and bounded HTML body.
- HTTP behaviour analyzer (feature 8): status, redirect chain, protocol,
  compression, caching, cookies, security-header posture (present/missing,
  informational) and a stable **HTTP DNA** fingerprint.
- Technology Confidence Engine (feature 13): JSON-driven, weighted, evidence-
  backed detection. Score -> HIGH/MEDIUM/LOW; every detection states its
  evidence. Extensible via `signatures/technologies.json` without code changes.
- Website DNA analyzer (feature 3): combined fingerprint over HTML skeleton,
  title pattern, meta keys, script/style hosts, HTTP DNA and content type,
  plus favicon hints for later phases.
- `signatures/` package with `technologies.json` and `security_headers.json`
  loaders (cached, graceful on missing files).
- `utils/html_parse.py` (stdlib `html.parser` page facts + skeleton) and
  `utils/http_parse.py` (header/cookie parsing, header fingerprint).
- New actions wired: `http`, `tech`, `dna`; extended `recon` to include HTTP,
  technology and DNA analysis.
- Manual redirect-chain following in the network gateway (each hop rate-limited),
  with HTTP version capture.

### Changed

- Network gateway records `redirect_chain` and `http_version` on `HttpResult`.

### Fixed

- Title pattern coarsening no longer lets the digit marker collide with letters
  (digits map to `0`, letters to `w`).
- Reduced a Tailwind CSS false-positive by requiring a stronger utility-class
  combination signal (still LOW confidence, never asserted as fact).

### Tests

- Added offline tests for HTML parsing, HTTP analyzer, the technology engine and
  Website DNA. 82 tests total.


### Added

- **Phase 2: Domain, DNS, RDAP, IP and TLS intelligence.**
- DNS collector + analyzer (A/AAAA/MX/NS/TXT/CAA/SOA) with stdlib fallback and
  optional dnspython enrichment; SPF/DMARC detection and mail/nameserver
  provider hints.
- TLS collector + analyzer: certificate fingerprint, issuer, validity, SAN,
  key type/size and signature algorithm; expired/expiring and weak-key signals.
- RDAP collector + analyzer: IANA-bootstrapped registration data (registrar,
  events, nameservers, EPP status) and RIR network data (ASN, range, country).
- Infrastructure relationship mapper correlator: builds an evidence-backed
  graph (`domain -> ip -> asn`, nameserver, mail, certificate, registrar) with
  per-edge confidence indicators.
- Digital footprint graph model (JSON export foundation).
- Phase 2 SQLite schema: `domains`, `dns_records`, `ips`, `certificates`,
  `relationships`, `timeline_events`; schema version marker.
- Storage layer (`database/repo.py`) persisting scans, DNS, certs, IPs,
  relationships, timeline events and snapshots in a single transaction.
- Terminal reporter rendering findings grouped by module with confidence badges
  and evidence lines; JSON reporter writing `report.json`.
- Per-action module selection for `recon`, `domain`, `dns`, `cert`, `email`,
  `compare`.
- PowerShell launcher (`vxrecon.ps1`, `vxrecon.cmd`) and `install.ps1` so
  VXRecon runs like `npx`/`npm -g` without manual `python vxrecon.py`.

### Fixed

- Registry no longer treats an analyzer's `consumes` (collector references) as
  same-kind dependencies; added explicit `depends` for within-kind ordering.
- TLS rich decode handles cryptography versions where SAN values are plain
  strings.
- `vxrecon.cmd` no longer recurses infinitely when a local `vxrecon` is on PATH.

### Tests

- Added offline tests for DNS/TLS/RDAP analyzers, the infrastructure mapper,
  graph export, Phase 2 schema and persistence. 58 tests total.


## [0.1.0] - 2026-01-01

### Added

- Phase 1 foundation: CLI router with command mode and interactive menu shell.
- Global flags: `--json`, `--quiet`, `--verbose`, `--offline`, `--no-save`,
  `--timeout`, `--rate`, `--db`, `--out`, `--no-color`, `--config`.
- `RunContext` runtime policy bag enforcing `--offline` and `--no-save`
  architecturally.
- Structured logging, exception taxonomy and fail-soft error handling.
- Module registry with dependency-ordered resolution and cycle detection.
- Synchronous pipeline with per-module error isolation and status tracking.
- Result contracts: `Finding`, `Evidence`, `ScanResult`, `Confidence`,
  `Status`, with order-independent snapshot hashing.
- Local SQLite database foundation (WAL mode, foreign keys) with `db init` and
  `db stats`.
- Local case management: `case create`, `case add`, `case list`.
- `doctor` environment self-check and `version` inventory.
- Single network gateway (`utils.net.http_get`) with offline enforcement,
  mandatory timeouts, honest User-Agent and per-host rate limiting.
- ASCII/Unicode-aware banner, theme and progress reporter.
- Validators for domains (incl. punycode TLDs), IPs and URLs.
- Test suite (offline) covering validators, results, registry, pipeline,
  database and offline enforcement.

[Unreleased]: https://github.com/vxrecon/vxrecon/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vxrecon/vxrecon/releases/tag/v0.1.0
