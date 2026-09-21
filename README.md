# VXRecon

**Advanced Passive OSINT & Digital Footprint Intelligence Framework**

VXRecon is a privacy-first, API-key-free, passive reconnaissance framework that
runs entirely on your own machine. It builds a local intelligence database of
digital footprints using public protocols (DNS, RDAP, HTTP, TLS) and public
data (robots.txt, sitemaps, certificate transparency) — without telemetry,
without accounts, and without sending your data anywhere.

> **VXRecon is a defensive / research tool.** Use it only on targets you own or
> are authorised to investigate. See [SECURITY.md](SECURITY.md) and
> [docs/ETHICS.md](docs/ETHICS.md).

## Why VXRecon is different

Most "OSINT tools" are a thin wrapper around an IP-lookup and a username
checker. VXRecon focuses on **evidence-based, correlated intelligence**:

- **Every detection carries evidence.** No finding is shown without stating why.
- **A relationship graph, not a list.** Domains, subdomains, IPs, ASNs,
  certificates and technologies are linked with confidence indicators.
- **Local memory between scans.** A SQLite store lets you diff scans over time.
- **Zero core dependencies.** The framework runs on the Python standard library.

## Feature status

| # | Feature | Status |
|---|---------|--------|
| 1 | Digital Footprint Graph | implemented |
| 2 | Infrastructure Relationship Mapper | implemented |
| 3 | Website DNA | implemented |
| 4 | Favicon Fingerprint | implemented |
| 5 | Website Change Intelligence | implemented |
| 6 | Certificate Relationship Explorer | implemented |
| 7 | DNS Timeline | implemented |
| 8 | HTTP Behaviour Fingerprint | implemented |
| 9 | Public File Exposure Mapper | implemented |
| 10 | JavaScript Endpoint Intelligence | implemented |
| 11 | Source Map Awareness | implemented |
| 12 | Email Infrastructure Map | implemented |
| 13 | Technology Confidence Engine | implemented |
| 14 | Infrastructure Similarity Engine | implemented |
| 15 | Local Intelligence Database | implemented |
| 16 | Intelligence Diff | implemented |
| 17 | Artifact Correlation | implemented |
| 18 | Local Case Management | implemented |
| 19 | Evidence Integrity | implemented |
| 20 | Investigation Timeline | implemented |

All 20 features are implemented across Phases 1-9. See
[docs/MODULES.md](docs/MODULES.md) for the module reference.

## Installation

```powershell
# From a source checkout
git clone https://github.com/vxrecon/vxrecon.git
cd vxrecon
python -m pip install -e .

# Or run without installing
python vxrecon.py version
```

Optional enrichment (never required):

```powershell
python -m pip install -e ".[full]"
```

## Usage

Interactive menu:

```powershell
vxrecon
```

Command mode:

```powershell
vxrecon recon example.com
vxrecon dns example.com
vxrecon domain example.com
vxrecon cert example.com
vxrecon dna https://example.com
vxrecon tech https://example.com
vxrecon http https://example.com
vxrecon files https://example.com
vxrecon js https://example.com
vxrecon subdomains example.com
vxrecon email example.com
vxrecon image cloudflare.com
vxrecon metadata ./photo.jpg
vxrecon graph example.com
vxrecon correlate example.com
vxrecon compare example-a.com example-b.com
vxrecon diff example.com
vxrecon timeline example.com
vxrecon report example.com
vxrecon case create investigation-001
vxrecon db stats
vxrecon doctor
```

Global flags:

```text
--json        machine-readable stdout
--quiet       suppress banners/progress (automation)
--no-banner   suppress the interactive banner
-v / --verbose
--offline     forbid ALL network access (use local data only)
--no-save     do not write to disk
--timeout N   per-request timeout in seconds
--rate N      max requests/second per host
--db PATH     custom database path
--out DIR     report output directory
--no-color    disable ANSI colors
--config FILE load a JSON or TOML config file
```

Precedence: **CLI flags > environment variables > config file > defaults**.
Environment variables: `VXRECON_HOME`, `VXRECON_TIMEOUT`, `VXRECON_RATE`,
`VXRECON_USER_AGENT`, `VXRECON_OFFLINE`, `VXRECON_NO_SAVE`, `VXRECON_DB`.

### Configuration file

```toml
# vxrecon.toml
timeout = 8.0
rate_rps = 1.5
user_agent = "MyOrg-Security/1.0"
```

```powershell
vxrecon recon example.com --config vxrecon.toml
```

### Shell completion

```powershell
# PowerShell
vxrecon completions powershell | Out-File -Append $PROFILE
# bash
vxrecon completions bash > ~/.local/share/bash-completion/completions/vxrecon
```

### Report formats

Every scan writes to `reports/<target>/`:

| File | Format |
|------|--------|
| `report.json` | machine-readable canonical JSON |
| `report.html` | self-contained HTML (no external assets) |
| `report.md` | Markdown for issues/wikis |
| `report.sarif` | SARIF 2.1.0 (GitHub Code Scanning / SIEM) |
| `graph.html` | interactive SVG relationship graph |
| `timeline.html` | investigation timeline |

### Database utilities

```powershell
vxrecon db stats            # row counts
vxrecon db targets          # list stored targets
vxrecon db relationships    # list graph edges
vxrecon db dns              # stored DNS records
vxrecon db certs            # stored certificates
vxrecon db export csv       # export tables (json|csv)
vxrecon db vacuum           # reclaim space
```

Flags may be placed before or after the action, e.g. both of these work:

```powershell
vxrecon --json dns example.com
vxrecon dns example.com --json
```

## Architecture

VXRecon is layered, with strict boundaries:

```text
CLI (ui/)  ->  Orchestrator (core/)  ->  Collectors / Analyzers / Correlators
                                              |            |
                                         Storage (SQLite)  Reporters
```

| Layer | Network? | Writes? | Purity |
|-------|----------|---------|--------|
| `collectors/` | yes (passive) | no | impure |
| `analyzers/` | no | no | pure |
| `correlators/` | no | no | pure |
| `database/` | no | yes | impure |
| `reporters/` | no | yes | impure |

**Single network gateway.** All outbound requests go through
`vxrecon.utils.net.http_get`, which enforces `--offline`, timeouts, an honest
User-Agent and per-host rate limiting. No other module may open a socket. This
makes the "no hidden network calls" guarantee enforceable rather than aspirational.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

## Privacy

- No telemetry, no analytics, no tracking, no phone-home.
- No API keys, tokens or accounts.
- All state lives in `~/.vxrecon` (override with `VXRECON_HOME`).
- `--offline` refuses every network request at the gateway.
- `--no-save` leaves no trace on disk.

## Limitations

- Passive only: no port scanning, no brute-forcing, no exploitation.
- Some historical DNS/certificate data is unavailable for free; VXRecon only
  records changes *it* has observed since the first scan. It never fabricates
  history.
- `dnspython` is required for TXT/MX/CAA/DMARC lookups; without it those
  records are marked as unavailable rather than guessed.

## Development

```powershell
python -m pip install -e ".[dev]"
python -m pytest
```

Tests run fully offline and never touch the network.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions must respect the
passive-only boundary described in [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
