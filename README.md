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

### Prerequisites

- **Python 3.11 or newer**, available as the `python` command.
  Verify with `python --version`. If `python` is not found on Windows, install
  from https://www.python.org/downloads/ and tick **"Add python.exe to PATH"**.
- **Git** (only needed for the "source checkout" method).
- No API keys, accounts, or cloud services are required.

> All commands below are given for both **PowerShell** and **Command Prompt
> (cmd.exe)**. Run them in the shell of your choice.

---

### Quick start (recommended)

**PowerShell:**

```powershell
git clone https://github.com/voixera/ReconV1.0.git
cd ReconV1.0
python -m pip install -e .
vxrecon doctor
```

**Command Prompt:**

```bat
git clone https://github.com/voixera/ReconV1.0.git
cd ReconV1.0
python -m pip install -e .
vxrecon doctor
```

`pip install -e .` installs VXRecon in editable mode and creates a `vxrecon`
command on your PATH (via the console script defined in `pyproject.toml`).

---

### Run without installing

If you only want to try VXRecon, you can run it straight from the checkout.

**PowerShell:**

```powershell
python vxrecon.py version
python vxrecon.py dns example.com
```

**Command Prompt:**

```bat
python vxrecon.py version
python vxrecon.py dns example.com
```

---

### PowerShell launcher (npx-style)

The repository ships a `vxrecon.ps1` bootstrap script so you can run VXRecon
from a checkout exactly like `npx` — no install step, all arguments forwarded.

**PowerShell:**

```powershell
# Run directly from the repository folder
.\vxrecon.ps1 doctor
.\vxrecon.ps1 recon example.com
.\vxrecon.ps1 dns example.com --json

# If script execution is blocked, either allow it for this session:
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\vxrecon.ps1 version

# ...or invoke it bypassing the policy for a single run:
powershell -NoProfile -ExecutionPolicy Bypass -File .\vxrecon.ps1 version
```

It locates a suitable Python interpreter automatically, prefers a globally
installed `vxrecon` if one exists, and falls back to the local source tree.

---

### Command Prompt launcher

The repository also ships `vxrecon.cmd` for `cmd.exe`. It uses a globally
installed `vxrecon` if present, otherwise forwards to the PowerShell bootstrap.

**Command Prompt:**

```bat
vxrecon.cmd doctor
vxrecon.cmd recon example.com
vxrecon.cmd dns example.com --json
```

> Note: from `cmd.exe` you must include the extension (`vxrecon.cmd`), because
> the file has no associated `PATHEXT` entry by default.

---

### Optional enrichment (never required)

VXRecon's core uses the standard library only. These extras make some features
richer (full DNS record types, image dimensions/EXIF, robust HTML parsing, rich
X.509 fields). Each is optional and has a graceful fallback.

**PowerShell:**

```powershell
# Install everything optional
python -m pip install -e ".[full]"

# Or pick individual extras
python -m pip install -e ".[dns]"      # dnspython  -> TXT/MX/CAA/DMARC
python -m pip install -e ".[image]"    # Pillow     -> dimensions, EXIF, pHash
python -m pip install -e ".[html]"     # beautifulsoup4 (stdlib fallback exists)
python -m pip install -e ".[crypto]"   # cryptography (ssl.getpeercert fallback)
```

**Command Prompt:**

```bat
python -m pip install -e ".[full]"
python -m pip install -e ".[dns]"
python -m pip install -e ".[image]"
python -m pip install -e ".[html]"
python -m pip install -e ".[crypto]"
```

---

### User-level install (no admin rights)

If you cannot install into the system environment, use `--user` or a virtual
environment.

**PowerShell:**

```powershell
# User-level
python -m pip install --user -e .
# Ensure the user Scripts dir is on PATH for this session
$env:Path += ";$([Environment]::GetFolderPath('UserProfile'))\AppData\Roaming\Python\Python313\Scripts"

# Or a virtual environment (recommended for isolation)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
vxrecon version
```

**Command Prompt:**

```bat
python -m pip install --user -e .

python -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e .
vxrecon version
```

---

### PATH / "vxrecon is not recognized"

The console script is installed into Python's `Scripts` directory. If the
command is not found, that directory is not on your PATH.

**PowerShell — find the directory and add it for the current session:**

```powershell
$scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
$env:Path += ";$scripts"
vxrecon version
```

**PowerShell — add it permanently (current user):**

```powershell
$scripts = python -c "import sysconfig; print(sysconfig.get_path('scripts'))"
[Environment]::SetEnvironmentVariable(
    "Path",
    [Environment]::GetEnvironmentVariable("Path", "User") + ";$scripts",
    "User")
```

**Command Prompt — add it for the current session:**

```bat
for /f "delims=" %I in ('python -c "import sysconfig; print(sysconfig.get_path('scripts'))"') do set "SCRIPTS=%I"
set "PATH=%PATH%;%SCRIPTS%"
vxrecon version
```

(Close and reopen your terminal after changing PATH permanently.)

---

### Verify the installation

Both shells:

```text
vxrecon version
vxrecon doctor
```

`doctor` runs an environment self-check (Python version, SQLite, SSL, optional
dependencies, workspace paths). If every line shows `OK`, you are ready.

---

### Install from PyPI / pipx (when published)

Once published, the same tool installs like any Python package.

**PowerShell:**

```powershell
python -m pip install vxrecon
# or, isolated like npm -g:
pipx install vxrecon
```

**Command Prompt:**

```bat
python -m pip install vxrecon
pipx install vxrecon
```

---

### Upgrade / uninstall

**PowerShell:**

```powershell
python -m pip install -e . --upgrade     # upgrade an editable install
python -m pip uninstall vxrecon          # remove the console script
```

**Command Prompt:**

```bat
python -m pip install -e . --upgrade
python -m pip uninstall vxrecon
```

---

### One-shot installer helper

For convenience the repo includes `install.ps1`, which installs VXRecon and
optionally adds a short `vx` alias.

**PowerShell:**

```powershell
.\install.ps1                 # core install
.\install.ps1 -Full           # install with [full] extras
.\install.ps1 -Shortcut       # also create a 'vx' command
.\install.ps1 -User           # user-level install
```

**Command Prompt (via PowerShell):**

```bat
powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
```

## Usage

Once installed (`pip install -e .`), the `vxrecon` command is available in both
PowerShell and Command Prompt.

Interactive menu:

**PowerShell / Command Prompt:**

```text
vxrecon
```

Inside the menu, the pattern is **`<number> <target>`** on one line, or a
command with its target. If you pick a number without a target, VXRecon prompts
for it (type `cancel` to go back).

```text
vxrecon > 1 example.com        # 1 = recon, target = example.com
vxrecon > 3 example.com        # 3 = DNS
vxrecon > dns example.com      # same thing, by command name
vxrecon > 15                   # database (no target needed)
vxrecon > help                 # show the menu
vxrecon > exit                 # quit
```

> **Tip:** the command mode below is usually faster for repeat work — it runs a
> single action and exits, so it is scriptable and automation-friendly.

Command mode (identical in PowerShell, Command Prompt and any terminal):

```text
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

> **Command Prompt tip:** if you run from a checkout without installing, use
> `vxrecon.cmd` (with extension) or `python vxrecon.py`. PowerShell users can
> also use the `.\vxrecon.ps1` launcher. See [Installation](#installation).

### Platform-specific notes

| Task | PowerShell | Command Prompt |
|------|------------|----------------|
| Run installed command | `vxrecon doctor` | `vxrecon doctor` |
| Run from checkout | `.\vxrecon.ps1 doctor` | `vxrecon.cmd doctor` |
| Plain python module | `python -m vxrecon doctor` | `python -m vxrecon doctor` |
| Add Scripts to PATH (session) | `$env:Path += ";$(python -c "import sysconfig;print(sysconfig.get_path('scripts'))")"` | `python -c "import sysconfig;print(sysconfig.get_path('scripts'))"` then `set PATH=%PATH%;<paste>` |
| Allow local scripts | `Set-ExecutionPolicy -Scope Process Bypass` | n/a |
| Set env var (session) | `$env:VXRECON_HOME = "$HOME\.vxrecon"` | `set VXRECON_HOME=%USERPROFILE%\.vxrecon` |

Environment variables work the same in both shells:
`VXRECON_HOME`, `VXRECON_TIMEOUT`, `VXRECON_RATE`, `VXRECON_USER_AGENT`,
`VXRECON_OFFLINE`, `VXRECON_NO_SAVE`, `VXRECON_DB`.


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
