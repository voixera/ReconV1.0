# Contributing to VXRecon

Thanks for your interest in improving VXRecon. This project values
correctness, auditability and restraint over feature count.

## Core principles

1. **Passive only.** Never add capabilities that require unauthorised access,
   brute-forcing, exploitation or evasion. See [SECURITY.md](SECURITY.md).
2. **Evidence-based.** Every detection must state its evidence. No finding
   without a reason.
3. **Standard library first.** New hard dependencies are discouraged; prefer
   optional extras with graceful fallbacks.
4. **One network gateway.** All requests go through
   `vxrecon.utils.net.http_get`. Never open a socket elsewhere.
5. **Fail soft.** A single failing module must never abort a run.

## Getting started

```powershell
git clone https://github.com/vxrecon/vxrecon.git
cd vxrecon
python -m pip install -e ".[dev]"
python -m pytest
```

## Coding standards

- Python 3.11+, full type hints on public functions.
- Docstrings on every module, class and public function.
- Small, testable functions. Prefer pure functions in `analyzers/` and
  `correlators/`.
- No hardcoded credentials, endpoints or API keys.
- Mandatory timeouts on all network calls (handled by the gateway).

## Adding a module

1. Implement a collector in `vxrecon/collectors/` returning a raw facts dict
   (and `{"_error": "..."}` for expected failures instead of raising).
2. Implement an analyzer in `vxrecon/analyzers/` turning raw facts into
   `Finding` objects with evidence.
3. Register the module in the appropriate registry setup.
4. Add tests under `tests/` that run offline.

## Pull requests

- Keep PRs focused; one logical change per PR.
- Include tests for new behaviour.
- Update `CHANGELOG.md` under the "Unreleased" section.
- Ensure `python -m pytest` passes.

## Commit messages

Use the imperative mood and a short summary line, e.g.
`analyzers: add favicon perceptual hash evidence`.
