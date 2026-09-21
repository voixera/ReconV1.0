# VXRecon Architecture

## Layered model

```text
        +-----------------------------------------------+
        |              CLI  (vxrecon/ui)                |
        |  argparse router + interactive menu shell     |
        +-----------------------+-----------------------+
                                |  RunContext
                                v
        +-----------------------------------------------+
        |            Orchestrator  (vxrecon/core)       |
        |  registry · pipeline · error isolation        |
        |  rate limiter · logging · result contracts    |
        +------+---------------+---------------+--------+
               |               |               |
               v               v               v
     +-----------+    +-------------+   +---------------+
     | COLLECTORS|    |  ANALYZERS  |   |  CORRELATORS  |
     |  (I/O)    |    |  (pure fn)  |   |   (pure fn)   |
     +-----+-----+    +------+------+   +-------+-------+
           |                 |                  |
           +--------+--------+--------+---------+
                    v                 v
             +-------------+   +-------------+
             |  STORAGE    |   |  REPORTERS  |
             |  (SQLite)   |   | term/json/  |
             |  evidence   |   | html/graph  |
             +-------------+   +-------------+
```

## The single network gateway

`vxrecon.utils.net.http_get` is the *only* function permitted to open a
socket. It enforces:

- `ctx.offline` (raises `NetworkDisabledError`),
- a mandatory timeout,
- an honest, identifiable User-Agent,
- per-host token-bucket rate limiting,
- structured results instead of exceptions for expected failures.

This design makes privacy guarantees testable: a CI check can assert that no
other module imports `socket`, `urllib`, `http.client` or `ssl` directly.

## Module contract

- **Collector** — `collect(target) -> dict`. Performs I/O. Returns raw facts,
  or `{"_error": "..."}` for expected failures.
- **Analyzer** — `analyze(target, raw, ctx) -> ScanResult`. Pure. Turns raw
  facts into evidence-backed findings.
- **Correlator** — `correlate(target, results, ctx) -> Graph`. Pure. Relates
  findings into a graph of nodes and edges with confidence indicators.

## Pipeline behaviour

1. Resolve modules in dependency order from the registry.
2. Run collectors; network collectors skipped (recorded) under `--offline`.
3. Run analyzers against the collected raw facts.
4. Run correlators against analyzer results.
5. Every module runs inside an isolation boundary; one failure never aborts
   the run. The failure is recorded and surfaced as a warning.

## Data flow

```text
target -> collectors (facts) -> analyzers (findings + evidence)
       -> correlators (graph)  -> storage (SQLite)
       -> reporters (terminal | json | html)
```

## Offline vs online

| Capability | Offline | Online |
|-----------|:-------:|:------:|
| Reveal analysis from stored artifacts | yes | yes |
| Technology detection from signatures | yes | yes |
| Favicon hashing / image metadata | yes | yes |
| Diff / timeline / similarity / correlation | yes | yes |
| Report generation | yes | yes |
| DNS / TLS / HTTP / RDAP / CT collection | no | yes |
