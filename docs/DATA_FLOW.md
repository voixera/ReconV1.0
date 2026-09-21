# VXRecon Data Flow

## Scan flow

```text
CLI parse (ui/cli.py)
   |
   v
RunContext  (enforce --offline, --no-save, timeout, rate, UA)
   |
   v
register_core_modules()  (core/bootstrap.py)
   |
   v
Pipeline.run(target)  (core/pipeline.py)
   |
   |-- select modules for the action (ui/actions.py _ACTION_MODULES)
   |
   |-- for each COLLECTOR (dependency ordered):
   |       collector.collect(target) -> raw dict
   |       (network collectors SKIPPED under --offline, recorded)
   |
   |-- for each ANALYZER (pure):
   |       analyzer.analyze(target, raw_outputs, ctx) -> ScanResult(findings)
   |
   |-- for each CORRELATOR (pure):
   |       correlator.correlate(target, results, ctx) -> Graph
   |
   v
PipelineReport  (outcomes, results, graph, durations, status)
   |
   +--> TerminalReporter  -> stdout
   +--> JsonReporter      -> report.json
   +--> HtmlReporter      -> report.html
   +--> graph_html        -> graph.html
   +--> timeline_html     -> timeline.html
   |
   +--> repo.persist_scan -> SQLite (scans, dns_records, certs, ips,
                                       relationships, timeline_events, snapshots)
```

## Finding model

```text
raw facts (dict)  --(analyzer)-->  Finding
                                    - key        e.g. "tech.cloudflare"
                                    - value      JSON-serializable
                                    - confidence HIGH | MEDIUM | LOW
                                    - evidence   [human-readable lines]   <- REQUIRED
                                    - evidence_ref Evidence (sha256, source_url, ...)
```

A `Finding` without evidence is a bug: every detection must state its reason.

## Evidence integrity (feature 19)

Artifacts (favicon, downloaded JS, HTTP bodies) carry an `Evidence` object:

```text
Evidence:
  source_url   where it came from
  http_status  status code at acquisition
  content_type MIME type
  sha256       hash of the bytes
  bytes        size
  acquired_at  ISO-8601 UTC timestamp
```

This is surfaced in reports as the **Evidence Integrity** table so a third
party can re-fetch and verify.

## Relationships (graph edges)

```text
Edge:
  src_kind, src_value  --relation-->  dst_kind, dst_value
  confidence           HIGH | MEDIUM | LOW
  evidence             why this edge exists
```

Relations describe **shared infrastructure indicators**. They never assert
ownership.

## Snapshots and diff

```text
scan N   -> snapshots(payload, summary_hash)
scan N+1 -> snapshots(payload, summary_hash)
                 |
                 v
         diff_snapshots(old, new) -> added | removed | changed
```

Only differences between two *stored* snapshots are reported. VXRecon never
fabricates history it did not observe.

## Offline behaviour

```text
--offline
  -> utils/net.http_get raises NetworkDisabledError
  -> pipeline marks network collectors SKIPPED (recorded, not hidden)
  -> analyzers run but report "no data"
  -> pure features still work: diff, timeline, similarity, correlation, reports
```

## Privacy guarantees

- Single network gateway (`utils/net.py`); no other module opens a socket.
- No telemetry, analytics, phone-home, API keys or accounts.
- `--no-save` leaves the filesystem untouched.
- All state under `~/.vxrecon` (override with `VXRECON_HOME`).
