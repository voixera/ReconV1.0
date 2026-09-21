# VXRecon Module Reference

Every module is registered explicitly in `vxrecon/core/bootstrap.py`. There are
three kinds: **collectors** (network I/O), **analyzers** (pure), and
**correlators** (pure).

## Collectors

| Name | File | Network | Provides | Notes |
|------|------|:-------:|----------|-------|
| `dns` | `collectors/dns_collector.py` | yes | dns | A/AAAA/MX/NS/TXT/CAA/SOA via stdlib + dnspython |
| `tls` | `collectors/tls_collector.py` | yes | certificate | read-only TLS handshake, DER decode |
| `rdap` | `collectors/rdap_collector.py` | yes | registration, network | IANA-bootstrapped, no API key |
| `http` | `collectors/http_collector.py` | yes | http | one GET, manual redirect chain |
| `ct` | `collectors/ct_collector.py` | yes | subdomains | Certificate Transparency (crt.sh), retry/backoff |
| `javascript` | `collectors/js_collector.py` | yes | javascript | same-origin `<script src>` only |
| `files` | `collectors/files_collector.py` | yes | robots, sitemap | robots.txt + declared sitemaps |
| `favicon` | `collectors/favicon_collector.py` | yes | favicon | page-referenced icon or `/favicon.ico` |
| `local_image` | `collectors/favicon_collector.py` | no | image | local image bytes for `image` action |

## Analyzers

| Name | File | Consumes | Emits | Notes |
|------|------|----------|-------|-------|
| `dns` | `analyzers/dns_analyzer.py` | dns | dns.*, mail.provider, email.spf/dmarc | provider hints |
| `tls` | `analyzers/tls_analyzer.py` | tls | tls.* | issuer, SAN, key, expiry, weak key |
| `rdap` | `analyzers/rdap_analyzer.py` | rdap | rdap.*, net.* | registrar, events, ASN, range |
| `http` | `analyzers/http_analyzer.py` | http | http.* | HTTP DNA + security headers |
| `technology` | `analyzers/technology.py` | http | tech.* | weighted, evidence-backed |
| `website_dna` | `analyzers/website_dna.py` | http, technology | dna.* | combined fingerprint |
| `subdomains` | `analyzers/subdomain_analyzer.py` | ct | subdomains.* | CT-derived names |
| `js_endpoints` | `analyzers/js_endpoint.py` | javascript | js.* | URLs/paths/domains (never contacted) |
| `sourcemap` | `analyzers/sourcemap.py` | javascript | sourcemap.* | availability read-only |
| `files` | `analyzers/files_analyzer.py` | files | files.* | robots/sitemap parsing |
| `favicon` | `analyzers/favicon_analyzer.py` | favicon, local_image | favicon.* | sha256/md5/ahash/dhash |
| `metadata` | `analyzers/metadata_analyzer.py` | (local) | metadata.* | EXIF, magic bytes, hashes |

## Correlators

| Name | File | Produces | Notes |
|------|------|----------|-------|
| `infra_mapper` | `correlators/infra_mapper.py` | domain→ip→asn→ns→mail→cert graph | evidence per edge |
| `cert_explorer` | `correlators/cert_explorer.py` | certificate→issuer/SAN graph | shared-cert indicator |
| `artifact` | `correlators/artifact.py` | artifact correlation graph | favicon/cert/DNA/tech/IP |

## Correlator utilities (pure, not registered as pipeline modules)

| Utility | File | Purpose |
|---------|------|---------|
| `diff_snapshots` | `correlators/diff.py` | snapshot-to-snapshot change list |
| `compare` | `correlators/similarity.py` | infrastructure similarity engine |

## Signature files

| File | Purpose |
|------|---------|
| `signatures/technologies.json` | weighted detection rules + evidence notes |
| `signatures/security_headers.json` | security header expectations |

## Adding a module

1. Subclass `BaseCollector` / `BaseAnalyzer` / `BaseCorrelator`.
2. Register a `ModuleSpec` in `core/bootstrap.py`.
3. Add the module name to the relevant action's selection in `ui/actions.py`.
4. Add offline tests under `tests/`.
