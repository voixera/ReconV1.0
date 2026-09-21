# Security Policy

## Scope

VXRecon is a **passive OSINT and defensive reconnaissance framework**. It is
designed to gather information exclusively from:

- publicly resolvable DNS records,
- public HTTP/HTTPS responses,
- public TLS certificate metadata,
- public registries (RDAP) and certificate transparency logs,
- files the user already possesses (for metadata/image analysis),
- the user's own local intelligence database.

## Explicitly out of scope

VXRecon will **never** implement, and contributions must not add:

- password cracking or credential stuffing,
- phishing or social-engineering payloads,
- malware, persistence or privilege escalation,
- exploit execution or vulnerability exploitation,
- destructive scanning, DoS or DDoS,
- brute-forcing of directories, subdomains or credentials,
- authentication/CAPTCHA bypass,
- evasion or stealth mechanisms,
- any form of unauthorised access.

If a desirable capability requires unauthorised access, it must be reframed as
a passive alternative or omitted.

## Network guarantees

- All network I/O flows through `vxrecon.utils.net.http_get`.
- Requests are read-only (HTTP GET), rate-limited per host, and time-bounded.
- The User-Agent clearly identifies VXRecon and links to the project.
- `--offline` causes the gateway to refuse every request.
- There is no telemetry, analytics or phone-home functionality, ever.

## Reporting a vulnerability

Please report security issues privately via the repository's security advisory
feature or by email to the maintainers listed in the project metadata. Do not
open a public issue for security-sensitive reports. We aim to acknowledge
reports within 72 hours.

## Responsible use

Users are solely responsible for complying with applicable laws and the terms of
service of any target. Only investigate systems you own or are explicitly
authorised to assess.
