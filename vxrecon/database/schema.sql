-- VXRecon local intelligence database schema (Phase 1 subset).
-- Phase 1 defines the identity, scan, snapshot, meta and case tables. Later
-- phases add dns_records, certificates, technologies, artifacts, evidence,
-- relationships and timeline_events via the same initialize() routine.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,
    value       TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    notes       TEXT,
    UNIQUE(kind, value)
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY,
    target_id     INTEGER NOT NULL REFERENCES targets(id),
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    tool_version  TEXT NOT NULL,
    mode          TEXT,
    status        TEXT,
    duration_ms   INTEGER
);

CREATE TABLE IF NOT EXISTS snapshots (
    id            INTEGER PRIMARY KEY,
    scan_id       INTEGER NOT NULL REFERENCES scans(id),
    target_id     INTEGER NOT NULL REFERENCES targets(id),
    created_at    TEXT NOT NULL,
    summary_hash  TEXT NOT NULL,
    payload       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cases (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL,
    description TEXT,
    path        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_targets (
    case_id    INTEGER NOT NULL REFERENCES cases(id),
    target_id  INTEGER NOT NULL REFERENCES targets(id),
    added_at   TEXT NOT NULL,
    PRIMARY KEY(case_id, target_id)
);

-- ===========================================================================
-- Phase 2: network facts (DNS, IP, certificates) and relationships.
-- ===========================================================================

CREATE TABLE IF NOT EXISTS domains (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    parent_id   INTEGER REFERENCES domains(id),
    tld         TEXT,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY,
    domain_id   INTEGER NOT NULL REFERENCES domains(id),
    record_type TEXT NOT NULL,
    name        TEXT NOT NULL,
    value       TEXT NOT NULL,
    ttl         INTEGER,
    observed_at TEXT NOT NULL,
    source      TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_lookup ON dns_records(domain_id, record_type, name);

CREATE TABLE IF NOT EXISTS ips (
    id          INTEGER PRIMARY KEY,
    address     TEXT NOT NULL UNIQUE,
    version     INTEGER,
    asn         TEXT,
    as_name     TEXT,
    country     TEXT,
    first_seen  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificates (
    id                 INTEGER PRIMARY KEY,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    subject_cn         TEXT,
    issuer_cn          TEXT,
    serial             TEXT,
    not_before         TEXT,
    not_after          TEXT,
    sig_alg            TEXT,
    key_type           TEXT,
    key_bits           INTEGER,
    san                TEXT,
    chain              TEXT,
    source             TEXT,
    observed_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS timeline_events (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER REFERENCES targets(id),
    scan_id     INTEGER REFERENCES scans(id),
    ts          TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    message     TEXT NOT NULL,
    data        TEXT
);
CREATE INDEX IF NOT EXISTS idx_tl_target ON timeline_events(target_id, ts);

CREATE TABLE IF NOT EXISTS relationships (
    id          INTEGER PRIMARY KEY,
    src_kind    TEXT NOT NULL,
    src_value   TEXT NOT NULL,
    dst_kind    TEXT NOT NULL,
    dst_value   TEXT NOT NULL,
    relation    TEXT NOT NULL,
    confidence  TEXT NOT NULL,
    evidence    TEXT,
    scan_id     INTEGER REFERENCES scans(id),
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rel_src ON relationships(src_kind, src_value);
CREATE INDEX IF NOT EXISTS idx_rel_dst ON relationships(dst_kind, dst_value);

