# Data Model Suggestion 2: Event-Sourced / CQRS Architecture

> Project: Password & Secrets Manager (Enterprise) · Candidate #415
> Approach: Append-only event store as the source of truth with materialized read projections via CQRS

---

## Summary

This approach treats every state change in the secrets management platform as an immutable event. Rather than storing the "current state" of a secret, lease, or session in mutable rows, the system records a stream of domain events (SecretCreated, SecretVersionAdded, SecretRotated, LeaseIssued, LeaseRevoked, SessionStarted, SessionEnded, AccessRequested, AccessApproved, etc.) in an append-only event store. Read-side projections materialize current state into queryable views optimized for specific use cases: a credential lookup projection, a compliance dashboard projection, a lease expiry projection, and so on.

This architecture is particularly well-suited to a secrets manager because **the audit trail is the data model** -- every action that touches a credential is a security-relevant event that must be captured, timestamped, and made tamper-evident. Instead of maintaining a separate audit log alongside the operational database, the event stream *is* the audit log.

ZITADEL, an open-source IAM system, successfully uses this approach in production, and the pattern is endorsed by Microsoft's Azure Architecture Center for systems where auditability is a first-class requirement.

---

## Architecture Overview

```
┌──────────────┐     ┌──────────────────┐     ┌──────────────────────┐
│  Command API │────▶│   Event Store    │────▶│  Projection Engine   │
│  (Write Side)│     │  (Append-Only)   │     │  (Async Consumers)   │
└──────────────┘     └──────────────────┘     └──────────┬───────────┘
                                                         │
                              ┌───────────────────────────┼────────────────┐
                              ▼                           ▼                ▼
                     ┌────────────────┐         ┌────────────────┐ ┌──────────────┐
                     │  Secrets View  │         │  Sessions View │ │ Audit View   │
                     │  (PostgreSQL)  │         │  (PostgreSQL)  │ │ (ClickHouse) │
                     └────────────────┘         └────────────────┘ └──────────────┘
                              ▲                           ▲                ▲
                     ┌────────────────┐         ┌────────────────┐ ┌──────────────┐
                     │  Query API     │         │  Session API   │ │ Compliance   │
                     │  (Read Side)   │         │  (Read Side)   │ │ Report API   │
                     └────────────────┘         └────────────────┘ └──────────────┘
```

---

## Key Entities and Event Streams

### Event Store Schema

```sql
-- Core event store table (append-only)
CREATE TABLE events (
    global_position  BIGSERIAL PRIMARY KEY,
    stream_id        UUID NOT NULL,
    stream_type      VARCHAR(64) NOT NULL,     -- 'Secret', 'Lease', 'Session', 'AccessRequest'
    event_type       VARCHAR(128) NOT NULL,     -- 'SecretCreated', 'SecretVersionAdded', etc.
    event_version    INT NOT NULL,              -- schema version of this event type
    sequence_number  INT NOT NULL,              -- position within the stream
    org_id           UUID NOT NULL,
    timestamp        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type       VARCHAR(20) NOT NULL,      -- 'user', 'service_account', 'system'
    actor_id         UUID NOT NULL,
    source_ip        INET,
    correlation_id   UUID,                      -- links related events across streams
    causation_id     UUID,                      -- the event that triggered this one
    payload          BYTEA NOT NULL,            -- encrypted event data (AES-256-GCM)
    payload_schema   VARCHAR(128),              -- schema registry reference
    metadata         BYTEA,                     -- encrypted supplementary data
    prev_hash        BYTEA,                     -- hash of previous event in stream
    entry_hash       BYTEA NOT NULL,            -- SHA-256(all fields + prev_hash)

    UNIQUE(stream_id, sequence_number)
);

CREATE INDEX idx_events_stream ON events(stream_id, sequence_number);
CREATE INDEX idx_events_type ON events(event_type, timestamp);
CREATE INDEX idx_events_org ON events(org_id, timestamp);
CREATE INDEX idx_events_correlation ON events(correlation_id);

-- Snapshot store for aggregate rehydration optimization
CREATE TABLE snapshots (
    stream_id        UUID PRIMARY KEY,
    stream_type      VARCHAR(64) NOT NULL,
    sequence_number  INT NOT NULL,             -- event position at snapshot time
    state            BYTEA NOT NULL,           -- encrypted serialized aggregate state
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Projection checkpoints (idempotent replay tracking)
CREATE TABLE projection_checkpoints (
    projection_name  VARCHAR(128) PRIMARY KEY,
    last_position    BIGINT NOT NULL DEFAULT 0,
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Domain Events Catalogue

```
── Secret Aggregate ──
SecretCreated           { engine_id, namespace_path, secret_path, initial_metadata }
SecretVersionAdded      { version, encrypted_value, encryption_key_id, checksum }
SecretVersionDestroyed  { version, reason }
SecretRotated           { old_version, new_version, rotation_method }
SecretSoftDeleted       { reason }
SecretRestored          { }
SecretPermanentlyDeleted { compliance_ref }
SecretMetadataUpdated   { changed_fields }

── Lease Aggregate ──
LeaseIssued             { engine_id, principal_type, principal_id, duration, credential_ref }
LeaseRenewed            { new_expiry }
LeaseRevoked            { reason, revoked_by }
LeaseExpired            { }

── Session Aggregate ──
SessionRequested        { user_id, account_id, session_type, justification }
SessionStarted          { proxy_endpoint, recording_ref }
SessionCommandExecuted  { command_hash, risk_score }
SessionShadowJoined     { shadow_user_id }
SessionTerminated       { reason, terminated_by }
SessionEnded            { duration, recording_size }
SessionRecordingSealed  { recording_hash, storage_path }

── AccessRequest Aggregate ──
AccessRequested         { requester_id, target_type, target_id, justification, duration }
AccessRiskScored        { risk_score, risk_factors }
ApprovalStepAssigned    { step_order, approver_type, approver_id }
ApprovalStepDecided     { step_order, decision, comment }
AccessApproved          { approved_duration, conditions }
AccessDenied            { reason }
AccessExpired           { }
AccessRevoked           { reason, revoked_by }

── Policy Aggregate ──
PolicyCreated           { name, policy_document, policy_language }
PolicyUpdated           { version, changes_summary }
PolicyActivated         { }
PolicyDeactivated       { reason }
PolicyDeleted           { }

── Identity Aggregate ──
UserCreated             { email, display_name, org_id }
UserUpdated             { changed_fields }
UserDeactivated         { reason }
ServiceAccountCreated   { name, org_id }
ServiceAccountKeyRotated { }
GroupCreated            { name }
GroupMemberAdded        { user_id }
GroupMemberRemoved      { user_id }
RoleAssigned            { role_id, principal_type, principal_id, namespace_id }
RoleRevoked             { role_id, principal_type, principal_id }
```

### Read-Side Projections

```sql
-- Projection: Current secrets (materialized from Secret events)
CREATE TABLE proj_secrets_current (
    secret_id        UUID PRIMARY KEY,
    engine_id        UUID NOT NULL,
    org_id           UUID NOT NULL,
    namespace_path   VARCHAR(1024) NOT NULL,
    secret_path      VARCHAR(1024) NOT NULL,
    current_version  INT NOT NULL,
    latest_encrypted_value BYTEA,
    encryption_key_id UUID,
    metadata         BYTEA,
    status           VARCHAR(20) NOT NULL,     -- 'active', 'soft_deleted', 'destroyed'
    created_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    last_accessed_at TIMESTAMPTZ,
    access_count     BIGINT DEFAULT 0
);

-- Projection: Active leases (materialized from Lease events)
CREATE TABLE proj_leases_active (
    lease_id         UUID PRIMARY KEY,
    engine_id        UUID NOT NULL,
    org_id           UUID NOT NULL,
    principal_type   VARCHAR(20) NOT NULL,
    principal_id     UUID NOT NULL,
    credential_ref   BYTEA,
    issued_at        TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    renewed_count    INT DEFAULT 0,
    status           VARCHAR(20) NOT NULL
);
CREATE INDEX idx_proj_leases_expiry ON proj_leases_active(expires_at) WHERE status = 'active';

-- Projection: Active sessions (materialized from Session events)
CREATE TABLE proj_sessions_active (
    session_id       UUID PRIMARY KEY,
    org_id           UUID NOT NULL,
    user_id          UUID NOT NULL,
    account_id       UUID NOT NULL,
    asset_hostname   VARCHAR(512),
    session_type     VARCHAR(16) NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ,
    shadow_users     UUID[],
    status           VARCHAR(20) NOT NULL,
    risk_score       DECIMAL(5,2)
);

-- Projection: Compliance timeline (materialized to ClickHouse for analytics)
-- This projection lives in ClickHouse, not PostgreSQL
-- CREATE TABLE proj_compliance_timeline (
--     org_id         UUID,
--     timestamp      DateTime64(3),
--     event_type     LowCardinality(String),
--     actor_id       UUID,
--     resource_type  LowCardinality(String),
--     resource_id    UUID,
--     result         LowCardinality(String),
--     risk_score     Float32,
--     compliance_controls Array(String)
-- ) ENGINE = MergeTree()
-- PARTITION BY toYYYYMM(timestamp)
-- ORDER BY (org_id, timestamp);
```

### Tamper-Evidence Chain

```
Event N:
  entry_hash = SHA-256(
    stream_id || sequence_number || event_type ||
    timestamp || actor_id || payload || prev_hash
  )

Event N+1:
  prev_hash  = entry_hash of Event N
  entry_hash = SHA-256(... || prev_hash)
```

The hash chain ensures that any modification or deletion of a historical event breaks the chain for every subsequent event in the stream. Periodic Merkle tree roots can be published to an external transparency log (e.g., Trillian or Sigstore Rekor) for independent verification.

---

## Aggregate Boundaries

| Aggregate | Stream ID | Key Invariants |
|-----------|-----------|---------------|
| Secret | secret_id | Version numbers are monotonically increasing; destroyed versions cannot be restored |
| Lease | lease_id | Expired leases cannot be renewed; revoked leases are terminal |
| Session | session_id | Sessions transition: requested -> started -> ended/terminated |
| AccessRequest | request_id | Approval steps must be decided in order; approved access has a bounded duration |
| Policy | policy_id | Only one version active at a time per policy_id |
| User | user_id | Deactivated users cannot create new sessions or leases |

---

## Pros

- **Audit trail is built-in, not bolted on.** Every state change is an event with actor, timestamp, and correlation context. There is no separate audit logging system to maintain, and no risk of audit and operational data diverging.
- **Complete temporal queries.** "What was the state of this secret at 3:47 PM last Tuesday?" is answered by replaying events up to that point. This is invaluable for incident response and forensic investigation.
- **Tamper-evident by design.** The hash chain on the event stream provides cryptographic proof of log integrity. Combined with external anchoring (Merkle roots in a transparency log), this meets the strictest compliance requirements for tamper-evident audit trails (PCI-DSS, SOC 2, NIS2).
- **Natural fit for regulatory retention.** Events are never deleted during the retention window; they are immutable records. Retention policies are enforced by partition drop after the window expires, not by row deletion.
- **Independent read scaling.** Each projection can be scaled, rebuilt, or replaced without touching the event store. A compliance dashboard can use ClickHouse while the secret lookup API uses PostgreSQL.
- **Decoupled feature evolution.** Adding a new feature (e.g., secrets sprawl detection) means adding a new projection consumer -- no schema migration on the write side.

## Cons

- **Operational complexity.** Event sourcing requires maintaining the event store, projection engine, checkpoint tracking, and snapshot management. The team must understand eventual consistency and idempotent processing.
- **Eventual consistency on reads.** After a command is processed, projections update asynchronously. A "read-your-write" guarantee requires either synchronous projection updates (reducing throughput) or a read-after-write pattern that queries the event store directly for the latest state.
- **Event schema evolution is hard.** Once an event type is published, its schema is immutable. Adding fields requires a new event version, and projection consumers must handle all versions. An event schema registry is essential.
- **Payload encryption complicates replay.** Since event payloads are encrypted, key rotation means either re-encrypting all events (expensive) or maintaining a key registry that maps each event to its DEK.
- **Larger storage footprint.** Storing every state change (rather than current state) consumes more storage. For high-volume operations like lease issuance, the event stream can grow very quickly.
- **Debugging difficulty.** Understanding the current state of an entity requires replaying its event stream or examining a projection. This is less intuitive for developers accustomed to reading a single row.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|---------------|
| Event store | PostgreSQL 16+ (partitioned events table) or EventStoreDB |
| Event serialization | Protocol Buffers with a schema registry (Buf) |
| Projection engine | Custom Go consumers using pgx, or use Marten (.NET) if C# |
| Read-side store (operational) | PostgreSQL for projections |
| Read-side store (analytics) | ClickHouse for compliance timeline and anomaly detection |
| Message transport | NATS JetStream or Apache Kafka for event distribution |
| Snapshot store | PostgreSQL (same instance as event store) |
| Tamper evidence | SHA-256 hash chain + periodic Merkle roots to Sigstore Rekor |
| Encryption | libsodium (NaCl) for event payload encryption |
| Key management | AWS KMS / Azure Key Vault / GCP Cloud KMS |

---

## Migration and Scaling Considerations

1. **Start with PostgreSQL as the event store.** The events table with BIGSERIAL global_position and partitioning by month is sufficient for most deployments. Only migrate to EventStoreDB or Kafka if the event volume exceeds what PostgreSQL can handle (typically >100K events/second sustained).

2. **Snapshot aggressively for long-lived aggregates.** Secrets with many versions should have snapshots taken every 50-100 events. Lease and session aggregates are short-lived and rarely need snapshots.

3. **Event versioning strategy.** Use the event_version field and a schema registry from day one. Define upcasting functions that transform old event shapes into new ones during projection replay. Never modify a published event schema.

4. **Projection rebuild capability.** Every projection must be rebuildable from scratch by replaying the event store from position 0. Test this in CI. The projection_checkpoints table tracks progress, enabling resume after failure.

5. **Partitioning and archival.** Partition the events table by month. After the regulatory retention period, detach old partitions and archive to object storage (S3/GCS) in Parquet format. Keep the partition metadata so that forensic replays can reattach archived partitions on demand.

6. **Multi-region deployment.** The event store can be replicated to read replicas in other regions. Write traffic goes to a single primary to preserve global ordering. For true multi-region writes, use Kafka with partition-per-org and conflict resolution at the aggregate level.

7. **Transition from Suggestion 1.** If the platform starts with the normalized relational model (Suggestion 1), it can transition to event sourcing incrementally: introduce the event store alongside the relational tables, dual-write during a migration period, then switch the read path to projections and retire direct relational reads.
