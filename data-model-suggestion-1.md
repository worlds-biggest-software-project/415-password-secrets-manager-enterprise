# Data Model Suggestion 1: Normalized Relational (PostgreSQL)

> Project: Password & Secrets Manager (Enterprise) · Candidate #415
> Approach: Fully normalized relational schema with PostgreSQL as the primary data store

---

## Summary

This approach models every domain concept as a discrete, normalized table in PostgreSQL. The encrypted secret payload is stored as `BYTEA` columns, while all metadata, access control, audit, and session management data live in standard relational tables with foreign key constraints. The schema enforces referential integrity at the database level and relies on PostgreSQL's mature transactional guarantees (MVCC, serializable isolation) for consistency.

This is the most conventional approach and mirrors the architectural choices made by Bitwarden (SQL Server / PostgreSQL via Entity Framework), Delinea Secret Server, and ManageEngine PAM360.

---

## Key Entities and Relationships

### Organizational Hierarchy

```sql
-- Multi-tenant organizational structure
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(256) NOT NULL,
    slug            VARCHAR(128) UNIQUE NOT NULL,
    parent_org_id   UUID REFERENCES organizations(id),
    billing_email   VARCHAR(320),
    use_secrets_mgr BOOLEAN DEFAULT true,
    use_pam         BOOLEAN DEFAULT true,
    max_seats       INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE namespaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    parent_id       UUID REFERENCES namespaces(id),
    name            VARCHAR(256) NOT NULL,
    path            LTREE NOT NULL,          -- e.g. 'acme.prod.databases'
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, path)
);
```

### Identity and Access Control

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    email           VARCHAR(320) NOT NULL,
    display_name    VARCHAR(256),
    password_hash   BYTEA,                   -- Argon2id hash
    master_key_enc  BYTEA,                   -- encrypted symmetric key
    public_key      BYTEA,                   -- RSA/Ed25519 public key
    mfa_enabled     BOOLEAN DEFAULT false,
    status          VARCHAR(20) DEFAULT 'active',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, email)
);

CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    external_id     VARCHAR(512),            -- SCIM external ID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE group_members (
    group_id        UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE service_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    public_key      BYTEA,
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Roles and policies (RBAC)
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    is_builtin      BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    policy_document TEXT NOT NULL,            -- HCL or Cedar policy text
    version         INT NOT NULL DEFAULT 1,
    is_active       BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE role_policies (
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    policy_id       UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, policy_id)
);

-- Principal-to-role assignments (polymorphic via principal_type)
CREATE TABLE role_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    principal_type  VARCHAR(20) NOT NULL,     -- 'user', 'group', 'service_account'
    principal_id    UUID NOT NULL,
    namespace_id    UUID REFERENCES namespaces(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by     UUID REFERENCES users(id)
);
CREATE INDEX idx_role_assignments_principal ON role_assignments(principal_type, principal_id);
```

### Secret Storage

```sql
-- Secrets engine registry
CREATE TABLE secrets_engines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    engine_type     VARCHAR(64) NOT NULL,     -- 'kv', 'database', 'pki', 'ssh', 'transit', 'cloud_iam'
    mount_path      VARCHAR(512) NOT NULL,
    config          BYTEA,                   -- encrypted engine config
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, mount_path)
);

-- Static secrets (KV engine)
CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id       UUID NOT NULL REFERENCES secrets_engines(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    path            VARCHAR(1024) NOT NULL,
    current_version INT NOT NULL DEFAULT 1,
    max_versions    INT DEFAULT 10,
    metadata        BYTEA,                   -- encrypted metadata
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,             -- soft delete
    UNIQUE(engine_id, path)
);

CREATE TABLE secret_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version         INT NOT NULL,
    encrypted_value BYTEA NOT NULL,          -- AES-256-GCM encrypted payload
    encryption_key_id UUID NOT NULL,         -- reference to key used
    checksum        BYTEA NOT NULL,          -- HMAC-SHA256
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by      UUID,                    -- user or service_account
    destroyed_at    TIMESTAMPTZ,
    UNIQUE(secret_id, version)
);

-- Encryption key registry (envelope encryption)
CREATE TABLE encryption_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    key_type        VARCHAR(32) NOT NULL,     -- 'dek', 'kek', 'transit'
    algorithm       VARCHAR(32) NOT NULL,     -- 'aes-256-gcm', 'chacha20-poly1305'
    encrypted_key   BYTEA NOT NULL,           -- KEK-encrypted DEK material
    kms_key_arn     VARCHAR(512),             -- external KMS reference
    version         INT NOT NULL DEFAULT 1,
    status          VARCHAR(20) DEFAULT 'active',
    rotated_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Dynamic Secrets and Leases

```sql
-- Dynamic credential leases
CREATE TABLE leases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id       UUID NOT NULL REFERENCES secrets_engines(id),
    principal_type  VARCHAR(20) NOT NULL,
    principal_id    UUID NOT NULL,
    lease_duration  INTERVAL NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    renewed_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    credential_ref  BYTEA,                   -- encrypted reference to issued credential
    status          VARCHAR(20) DEFAULT 'active'
);
CREATE INDEX idx_leases_expiry ON leases(expires_at) WHERE status = 'active';

-- Rotation schedules
CREATE TABLE rotation_configs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id),
    rotation_period INTERVAL NOT NULL,
    last_rotated_at TIMESTAMPTZ,
    next_rotation   TIMESTAMPTZ NOT NULL,
    rotation_lambda VARCHAR(512),            -- rotation function reference
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Privileged Session Management

```sql
CREATE TABLE managed_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    asset_type      VARCHAR(32) NOT NULL,     -- 'server', 'database', 'network_device', 'saas_app'
    hostname        VARCHAR(512),
    ip_address      INET,
    port            INT,
    platform        VARCHAR(64),              -- 'linux', 'windows', 'postgresql', 'mysql'
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE privileged_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES managed_assets(id),
    account_name    VARCHAR(256) NOT NULL,
    account_type    VARCHAR(32),              -- 'local_admin', 'domain_admin', 'dba', 'root'
    credential_id   UUID REFERENCES secrets(id),
    last_verified   TIMESTAMPTZ,
    last_changed    TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'managed',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    account_id      UUID NOT NULL REFERENCES privileged_accounts(id),
    session_type    VARCHAR(16) NOT NULL,     -- 'ssh', 'rdp', 'database', 'web'
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    recording_path  VARCHAR(1024),            -- object storage path for recording
    recording_size  BIGINT,
    status          VARCHAR(20) DEFAULT 'active',
    termination_reason VARCHAR(64)
);
CREATE INDEX idx_sessions_active ON sessions(org_id, status) WHERE status = 'active';
```

### JIT Access and Approval Workflows

```sql
CREATE TABLE access_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    requester_id    UUID NOT NULL REFERENCES users(id),
    target_type     VARCHAR(32) NOT NULL,     -- 'secret', 'account', 'asset', 'namespace'
    target_id       UUID NOT NULL,
    justification   TEXT NOT NULL,
    requested_duration INTERVAL NOT NULL,
    risk_score      DECIMAL(5,2),
    status          VARCHAR(20) DEFAULT 'pending',  -- pending, approved, denied, expired
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

CREATE TABLE approval_steps (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    step_order      INT NOT NULL,
    approver_type   VARCHAR(20) NOT NULL,     -- 'user', 'group', 'manager'
    approver_id     UUID NOT NULL,
    decision        VARCHAR(20),              -- 'approved', 'denied'
    comment         TEXT,
    decided_at      TIMESTAMPTZ,
    PRIMARY KEY (request_id, step_order)  -- note: composite, drops the UUID PK
);
```

### Audit Logging

```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type      VARCHAR(20) NOT NULL,     -- 'user', 'service_account', 'system'
    actor_id        UUID NOT NULL,
    action          VARCHAR(64) NOT NULL,     -- 'secret.read', 'session.start', 'policy.update'
    resource_type   VARCHAR(32) NOT NULL,
    resource_id     UUID,
    resource_path   VARCHAR(1024),
    source_ip       INET,
    user_agent      VARCHAR(512),
    request_id      UUID,
    result          VARCHAR(20) NOT NULL,     -- 'success', 'denied', 'error'
    detail          TEXT,
    prev_hash       BYTEA,                   -- hash chain for tamper evidence
    entry_hash      BYTEA NOT NULL
) PARTITION BY RANGE (timestamp);

-- Monthly partitions for audit log scalability
CREATE TABLE audit_logs_2026_01 PARTITION OF audit_logs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');
-- ... additional partitions created automatically
```

---

## Entity Relationship Summary

```
Organization  1──*  Namespace
Organization  1──*  User
Organization  1──*  Group
Organization  1──*  ServiceAccount
Organization  1──*  Role
Organization  1──*  Policy
Organization  1──*  SecretsEngine
Organization  1──*  ManagedAsset

Namespace     1──*  Secret
Namespace     1──*  ManagedAsset

User          *──*  Group         (via group_members)
Role          *──*  Policy        (via role_policies)
Role          1──*  RoleAssignment

Secret        1──*  SecretVersion
Secret        1──1  RotationConfig
SecretVersion ──1   EncryptionKey

SecretsEngine 1──*  Secret
SecretsEngine 1──*  Lease

ManagedAsset  1──*  PrivilegedAccount
PrivilegedAccount ──1 Secret (credential)
PrivilegedAccount 1──* Session

User          1──*  AccessRequest
AccessRequest 1──*  ApprovalStep
```

---

## Pros

- **Referential integrity enforced at the database level.** Foreign keys, unique constraints, and check constraints prevent orphaned records and data corruption without application-level guards.
- **Mature tooling ecosystem.** PostgreSQL has decades of production tooling: pgBackRest for backups, pg_repack for maintenance, pgAudit for database-level audit, logical replication for read scaling, and extensive ORM support (Entity Framework, SQLAlchemy, GORM).
- **Strong query capability.** Complex access control queries (e.g., "which users can reach this production database through any role chain?") are expressible in standard SQL with CTEs and recursive queries.
- **Transactional consistency.** Multi-table operations (e.g., creating a secret version + updating the secret's current_version + writing an audit log entry) are atomic within a single transaction.
- **Time-series partitioning for audit logs.** PostgreSQL native partitioning handles high-volume audit logs with partition pruning for time-range queries.
- **Regulatory familiarity.** Auditors and compliance teams understand relational schemas; ERDs map directly to control documentation.

## Cons

- **Rigid schema evolution.** Adding new secret types, engine types, or policy attributes requires ALTER TABLE migrations. In a platform that must support pluggable secrets engines, this can become a bottleneck.
- **Polymorphic access control complexity.** The principal_type / principal_id pattern (used in role_assignments, leases, etc.) breaks foreign key constraints and requires application-level validation.
- **Encryption at the application layer.** PostgreSQL does not natively manage envelope encryption -- the application must encrypt before INSERT and decrypt after SELECT, adding complexity to every data path.
- **Horizontal scaling limits.** While read replicas and partitioning help, a single-writer PostgreSQL instance eventually becomes a bottleneck for very large multi-tenant deployments.
- **Audit log volume.** At enterprise scale (millions of secret accesses per day), the audit_logs table grows rapidly. Even with partitioning, hot partitions can strain write throughput. Eventually, audit data may need to be offloaded to a dedicated store (e.g., ClickHouse, S3 + Parquet).
- **No built-in tree traversal for namespace hierarchies.** The LTREE extension helps but is a non-standard PostgreSQL feature.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|---------------|
| Primary database | PostgreSQL 16+ with pgcrypto, ltree extensions |
| Connection pooling | PgBouncer or Supavisor |
| Backup / PITR | pgBackRest with continuous archiving to S3 |
| Read scaling | Streaming replication with read replicas |
| Audit extension | pgAudit for database-level access logging |
| ORM | GORM (Go), SQLAlchemy (Python), or Prisma (Node) |
| Migrations | golang-migrate, Flyway, or Alembic |
| Encryption library | libsodium (NaCl) or Go's crypto/aes + crypto/cipher |
| Key management | AWS KMS, Azure Key Vault, or GCP Cloud KMS for KEK storage |

---

## Migration and Scaling Considerations

1. **Schema versioning from day one.** Use numbered migrations (not auto-diff tools) so every deployment is reproducible. Store the migration version in a `schema_migrations` table.

2. **Partition audit logs at creation.** Create partitions automatically via a cron job or pg_partman. Plan for partition detach and archive to cold storage after the compliance retention window (typically 1-7 years).

3. **Envelope encryption key rotation.** When rotating DEKs, re-encrypt only the DEK with the new KEK -- do not re-encrypt every secret version. Store the encryption_key_id on each secret_version row so old data can still be decrypted with the correct DEK.

4. **Tenant isolation strategy.** Start with shared tables + org_id filtering (row-level security in PostgreSQL). If compliance requires stronger isolation, migrate to schema-per-tenant or database-per-tenant with Citus or separate PostgreSQL instances.

5. **Read replica routing.** Route audit log queries, compliance reports, and search to read replicas. Write path (secret creation, rotation, session start) goes to the primary.

6. **Eventual transition path.** If the platform outgrows a single PostgreSQL cluster, the normalized schema is straightforward to shard by org_id or to migrate into a CQRS architecture (Suggestion 2) where the relational store becomes the write side and a search/analytics store handles the read side.
