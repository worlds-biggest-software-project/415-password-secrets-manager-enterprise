# Data Model Suggestion 3: Hybrid Relational + JSONB/Document Approach

> Project: Password & Secrets Manager (Enterprise) · Candidate #415
> Approach: PostgreSQL with relational tables for core entities and JSONB columns for extensible, schema-flexible data

---

## Summary

This approach uses PostgreSQL as a single data store but strategically divides the schema into two tiers:

1. **Relational tier** -- normalized tables with strict schemas for entities that require referential integrity, transactional consistency, and well-defined query patterns (organizations, users, groups, roles, policies, leases, sessions, access requests).

2. **Document tier** -- JSONB columns on key tables for data that varies by secret type, engine configuration, asset platform, policy language, or integration target. Instead of creating dozens of narrow tables for each secret engine variant or asset platform, the varying attributes live in typed JSONB columns with CHECK constraints and GIN indexes.

This mirrors the pattern used by Supabase Vault (PostgreSQL extension with encrypted JSONB), AWS Secrets Manager (metadata as structured JSON alongside encrypted BLOB payloads), and 1Password Connect (item templates as JSON documents within a relational container). It gives the platform the rigidity of a relational model where it matters (access control, audit, multi-tenancy) and the flexibility of a document store where variability is high (secret shapes, engine configs, asset metadata, compliance mappings).

---

## Key Design Principles

1. **JSONB for variability, columns for query predicates.** If a field is used in WHERE clauses, JOIN conditions, or foreign keys, it is a column. If it varies by type or is only read as part of a larger payload, it lives in JSONB.
2. **Encrypted BYTEA for secret values, JSONB for secret metadata.** The actual credential payload is always AES-256-GCM encrypted in a BYTEA column. The metadata (key names, tags, rotation schedule, compliance labels) is stored as JSONB for flexible querying.
3. **CHECK constraints on JSONB.** Use `jsonb_typeof` and key-existence checks to enforce structural invariants without a rigid column schema.
4. **GIN indexes on JSONB paths.** Enable efficient queries on tags, labels, compliance mappings, and custom attributes without full table scans.

---

## Key Entities and Schema

### Organizational Hierarchy (Relational)

```sql
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(256) NOT NULL,
    slug            VARCHAR(128) UNIQUE NOT NULL,
    parent_org_id   UUID REFERENCES organizations(id),
    settings        JSONB NOT NULL DEFAULT '{}',
    -- settings: { "mfa_policy": "required", "session_recording": true,
    --             "allowed_engines": ["kv","database","pki","ssh"],
    --             "compliance_frameworks": ["soc2","pci-dss","hipaa"],
    --             "retention_days": 2555 }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE namespaces (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    parent_id       UUID REFERENCES namespaces(id),
    name            VARCHAR(256) NOT NULL,
    path            LTREE NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata: { "environment": "production", "team": "platform-eng",
    --             "cost_center": "CC-4420", "tags": ["critical","pci-scope"] }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, path)
);
CREATE INDEX idx_namespaces_metadata ON namespaces USING GIN (metadata);
```

### Identity and Access Control (Relational + JSONB for federation metadata)

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    email           VARCHAR(320) NOT NULL,
    display_name    VARCHAR(256),
    password_hash   BYTEA,
    master_key_enc  BYTEA,
    public_key      BYTEA,
    status          VARCHAR(20) DEFAULT 'active',
    mfa_config      JSONB NOT NULL DEFAULT '{}',
    -- mfa_config: { "methods": ["totp","webauthn"], "backup_codes_hash": "...",
    --              "webauthn_credentials": [{ "id": "...", "public_key": "...",
    --                                         "sign_count": 42 }] }
    federation      JSONB NOT NULL DEFAULT '{}',
    -- federation: { "oidc_subject": "...", "saml_name_id": "...",
    --              "scim_external_id": "...", "idp_groups": ["admins","sre"] }
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, email)
);
CREATE INDEX idx_users_federation ON users USING GIN (federation);

CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    external_id     VARCHAR(512),
    metadata        JSONB NOT NULL DEFAULT '{}',
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
    auth_config     JSONB NOT NULL DEFAULT '{}',
    -- auth_config: { "method": "approle", "role_id": "...",
    --               "bound_cidrs": ["10.0.0.0/8"], "token_ttl": "1h" }
    --   or: { "method": "kubernetes", "namespace": "prod",
    --         "service_account": "vault-agent", "audiences": ["vault"] }
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### Policies (Relational structure, JSONB for policy rules)

```sql
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    policy_language VARCHAR(32) NOT NULL DEFAULT 'cedar',  -- 'cedar', 'rego', 'hcl'
    policy_document TEXT NOT NULL,
    compiled_rules  JSONB,
    -- compiled_rules: pre-parsed policy representation for fast evaluation
    -- { "rules": [
    --     { "effect": "permit", "principal": {"type":"group","id":"sre-team"},
    --       "action": "secret.read", "resource": {"path":"prod/databases/*"},
    --       "conditions": {"time_window": "on-call", "mfa_required": true} }
    -- ]}
    version         INT NOT NULL DEFAULT 1,
    is_active       BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    name            VARCHAR(256) NOT NULL,
    description     TEXT,
    permissions     JSONB NOT NULL DEFAULT '[]',
    -- permissions: [
    --   { "action": "secret.*", "resource": "namespaces/prod/*" },
    --   { "action": "session.start", "resource": "assets/databases/*" },
    --   { "action": "approval.decide", "resource": "requests/*" }
    -- ]
    is_builtin      BOOLEAN DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_roles_permissions ON roles USING GIN (permissions);

CREATE TABLE role_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    principal_type  VARCHAR(20) NOT NULL CHECK (principal_type IN ('user','group','service_account')),
    principal_id    UUID NOT NULL,
    namespace_id    UUID REFERENCES namespaces(id),
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    assigned_by     UUID REFERENCES users(id),
    conditions      JSONB NOT NULL DEFAULT '{}',
    -- conditions: { "time_bound": "2026-06-01/2026-07-01",
    --              "require_mfa": true, "source_cidrs": ["10.0.0.0/8"] }
    UNIQUE(role_id, principal_type, principal_id, namespace_id)
);
```

### Secrets Engine Registry and Secrets (JSONB for engine-specific configuration)

```sql
CREATE TABLE secrets_engines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    engine_type     VARCHAR(64) NOT NULL,
    mount_path      VARCHAR(512) NOT NULL,
    config          JSONB NOT NULL DEFAULT '{}',
    -- KV engine:      { "max_versions": 10, "cas_required": false }
    -- Database engine: { "plugin": "postgresql", "connection_url": "...(encrypted ref)...",
    --                    "max_open_connections": 5, "max_ttl": "24h",
    --                    "allowed_roles": ["readonly","readwrite"] }
    -- PKI engine:     { "max_ttl": "87600h", "issuing_certificates": "...",
    --                   "crl_distribution_points": ["..."] }
    -- SSH engine:     { "key_type": "ca", "default_ttl": "30m",
    --                   "allowed_users": "*", "allowed_extensions": "permit-pty" }
    -- Transit engine: { "convergent_encryption": false, "derived": false,
    --                   "min_encryption_version": 1 }
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, mount_path)
);

CREATE TABLE secrets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id       UUID NOT NULL REFERENCES secrets_engines(id),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    path            VARCHAR(1024) NOT NULL,
    secret_type     VARCHAR(32) NOT NULL,      -- 'kv', 'database_cred', 'ssh_key', 'certificate',
                                                -- 'api_key', 'cloud_iam', 'password'
    current_version INT NOT NULL DEFAULT 1,
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- Common metadata:
    -- { "tags": ["production","pci-scope"],
    --   "owner": "platform-team",
    --   "compliance_labels": ["PCI-DSS-8.3","SOC2-CC6.1"],
    --   "custom_fields": { "application": "checkout-service", "tier": "critical" } }
    --
    -- Type-specific metadata:
    -- For password:    { "username": "admin", "url": "https://...", "password_policy": "complex-32" }
    -- For certificate: { "common_name": "api.example.com", "san": ["..."],
    --                    "issuer": "internal-ca", "not_after": "2027-01-15T00:00:00Z" }
    -- For SSH key:     { "key_algorithm": "ed25519", "fingerprint": "SHA256:..." }
    rotation_config JSONB,
    -- rotation_config: { "period": "30d", "auto_rotate": true,
    --                    "rotation_method": "plugin", "last_rotated": "...",
    --                    "next_rotation": "...", "notification_channels": ["slack-ops"] }
    status          VARCHAR(20) DEFAULT 'active',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at      TIMESTAMPTZ,
    UNIQUE(engine_id, path)
);
CREATE INDEX idx_secrets_metadata ON secrets USING GIN (metadata);
CREATE INDEX idx_secrets_type ON secrets(org_id, secret_type);
CREATE INDEX idx_secrets_tags ON secrets USING GIN ((metadata -> 'tags'));

CREATE TABLE secret_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id       UUID NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version         INT NOT NULL,
    encrypted_value BYTEA NOT NULL,
    encryption_key_id UUID NOT NULL,
    checksum        BYTEA NOT NULL,
    value_schema    JSONB,
    -- value_schema: describes the structure of the decrypted payload
    -- { "fields": ["username","password","connection_string"],
    --   "format": "json", "encoding": "utf-8" }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_type VARCHAR(20),
    created_by_id   UUID,
    destroyed_at    TIMESTAMPTZ,
    UNIQUE(secret_id, version)
);
```

### Dynamic Secrets and Leases (Relational + JSONB for engine-specific lease data)

```sql
CREATE TABLE leases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    engine_id       UUID NOT NULL REFERENCES secrets_engines(id),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    principal_type  VARCHAR(20) NOT NULL,
    principal_id    UUID NOT NULL,
    lease_duration  INTERVAL NOT NULL,
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    renewed_at      TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    credential_ref  BYTEA,
    status          VARCHAR(20) DEFAULT 'active',
    lease_data      JSONB NOT NULL DEFAULT '{}',
    -- Database lease:  { "db_username": "v-svc-readonly-x9f2k", "db_name": "orders",
    --                    "roles": ["SELECT"], "connection_limit": 5 }
    -- AWS IAM lease:   { "access_key_id": "AKIA...", "arn": "arn:aws:iam::...",
    --                    "policy_arns": ["..."] }
    -- SSH cert lease:  { "serial": "...", "key_id": "...", "valid_principals": ["ubuntu"] }
    -- PKI cert lease:  { "serial_number": "...", "common_name": "api.example.com" }
    revocation_data JSONB
    -- revocation_data: { "method": "drop_user", "target": "v-svc-readonly-x9f2k",
    --                    "revoked_at": "...", "revoked_by": "system/lease-revoker" }
);
CREATE INDEX idx_leases_expiry ON leases(expires_at) WHERE status = 'active';
CREATE INDEX idx_leases_principal ON leases(principal_type, principal_id);
```

### Managed Assets and Sessions (Relational + JSONB for platform-specific attributes)

```sql
CREATE TABLE managed_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    namespace_id    UUID NOT NULL REFERENCES namespaces(id),
    asset_type      VARCHAR(32) NOT NULL,
    hostname        VARCHAR(512),
    ip_address      INET,
    port            INT,
    platform        VARCHAR(64),
    status          VARCHAR(20) DEFAULT 'active',
    attributes      JSONB NOT NULL DEFAULT '{}',
    -- Linux server:    { "os_version": "Ubuntu 24.04", "ssh_port": 22,
    --                    "host_keys": ["SHA256:..."], "sudo_config": "NOPASSWD" }
    -- Windows server:  { "os_version": "Server 2025", "rdp_port": 3389,
    --                    "domain": "corp.example.com", "ou": "OU=Servers,DC=..." }
    -- Database:        { "engine": "postgresql", "version": "16.3",
    --                    "ssl_mode": "verify-full", "databases": ["orders","inventory"] }
    -- Network device:  { "vendor": "cisco", "model": "ISR 4431",
    --                    "management_protocol": "ssh", "firmware": "17.6.3" }
    -- SaaS app:        { "provider": "aws", "console_url": "https://...",
    --                    "federation_type": "saml" }
    discovery_data  JSONB,
    -- discovery_data: { "discovered_at": "...", "discovery_source": "ad_scan",
    --                   "unmanaged_accounts": ["backup_admin","test_user"] }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_assets_attributes ON managed_assets USING GIN (attributes);
CREATE INDEX idx_assets_type ON managed_assets(org_id, asset_type);

CREATE TABLE privileged_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id        UUID NOT NULL REFERENCES managed_assets(id),
    account_name    VARCHAR(256) NOT NULL,
    account_type    VARCHAR(32),
    credential_id   UUID REFERENCES secrets(id),
    last_verified   TIMESTAMPTZ,
    last_changed    TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'managed',
    account_config  JSONB NOT NULL DEFAULT '{}',
    -- account_config: { "password_policy": "complex-32", "rotation_period": "30d",
    --                   "checkout_exclusive": true, "max_checkout_duration": "8h",
    --                   "notification_on_checkout": true }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    account_id      UUID NOT NULL REFERENCES privileged_accounts(id),
    session_type    VARCHAR(16) NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    status          VARCHAR(20) DEFAULT 'active',
    recording_ref   JSONB,
    -- recording_ref: { "video_path": "s3://recordings/2026/05/...",
    --                  "keystroke_path": "s3://recordings/2026/05/...",
    --                  "video_size_bytes": 15234567, "duration_seconds": 3420,
    --                  "video_hash": "sha256:...", "sealed": true }
    session_metadata JSONB NOT NULL DEFAULT '{}',
    -- session_metadata: { "client_ip": "10.2.3.45", "client_type": "web_terminal",
    --                     "proxy_node": "proxy-us-east-1a",
    --                     "commands_executed": 47, "risk_score": 0.12,
    --                     "risk_alerts": [{ "type": "unusual_command", "cmd_hash": "...",
    --                                       "timestamp": "...", "score": 0.85 }] }
    termination_reason VARCHAR(64)
);
CREATE INDEX idx_sessions_active ON sessions(org_id) WHERE status = 'active';
```

### JIT Access Requests (Relational + JSONB for flexible approval workflows)

```sql
CREATE TABLE access_requests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    requester_id    UUID NOT NULL REFERENCES users(id),
    target_type     VARCHAR(32) NOT NULL,
    target_id       UUID NOT NULL,
    justification   TEXT NOT NULL,
    requested_duration INTERVAL NOT NULL,
    risk_score      DECIMAL(5,2),
    risk_factors    JSONB,
    -- risk_factors: { "off_hours": true, "first_time_asset": true,
    --                "unusual_geo": false, "risk_model_version": "v2.3",
    --                "similar_requests_30d": 0, "requester_risk_tier": "medium" }
    workflow_config JSONB NOT NULL,
    -- workflow_config: { "steps": [
    --   { "order": 1, "type": "auto_approve", "condition": "risk_score < 0.3" },
    --   { "order": 2, "type": "manager_approval", "timeout": "4h" },
    --   { "order": 3, "type": "security_team", "approvers_group": "security-oncall",
    --     "min_approvals": 1, "timeout": "8h" }
    -- ], "escalation": { "on_timeout": "deny", "notify": ["security-leads"] } }
    status          VARCHAR(20) DEFAULT 'pending',
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

CREATE TABLE approval_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES access_requests(id) ON DELETE CASCADE,
    step_order      INT NOT NULL,
    approver_id     UUID NOT NULL REFERENCES users(id),
    decision        VARCHAR(20) NOT NULL,
    comment         TEXT,
    decided_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(request_id, step_order, approver_id)
);
```

### Audit Log (Relational + JSONB for extensible detail)

```sql
CREATE TABLE audit_logs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_type      VARCHAR(20) NOT NULL,
    actor_id        UUID NOT NULL,
    action          VARCHAR(64) NOT NULL,
    resource_type   VARCHAR(32) NOT NULL,
    resource_id     UUID,
    resource_path   VARCHAR(1024),
    result          VARCHAR(20) NOT NULL,
    source_ip       INET,
    request_id      UUID,
    detail          JSONB NOT NULL DEFAULT '{}',
    -- detail: { "user_agent": "vault-cli/1.2.0", "session_id": "...",
    --           "policy_evaluated": "prod-readonly", "denial_reason": "...",
    --           "changed_fields": ["rotation_period","max_ttl"],
    --           "compliance_controls": ["PCI-DSS-8.3.1","SOC2-CC6.1"] }
    prev_hash       BYTEA,
    entry_hash      BYTEA NOT NULL
) PARTITION BY RANGE (timestamp);
CREATE INDEX idx_audit_detail ON audit_logs USING GIN (detail);
```

### Secrets Sprawl Detection (JSONB-heavy)

```sql
CREATE TABLE sprawl_findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES organizations(id),
    scan_id         UUID NOT NULL,
    source_type     VARCHAR(32) NOT NULL,      -- 'git_repo', 'ci_env', 'saas_config', 'cloud_param'
    source_ref      VARCHAR(1024) NOT NULL,     -- repo URL, CI pipeline ID, etc.
    finding         JSONB NOT NULL,
    -- finding: { "secret_type": "aws_access_key", "file_path": "deploy/config.yaml",
    --            "line_number": 42, "commit_sha": "abc123",
    --            "author_email": "dev@example.com", "severity": "critical",
    --            "blast_radius": "production_aws_account",
    --            "matched_vault_secret": "uuid-of-known-secret",
    --            "remediation_status": "pending",
    --            "false_positive": false, "ai_confidence": 0.97 }
    status          VARCHAR(20) DEFAULT 'open',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);
CREATE INDEX idx_sprawl_finding ON sprawl_findings USING GIN (finding);
CREATE INDEX idx_sprawl_status ON sprawl_findings(org_id, status) WHERE status = 'open';
```

---

## Pros

- **Single database engine.** PostgreSQL handles both structured and semi-structured data. No need to operate a separate document store (MongoDB, DynamoDB) alongside the relational database.
- **Flexible extensibility for secrets engines.** Adding a new engine type (e.g., a Kubernetes service account engine, a Snowflake dynamic credential engine) requires no schema migration -- only new JSONB payloads in the existing config and lease_data columns.
- **Rich querying on semi-structured data.** GIN-indexed JSONB enables queries like "find all secrets tagged 'pci-scope' in namespace 'prod'" or "find all assets where attributes->>'vendor' = 'cisco'" without schema changes.
- **Referential integrity where it counts.** Foreign keys on org_id, namespace_id, engine_id, user_id, and group_id enforce the core entity graph. JSONB is used only for attributes that vary by type or context.
- **Natural compliance label mapping.** Storing compliance_controls and compliance_labels as JSONB arrays in secrets and audit logs allows dynamic mapping to new regulatory frameworks without ALTER TABLE.
- **Practical migration path.** If starting from the normalized model (Suggestion 1), adding JSONB columns to existing tables is a non-breaking migration. If moving toward event sourcing (Suggestion 2), the JSONB payloads map directly to event payload schemas.
- **Lower storage overhead than event sourcing.** Stores current state with version history, not every intermediate event. Audit logging is explicit but compact.

## Cons

- **No compile-time schema validation for JSONB.** Application code must validate JSONB structure. Bugs in JSONB payload construction can go undetected until runtime. Mitigation: use JSON Schema validation in the application layer and CHECK constraints in PostgreSQL.
- **JSONB indexing costs.** GIN indexes on large JSONB columns consume significant storage and slow writes. If every row has a different JSONB shape, the index becomes less selective.
- **Temptation to over-use JSONB.** Without discipline, developers will put everything in JSONB, gradually losing the benefits of the relational tier. Requires clear guidelines: "if it is a foreign key, a query predicate, or an ordering dimension, it is a column."
- **Reporting complexity.** Generating compliance reports requires extracting and aggregating data from JSONB columns, which is more complex than querying flat relational tables. Views and materialized views can help but add maintenance overhead.
- **PostgreSQL version dependency.** Advanced JSONB features (jsonb_path_query, SQL/JSON standard functions) are PostgreSQL 12+. GIN index improvements are ongoing. The schema depends on a modern PostgreSQL version.
- **Same horizontal scaling limits as the relational model.** Single-writer PostgreSQL. For very large deployments, consider Citus for distributed tables or shard by org_id.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|---------------|
| Primary database | PostgreSQL 16+ with pgcrypto, ltree, and pg_trgm extensions |
| JSONB validation | JSON Schema validation in application code (ajv for Node, jsonschema for Python) |
| ORM / query builder | GORM with custom JSONB scanning (Go), SQLAlchemy with JSONB type (Python) |
| Migrations | golang-migrate or Flyway; JSONB column additions are non-breaking |
| Full-text search on metadata | pg_trgm + GIN for trigram search on JSONB text values |
| Audit log offloading | Stream partitioned audit_logs to ClickHouse or S3 Parquet for analytics |
| Encryption | libsodium for payload encryption; PostgreSQL pgcrypto for utility functions only |
| Key management | AWS KMS / Azure Key Vault / GCP Cloud KMS |

---

## Migration and Scaling Considerations

1. **JSONB schema registry.** Maintain a schema registry (in code or as a table) that defines the expected JSONB shapes for each engine_type, secret_type, asset_type, and session_type. Validate on write. This prevents JSONB from becoming an untyped dumping ground.

2. **Materialized views for reporting.** Create materialized views that flatten JSONB columns into relational form for compliance reports. Refresh these on a schedule (e.g., hourly) rather than querying JSONB in real time for dashboards.

   ```sql
   CREATE MATERIALIZED VIEW mv_compliance_secrets AS
   SELECT s.id, s.org_id, s.path, s.secret_type, s.status,
          jsonb_array_elements_text(s.metadata->'compliance_labels') AS compliance_label,
          jsonb_array_elements_text(s.metadata->'tags') AS tag,
          s.updated_at
   FROM secrets s
   WHERE s.status = 'active';
   ```

3. **JSONB column size monitoring.** Monitor the average size of JSONB columns. If a JSONB column consistently exceeds 10KB, consider extracting frequently-accessed subkeys into proper columns. PostgreSQL TOAST handles large values but at a performance cost.

4. **Gradual schema promotion.** When a JSONB field becomes universally used and appears in critical query paths, promote it to a dedicated column with a backfill migration. For example, if `metadata->>'owner'` is used in every secrets query, add an `owner` column and backfill from JSONB.

5. **Partition strategy.** Partition audit_logs by month. Consider partitioning leases by status (active vs. expired) using list partitioning to keep the active partition small and fast. Partition secrets by org_id if a single organization dominates storage.

6. **Cross-cloud sync.** The JSONB approach simplifies cloud sync: each cloud provider's native secret format (AWS Secrets Manager JSON, Azure Key Vault metadata, GCP Secret Manager labels) maps naturally to JSONB without schema changes per provider.
