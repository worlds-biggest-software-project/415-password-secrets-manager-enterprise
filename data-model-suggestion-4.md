# Data Model Suggestion 4: Barrier-Encrypted Hierarchical KV Store with Graph Access Overlay

> Project: Password & Secrets Manager (Enterprise) · Candidate #415
> Approach: Domain-specific architecture inspired by HashiCorp Vault's barrier encryption and path-based storage, extended with a graph database overlay for access path analysis and privilege escalation detection

---

## Summary

This approach is purpose-built for the secrets management domain. Rather than starting from a general-purpose relational or document database and adapting it, it adopts the architectural patterns proven by HashiCorp Vault and CyberArk -- then extends them with a graph layer that no current product offers natively.

The architecture has three tiers:

1. **Barrier-encrypted hierarchical KV store** -- A path-addressable, tree-structured key-value store where all data passes through an encryption barrier before reaching the physical storage backend. Every write is envelope-encrypted with a per-entry Data Encryption Key (DEK), and DEKs are wrapped by a Key Encryption Key (KEK) held in an external KMS/HSM. The storage backend (Raft-based embedded or PostgreSQL) never sees plaintext. This is the pattern Vault uses, and it is the industry-proven approach for a secrets manager.

2. **Append-only audit journal** -- A separate, hash-chained, append-only log for all operations. This is not event sourcing (the KV store is the source of truth for current state), but a cryptographically verifiable audit trail for compliance and forensics.

3. **Graph access overlay** -- A Neo4j or in-memory graph structure that models the relationships between identities (users, groups, service accounts), roles, policies, namespaces, secrets, assets, and sessions. This enables queries that are impractical in a relational model: "Show all paths from this contractor account to production database credentials," "Which role changes would eliminate this privilege escalation risk?" and "What is the blast radius if this service account is compromised?"

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        API / CLI / Browser                          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                 ┌─────────────┴─────────────┐
                 │      Security Barrier      │
                 │  (AES-256-GCM encryption)  │
                 └─────────────┬─────────────┘
                               │
        ┌──────────────────────┼─────────────────────┐
        ▼                      ▼                     ▼
┌───────────────┐    ┌─────────────────┐    ┌───────────────────┐
│  Hierarchical │    │  Audit Journal  │    │  Graph Overlay    │
│  KV Store     │    │  (Append-Only)  │    │  (Neo4j / Memgraph│
│  (Raft/PG)    │    │  (PG Partitioned│    │   or in-memory)   │
│               │    │   + S3 archive) │    │                   │
│  sys/         │    │                 │    │  (User)──[:HAS_   │
│  auth/        │    │  entry_hash =   │    │    ROLE]──(Role)  │
│  secret/      │    │  H(prev||data)  │    │  (Role)──[:GRANTS │
│  identity/    │    │                 │    │    ]──(Policy)    │
│  cubbyhole/   │    │                 │    │  (Policy)──[:PERM │
│  lease/       │    │                 │    │    ITS]──(Path)   │
└───────────────┘    └─────────────────┘    └───────────────────┘
```

---

## Tier 1: Barrier-Encrypted Hierarchical KV Store

### Path Structure

All data in the platform is addressed by hierarchical paths, with each secrets engine, auth method, and system component mounted at a unique path prefix. A random UUID is assigned to each mount point, isolating engine data at the physical storage layer.

```
sys/
  policy/                       -- Policy documents
  mounts/                       -- Secrets engine mount table
  auth/                         -- Auth method mount table
  seal/                         -- Seal configuration
  config/                       -- System configuration

auth/
  oidc/                         -- OIDC auth method
    config                      -- OIDC provider config
    role/<role-name>             -- OIDC role definitions
  kubernetes/
    config
    role/<role-name>
  approle/
    role/<role-name>/
      role-id
      secret-id

identity/
  entity/<entity-id>            -- Canonical identity entities
  entity-alias/<alias-id>       -- Auth-method-specific aliases
  group/<group-id>              -- Groups of entities
  oidc/                         -- OIDC identity tokens config

secret/
  kv/<mount-uuid>/
    data/<path>                 -- Secret data (current version)
    metadata/<path>             -- Secret metadata and version list
    delete/<path>               -- Soft-delete markers
    destroy/<path>              -- Hard-destroy markers
  database/<mount-uuid>/
    config/<connection-name>    -- Database connection configs
    role/<role-name>            -- Dynamic credential role defs
    creds/<role-name>           -- Credential generation endpoint
  pki/<mount-uuid>/
    config/
    roles/<role-name>
    issue/<role-name>
    cert/<serial>
  ssh/<mount-uuid>/
    config/ca
    roles/<role-name>
    sign/<role-name>
  transit/<mount-uuid>/
    keys/<key-name>
    encrypt/<key-name>
    decrypt/<key-name>

pam/
  assets/<asset-id>             -- Managed asset definitions
  accounts/<account-id>         -- Privileged account configs
  sessions/<session-id>         -- Session state and metadata
  recordings/<session-id>       -- Recording references

lease/
  <lease-id>                    -- Active lease state
```

### Physical Storage Interface

```go
// Physical storage backend interface
type Backend interface {
    // Put stores an entry at the given path
    Put(ctx context.Context, entry *Entry) error
    // Get retrieves an entry at the given path
    Get(ctx context.Context, path string) (*Entry, error)
    // Delete removes an entry at the given path
    Delete(ctx context.Context, path string) error
    // List returns the child keys at a given path prefix
    List(ctx context.Context, prefix string) ([]string, error)
}

type Entry struct {
    Key       string    // path within the mount's UUID namespace
    Value     []byte    // encrypted payload (ciphertext)
    SealWrap  bool      // whether additional seal-wrap encryption applies
}
```

### Barrier Encryption Model

```
                    ┌─────────────────────────────┐
                    │   External KMS / HSM         │
                    │   (AWS KMS, Azure KV, etc.)  │
                    │                              │
                    │   Root Key (never exported)  │
                    └──────────┬──────────────────┘
                               │ wraps
                    ┌──────────▼──────────────────┐
                    │   Master Key                 │
                    │   (reconstructed from        │
                    │    Shamir shares or auto-     │
                    │    unsealed via KMS)          │
                    └──────────┬──────────────────┘
                               │ encrypts
                    ┌──────────▼──────────────────┐
                    │   Barrier Encryption Key     │
                    │   (AES-256-GCM)              │
                    │   Encrypts all data before   │
                    │   it reaches the storage     │
                    │   backend                    │
                    └──────────┬──────────────────┘
                               │ encrypts
                    ┌──────────▼──────────────────┐
                    │   Per-Entry DEKs (optional)  │
                    │   For high-value paths,      │
                    │   additional per-entry keys  │
                    │   wrapped by the barrier key │
                    └─────────────────────────────┘
```

### Storage Backend Options

```sql
-- Option A: PostgreSQL as the physical backend
-- (mirrors Vault's PostgreSQL storage backend schema)
CREATE TABLE vault_kv_store (
    parent_path TEXT NOT NULL,
    path        TEXT NOT NULL,
    key         TEXT NOT NULL,
    value       BYTEA,                       -- always ciphertext
    updated_at  TIMESTAMPTZ DEFAULT now(),
    CONSTRAINT pkey PRIMARY KEY (path, key)
);
CREATE INDEX idx_vault_kv_parent ON vault_kv_store(parent_path);

-- Option B: Embedded Raft storage (recommended for production)
-- Uses bbolt (BoltDB) as the local storage engine on each Raft node.
-- Data is replicated across a 3- or 5-node Raft cluster for HA.
-- No external database dependency.
```

---

## Tier 2: Append-Only Audit Journal

The audit journal is a separate data store from the KV store. It receives a structured record for every API call that passes through the barrier, regardless of success or failure.

```sql
-- Audit journal (PostgreSQL, partitioned by month)
CREATE TABLE audit_journal (
    id              BIGSERIAL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now(),
    entry_type      VARCHAR(16) NOT NULL,      -- 'request', 'response'
    org_id          UUID NOT NULL,

    -- Request metadata
    operation       VARCHAR(16) NOT NULL,      -- 'read', 'write', 'delete', 'list'
    path            VARCHAR(2048) NOT NULL,
    mount_type      VARCHAR(64),
    mount_accessor  VARCHAR(64),

    -- Actor identification
    auth_method     VARCHAR(64),
    token_accessor  VARCHAR(128),
    entity_id       UUID,
    display_name    VARCHAR(256),
    policies        TEXT[],                    -- policies evaluated for this request
    source_ip       INET,

    -- Result
    status_code     INT,
    error_message   TEXT,

    -- Tamper evidence
    prev_hash       BYTEA,
    entry_hash      BYTEA NOT NULL,            -- SHA-256(timestamp||path||actor||prev_hash||...)

    -- Structured request/response data (encrypted)
    request_data    BYTEA,                     -- encrypted request payload
    response_wrap   BYTEA,                     -- encrypted response metadata (never raw secrets)

    PRIMARY KEY (timestamp, id)
) PARTITION BY RANGE (timestamp);

-- Merkle tree roots published hourly to external transparency log
CREATE TABLE audit_merkle_roots (
    window_start    TIMESTAMPTZ PRIMARY KEY,
    window_end      TIMESTAMPTZ NOT NULL,
    root_hash       BYTEA NOT NULL,
    entry_count     BIGINT NOT NULL,
    published_to    VARCHAR(256),              -- e.g., 'sigstore-rekor', 'internal-ledger'
    published_at    TIMESTAMPTZ
);
```

---

## Tier 3: Graph Access Overlay

The graph overlay is a secondary, eventually-consistent projection of the identity and access control data from the KV store. It is rebuilt periodically or updated via change-data-capture from the KV store. It is **not** the source of truth for access decisions -- that remains the policy engine evaluating against the KV store -- but it provides analytical capabilities that no relational model can efficiently deliver.

### Graph Schema (Neo4j / Memgraph Cypher)

```cypher
// Identity nodes
CREATE (u:User {id: $id, email: $email, org_id: $org_id, status: 'active'})
CREATE (g:Group {id: $id, name: $name, org_id: $org_id})
CREATE (sa:ServiceAccount {id: $id, name: $name, org_id: $org_id})

// Organizational nodes
CREATE (o:Organization {id: $id, name: $name})
CREATE (ns:Namespace {id: $id, path: 'acme.prod.databases', org_id: $org_id})

// Access control nodes
CREATE (r:Role {id: $id, name: 'database-admin', org_id: $org_id})
CREATE (p:Policy {id: $id, name: 'prod-db-readonly', effect: 'allow'})

// Resource nodes
CREATE (s:Secret {id: $id, path: 'secret/kv/prod/db/orders-creds', type: 'database_cred'})
CREATE (e:Engine {id: $id, type: 'database', mount_path: 'secret/database/prod'})
CREATE (a:Asset {id: $id, hostname: 'db-orders-01.prod', type: 'database'})
CREATE (pa:PrivilegedAccount {id: $id, name: 'admin', asset_id: $asset_id})

// Relationships
CREATE (u)-[:MEMBER_OF]->(g)
CREATE (u)-[:HAS_ROLE {namespace_id: $ns_id, assigned_at: datetime()}]->(r)
CREATE (g)-[:HAS_ROLE {namespace_id: $ns_id}]->(r)
CREATE (sa)-[:HAS_ROLE]->(r)
CREATE (r)-[:BOUND_TO_POLICY]->(p)
CREATE (p)-[:PERMITS {actions: ['read','list'], conditions: {mfa: true}}]->(ns)
CREATE (ns)-[:CONTAINS]->(s)
CREATE (ns)-[:CONTAINS]->(a)
CREATE (s)-[:CREDENTIAL_FOR]->(pa)
CREATE (pa)-[:ACCOUNT_ON]->(a)
CREATE (a)-[:IN_NAMESPACE]->(ns)
CREATE (ns)-[:CHILD_OF]->(parent_ns)
CREATE (e)-[:MOUNTED_IN]->(ns)

// Session and lease relationships (temporal)
CREATE (u)-[:ACTIVE_SESSION {session_id: $sid, started_at: datetime()}]->(pa)
CREATE (sa)-[:ACTIVE_LEASE {lease_id: $lid, expires_at: datetime()}]->(e)

// Access request relationships
CREATE (u)-[:REQUESTED_ACCESS {request_id: $rid, status: 'pending'}]->(pa)
CREATE (approver)-[:APPROVED {decision_at: datetime()}]->(request:AccessRequest)
```

### Key Graph Queries

```cypher
-- 1. Privilege escalation detection:
-- "What are all paths from any user to production database credentials?"
MATCH path = (u:User)-[*1..6]->(s:Secret {type: 'database_cred'})
WHERE s.path STARTS WITH 'secret/kv/prod/'
RETURN u.email, [r IN relationships(path) | type(r)] AS access_chain,
       length(path) AS hops
ORDER BY hops ASC

-- 2. Blast radius analysis:
-- "If this service account is compromised, what can the attacker reach?"
MATCH (sa:ServiceAccount {id: $compromised_sa_id})
MATCH path = (sa)-[*1..5]->(target)
WHERE target:Secret OR target:Asset OR target:PrivilegedAccount
RETURN target, [r IN relationships(path) | type(r)] AS path_types,
       length(path) AS distance
ORDER BY distance ASC

-- 3. Least-privilege recommendation:
-- "This user has access to 47 secrets but only accessed 3 in the last 90 days"
MATCH (u:User {id: $user_id})-[:HAS_ROLE]->(r:Role)-[:BOUND_TO_POLICY]->(p:Policy)
      -[:PERMITS]->(ns:Namespace)-[:CONTAINS]->(s:Secret)
WITH u, collect(s) AS accessible_secrets
MATCH (u)-[:ACCESSED {timestamp: t}]->(accessed:Secret)
WHERE t > datetime() - duration('P90D')
WITH u, accessible_secrets, collect(accessed) AS actually_accessed
RETURN u.email,
       size(accessible_secrets) AS total_accessible,
       size(actually_accessed) AS actually_used,
       [s IN accessible_secrets WHERE NOT s IN actually_accessed | s.path] AS unused_access

-- 4. Policy change impact preview:
-- "If we remove this role, who loses access to what?"
MATCH (r:Role {id: $role_to_remove})<-[:HAS_ROLE]-(principal)
MATCH (r)-[:BOUND_TO_POLICY]->(p:Policy)-[:PERMITS]->(ns:Namespace)-[:CONTAINS]->(resource)
RETURN principal.email AS affected_principal,
       collect(resource.path) AS lost_access

-- 5. Cross-namespace access audit:
-- "Which identities have access across both staging and production namespaces?"
MATCH (u)-[:HAS_ROLE]->(r1:Role)-[:BOUND_TO_POLICY]->()-[:PERMITS]->(ns1:Namespace)
MATCH (u)-[:HAS_ROLE]->(r2:Role)-[:BOUND_TO_POLICY]->()-[:PERMITS]->(ns2:Namespace)
WHERE ns1.path STARTS WITH 'acme.staging' AND ns2.path STARTS WITH 'acme.prod'
RETURN u.email, collect(DISTINCT ns1.path) AS staging_access,
       collect(DISTINCT ns2.path) AS prod_access
```

---

## Integration Between Tiers

```
KV Store (Source of Truth)                    Graph Overlay (Analytical)
━━━━━━━━━━━━━━━━━━━━━━━━                    ━━━━━━━━━━━━━━━━━━━━━━━━━
identity/entity/<id>          ──CDC──▶        (:User) or (:ServiceAccount)
identity/group/<id>           ──CDC──▶        (:Group) + [:MEMBER_OF]
sys/policy/<name>             ──CDC──▶        (:Policy) + [:PERMITS]
sys/mounts/<path>             ──CDC──▶        (:Engine) + [:MOUNTED_IN]
secret/kv/.../metadata/<path> ──CDC──▶        (:Secret) + [:CONTAINS]
pam/assets/<id>               ──CDC──▶        (:Asset)
pam/accounts/<id>             ──CDC──▶        (:PrivilegedAccount)
lease/<id>                    ──CDC──▶        [:ACTIVE_LEASE]

CDC = Change Data Capture via audit journal events or KV store watches
Graph is rebuilt on startup and incrementally updated during operation.
The graph is never consulted for access control decisions (that is the
policy engine + KV store). The graph is for analytics, visualization,
and AI-powered recommendations only.
```

---

## Pros

- **Domain-native storage model.** The path-based KV store directly represents the mental model of secrets management: mount points, path hierarchies, namespaces, and scoped access. No impedance mismatch between the domain and the data model.
- **Proven barrier encryption architecture.** The two-tier key hierarchy (Master Key wrapping Barrier Key wrapping per-entry DEKs) is the architecture that HashiCorp Vault uses in production at thousands of enterprises. It is well-understood, auditable, and compatible with FIPS 140-3 requirements when backed by a certified HSM.
- **Storage backend flexibility.** The Backend interface abstraction means the platform can run on embedded Raft (zero external dependencies), PostgreSQL (for teams with existing PG infrastructure), or cloud KV stores (DynamoDB, Cloud Spanner) without changing any code above the barrier.
- **Graph-powered access intelligence.** No competing product offers built-in graph-based privilege escalation detection, blast radius analysis, or least-privilege recommendations. This is a genuine differentiator and maps directly to the AI-native features described in the project README (anomaly detection, least-privilege recommendations, risk-aware approval routing).
- **Clean separation of concerns.** The KV store handles operations (read/write secrets). The audit journal handles compliance. The graph handles analytics. Each can be scaled, upgraded, or replaced independently.
- **Pluggable secrets engine architecture.** New engine types (database, PKI, SSH, transit, cloud IAM) are just new path prefixes with their own request handlers. No schema migration required.

## Cons

- **Highest implementation complexity.** Three data tiers (KV store, audit journal, graph) must be built, deployed, and maintained. This is significantly more complex than a single PostgreSQL schema.
- **Graph database operational overhead.** Neo4j or Memgraph adds another database to operate, back up, and secure. For smaller deployments, the graph overhead may not be justified. Mitigation: use an in-memory graph (e.g., built with Go's gonum/graph library) for small deployments, with Neo4j as an option for large enterprises.
- **Eventually consistent graph.** The graph overlay lags the KV store. A role assignment may take seconds to appear in the graph. This is acceptable for analytics but means the graph should never be used for access control decisions.
- **KV store limits complex queries.** The path-based KV store does not support relational joins or complex queries natively. Answering "list all secrets expiring in the next 7 days" requires either a full tree scan or a secondary index (maintained separately). Projections or PostgreSQL-backed indexes mitigate this.
- **Custom implementation required.** Unlike the relational approaches (Suggestions 1-3) where the schema runs on PostgreSQL out of the box, the barrier-encrypted KV store requires custom implementation of the encryption barrier, path routing, and secrets engine plugin system.
- **Talent pool.** Fewer engineers are experienced with building and operating barrier-encrypted KV stores or graph databases compared to PostgreSQL schemas.

---

## Technology Recommendations

| Component | Recommendation |
|-----------|---------------|
| KV store engine | Custom Go implementation with bbolt (Raft) or PostgreSQL backend |
| Raft consensus | hashicorp/raft library (MPL-2.0) |
| Barrier encryption | AES-256-GCM via Go's crypto/aes + crypto/cipher; seal wrap via cloud KMS SDKs |
| Key management | AWS KMS, Azure Key Vault, GCP Cloud KMS, or PKCS#11 for on-prem HSM |
| Audit journal | PostgreSQL 16+ (partitioned) with hash chain verification |
| Graph database | Neo4j Community (GPLv3) for large deployments; in-memory gonum/graph for small |
| Graph sync | Custom CDC consumer reading from audit journal |
| Transparency log | Sigstore Rekor for Merkle root publication |
| Secrets engine plugins | gRPC plugin interface (like Vault's go-plugin framework) |
| API layer | Go with gRPC + REST gateway (grpc-gateway) |

---

## Migration and Scaling Considerations

1. **Start without the graph.** For MVP, implement tiers 1 and 2 only (KV store + audit journal). The graph overlay can be added as a v1.1 feature once the core platform is stable. The audit journal provides the CDC source needed to bootstrap the graph later.

2. **Raft cluster sizing.** Start with a 3-node Raft cluster for HA. Scale to 5 nodes for large deployments. Each node holds a full copy of the encrypted data. Storage requirements are modest (most vault deployments are <100GB) since secrets are small.

3. **Seal/unseal automation.** Use auto-unseal with cloud KMS to avoid manual Shamir share ceremony on restart. This is the production-standard approach used by Vault Enterprise and all major cloud-hosted vault services.

4. **Graph rebuild strategy.** The graph overlay should be fully rebuildable from the KV store's current state (by listing all identity, policy, and secret paths) or from an audit journal replay. Test graph rebuild in CI. Target rebuild time: <5 minutes for 100K nodes.

5. **Performance budgets.** Secret read latency must be <10ms (p99). The barrier encryption adds ~1ms overhead per operation. The graph is never in the read path for secret access, so it does not affect operational latency.

6. **Migration from relational (Suggestions 1-3).** If the platform starts with a PostgreSQL relational model, the migration path to a barrier-encrypted KV store requires:
   - Implementing the barrier and Backend interface
   - Writing a migration tool that reads each relational row, encrypts it through the barrier, and writes it to the KV path structure
   - Running both systems in parallel during cutover
   - This is a significant engineering effort and should only be undertaken if the platform reaches a scale or security posture where the KV model provides clear benefits over the relational model.

7. **Vault API compatibility.** Consider implementing a Vault-compatible HTTP API subset. This allows existing Vault CLI tools, SDKs, and integrations (Terraform vault provider, Kubernetes CSI driver) to work with the platform without modification. The path-based data model makes this feasible because the API structure maps directly to the KV path structure.
