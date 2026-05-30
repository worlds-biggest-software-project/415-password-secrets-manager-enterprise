# Password & Secrets Manager (Enterprise) — Phased Development Plan

> Project: 415-password-secrets-manager-enterprise · Created: 2026-05-30
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

This plan synthesizes `research.md`, `features.md`, `standards.md`, `README.md`, and the four `data-model-suggestion-*.md` files. It targets the MVP scope in `features.md` first (encrypted vault, RBAC + SSO/SCIM, REST API + SDKs, CLI + browser extension, tamper-evident audit, auto-rotation, SOC 2 / PCI-DSS reporting), then layers in the v1.1 differentiators (dynamic secrets, JIT access, session proxy, K8s, multi-cloud sync, AI policy authoring, sprawl scanner).

The data model follows **Suggestion 3 (Hybrid Relational + JSONB)** as the primary store, with the **barrier-encryption pattern from Suggestion 4** for the crypto layer and the **hash-chained append-only audit journal** common to Suggestions 1, 2, and 4. This combination gives strict integrity for access-control/audit data while allowing schema-flexible storage for the many pluggable secrets-engine and asset variants without per-variant migrations.

---

## Technology Decisions

| Concern | Choice | Rationale |
|---------|--------|-----------|
| Primary language | **Go 1.23+** | Vault, OpenBao, Bitwarden core, and Kubernetes are all Go or Go-adjacent; the ecosystem has mature libraries for crypto (`crypto/*`, `filippo.io/age`), Raft (`hashicorp/raft`), KMIP/PKCS#11 bindings, gRPC plugins, and cloud SDKs. Single static binary suits self-hosted, low-ops deployment — a core differentiator vs. Vault's operational complexity. Strong concurrency model fits the session-proxy and lease-expiry workloads. |
| API framework | **Go stdlib `net/http` + `chi` router** with **`oapi-codegen`** generating handlers from a hand-authored OpenAPI 3.1 spec | OpenAPI 3.1 is mandated by `standards.md`; spec-first guarantees the published spec and SDK generation stay in sync. `chi` is lightweight, middleware-friendly, and avoids heavy framework lock-in. |
| Secondary API | **gRPC** (`grpc-go` + Protocol Buffers) for the secrets-engine plugin interface and node-to-node replication | `standards.md` notes Vault uses protobuf/gRPC for plugin RPC; this isolates pluggable engines in separate processes and enables third-party engines. |
| Database | **PostgreSQL 16+** (relational tables + JSONB columns + `ltree`) | Data-model Suggestion 3. JSONB absorbs engine/asset/policy variability without `ALTER TABLE` churn; relational tables enforce integrity for tenancy, RBAC, leases, and audit. `ltree` models the namespace hierarchy. |
| Migrations | **golang-migrate** with numbered, reversible SQL files | Suggestion 1/3 recommendation: reproducible, non-auto-diff migrations; version recorded in `schema_migrations`. |
| Query layer | **`sqlc`** (generates type-safe Go from SQL) + `pgx` driver | Type-safe queries without ORM magic; `pgx` exposes JSONB, `ltree`, `INET`, and `COPY` needed for audit ingest. |
| Task queue / async | **PostgreSQL-backed queue via `riverqueue/river`** | Rotation jobs, lease expiry sweeps, sprawl scans, and SIEM export are async. River uses the same Postgres instance (no extra infra — supports the low-ops goal) with transactional job enqueue. |
| Cache / coordination | **embedded `hashicorp/raft` (single-binary) OR Redis (HA mode)** | Seal/unseal state, leader election for the lease-expiry worker, and short-lived nonce storage. Single-node uses BoltDB-backed Raft; HA uses Redis. |
| Crypto | **`crypto/aes` (AES-256-GCM), `golang.org/x/crypto/chacha20poly1305`, `filippo.io/age`, Argon2id (`golang.org/x/crypto/argon2`)** — no custom schemes | `README.md` and `research.md` mandate audited primitives only. AES-256-GCM = FIPS 197; Argon2id for password hashing per OWASP. |
| External KMS / HSM | **KMIP 2.1 client + PKCS#11 (`miekg/pkcs11`)**; cloud KMS via AWS/Azure/GCP SDKs | `standards.md`: KMIP/PKCS#11 non-negotiable for FSI/gov. KEK lives in external KMS/HSM; the vault never holds the root key in plaintext at rest. |
| AuthN (humans) | **OIDC + SAML 2.0 + WebAuthn/FIDO2** (`coreos/go-oidc`, `crewjam/saml`, `go-webauthn/webauthn`) | SSO mandated by MVP; WebAuthn = phishing-resistant MFA per NIST SP 800-63B AAL3. |
| AuthN (machines) | **OAuth 2.0 client-credentials, JWT (RFC 9068), mTLS (RFC 8705), DPoP (RFC 9449)**, plus AppRole-style and Kubernetes/cloud-IAM auth | `standards.md` token suite; sender-constrained tokens for high-value secrets APIs. |
| Provisioning | **SCIM 2.0** (RFC 7643/7644) server endpoints | MVP requirement for user lifecycle. |
| Policy engine | **Cedar** (`cedar-policy/cedar-go`) as primary, with a translation layer from natural language | Cedar (per `standards.md`) is analyzable/decidable — enables the AI "explain & verify generated policy" feature and is safer than Rego for least-privilege validation. |
| AI / LLM | **Anthropic Claude via provider-agnostic interface** (pluggable) | NL→policy authoring, secret classification, sprawl-leak triage, JIT justification capture. Provider abstraction so self-hosted deployments can swap to a local model. |
| Frontend | **React 18 + TypeScript + Vite + TanStack Query + shadcn/ui** | Admin console, approval inbox, session replay viewer, compliance dashboards. SPA talks to the same OpenAPI-defined REST API. |
| Browser extension | **WebExtension (Manifest V3) in TypeScript** | MVP password-vault access; shares the generated TS SDK with the SPA. |
| CLI | **Go (`spf13/cobra`)**, single static binary | Human + CI/CD use; `.env` replacement via a `run` subcommand. |
| SDKs | Generated for **Go, Python, Node, Java** from the OpenAPI spec (`openapi-generator`) | MVP requirement; spec-first keeps them current. |
| Session proxy | **Go `golang.org/x/crypto/ssh`** (SSH), `gorilla/websocket` (web/RDP gateway), DB wire-protocol proxies | v1.1 session recording; clean-room implementation (avoids patent-encumbered designs per `features.md` legal note). |
| Object storage | **S3-compatible (`minio-go`)** | Session recordings and detached audit-log partitions. |
| Containerisation | **Docker + distroless base; Helm chart; Kubernetes operator + CSI driver** | Self-hosted/cloud/hybrid per `README.md`; K8s integration is v1.1. |
| Observability | **OpenTelemetry traces/metrics; structured `slog` logs; Prometheus endpoint** | NIST SP 800-204C microservices guidance. |
| Eventing | **CloudEvents 1.0 envelope; AsyncAPI 3.0 spec; webhooks** | `standards.md` event formats for secret-changed / audit streams. |
| Testing | **Go `testing` + `testify` + `testcontainers-go`**; **Playwright** for SPA/extension E2E | `testcontainers` spins real Postgres for integration tests; Playwright for browser flows. |
| Quality tools | **`golangci-lint`, `gofumpt`, `go vet`, `govulncheck`; `eslint` + `prettier` + `tsc` (frontend)** | Standard Go + TS toolchains; `govulncheck` supports the SSDF supply-chain posture. |
| Supply chain | **SLSA v1.0 provenance, signed releases (cosign), SBOM (syft)** | `standards.md` SLSA/SSDF; trust is a procurement gate for this category. |

### Project Structure

```
secrets-platform/
├── go.mod
├── Dockerfile
├── docker-compose.yml                 # postgres + minio + app for local dev
├── Makefile                           # build, test, lint, migrate, gen
├── api/
│   ├── openapi.yaml                   # OpenAPI 3.1 — source of truth for REST
│   ├── asyncapi.yaml                  # event stream spec
│   └── proto/                         # gRPC: engine plugin + replication
│       ├── engine.proto
│       └── replication.proto
├── cmd/
│   ├── vaultd/                        # server daemon main
│   ├── vault/                         # CLI (cobra)
│   ├── operator/                      # k8s operator (v1.1)
│   └── csi/                           # CSI driver (v1.1)
├── internal/
│   ├── barrier/                       # envelope encryption barrier (Suggestion 4)
│   ├── keystore/                      # KEK/DEK lifecycle, KMS/HSM/KMIP/PKCS#11
│   ├── seal/                          # seal/unseal, Shamir + KMS auto-unseal
│   ├── storage/                       # pgx + sqlc generated queries
│   │   ├── migrations/                # golang-migrate numbered SQL
│   │   └── queries/                   # *.sql for sqlc
│   ├── tenancy/                       # orgs, namespaces (ltree), row-level isolation
│   ├── identity/                      # users, groups, service accounts, SCIM
│   ├── auth/                          # OIDC, SAML, WebAuthn, OAuth, mTLS, DPoP, AppRole
│   ├── authz/                         # Cedar policy engine + RBAC resolution
│   ├── secrets/                       # KV engine + engine registry/mount table
│   ├── engines/                       # pluggable engines (gRPC clients + builtins)
│   │   ├── kv/
│   │   ├── database/                  # dynamic DB creds (pg, mysql)
│   │   ├── cloudiam/                  # AWS/Azure/GCP dynamic IAM
│   │   ├── pki/                       # X.509 CA + ACME
│   │   ├── ssh/                       # SSH CA / dynamic SSH
│   │   └── transit/                   # encryption-as-a-service (backlog)
│   ├── lease/                         # lease lifecycle, expiry sweeper, revocation
│   ├── rotation/                      # static-secret rotation jobs
│   ├── sync/                          # multi-cloud secret sync (v1.1)
│   ├── jit/                           # access requests + approval workflows
│   ├── session/                       # privileged session proxy + recording (v1.1)
│   ├── audit/                         # hash-chained journal, sinks, SIEM export
│   ├── compliance/                    # report templates (SOC2/PCI-DSS), evidence mapping
│   ├── ai/                            # NL→Cedar, classification, leak triage, JIT intent
│   ├── sprawl/                        # secrets sprawl scanner (v1.1)
│   ├── events/                        # CloudEvents emitter, webhook dispatcher
│   ├── api/                           # chi router, oapi-codegen handlers, middleware
│   ├── jobs/                          # river queue workers
│   ├── mcp/                           # MCP server exposing scoped vault tools (v1.1)
│   └── config/                        # config loading + validation
├── sdks/                              # generated Go/Python/Node/Java clients
├── web/                               # React admin console (Vite)
├── extension/                         # Manifest V3 browser extension
├── deploy/
│   ├── helm/
│   └── k8s/
├── test/
│   ├── integration/                   # testcontainers-based
│   ├── e2e/                           # Playwright
│   └── fixtures/                      # sample policies, SARIF-like exports, configs
└── docs/
```

---

## Phase 1: Foundation — Project Skeleton, Config, Storage, Migrations

### Purpose
Establish the buildable skeleton: module layout, configuration loading, PostgreSQL connectivity, the migration framework, and CI. After this phase the server boots, connects to Postgres, applies migrations, and exposes a health endpoint. Everything downstream depends on this.

### Tasks

#### 1.1 — Repository scaffold, build tooling, CI
**What**: Create the Go module, `Makefile`, Dockerfile, docker-compose for local dev, and a CI pipeline.

**Design**:
- `go.mod` module path `github.com/<org>/secrets-platform`, Go 1.23.
- `Makefile` targets: `build`, `test`, `test-integration`, `lint`, `gen` (oapi-codegen + sqlc + protoc), `migrate-up`, `migrate-down`, `run`.
- `docker-compose.yml` services: `postgres:16` (with `ltree` available), `minio`, `vaultd`.
- Distroless multi-stage Dockerfile producing a static binary.
- CI (GitHub Actions): `lint` (golangci-lint), `govulncheck`, `test`, `test-integration` (testcontainers), `build`, SBOM (`syft`), provenance (SLSA generator).

**Testing**:
- `Unit: make build → binary produced, exit 0`.
- `CI smoke: docker-compose up → vaultd container reaches healthy state`.

#### 1.2 — Configuration loader
**What**: Typed configuration from file + environment with validation and sane defaults.

**Design**:
```go
type Config struct {
    Listen       ListenConfig   `yaml:"listen"`
    Database     DBConfig       `yaml:"database"`
    Seal         SealConfig     `yaml:"seal"`        // shamir | awskms | azurekv | gcpkms | pkcs11
    Storage      StorageConfig  `yaml:"storage"`     // S3-compatible for recordings/archive
    Telemetry    TelemetryConfig`yaml:"telemetry"`
    AI           AIConfig       `yaml:"ai"`          // provider, endpoint, model, enabled
    LogLevel     string         `yaml:"log_level"`   // default "info"
}
type DBConfig struct {
    URL          string `yaml:"url" env:"VAULT_DB_URL"`        // required
    MaxConns     int32  `yaml:"max_conns" env-default:"20"`
    StatementTimeout time.Duration `yaml:"statement_timeout" env-default:"30s"`
}
```
- Precedence: explicit env var > config file > default. Use `kelseyhightower/envconfig` + YAML.
- `Validate()` returns aggregated errors naming each invalid field.

**Testing**:
- `Unit: valid YAML → Config with defaults filled (MaxConns=20, LogLevel="info")`.
- `Unit: missing DB URL → ValidationError mentions "database.url"`.
- `Unit: env var overrides file value → env wins`.
- `Unit: invalid seal type "foo" → error lists allowed values`.

#### 1.3 — PostgreSQL connection + migration runner
**What**: `pgxpool` connection wrapper and golang-migrate integration.

**Design**:
- `storage.NewPool(ctx, DBConfig) (*pgxpool.Pool, error)` with health ping and statement timeout.
- Embed migrations via `//go:embed migrations/*.sql`; expose `Migrate(ctx, pool) (appliedVersion uint, err error)`.
- First migration `0001_init.sql` creates `schema_migrations` (managed by the tool) plus the `ltree` and `pgcrypto` extensions.
- Health endpoint `GET /v1/sys/health` returns `{ "initialized": bool, "sealed": bool, "version": "x.y.z", "db_ok": bool }`.

**Testing**:
- `Integration (testcontainers): fresh Postgres → Migrate applies all up migrations, version matches highest file`.
- `Integration: Migrate is idempotent on second call (no error, no change)`.
- `Integration: down migration reverts cleanly`.
- `Unit (mocked): /v1/sys/health with db down → db_ok=false, 503`.

#### 1.4 — HTTP server bootstrap + middleware
**What**: `chi` server with structured logging, request IDs, panic recovery, RFC 9457 error responses, and OTel.

**Design**:
- Middleware chain: requestID → otel → recoverer → slog access log → contentType.
- Standard error type emitted per **RFC 9457 Problem Details**:
```go
type Problem struct {
    Type   string `json:"type"`     // URI
    Title  string `json:"title"`
    Status int    `json:"status"`
    Detail string `json:"detail,omitempty"`
    Instance string `json:"instance,omitempty"`
    Errors []FieldError `json:"errors,omitempty"`
}
```
- TLS 1.3 minimum (RFC 8446) enforced on the listener.

**Testing**:
- `Unit: handler panics → 500 Problem with type/title, request_id in log`.
- `Unit: unknown route → 404 Problem`.
- `Unit: TLS config rejects TLS 1.2 handshake`.

---

## Phase 2: Cryptographic Barrier, Seal/Unseal, Key Management

### Purpose
Implement the security heart of the platform: the encryption barrier through which all secret data passes, the seal/unseal lifecycle, and envelope key management backed by external KMS/HSM. No plaintext secret ever reaches the storage backend. This must be correct before any secret is stored.

### Tasks

#### 2.1 — Envelope encryption barrier
**What**: An encrypt/decrypt barrier using per-entry DEKs wrapped by a KEK.

**Design** (pattern from Suggestion 4, primitives per FIPS 197 / NIST SP 800-57):
```go
type Barrier interface {
    Encrypt(ctx context.Context, plaintext []byte, aad []byte) (Ciphertext, error)
    Decrypt(ctx context.Context, ct Ciphertext, aad []byte) ([]byte, error)
}
type Ciphertext struct {
    KeyID      string `json:"k"`   // DEK id (which DEK; DEK is KEK-wrapped at rest)
    Nonce      []byte `json:"n"`   // 96-bit GCM nonce, unique per encryption
    Ciphertext []byte `json:"c"`   // AES-256-GCM output incl. auth tag
    Alg        string `json:"a"`   // "aes-256-gcm" | "chacha20-poly1305"
}
```
- DEK generated via `crypto/rand`; KEK obtained from the keystore (2.3). AAD binds ciphertext to `org_id + secret path` to prevent confused-deputy/relocation attacks.
- DEKs cached in memory only while unsealed; zeroized on seal.

**Testing**:
- `Unit: Encrypt then Decrypt round-trips arbitrary bytes`.
- `Unit: tampered ciphertext byte → Decrypt returns auth error (GCM tag mismatch)`.
- `Unit: wrong AAD → Decrypt fails`.
- `Unit: two encryptions of same plaintext → different nonces, different ciphertext`.
- `Unit: nonce never repeats across 1e6 encryptions (statistical/uniqueness check)`.

#### 2.2 — Seal / unseal lifecycle
**What**: Seal state machine with Shamir key shares and KMS auto-unseal.

**Design**:
- States: `uninitialized → sealed → unsealed → sealed` (re-seal). Persisted seal config in storage; root key never written in plaintext.
- `Init(shares, threshold)` → generates root key, splits via Shamir (`hashicorp/vault/shamir` equivalent or `codahale/sss`), returns N unseal shares once.
- `Unseal(share)` accumulates shares until threshold reached → decrypts the stored encrypted root key → loads KEK into barrier.
- Auto-unseal mode: root key wrapped by external KMS; `Unseal()` calls KMS `Decrypt`.
- Endpoints: `PUT /v1/sys/init`, `PUT /v1/sys/unseal`, `PUT /v1/sys/seal`, `GET /v1/sys/seal-status`.

**Testing**:
- `Unit: Init with shares=5 threshold=3 → 5 shares returned, status sealed`.
- `Unit: providing 3 valid shares → unsealed; providing 2 → still sealed, progress=2`.
- `Unit: wrong share → progress does not advance, error`.
- `Integration (mocked KMS): auto-unseal calls KMS.Decrypt once and unseals`.
- `Unit: operations on sealed vault → 503 "vault is sealed"`.

#### 2.3 — Keystore: KEK lifecycle, KMS/HSM/KMIP/PKCS#11
**What**: Pluggable KEK provider abstraction and DEK registry.

**Design**:
```go
type KeyProvider interface {
    WrapKey(ctx context.Context, dek []byte) (wrapped []byte, keyRef string, err error)
    UnwrapKey(ctx context.Context, wrapped []byte, keyRef string) ([]byte, error)
    RotateKEK(ctx context.Context) (newRef string, err error)
}
// implementations: shamirProvider, awsKMSProvider, azureKVProvider, gcpKMSProvider,
//                  kmipProvider (KMIP 2.1), pkcs11Provider (PKCS#11 v3.1)
```
- `encryption_keys` table (from Suggestion 1) stores wrapped DEK material, `kms_key_arn`/`keyRef`, algorithm, version, status.
- KEK rotation re-wraps DEKs only (does not re-encrypt secret payloads) per Suggestion 1 §3.

**Testing**:
- `Unit (shamir provider): WrapKey/UnwrapKey round-trips`.
- `Integration (mocked AWS KMS): WrapKey calls Encrypt, UnwrapKey calls Decrypt`.
- `Integration (softhsm2 via testcontainers): pkcs11Provider wraps/unwraps against a real soft-HSM`.
- `Unit: KEK rotation produces new keyRef; existing DEKs still unwrap`.

---

## Phase 3: Tenancy, Identity, RBAC, and the Cedar Authorization Engine

### Purpose
Build multi-tenant organization/namespace structure, the identity model (users, groups, service accounts), and the authorization core (RBAC + Cedar policy evaluation). This is the gatekeeper every API call passes through. After this phase, principals exist and access decisions can be made — even though no secrets are stored yet.

### Tasks

#### 3.1 — Organizations and namespaces
**What**: Org and namespace tables with `ltree` hierarchy and row-level isolation.

**Design**: Use the `organizations` and `namespaces` DDL from Suggestion 1 (with the JSONB `settings` extension from Suggestion 3 added to `organizations`). Enforce tenant isolation via PostgreSQL **row-level security** keyed on `org_id` set from the request context (`SET LOCAL app.current_org = $1`).
- Endpoints: `POST/GET/PATCH/DELETE /v1/orgs`, `.../namespaces`.

**Testing**:
- `Integration: create namespace 'acme.prod.db' → ltree path stored, queryable by ancestor 'acme.prod'`.
- `Integration: RLS prevents org A reading org B namespaces`.
- `Unit: duplicate namespace path in same org → 409`.

#### 3.2 — Identity: users, groups, service accounts
**What**: Principal entities with Argon2id password hashing for local users.

**Design**: `users`, `groups`, `group_members`, `service_accounts` DDL from Suggestion 1. Password hashing: Argon2id (m=64MB, t=3, p=2 defaults, tunable). Service accounts hold an Ed25519 public key for mTLS/JWT auth.
```go
type Principal struct {
    ID   uuid.UUID
    Kind PrincipalKind // user | group | service_account
    OrgID uuid.UUID
}
```

**Testing**:
- `Unit: password hashed with Argon2id, verify succeeds; wrong password fails`.
- `Integration: add user to group → group_members row; cascade delete on user removal`.
- `Unit: create service account → Ed25519 keypair, private key returned once`.

#### 3.3 — RBAC: roles, policies, assignments
**What**: Role/policy/assignment tables and the principal→effective-permissions resolver.

**Design**: `roles`, `policies`, `role_policies`, `role_assignments` DDL from Suggestion 1. `policies.policy_document` stores **Cedar** policy text. Resolver walks group memberships + direct assignments to gather all policies in scope for `(principal, namespace)`.

**Testing**:
- `Unit: user in group with role R → resolver returns R's policies`.
- `Integration: recursive query "which principals can reach namespace X" returns expected set`.

#### 3.4 — Cedar authorization engine
**What**: Evaluate Cedar policies for every protected operation.

**Design**:
```go
type AccessRequest struct {
    Principal Principal
    Action    string      // "secret:read", "session:start", "policy:write"
    Resource  ResourceRef // type + id + namespace path + JSONB attributes
    Context   map[string]any // time, source_ip, mfa_level (AAL), risk_score
}
func (e *Engine) IsAuthorized(ctx, AccessRequest) (Decision, []PolicyID, error)
// Decision: Allow | Deny ; returns determining policies for audit + AI explanation
```
- Maps to **OWASP ASVS V4 (access control)** and **NIST SP 800-53 AC-6 (least privilege)**.
- Middleware `RequireAuthz(action)` wraps protected routes; emits an audit entry with the determining policy IDs.

**Testing**:
- `Unit: allow policy for action+resource → Allow with policy id`.
- `Unit: no matching permit → Deny (default-deny)`.
- `Unit: forbid overrides permit → Deny`.
- `Unit: context condition (mfa_level >= AAL2 required) not met → Deny`.
- `Integration: protected route without permission → 403 Problem, audit entry result="denied"`.

---

## Phase 4: KV Secrets Engine, Versioning, and the Audit Journal

### Purpose
Deliver the MVP core: store, version, read, and roll back static secrets through the barrier, with every operation written to a tamper-evident, hash-chained audit journal. After this phase the platform is a working encrypted vault with an immutable audit trail.

### Tasks

#### 4.1 — Secrets engine mount registry
**What**: Mount table mapping paths to engine instances.

**Design**: `secrets_engines` DDL from Suggestion 1 with `config` stored as barrier-encrypted JSONB (Suggestion 3 flexibility for per-engine config shapes). Engine factory resolves `engine_type` → builtin handler or gRPC plugin client.
- Endpoints: `POST /v1/sys/mounts`, `GET /v1/sys/mounts`, `DELETE /v1/sys/mounts/{path}`.

**Testing**:
- `Integration: mount kv engine at 'secret/' → row created, config encrypted`.
- `Unit: duplicate mount path → 409`.

#### 4.2 — KV engine: write/read/versioning/rollback
**What**: Versioned key-value secrets through the barrier.

**Design**: `secrets`, `secret_versions` DDL from Suggestion 1. Write creates a new `secret_versions` row (barrier-encrypted `encrypted_value`, HMAC-SHA256 `checksum`, `encryption_key_id`), increments `current_version`, prunes beyond `max_versions` (soft-destroy). Secret payload is arbitrary JSON (JSONB after decrypt) to support any secret shape.
- Endpoints:
  - `POST /v1/secret/data/{path}` body `{ "data": {...}, "options": {"cas": n} }` (check-and-set)
  - `GET /v1/secret/data/{path}?version=n`
  - `GET /v1/secret/metadata/{path}` → version list
  - `POST /v1/secret/undelete/{path}` / `DELETE` (soft) / `POST /destroy`
- CAS prevents lost updates (optimistic concurrency on `current_version`).

**Testing**:
- `Integration: write v1 then v2 → read latest = v2, read ?version=1 = v1`.
- `Integration: CAS with stale version → 409, no new version`.
- `Integration: exceed max_versions → oldest version destroyed`.
- `Integration: soft-delete then undelete → readable again`.
- `Integration: stored ciphertext in DB is not equal to plaintext (no plaintext leak)`.

#### 4.3 — Hash-chained tamper-evident audit journal
**What**: Append-only audit log with a per-org hash chain and pluggable sinks.

**Design**: `audit_logs` partitioned DDL from Suggestion 1. Each entry: `entry_hash = SHA256(prev_hash || canonical_json(entry_without_hash))`. Sinks: Postgres (default), file, syslog (RFC 5424), socket. Request and response are HMAC-redacted for secret values. Verification routine walks the chain to detect tampering.
- Maps to **SOC 2 CC7**, **PCI-DSS Req 10**, **NIST AU family**.

**Testing**:
- `Unit: entry_hash chains from prev_hash; altering any entry breaks verification`.
- `Integration: every secret read/write produces an audit entry with actor, action, resource_path, result`.
- `Unit: secret values never appear in audit detail (redaction)`.
- `Integration: syslog sink emits RFC 5424-formatted line`.
- `Integration (mocked clock): monthly partition auto-created for new month`.

#### 4.4 — CloudEvents emission + webhook dispatch
**What**: Emit `secret.created`, `secret.updated`, etc., as CloudEvents to webhooks.

**Design**: CloudEvents 1.0 envelope; AsyncAPI 3.0 spec in `api/asyncapi.yaml`. Webhook delivery via River jobs with retry + HMAC signature header. Subscriptions stored with JSONB filter (Suggestion 3).

**Testing**:
- `Integration: secret write → CloudEvent enqueued, delivered to mock endpoint with valid HMAC`.
- `Unit: delivery failure → retried with backoff, then dead-lettered`.

---

## Phase 5: Authentication Methods, Tokens, and the SCIM Server

### Purpose
Let real principals authenticate. Implement human SSO (OIDC/SAML/WebAuthn) and machine auth (OAuth client-credentials, JWT, mTLS, DPoP, AppRole, Kubernetes/cloud-IAM), token issuance/introspection/revocation, and SCIM user provisioning. After this phase the API is usable by humans and workloads under real credentials.

### Tasks

#### 5.1 — Token service
**What**: Issue, introspect, and revoke access tokens.

**Design**: JWT access tokens per **RFC 9068** (signed Ed25519/ES256), with `scope`, `org`, `namespace`, `aal`, optional DPoP `cnf` thumbprint. Endpoints: `POST /v1/auth/token` (introspection-backed reference tokens for revocability), `POST /v1/auth/introspect` (RFC 7662), `POST /v1/auth/revoke` (RFC 7009). Token-to-lease binding so revoking a token revokes derived dynamic secrets.

**Testing**:
- `Unit: issued JWT validates against published JWKS; tampered token rejected`.
- `Unit: revoked token → introspection active=false`.
- `Unit: DPoP-bound token without matching proof → 401`.

#### 5.2 — Human auth: OIDC, SAML, WebAuthn/FIDO2
**What**: SSO login flows and phishing-resistant MFA.

**Design**: OIDC code flow + PKCE (RFC 7636); SAML 2.0 SP; WebAuthn registration/assertion mapping authenticator strength to **NIST SP 800-63B AAL** levels recorded in the token `aal` claim and available to Cedar context.

**Testing**:
- `Integration (mock IdP): OIDC callback with valid code → session + token issued`.
- `Integration: SAML assertion with invalid signature → 401`.
- `Unit: WebAuthn assertion verifies; replayed challenge → rejected`.

#### 5.3 — Machine auth methods
**What**: AppRole, mTLS (RFC 8705), Kubernetes service-account JWT, and AWS/Azure/GCP IAM auth.

**Design**: Pluggable `AuthMethod` interface returning a `Principal` + granted policies. Kubernetes auth validates the projected SA token against the cluster's TokenReview API; cloud-IAM auth validates signed identity documents.

**Testing**:
- `Unit: AppRole role_id+secret_id → token with role's policies`.
- `Integration (mocked TokenReview): valid K8s SA token → authenticated`.
- `Unit: mTLS client cert not in trust list → 401`.

#### 5.4 — SCIM 2.0 server
**What**: User/group provisioning endpoints.

**Design**: SCIM 2.0 (RFC 7643/7644) `/scim/v2/Users`, `/Groups` with filtering, PATCH, and `externalId` mapping to the `groups.external_id`/user records.

**Testing**:
- `Integration: SCIM POST /Users → user created, externalId stored`.
- `Integration: SCIM PATCH deactivate → user status=disabled, tokens revoked`.
- `Unit: SCIM filter "userName eq x" → correct subset`.

---

## Phase 6: Auto-Rotation, REST API Spec, SDKs, and CLI (MVP completion)

### Purpose
Complete the MVP surface: scheduled rotation for common targets, the finalized OpenAPI spec with generated SDKs, and the CLI for humans and CI/CD. After this phase the MVP from `features.md` is functionally complete (vault + RBAC/SSO/SCIM + API/SDKs + CLI + audit + rotation).

### Tasks

#### 6.1 — Static-secret auto-rotation
**What**: Scheduled rotation for PostgreSQL, MySQL, AWS IAM, SSH keys, and Active Directory.

**Design**: `rotation_configs` DDL from Suggestion 1; per-target `Rotator` interface; River cron jobs select due rotations (`next_rotation <= now()`), perform target-specific credential change, write new secret version, update `last_rotated_at`/`next_rotation`. Rotation steps stored as JSONB config (Suggestion 3) for target variability.
```go
type Rotator interface {
    Rotate(ctx context.Context, current SecretData, cfg json.RawMessage) (SecretData, error)
}
```

**Testing**:
- `Integration (testcontainers postgres target): rotate DB password → new password works, old eventually revoked`.
- `Integration (mocked AWS): IAM access key rotated, previous key scheduled for deletion`.
- `Unit: rotation failure → config marked errored, alert event emitted, secret unchanged`.

#### 6.2 — OpenAPI 3.1 spec finalization + handler generation
**What**: Author the complete `api/openapi.yaml` and wire `oapi-codegen` handlers.

**Design**: OpenAPI 3.1 (JSON Schema 2020-12) covering all Phase 1–6 endpoints; security schemes for bearer JWT, mTLS, DPoP; RFC 9457 error schema. `make gen` regenerates server stubs and the published spec is served at `GET /v1/sys/openapi.json`.

**Testing**:
- `Unit: spec validates against OpenAPI 3.1 meta-schema`.
- `Integration: every registered chi route appears in the spec (drift test)`.

#### 6.3 — SDK generation (Go, Python, Node, Java)
**What**: Generate and smoke-test client SDKs.

**Design**: `openapi-generator` configs per language in `sdks/`; thin hand-written auth helpers (DPoP signing, token refresh) layered on generated cores.

**Testing**:
- `Integration: each SDK reads then writes a secret against a live test server`.
- `CI: SDK generation is reproducible (no diff on regenerate)`.

#### 6.4 — CLI
**What**: `vault` cobra CLI for login, secret CRUD, and `.env` replacement.

**Design**: Commands: `vault login`, `vault kv get/put/list`, `vault token`, `vault run -- <cmd>` (injects secrets as env vars into a subprocess, never writing a file), `vault export`. Reads config from `~/.vault/config` + env. Uses the Go SDK.

**Testing**:
- `E2E: vault kv put then get → value round-trips, exit 0`.
- `E2E: vault run -- printenv SECRET → secret present in child env, absent from parent`.
- `E2E: vault login with bad creds → exit 1, error to stderr`.

---

## Phase 7: Compliance Reporting, Admin Console, and Browser Extension

### Purpose
Ship the human-facing surfaces and the compliance evidence that drive enterprise procurement: SOC 2 / PCI-DSS report templates derived from the audit journal, the React admin console, and the password-vault browser extension. Completes the MVP user experience.

### Tasks

#### 7.1 — Compliance report templates (SOC 2, PCI-DSS)
**What**: Generate evidence reports mapping audit data to control objectives.

**Design**: Template definitions map control IDs (SOC 2 CC6/CC7, PCI-DSS Req 7/8/10) to audit queries. Output formats: PDF and CSV. Live evidence linking (which audit entries satisfy which control).
- Endpoint: `POST /v1/compliance/reports` `{ "framework": "soc2|pci-dss", "period": {...} }` → report job.

**Testing**:
- `Integration: generate SOC 2 report over fixture audit data → CC6.1 section cites expected access events`.
- `Unit: empty period → report with "no evidence" markers, not an error`.

#### 7.2 — React admin console
**What**: SPA for org/namespace/identity/policy management, secret browsing (with reveal gating), and audit search.

**Design**: React + Vite + TanStack Query + shadcn/ui; uses generated TS SDK. Secret reveal requires step-up auth (WebAuthn) and is itself audited. Audit log viewer with filters and chain-verification badge.

**Testing**:
- `E2E (Playwright): admin creates namespace + policy, assigns role → reflected via API`.
- `E2E: reveal secret triggers WebAuthn step-up; cancel → value stays masked`.
- `vercel:react-best-practices checklist passes for new components`.

#### 7.3 — Browser extension (Manifest V3)
**What**: Password-vault access and autofill.

**Design**: MV3 extension in TS sharing the SDK; background service worker holds a short-lived session token; content script offers autofill on matched domains. Vault stays server-side; extension never persists plaintext.

**Testing**:
- `E2E (Playwright + extension): login, list items, autofill into a test login form`.
- `Unit: token expiry → extension re-prompts, does not cache plaintext`.

---

## Phase 8: Dynamic Secrets, Leases, PKI/SSH/Cloud-IAM Engines (v1.1)

### Purpose
Add the headline Vault-class differentiator: per-consumer, time-bound dynamic credentials with lease-based expiry and revocation across databases, cloud IAM, PKI, and SSH. After this phase the platform matches Vault's core dynamic-secrets value.

### Tasks

#### 8.1 — Lease manager
**What**: Lease lifecycle with TTL, renewal, revocation, and expiry sweeper.

**Design**: `leases` DDL from Suggestion 1 (indexed on `expires_at` where active). River cron sweeper revokes expired leases by invoking the issuing engine's `Revoke`. Token revocation cascades to child leases.
```go
type LeaseManager interface {
    Issue(ctx, engineID uuid.UUID, principal Principal, ttl time.Duration, cred CredentialRef) (Lease, error)
    Renew(ctx, leaseID uuid.UUID, increment time.Duration) (Lease, error)
    Revoke(ctx, leaseID uuid.UUID) error
}
```

**Testing**:
- `Integration: issue lease ttl=1s → after sweep, lease revoked and engine Revoke called`.
- `Unit: renew past max_ttl → capped at max_ttl`.
- `Integration: revoke parent token → child leases revoked`.

#### 8.2 — gRPC engine plugin interface + database engine
**What**: Plugin protocol and the dynamic database-credentials engine.

**Design**: `engine.proto` defines `CreateCredential`, `RevokeCredential`, `Rotate`, `Configure`. Builtin database engine creates scoped per-lease DB users (PostgreSQL/MySQL) with a creation-statement template (JSONB config), returns credentials tied to a lease.

**Testing**:
- `Integration (testcontainers pg): read dynamic DB creds → new DB user created, connects, revoked on lease expiry`.
- `Unit: plugin handshake/version mismatch → engine refused`.

#### 8.3 — PKI engine (X.509 + ACME) and SSH engine
**What**: Internal CA issuing short-lived certs; SSH CA issuing signed principals.

**Design**: PKI per **RFC 5280**; ACME issuance per **RFC 8555**. SSH CA signs user/host certs (RFC 4252/4253) with TTL. Both register issued material as leases.

**Testing**:
- `Integration: issue leaf cert from internal CA → chains to CA, expires at TTL`.
- `Integration: ACME order against internal CA → certificate issued`.
- `Integration: SSH cert signed → validates against CA, principals correct`.

#### 8.4 — Cloud-IAM dynamic credentials
**What**: Dynamic AWS/Azure/GCP credentials.

**Design**: AWS engine assumes a role / creates temporary STS credentials per lease; Azure/GCP analogues. Scoped to least privilege via configured policy bindings.

**Testing**:
- `Integration (mocked STS): read aws creds → AssumeRole called, lease tracks expiry`.

---

## Phase 9: JIT Access, Approval Workflows, and AI Policy Authoring (v1.1)

### Purpose
Deliver zero-standing-privilege human access and the flagship AI-native differentiators: conversational JIT requests, risk-aware approval routing, and natural-language→Cedar policy authoring with verification.

### Tasks

#### 9.1 — Access requests + multi-tier approval workflow
**What**: Time-bounded access requests with configurable approval chains.

**Design**: `access_requests`, `approval_steps` DDL from Suggestion 1 (fix the composite-PK note: keep the UUID PK, add `UNIQUE(request_id, step_order)`). State machine `pending → approved/denied → expired`. On full approval, a scoped, TTL-bound grant (lease/token) is issued. Slack/Teams/webhook approval notifications.

**Testing**:
- `Integration: 2-step approval, both approve → grant issued with requested TTL`.
- `Integration: any denial → request denied, no grant`.
- `Unit: request expires before approval → status expired, no grant`.

#### 9.2 — AI risk scoring + conversational JIT intent capture
**What**: Risk score on each request and intent-based justification capture.

**Design**: `ai` package builds a risk score from context (off-hours, unfamiliar asset, first-time access, sensitivity) surfaced inline on the approval; LLM extracts structured intent from a free-text justification. Score persisted in `access_requests.risk_score`; routes high-risk requests to stricter approval tiers.

**Testing**:
- `Unit (mocked LLM): off-hours + sensitive target → elevated risk score, routed to manager+security tier`.
- `Unit: LLM unavailable → fallback heuristic score, request not blocked`.

#### 9.3 — Natural-language → Cedar policy authoring
**What**: Generate, explain, and verify Cedar policies from plain English.

**Design**: Prompt template:
```
System: You translate access-control intent into Cedar policy. Output ONLY valid Cedar.
Available entity types: User, Group, ServiceAccount, Role, Namespace, Secret, Asset.
Available actions: secret:read, secret:write, session:start, ...
User intent: "{NL_REQUEST}"
Constraints: prefer least privilege; add time/context conditions when implied.
```
- Generated policy is **parsed and validated** by the Cedar engine before saving; the system shows a plain-English back-translation and the set of principals/resources it would grant, for human confirmation. Never auto-applied without confirmation.

**Testing**:
- `Unit (mocked LLM): "allow on-call SREs to read prod DB replicas during incidents" → valid Cedar with time/oncall condition, parses`.
- `Unit: LLM emits invalid Cedar → rejected with parse error, not saved`.
- `Integration: confirmed policy → stored, immediately enforced by authz engine`.

---

## Phase 10: Privileged Session Proxy & Recording (v1.1)

### Purpose
Add PAM-class session brokering: connect to SSH/RDP/database targets through the platform without exposing raw credentials, with tamper-evident recording. This closes the human-PAM gap that pure secrets managers lack.

### Tasks

#### 10.1 — Asset & privileged-account inventory
**What**: Managed assets and the privileged accounts on them.

**Design**: `managed_assets`, `privileged_accounts` DDL from Suggestion 1, with platform-specific connection details in JSONB (Suggestion 3). Heartbeat job verifies stored credentials still work.

**Testing**:
- `Integration: register SSH asset + account → heartbeat confirms credential validity`.

#### 10.2 — SSH session proxy with recording
**What**: Brokered SSH sessions with keystroke/IO recording.

**Design**: Clean-room SSH proxy (`golang.org/x/crypto/ssh`) injecting the brokered credential; records the session stream to S3-compatible storage; `sessions` row tracks `recording_path`, hashes the recording for tamper evidence. Web terminal via WebSocket. (Avoid patent-encumbered live-shadow design per `features.md`; live shadow/terminate stays backlog.)

**Testing**:
- `Integration (testcontainers sshd): broker session → command executes, recording stored, hash recorded`.
- `Unit: recording tamper → hash verification fails`.
- `Integration: session end → ended_at set, lease revoked`.

#### 10.3 — Database session proxy
**What**: Brokered DB sessions with command-level audit.

**Design**: PostgreSQL/MySQL wire-protocol proxy that authenticates the user, injects brokered DB creds, and logs statements to the audit journal.

**Testing**:
- `Integration (testcontainers pg): proxied query executes; statement appears in audit log`.

---

## Phase 11: Kubernetes Integration, Multi-Cloud Sync, and MCP Server (v1.1)

### Purpose
Meet developers and workloads where they run: K8s CSI driver/operator/injector, write-once/sync-everywhere multi-cloud distribution, and an MCP server exposing scoped vault operations to AI agents.

### Tasks

#### 11.1 — Kubernetes CSI driver + operator + injector
**What**: Mount secrets into pods and sync to K8s Secrets.

**Design**: CSI driver (Secrets Store CSI pattern) authenticates pods via the K8s auth method (Phase 5.3) and mounts secrets as files; operator reconciles a `VaultSecret` CRD into native K8s Secrets; mutating webhook injects an agent sidecar.

**Testing**:
- `Integration (kind cluster): pod with CSI volume → secret file present, rotated on change`.
- `Integration: VaultSecret CRD → K8s Secret materialized and kept in sync`.

#### 11.2 — Multi-cloud secret sync
**What**: Push secrets to AWS Secrets Manager, Azure Key Vault, GCP Secret Manager.

**Design**: Sync-first model (Doppler-style): a `SyncTarget` (JSONB config per provider, Suggestion 3) defines destination + mapping; on secret change a River job upserts to the destination; bi-directional drift detection optional.

**Testing**:
- `Integration (mocked AWS): secret update → PutSecretValue called on target`.
- `Unit: sync conflict (external change) → flagged, not silently overwritten`.

#### 11.3 — MCP server for AI-agent access
**What**: Expose scoped vault tools to LLM agents.

**Design**: MCP server (per `standards.md` MCP spec) exposing tools `list_secrets`, `read_secret` (policy-gated), `request_jit_access`. Auth via the **MCP OAuth 2.1 profile with PAR + DPoP**; agent identity is a first-class principal kind. Every tool call is authorized by Cedar and audited.

**Testing**:
- `Integration: MCP read_secret with scoped token → returns only authorized secrets`.
- `Unit: agent token lacking scope → tool returns authorization error, audited`.

---

## Phase 12: Secrets Sprawl Scanner, AI Classification & Leak Triage, Anomaly Detection (v1.1 → backlog)

### Purpose
Add proactive security intelligence: discover leaked secrets across Git/SaaS/cloud, classify discovered secrets by severity and blast radius, triage which leaks are exploitable, and flag anomalous access — the AI-augmentation candidates from `features.md`.

### Tasks

#### 12.1 — Secrets sprawl scanner
**What**: Scan Git repos, SaaS configs, and cloud accounts for leaked credentials.

**Design**: Detector registry (regex + entropy + verified-credential checks) over connectors (Git provider APIs, cloud configs). Findings stored with JSONB detail; verification attempts a non-destructive auth to determine if a leaked credential is live.

**Testing**:
- `Integration: scan fixture repo with planted AWS key → finding with type, location, validity`.
- `Unit: dummy/example key → classified low/invalid`.

#### 12.2 — AI secret classification & leak triage
**What**: Classify discovered secrets and rank leaks by exploitability.

**Design**: LLM-assisted classification of secret type, severity, and blast radius (which systems the credential can reach, via the graph reachability ideas from Suggestion 4); triage ranks leaks by whether they are live and high-blast-radius.

**Testing**:
- `Unit (mocked LLM): live prod DB credential → severity=critical, blast radius lists reachable assets`.
- `Unit: classifier fallback when LLM down → rule-based severity`.

#### 12.3 — Behavioural anomaly detection (backlog)
**What**: Flag unusual access patterns (off-hours, unfamiliar asset, atypical sequences).

**Design**: Baseline per-principal access profiles from the audit journal; score deviations and raise risk events that feed JIT risk scoring (9.2) and alerts. Statistical baseline first; ML model optional.

**Testing**:
- `Unit: principal accessing never-before-seen asset at 3am → anomaly event raised`.
- `Unit: normal pattern → no anomaly`.

---

## Phase Summary & Dependencies

```
Phase 1: Foundation (storage, config, server)         ─── required by everything
   │
Phase 2: Crypto Barrier + Seal + Keystore             ─── requires P1
   │
Phase 3: Tenancy + Identity + RBAC + Cedar            ─── requires P1
   │   (P2 and P3 can be built in parallel after P1)
   ├──────────────┐
Phase 4: KV Engine + Audit Journal                    ─── requires P2 + P3
   │
Phase 5: Auth Methods + Tokens + SCIM                 ─── requires P3 (+P4 for audit)
   │
Phase 6: Rotation + OpenAPI/SDKs + CLI  ── MVP DONE    ─── requires P4 + P5
   │
   ├── Phase 7: Compliance + Admin UI + Extension      ─── requires P4 + P5 (parallel w/ P8)
   │
Phase 8: Dynamic Secrets + Leases + Engines (v1.1)     ─── requires P4 + P5
   │
Phase 9: JIT + Approvals + AI Policy Authoring         ─── requires P8 (leases) + P3 (Cedar)
   │
Phase 10: Session Proxy + Recording                    ─── requires P8 (leases) (parallel w/ P11)
   │
Phase 11: K8s + Multi-cloud Sync + MCP                 ─── requires P5 (auth) + P8 (parallel w/ P10)
   │
Phase 12: Sprawl Scanner + AI Classify + Anomaly       ─── requires P4 (audit) + P9 (AI infra)
```

**Parallelism opportunities**
- Phases **2 and 3** can be developed concurrently once Phase 1 lands.
- Phase **7** (human-facing MVP) can be built in parallel with Phase **8** (dynamic secrets) — they share Phases 4/5 but not each other.
- Phases **10 and 11** can proceed concurrently after Phase 8.

---

## Definition of Done (per phase)

Every phase must satisfy all of the following before it is considered complete:

1. All tasks in the phase implemented.
2. All unit and integration tests pass; integration tests run against real dependencies via `testcontainers` (Postgres, soft-HSM, sshd, kind) where specified.
3. `golangci-lint`, `gofumpt`, and `go vet` pass with no findings; frontend `eslint`/`tsc` clean for UI phases.
4. `govulncheck` reports no known vulnerabilities in dependencies.
5. Docker image builds; `docker-compose up` brings the stack to a healthy state.
6. The phase's feature works end-to-end (demonstrated by the named E2E test or a documented manual check).
7. New configuration options documented in `docs/` with defaults.
8. New REST endpoints appear in `api/openapi.yaml` and pass the route-drift test (6.2); new events appear in `api/asyncapi.yaml`.
9. New database changes ship as numbered, reversible golang-migrate migrations; `up` then `down` then `up` is clean.
10. No plaintext secret material is written to logs, audit entries, or the storage backend (verified by the redaction/no-leak tests).
11. Generated artifacts (SDKs, oapi-codegen handlers, sqlc, protobuf) regenerate with no diff (`make gen` is reproducible).
12. SBOM and SLSA provenance generated for any released binary.
