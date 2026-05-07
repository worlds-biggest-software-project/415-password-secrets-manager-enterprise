# Password & Secrets Manager (Enterprise) — Feature & Functionality Survey

> Candidate #415 · Researched: 2026-05-06

## Solutions Analysed

| Tool | Type | Licence / Model | URL |
|------|------|-----------------|-----|
| CyberArk Privileged Access Manager | Enterprise PAM | Commercial (proprietary) | https://www.cyberark.com/products/privileged-access-manager/ |
| Delinea Secret Server | Enterprise PAM | Commercial (proprietary) | https://delinea.com/products/secret-server |
| BeyondTrust Password Safe | Enterprise PAM | Commercial (proprietary) | https://www.beyondtrust.com/products/password-safe |
| HashiCorp Vault (IBM) | Secrets management | BUSL 1.1 (source available) + Enterprise | https://www.vaultproject.io/ |
| Keeper Secrets Manager | Unified password + secrets | Commercial (proprietary, zero-knowledge) | https://www.keepersecurity.com/secrets-manager.html |
| 1Password Business / Secrets Automation | Password + DevOps secrets | Commercial (proprietary) | https://1password.com/secrets-automation |
| Bitwarden Secrets Manager | Password + secrets | Open source (AGPLv3) + Commercial | https://bitwarden.com/products/secrets-manager/ |
| JumpServer | Open-source PAM | GPLv3 + Enterprise | https://www.jumpserver.com/ |
| ManageEngine PAM360 | Mid-market PAM | Commercial (proprietary) | https://www.manageengine.com/privileged-access-management/ |
| Securden Unified PAM | SMB/mid-market PAM | Commercial (proprietary) | https://www.securden.com/ |
| AWS Secrets Manager | Cloud-native secrets | Commercial (managed) | https://aws.amazon.com/secrets-manager/ |
| Doppler | Developer-focused secrets | Commercial + free tier | https://www.doppler.com/ |

---

## Feature Analysis by Solution

### CyberArk Privileged Access Manager

**Core features**
- Centralised credential vault with FIPS 140-2 validated encryption
- Privileged session management with full session recording and keystroke logging
- Just-in-time provisioning and zero standing privileges workflows
- Automatic credential rotation across Windows, Unix, databases, network devices
- Threat analytics with behavioural anomaly detection
- Endpoint Privilege Manager for least-privilege enforcement on workstations

**Differentiating features**
- Largest connector ecosystem (1,000+ integrations)
- AI/ML-driven privileged threat analytics (CyberArk Privileged Threat Analytics)
- Comprehensive compliance pre-mapped reports (SOX, PCI-DSS, HIPAA, NIS2)
- Vendor PAM for third-party access without VPN

**UX patterns**
- Web-based portal plus native clients
- Approval workflows with multi-tier escalation
- Risk scoring surfaced inline with access requests

**Integration points**
- ServiceNow, Jira, Splunk, QRadar, ArcSight
- AD/LDAP, Azure AD, Okta, Ping
- Cloud providers (AWS, Azure, GCP) and Kubernetes
- REST API and SDK

**Known gaps**
- Heavy deployment footprint; long implementation timelines
- Premium pricing limits SMB adoption
- Steep learning curve for administrators

**Licence / IP notes**
- Proprietary commercial. Several patents around session isolation and credential vault architecture.

---

### Delinea Secret Server

**Core features**
- Encrypted secret vault with role-based access controls
- Heartbeat (verifies stored credentials still work) and dependency mapping
- Discovery scanning for unmanaged privileged accounts
- Web launchers for RDP/SSH/web sessions without exposing credentials
- Custom secret templates
- Workflow approval with time-limited access

**Differentiating features**
- Strong Active Directory integration and bulk operations
- DevOps Secrets Vault as a separate, lighter SKU for machine secrets
- Cloud Suite for Linux/Unix server identity bridging

**UX patterns**
- Folder-based hierarchy for secret organisation
- Browser extension for one-click launches
- Mobile app with biometric unlock

**Integration points**
- ServiceNow, SIEMs, Slack/Teams approvals
- Ansible, Chef, Puppet, Jenkins
- SCIM and SAML SSO

**Known gaps**
- Dynamic secrets capability lags HashiCorp Vault
- Cloud-native deployment story still maturing

**Licence / IP notes**
- Proprietary commercial.

---

### BeyondTrust Password Safe

**Core features**
- Privileged credential and session management
- Adaptive access with context-aware policies
- Automatic privileged account discovery
- Secure remote access with no VPN required
- Application-to-application password management

**Differentiating features**
- Tight pairing with BeyondTrust Privileged Remote Access for vendor sessions
- Strong MSP / multi-tenant capabilities
- Endpoint privilege management on the same platform

**UX patterns**
- Unified console across PAM and remote access modules
- Policy-driven access with dynamic risk scoring

**Integration points**
- ITSM (ServiceNow, Cherwell)
- SIEM and SOAR platforms
- AD, Azure AD, Okta

**Known gaps**
- UI complexity due to breadth of modules
- Licensing model can be opaque

**Licence / IP notes**
- Proprietary commercial.

---

### HashiCorp Vault (IBM)

**Core features**
- Static and dynamic secrets engines (database, AWS, GCP, Azure, PKI, SSH, etc.)
- Transit secrets engine for encryption-as-a-service (no key exposure)
- Identity-based access via auth methods (Kubernetes, OIDC, AppRole, AWS IAM, etc.)
- Lease-based secret expiry and revocation
- Replication (DR and performance) for enterprise tier
- Audit logging to file, syslog, or socket sinks

**Differentiating features**
- Pluggable secrets engine architecture
- Dynamic secrets generation (DB credentials per app instance)
- Transit engine for application-level encryption without key custody
- Strong Kubernetes integration via CSI driver and Vault Agent injector

**UX patterns**
- CLI-first with web UI as secondary
- Policy-as-code (HCL) for access definitions
- Namespaces for multi-tenancy

**Integration points**
- Kubernetes, Terraform, Ansible, Consul
- Cloud IAM (AWS, Azure, GCP)
- SIEM via audit log streaming
- HTTP API and SDKs (Go, Java, Python, Ruby, Node)

**Known gaps**
- Operational complexity (raft/seal/unseal, key rotation)
- License change to BUSL in 2023 fractured open-source community (forked as OpenBao)
- UI is functional but not polished compared to commercial PAM

**Licence / IP notes**
- BUSL 1.1 (source-available) since 2023; community fork OpenBao under MPL-2.0.

---

### Keeper Secrets Manager

**Core features**
- Zero-knowledge end-to-end encrypted vault
- Combined password manager and secrets manager
- BreachWatch monitoring for compromised credentials
- Role-based access and team folders
- KeeperPAM for privileged session management
- Compliance reporting for SOC 2, ISO 27001, FedRAMP

**Differentiating features**
- True zero-knowledge architecture (vendor cannot decrypt customer data)
- Unified UX across consumer and enterprise tiers
- FedRAMP authorised, StateRAMP, ITAR

**UX patterns**
- Mature browser extensions and mobile apps
- Single sign-on with SCIM provisioning

**Integration points**
- CI/CD: GitHub Actions, GitLab, Jenkins, Azure DevOps, Terraform
- AWS, Azure, GCP secret rotation
- SDKs in 8+ languages

**Known gaps**
- DevOps secrets manager less mature than Vault for dynamic secrets
- Smaller PAM connector library than CyberArk

**Licence / IP notes**
- Proprietary commercial.

---

### 1Password Business / Secrets Automation

**Core features**
- End-to-end encrypted vaults with Secret Key + master password
- Watchtower for breached credential and weak password monitoring
- Secrets Automation with CLI, SDKs, and Connect server
- SSH key management and Git commit signing
- SCIM provisioning bridge

**Differentiating features**
- Best-in-class consumer-grade UX brought to enterprise
- Developer-first features (1Password CLI, op run, .env file injection)
- Unique "secret references" replacing literal secret values in config

**UX patterns**
- Native apps across all platforms with shell integration
- Quick Access overlay for credential injection
- Item-based model with templates

**Integration points**
- Terraform, Kubernetes operator, GitHub Actions, GitLab CI
- Slack, Okta, Azure AD, JumpCloud
- Webhooks and Events API

**Known gaps**
- Limited PAM session recording and management
- No built-in privileged session proxy

**Licence / IP notes**
- Proprietary commercial.

---

### Bitwarden Secrets Manager

**Core features**
- Open-source password manager (AGPLv3) with secrets manager add-on
- End-to-end encryption with optional self-hosting
- Machine accounts for service-to-service authentication
- Project-based organisation of secrets
- CLI and SDKs (Go, Python, JS, C#, Java, Ruby)

**Differentiating features**
- Genuinely open-source vault with reproducible self-hosted deployment
- Combined password + secrets in single platform
- Lightweight, container-friendly server

**UX patterns**
- Familiar password manager UX extended to developer flows
- Web vault, browser extensions, mobile apps

**Integration points**
- GitHub Actions, GitLab CI, Kubernetes operator (in development)
- SCIM and SSO

**Known gaps**
- Newer entrant to secrets management; smaller integration library
- No native dynamic secrets generation

**Licence / IP notes**
- AGPLv3 for core; Bitwarden License for SDK components.

---

### JumpServer

**Core features**
- Open-source bastion host and PAM
- Asset management for SSH/RDP/database/web hosts
- Session recording and command auditing
- MFA and RBAC
- Web-based terminal and file transfer

**Differentiating features**
- Fully open-source (GPLv3) with paid enterprise edition
- Lightweight footprint suitable for mid-market
- Database session proxy with command-level audit

**UX patterns**
- Web-based access portal; no client install needed
- Session replay viewer

**Integration points**
- LDAP/AD, OIDC, SAML
- Ansible for credential rotation
- Webhook-based event notifications

**Known gaps**
- Less polished UX than commercial alternatives
- Limited dynamic secrets / cloud secrets management

**Licence / IP notes**
- GPLv3.

---

### ManageEngine PAM360

**Core features**
- Privileged credential vault with rotation
- Privileged session management with shadow/terminate
- Application credential security (A2A)
- Privileged user behaviour analytics
- Remote access without VPN

**Differentiating features**
- Strong price-performance for mid-market
- Bundled SSL/TLS certificate lifecycle management
- Tight integration with ManageEngine ecosystem (ServiceDesk, ADManager)

**UX patterns**
- Single console for vault, sessions, and certificates
- Pre-built dashboards for compliance views

**Integration points**
- ServiceNow, Jira, Splunk
- AD, Azure AD, Okta
- REST API

**Known gaps**
- Limited dynamic secrets capability
- Cloud-native deployment trails newer entrants

**Licence / IP notes**
- Proprietary commercial.

---

### Securden Unified PAM

**Core features**
- Password vault with auto-fill browser extensions
- Just-in-time access for Windows/Linux servers
- Session recording and live monitoring
- Endpoint privilege management
- Application credential management

**Differentiating features**
- Aggressive pricing for SMB and mid-market
- Quick deployment (claims hours not weeks)
- Bundled JIT, vault, sessions, and EPM in single product

**UX patterns**
- Simplified admin console
- Wizard-based onboarding

**Integration points**
- AD, Azure AD, SIEM
- ServiceNow, Jira approvals

**Known gaps**
- Smaller customer base; less third-party validation
- Connector library smaller than tier-1 PAM vendors

**Licence / IP notes**
- Proprietary commercial.

---

### AWS Secrets Manager

**Core features**
- Managed secret storage with KMS-backed encryption
- Automatic rotation via Lambda functions for RDS, Redshift, DocumentDB
- Fine-grained IAM policies for access control
- Cross-region replication
- VPC endpoint support

**Differentiating features**
- Native AWS integration (no infra to run)
- Pay-per-secret pricing
- Tight integration with RDS, ECS, Lambda, EKS

**UX patterns**
- AWS Console UI
- CLI and SDK driven for app use

**Integration points**
- AWS-native: RDS, ECS, EKS, Lambda, CodeBuild
- CloudTrail audit logging
- EventBridge events

**Known gaps**
- AWS-only; not suitable for multi-cloud secret management
- Limited PAM functionality (session, recording, JIT for humans)

**Licence / IP notes**
- Managed service; proprietary.

---

### Doppler

**Core features**
- Developer-first secrets manager
- Environment, service, and config branching model
- Secret references and inheritance
- Universal secrets sync to 50+ destinations
- CLI for local development (.env replacement)

**Differentiating features**
- Sync-first architecture: write once, push to AWS/GCP/Vercel/Netlify/etc.
- Dashboard UX optimised for developer workflows
- Audit logging with Slack/webhook notifications

**UX patterns**
- GitHub-like project/environment hierarchy
- Web UI optimised for engineers, not security admins

**Integration points**
- Vercel, Netlify, Render, Fly.io, Heroku, Cloudflare
- AWS Secrets Manager, GCP Secret Manager, Azure Key Vault sync
- Kubernetes operator

**Known gaps**
- No human PAM features (sessions, JIT, recording)
- Compliance posture lighter than enterprise PAM

**Licence / IP notes**
- Proprietary commercial.

---

## Cross-Cutting Feature Themes

### Table-Stakes Features
- Encrypted credential vault with envelope encryption (KMS/HSM-backed)
- Role-based access control and SSO/SCIM integration
- Audit logging with SIEM export (CEF/LEEF/JSON)
- Browser extension and CLI access
- Automatic credential rotation for common targets (DBs, cloud IAM, SSH, AD)
- REST API and SDKs (at minimum: Go, Python, Java, Node)
- MFA enforcement and step-up authentication
- Approval workflows
- Compliance reporting templates (SOC 2, PCI-DSS, HIPAA, NIS2)
- Secret versioning and rollback

### Differentiating Features
- Dynamic secrets (per-consumer, time-bound credentials)
- Privileged session management with recording and live shadow/terminate
- Just-in-time access with no standing privileges
- Encryption-as-a-service (transit) without key exposure
- Zero-knowledge architecture
- Sync-first model (centralise then distribute to consumers)
- Vendor / third-party access without VPN
- Secret references in configs (no plaintext values committed)

### Underserved Areas / Opportunities
- Unified UX across human (PAM) and machine (secrets) credentials — most vendors do one well
- Self-hosted, modern, low-operational-overhead alternative to Vault (OpenBao gap)
- Secrets sprawl detection across SaaS, cloud, and CI/CD without manual inventory
- AI-assisted policy authoring (humans struggle with HCL/Rego/JSON policy languages)
- Risk-aware approval routing using behavioural context
- Compliance evidence automation (live mapping of audit logs to control objectives)
- Cross-cloud dynamic secrets (consistent abstraction across AWS, Azure, GCP)
- Developer-friendly local-dev experience with same primitives as production

### AI-Augmentation Candidates
- Anomaly detection on access patterns (off-hours, unusual asset, unusual command sequences)
- Natural-language policy authoring ("allow on-call SREs to access prod DB read replicas during incidents")
- Auto-classification of discovered secrets (severity, type, blast radius)
- Recommendation engine for least-privilege scoping based on actual usage
- Secret leak triage from code/SaaS scanning (which leaks are exploitable, which are dummies)
- Auto-generated compliance narratives from audit log evidence
- Conversational JIT access requests with intent-based justification capture
- Predictive rotation (rotate ahead of likely compromise based on threat intel)

---

## Legal & IP Summary

The PAM and secrets management category is heavily patented by incumbents. CyberArk, BeyondTrust, and Delinea hold patents covering session isolation techniques, credential injection without disclosure, and privileged threat analytics methodologies. A new entrant should conduct a freedom-to-operate analysis before implementing session-recording-with-live-shadow or specific behavioural analytics methods.

HashiCorp's 2023 licence change from MPL-2.0 to BUSL 1.1 makes Vault unsuitable as a base for a competing commercial product. The Linux Foundation-hosted OpenBao fork (MPL-2.0) is a viable starting point for derivative work. JumpServer (GPLv3) and Bitwarden (AGPLv3) impose strong copyleft obligations that propagate to derivatives, including network-served derivatives in the AGPL case — these licences are not suitable as foundations for a permissively licensed product.

For a new project, an MPL-2.0 or Apache-2.0 base, with original session-management code, is the cleanest path. Do not import code from copyleft vaults. Cryptographic primitives should rely on audited libraries (libsodium, age, BoringSSL) and the project should not invent new cryptographic schemes.

---

## Recommended Feature Scope

**Must-have (MVP)**
- KMS/HSM-backed encrypted secret store with namespace/project hierarchy
- RBAC with SSO (OIDC/SAML) and SCIM provisioning
- REST API and SDKs (Go, Python, Node, Java)
- CLI for human and CI/CD use; browser extension for password vault
- Tamper-evident audit log with SIEM export
- Auto-rotation for common targets (PostgreSQL, MySQL, AWS IAM, SSH keys, AD)
- Compliance report templates for SOC 2 and PCI-DSS

**Should-have (v1.1)**
- Dynamic secrets engines (database, cloud IAM, PKI, SSH)
- Just-in-time access with approval workflow
- Privileged session proxy with recording for SSH/RDP/database
- Kubernetes integration (CSI driver and operator)
- Multi-cloud secret sync (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)
- AI-assisted policy authoring from natural language
- Secrets sprawl scanner (Git, SaaS, cloud)

**Nice-to-have (backlog)**
- Encryption-as-a-service (transit engine)
- Vendor / third-party privileged access portal without VPN
- Behavioural anomaly detection on access patterns
- Live shadow / terminate for active privileged sessions
- FedRAMP / FIPS 140-3 validated builds
- Compliance evidence narrative auto-generation
- Cross-cloud dynamic secrets abstraction
