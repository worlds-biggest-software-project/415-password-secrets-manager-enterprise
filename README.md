# Password & Secrets Manager (Enterprise)

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> A unified, AI-augmented platform for managing both human credentials and machine secrets under a zero-trust architecture, replacing fragmented enterprise PAM and secrets management tooling.

Enterprise password vaults and secrets managers solve two sides of the same problem: securing privileged human access and machine-to-machine credentials. Today, most organisations stitch together separate PAM and secrets management tools, each with its own policy language, audit trail, and operational overhead. This project delivers a single, self-hostable platform that unifies both domains with modern UX, dynamic secrets, just-in-time access, and AI-assisted policy authoring.

---

## Why Password & Secrets Manager (Enterprise)?

- **Vault's licence change fractured its community.** HashiCorp's 2023 switch from MPL-2.0 to BUSL 1.1 left enterprises and open-source contributors without a permissively licensed, production-grade secrets manager. The OpenBao fork exists but lacks the investment and feature velocity of a purpose-built platform.
- **Enterprise PAM vendors price out mid-market buyers.** CyberArk, BeyondTrust, and Delinea target large enterprises with opaque licensing and implementation timelines measured in months. SMBs and mid-market teams are underserved.
- **No single tool covers both humans and machines well.** CyberArk excels at PAM but lags on developer-facing secrets. Vault excels at dynamic secrets but has no session recording or JIT human access. Teams end up running both.
- **Policy authoring remains painful.** HCL, Rego, and JSON policy languages are a barrier to correct least-privilege configuration. Teams over-provision access because writing tight policies is hard.
- **Secrets sprawl is invisible.** Credentials leak into Git repos, CI/CD environment variables, SaaS configs, and Slack messages. Most organisations have no automated way to detect or remediate this sprawl.

---

## Key Features

### Encrypted Credential Vault

- KMS/HSM-backed encrypted secret store with envelope encryption
- Namespace and project hierarchy for multi-team organisation
- Secret versioning with rollback
- Browser extension for human password vault access
- Zero-knowledge architecture option

### Just-in-Time Access & Approval Workflows

- Time-bounded, single-use credentials issued on demand
- Multi-tier approval workflows with configurable escalation
- No standing privileges -- access expires automatically at session end
- Conversational JIT access requests with intent-based justification capture

### Dynamic Secrets & Automatic Rotation

- Per-consumer, time-bound credentials for databases, cloud IAM, PKI, and SSH
- Auto-rotation for PostgreSQL, MySQL, AWS IAM, SSH keys, and Active Directory
- Cross-cloud secret sync to AWS Secrets Manager, Azure Key Vault, and GCP Secret Manager
- Lease-based expiry and revocation

### Privileged Session Management

- Session proxy with recording for SSH, RDP, and database connections
- Tamper-evident audit logs with SIEM export (CEF/LEEF/JSON)
- Compliance report templates pre-mapped to SOC 2, PCI-DSS, HIPAA, and NIS2
- Live session shadowing and termination (backlog)

### DevOps & CI/CD Integration

- CLI for human and pipeline use; replaces .env files in local development
- REST API and SDKs in Go, Python, Node, and Java
- Kubernetes integration via CSI driver and operator
- Native connectors for GitHub Actions, GitLab CI, Jenkins, Terraform, and Ansible
- Secrets sprawl scanner across Git repositories, SaaS platforms, and cloud accounts

---

## AI-Native Advantage

AI transforms secrets management from a reactive, policy-heavy discipline into an adaptive system. The platform uses behavioural anomaly detection to flag unusual access patterns -- off-hours requests, unfamiliar assets, atypical command sequences -- and surfaces risk scores inline with access requests. Natural-language policy authoring lets administrators write rules like "allow on-call SREs to access prod DB read replicas during incidents" instead of hand-crafting HCL. AI also powers automatic classification of discovered secrets by severity and blast radius, least-privilege recommendations based on actual usage patterns, and predictive credential rotation driven by threat intelligence.

---

## Tech Stack & Deployment

The platform targets self-hosted, cloud, and hybrid deployment models. Cryptographic primitives rely on audited libraries (libsodium, BoringSSL) -- no custom cryptographic schemes. The architecture supports pluggable secrets engines following the pattern proven by HashiCorp Vault, with a clean-room implementation under Apache-2.0 or MPL-2.0 licensing.

Key integration surfaces include OIDC/SAML for SSO, SCIM for user provisioning, Kubernetes CSI and operator patterns, and cloud provider IAM for dynamic credential generation across AWS, Azure, and GCP.

---

## Market Context

The privileged access management market is mature and growing, driven by regulatory mandates (SOX, PCI-DSS, HIPAA, NIS2) and cyber insurance requirements that increasingly demand evidence of PAM controls. Incumbents like CyberArk command premium pricing that excludes mid-market buyers, while HashiCorp Vault's licence change to BUSL 1.1 has created a gap for a genuinely open-source, enterprise-grade alternative. Primary buyers are security teams, platform engineering groups, and DevOps organisations in regulated industries.

---

## Project Status

> This project is in the **research and specification phase**.
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. Research indicates Apache-2.0 or MPL-2.0 as the cleanest licensing path for a new entrant in this space, avoiding copyleft obligations from AGPLv3 (Bitwarden) and GPLv3 (JumpServer) codebases, and steering clear of BUSL 1.1 restrictions (HashiCorp Vault). See [discussion](#) for context.
