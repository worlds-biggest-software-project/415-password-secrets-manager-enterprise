# Standards & API Reference

> Project: Password & Secrets Manager (Enterprise) · Generated: 2026-05-06

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022 — Information security management systems** — https://www.iso.org/standard/27001 — The foundational ISMS standard against which enterprise password and secrets management programmes are typically certified; Annex A controls A.5.15–A.5.18 cover access control and privileged access.
- **ISO/IEC 27002:2022 — Information security controls** — https://www.iso.org/standard/75652.html — Implementation guidance for the controls referenced in 27001, including 8.2 (privileged access rights) and 8.5 (secure authentication).
- **ISO/IEC 27017:2015 — Cloud services security controls** — https://www.iso.org/standard/43757.html — Cloud-specific extension covering shared responsibility for credential and key management.
- **ISO/IEC 27018:2019 — PII protection in public cloud** — https://www.iso.org/standard/76559.html — Where vault contents may include PII, governs processor obligations.
- **ISO/IEC 19790:2025 — Security requirements for cryptographic modules** — https://www.iso.org/standard/52906.html — International equivalent of FIPS 140; relevant for HSM and key-store certification.
- **ISO/IEC 11770 series — Key management** — https://www.iso.org/standard/73206.html — Key management framework covering key lifecycle, agreement, and transport.
- **ISO/IEC 15408 (Common Criteria)** — https://www.iso.org/standard/72891.html — Used for formal security evaluation of PAM/vault products at EAL levels.

### W3C & IETF Standards

- **RFC 6749 — OAuth 2.0 Authorization Framework** — https://datatracker.ietf.org/doc/html/rfc6749 — Authorisation flows used between clients, vault, and identity providers.
- **RFC 6750 — OAuth 2.0 Bearer Token Usage** — https://datatracker.ietf.org/doc/html/rfc6750 — Bearer token semantics used for vault API authentication.
- **RFC 8414 — OAuth 2.0 Authorization Server Metadata** — https://datatracker.ietf.org/doc/html/rfc8414 — Discovery endpoint for OAuth-protected APIs.
- **RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens** — https://datatracker.ietf.org/doc/html/rfc9068 — Standard JWT format for access tokens issued to vault clients.
- **RFC 7519 — JSON Web Token (JWT)** — https://datatracker.ietf.org/doc/html/rfc7519 — Token format used for service-to-service authentication.
- **RFC 7515 / 7516 / 7517 / 7518 — JSON Web Signature/Encryption/Key/Algorithms (JOSE)** — https://datatracker.ietf.org/doc/html/rfc7515 — Crypto envelope formats relevant to token and secret encryption.
- **RFC 7591 / 7592 — OAuth 2.0 Dynamic Client Registration** — https://datatracker.ietf.org/doc/html/rfc7591 — Used when vault must register many CI/CD clients dynamically.
- **RFC 8252 — OAuth 2.0 for Native Apps** — https://datatracker.ietf.org/doc/html/rfc8252 — Best practice for desktop/mobile vault clients.
- **RFC 7636 — PKCE** — https://datatracker.ietf.org/doc/html/rfc7636 — Required for public clients accessing vault APIs.
- **RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication** — https://datatracker.ietf.org/doc/html/rfc8705 — mTLS-based client authentication for high-assurance secrets clients.
- **RFC 9101 — JWT Secured Authorization Request (JAR)** — https://datatracker.ietf.org/doc/html/rfc9101 — Stronger authentication of authorisation requests.
- **RFC 9126 — OAuth 2.0 Pushed Authorization Requests (PAR)** — https://datatracker.ietf.org/doc/html/rfc9126 — Recommended for FAPI-aligned deployments.
- **RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)** — https://datatracker.ietf.org/doc/html/rfc9449 — Sender-constrained tokens for high-value secrets APIs.
- **RFC 7662 — OAuth 2.0 Token Introspection** — https://datatracker.ietf.org/doc/html/rfc7662 — Vault-side token validation pattern.
- **RFC 7009 — OAuth 2.0 Token Revocation** — https://datatracker.ietf.org/doc/html/rfc7009 — Revocation of compromised vault tokens.
- **OpenID Connect Core 1.0** — https://openid.net/specs/openid-connect-core-1_0.html — Identity federation between vault and corporate IdP.
- **SCIM 2.0 (RFC 7643 / 7644)** — https://datatracker.ietf.org/doc/html/rfc7644 — User and group provisioning standard for vault user lifecycle.
- **SAML 2.0 (OASIS)** — https://docs.oasis-open.org/security/saml/v2.0/ — Enterprise SSO protocol still required by many large customers.
- **RFC 4252 — SSH Authentication Protocol** — https://datatracker.ietf.org/doc/html/rfc4252 — Required for SSH credential brokering and certificate authority features.
- **RFC 4253 — SSH Transport Layer Protocol** — https://datatracker.ietf.org/doc/html/rfc4253 — Underpinning protocol for SSH session proxies.
- **RFC 5280 — X.509 PKI Certificate and CRL Profile** — https://datatracker.ietf.org/doc/html/rfc5280 — Required for PKI/certificate engine.
- **RFC 8555 — ACME (Automatic Certificate Management Environment)** — https://datatracker.ietf.org/doc/html/rfc8555 — Issuance of TLS certificates from an internal vault CA.
- **RFC 8446 — TLS 1.3** — https://datatracker.ietf.org/doc/html/rfc8446 — Minimum transport layer for vault APIs.
- **RFC 5424 — Syslog Protocol** — https://datatracker.ietf.org/doc/html/rfc5424 — Standard transport for audit log export.
- **RFC 9457 — Problem Details for HTTP APIs** — https://datatracker.ietf.org/doc/html/rfc9457 — Recommended error response format for vault APIs.
- **RFC 7807 (obsoleted by 9457)** — Predecessor of 9457; many existing tools still emit this format.
- **W3C WebAuthn Level 3** — https://www.w3.org/TR/webauthn-3/ — Phishing-resistant MFA for human vault access.
- **FIDO2 / CTAP 2.1** — https://fidoalliance.org/specs/ — Hardware authenticator protocol underlying WebAuthn.

### Data Model & API Specifications

- **OpenAPI Specification 3.1.0** — https://spec.openapis.org/oas/v3.1.0 — Standard for vault REST API definitions; aligns with JSON Schema 2020-12.
- **JSON Schema 2020-12** — https://json-schema.org/specification — Schema language for secret templates and policy validation.
- **GraphQL October 2021 Specification** — https://spec.graphql.org/October2021/ — Alternative API style; some modern vaults expose GraphQL alongside REST.
- **AsyncAPI 3.0** — https://www.asyncapi.com/docs/reference/specification/v3.0.0 — Specification for event streams (audit events, secret-changed webhooks).
- **CloudEvents 1.0 (CNCF)** — https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md — Standard event envelope for emitted vault events.
- **JMESPath / JSONPath (RFC 9535)** — https://datatracker.ietf.org/doc/html/rfc9535 — Used for policy expressions and selectors.
- **Open Policy Agent / Rego** — https://www.openpolicyagent.org/docs/latest/ — De-facto policy-as-code language for fine-grained access decisions.
- **Cedar Policy Language** — https://www.cedarpolicy.com/ — AWS-originated alternative to Rego, increasingly common in IAM tooling.
- **KMIP 2.1 (OASIS)** — https://docs.oasis-open.org/kmip/kmip-spec/v2.1/kmip-spec-v2.1.html — Key Management Interoperability Protocol for HSM and external KMS integration.
- **PKCS#11 v3.1** — https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.1/pkcs11-base-v3.1.html — Standard API for cryptographic tokens (HSMs, smart cards).
- **Protocol Buffers (Google)** — https://protobuf.dev/ — Used by HashiCorp Vault and others for plugin RPC interfaces.
- **gRPC** — https://grpc.io/docs/ — Common transport for plugin and replication APIs.

### Security & Authentication Standards

- **NIST SP 800-63B / 800-63-4 — Digital Identity Guidelines** — https://pages.nist.gov/800-63-4/ — Authenticator assurance levels (AAL) governing MFA strength for vault access.
- **NIST SP 800-53 Rev. 5 — Security and Privacy Controls** — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final — Foundational US federal control catalogue; AC-2, AC-6, IA-5, AU families directly apply.
- **NIST SP 800-57 Part 1 Rev. 5 — Key Management Recommendations** — https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final — Key lifecycle and cryptoperiods for stored secrets.
- **NIST SP 800-131A Rev. 3 — Transitioning Cryptographic Algorithms** — https://csrc.nist.gov/pubs/sp/800/131/a/r3/final — Approved/deprecated algorithm guidance.
- **NIST SP 800-208 — Stateful Hash-Based Signatures** — https://csrc.nist.gov/pubs/sp/800/208/final — Relevant for long-lived signing keys protected by the vault.
- **NIST FIPS 140-3 — Security Requirements for Cryptographic Modules** — https://csrc.nist.gov/pubs/fips/140-3/final — Module validation required for federal customers.
- **NIST FIPS 197 — AES** — https://csrc.nist.gov/pubs/fips/197/final — Symmetric encryption standard.
- **NIST FIPS 186-5 — Digital Signature Standard** — https://csrc.nist.gov/pubs/fips/186-5/final — Signature algorithms.
- **NIST FIPS 203 / 204 / 205 — Post-Quantum Cryptography** — https://csrc.nist.gov/projects/post-quantum-cryptography — ML-KEM, ML-DSA, SLH-DSA; PQ migration roadmap for long-lived secrets.
- **NIST SP 800-204C — Microservices-based App Sec** — https://csrc.nist.gov/pubs/sp/800/204/c/final — Service-mesh and secrets-in-microservices guidance.
- **OWASP ASVS 4.0 (5.0 draft)** — https://owasp.org/www-project-application-security-verification-standard/ — Verification requirements; sections V2 (auth), V6 (cryptography), V8 (data protection), V10 (malicious code).
- **OWASP Secrets Management Cheat Sheet** — https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html — Practitioner guidance referenced by many enterprise procurement teams.
- **OWASP Top 10 (2021 / 2025 candidate)** — https://owasp.org/www-project-top-ten/ — Hardening reference, especially A02 Cryptographic Failures and A07 Identification & Authentication Failures.
- **CIS Critical Security Controls v8.1** — https://www.cisecurity.org/controls — Controls 5 (Account Management) and 6 (Access Control Management) directly relevant.
- **PCI DSS v4.0.1** — https://www.pcisecuritystandards.org/document_library/ — Requirements 7 and 8 govern privileged access; vault offerings often pre-mapped.
- **HIPAA Security Rule (45 CFR §164.308–.312)** — https://www.hhs.gov/hipaa/ — Administrative and technical safeguards on access management.
- **SOC 2 Trust Services Criteria (AICPA)** — https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2 — CC6 (Logical and Physical Access) and CC7 (System Operations) commonly evidenced via vault logs.
- **EU NIS2 Directive (2022/2555)** — https://eur-lex.europa.eu/eli/dir/2022/2555/oj — Mandates privileged access controls for in-scope EU entities.
- **EU DORA (2022/2554)** — https://eur-lex.europa.eu/eli/reg/2022/2554/oj — Financial-sector ICT risk; covers privileged access and third-party access.
- **GDPR (Regulation 2016/679)** — https://eur-lex.europa.eu/eli/reg/2016/679/oj — Vault contents may be PII; Articles 25 (data protection by design) and 32 (security of processing) apply.
- **FedRAMP Rev. 5 baselines** — https://www.fedramp.gov/ — US federal cloud authorisation; vaults serving US gov customers typically authorised at Moderate or High.
- **NIST SSDF (SP 800-218)** — https://csrc.nist.gov/projects/ssdf — Secure software development; covers secret management in build pipelines.
- **CNCF SLSA Framework v1.0** — https://slsa.dev/spec/v1.0/ — Supply-chain integrity; vaults often integrated for build-time secret provenance.

### MCP Server Specifications

- **Model Context Protocol Specification** — https://modelcontextprotocol.io/specification — MCP servers can expose vault read operations to AI agents under tightly scoped auth, enabling AI assistants to retrieve approved credentials without persistent access.
- **MCP Authorization (OAuth 2.1 profile)** — https://modelcontextprotocol.io/specification/draft/basic/authorization — Recommended pattern for AI-agent access to vault MCP servers using PAR + DPoP.
- **MCP Tools and Resources** — https://modelcontextprotocol.io/docs/concepts/tools — Pattern for exposing vault actions (list secrets, request JIT access) as scoped tools to LLM agents.

---

## Similar Products — Developer Documentation & APIs

### HashiCorp Vault
- **Description:** Identity-based secrets and encryption management with static and dynamic secrets engines, transit encryption, and pluggable auth methods.
- **API Documentation:** https://developer.hashicorp.com/vault/api-docs
- **SDKs/Libraries:** Go (https://github.com/hashicorp/vault/tree/main/api), Python (hvac, https://github.com/hvac/hvac), Java (https://github.com/jOpenLibs/vault-java-driver), Node (https://github.com/nodevault/node-vault), Ruby (vault-ruby).
- **Developer Guide:** https://developer.hashicorp.com/vault/tutorials
- **Standards:** REST/JSON over HTTPS; no formal OpenAPI spec but generated specs available; gRPC for plugins.
- **Authentication:** AppRole, AWS IAM, Azure, GCP, Kubernetes service accounts, OIDC/JWT, TLS certificates, LDAP, Userpass, Tokens.

### OpenBao (Linux Foundation)
- **Description:** MPL-2.0 community fork of HashiCorp Vault preserving the open-source line after Vault's BUSL relicensing.
- **API Documentation:** https://openbao.org/api-docs/
- **SDKs/Libraries:** Go (https://github.com/openbao/openbao/tree/main/api); community SDKs largely compatible with hvac and node-vault.
- **Developer Guide:** https://openbao.org/docs/
- **Standards:** REST/JSON; API-compatible with Vault.
- **Authentication:** Same auth methods as Vault.

### CyberArk Privileged Access Manager
- **Description:** Tier-1 enterprise PAM platform with vault, session management, and privileged threat analytics.
- **API Documentation:** https://docs.cyberark.com/pam-self-hosted/latest/en/Content/SDK/Central-Credential-Provider-APIs.htm
- **SDKs/Libraries:** REST API; Java/.NET sample SDKs; PowerShell module (https://github.com/pspete/psPAS).
- **Developer Guide:** https://developer.cyberark.com/
- **Standards:** REST/JSON; SOAP legacy endpoints for older modules.
- **Authentication:** CyberArk authentication, LDAP, RADIUS, SAML, OIDC, Windows authentication.

### Delinea Secret Server
- **Description:** Enterprise PAM with strong AD integration and a separate DevOps Secrets Vault SKU.
- **API Documentation:** https://docs.delinea.com/online-help/secret-server/api-scripting/rest-api/index.htm
- **SDKs/Libraries:** SDK CLI, Python SDK (https://github.com/DelineaXPM/python-tss-sdk), PowerShell module.
- **Developer Guide:** https://docs.delinea.com/online-help/secret-server/start.htm
- **Standards:** REST/JSON; OData query support.
- **Authentication:** OAuth 2.0, SAML, AD integrated, MFA.

### BeyondTrust Password Safe
- **Description:** Privileged credential management combined with secure remote access modules.
- **API Documentation:** https://www.beyondtrust.com/docs/beyondinsight-password-safe/ps/api/index.htm
- **SDKs/Libraries:** REST API; PowerShell sample modules.
- **Developer Guide:** https://www.beyondtrust.com/docs/beyondinsight-password-safe/index.htm
- **Standards:** REST/JSON.
- **Authentication:** API key, OAuth, mTLS, AD/SAML.

### Keeper Secrets Manager
- **Description:** Zero-knowledge secrets manager combined with the Keeper password vault for unified human + machine credential management.
- **API Documentation:** https://docs.keeper.io/secrets-manager/secrets-manager/overview
- **SDKs/Libraries:** Python (https://github.com/Keeper-Security/secrets-manager/tree/master/sdk/python), Java, Go, .NET, JavaScript, PowerShell, Bash CLI (Commander).
- **Developer Guide:** https://docs.keeper.io/secrets-manager/secrets-manager/developer-sdk-library
- **Standards:** REST/JSON; client-side encryption envelope.
- **Authentication:** One-time access tokens bootstrapping device-specific key pairs; zero-knowledge end-to-end encryption.

### 1Password Connect / Secrets Automation
- **Description:** Programmatic access to 1Password vaults via on-prem Connect server or hosted Service Accounts.
- **API Documentation:** https://developer.1password.com/docs/connect/connect-api-reference/
- **SDKs/Libraries:** Go (https://github.com/1Password/connect-sdk-go), Python, JavaScript, .NET; CLI (`op`).
- **Developer Guide:** https://developer.1password.com/
- **Standards:** REST/JSON; OpenAPI spec published.
- **Authentication:** Bearer tokens scoped to vaults; Service Account tokens for Connect.

### AWS Secrets Manager
- **Description:** Managed AWS service for storing and rotating database credentials, API keys, and arbitrary secrets.
- **API Documentation:** https://docs.aws.amazon.com/secretsmanager/latest/apireference/Welcome.html
- **SDKs/Libraries:** All AWS SDKs (https://aws.amazon.com/developer/tools/) including Java, Python (boto3), Go, JavaScript, .NET, Ruby, PHP, C++, Rust.
- **Developer Guide:** https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html
- **Standards:** AWS API protocol (JSON over HTTPS); Smithy IDL definitions.
- **Authentication:** AWS SigV4 with IAM credentials; IAM Roles for Service Accounts (IRSA) on EKS.

### Azure Key Vault
- **Description:** Microsoft-managed key, secret, and certificate store for Azure workloads with HSM-backed Premium tier.
- **API Documentation:** https://learn.microsoft.com/en-us/rest/api/keyvault/
- **SDKs/Libraries:** .NET, Java, Python, Node, Go (https://github.com/Azure/azure-sdk-for-go).
- **Developer Guide:** https://learn.microsoft.com/en-us/azure/key-vault/general/developers-guide
- **Standards:** REST/JSON; OData filtering.
- **Authentication:** Microsoft Entra ID (Azure AD) tokens; Managed Identities; certificate authentication.

### Google Cloud Secret Manager
- **Description:** Google-managed secret store for GCP workloads with envelope encryption via Cloud KMS.
- **API Documentation:** https://cloud.google.com/secret-manager/docs/reference/rest
- **SDKs/Libraries:** All GCP client libraries (https://cloud.google.com/secret-manager/docs/reference/libraries) including Go, Java, Python, Node, Ruby, PHP, .NET, C++.
- **Developer Guide:** https://cloud.google.com/secret-manager/docs
- **Standards:** REST and gRPC; Protocol Buffers definitions.
- **Authentication:** Google IAM; Workload Identity Federation; service account keys.

### Doppler
- **Description:** Developer-first secrets manager with sync to 50+ destinations (cloud, hosting, CI/CD).
- **API Documentation:** https://docs.doppler.com/reference/api
- **SDKs/Libraries:** CLI (https://github.com/DopplerHQ/cli); language SDKs in Node, Python, Go via REST.
- **Developer Guide:** https://docs.doppler.com/docs
- **Standards:** REST/JSON; OpenAPI spec.
- **Authentication:** Service Tokens, Personal Tokens, OIDC for CI/CD (GitHub, GitLab).

### Bitwarden Secrets Manager
- **Description:** Open-source secrets manager extending the Bitwarden password vault.
- **API Documentation:** https://bitwarden.com/help/secrets-manager-api/
- **SDKs/Libraries:** Bitwarden SDK (Rust core with bindings) — Go, Python, C#, Java, Node, Ruby (https://github.com/bitwarden/sdk-secrets).
- **Developer Guide:** https://bitwarden.com/help/secrets-manager-overview/
- **Standards:** REST/JSON; client-side encryption.
- **Authentication:** Machine accounts with access tokens; API keys; OIDC for users.

### Infisical
- **Description:** Open-source (MIT) secret management platform with end-to-end encryption and SDKs for popular languages.
- **API Documentation:** https://infisical.com/docs/api-reference/overview
- **SDKs/Libraries:** Node, Python, Java, Go, .NET, Ruby, Rust (https://github.com/Infisical).
- **Developer Guide:** https://infisical.com/docs/documentation/getting-started/introduction
- **Standards:** REST/JSON; OpenAPI.
- **Authentication:** Universal Auth (client ID + secret), Token Auth, Kubernetes Auth, AWS IAM Auth, GCP IAM Auth, OIDC Auth.

---

## Notes

The category is at an inflection point on three vectors:

1. **Post-quantum migration.** NIST FIPS 203/204/205 finalised in 2024–2025; long-lived secrets (root keys, code-signing keys) need to be re-issued under PQ algorithms or wrapped via hybrid schemes. Vault products are still adding ML-KEM/ML-DSA support across their PKI engines.

2. **Open-source landscape reshaping.** HashiCorp Vault's BUSL relicensing (2023) and IBM acquisition (2024) created the OpenBao fork under the Linux Foundation. The licensing position of new entrants matters more than ever for procurement at sceptical enterprises.

3. **AI-agent identity.** Standards for issuing scoped, short-lived credentials to non-deterministic AI agents are still being drafted. The MCP authorization profile is one early attempt; expect IETF and OpenID Foundation work in this space over the next 12–24 months. A new vault should plan for "agent identity" as a first-class auth method alongside human and workload identities.

4. **KMIP and PKCS#11 remain relevant.** Despite cloud-native momentum, FSI and government customers still require KMIP/PKCS#11 interfaces for HSM interoperability. Coverage of these standards is non-negotiable for tier-1 enterprise sales.
