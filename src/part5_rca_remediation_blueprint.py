"""
Part 5: Chapter 10, Chapter 11, and Chapter 12 of the Vercel Security Breach Case Study.
Realistic, human-authored root cause analysis, zero trust architecture blueprint, and developer playbook.
"""

PART5_CONTENT = """## Chapter 10: Root Cause Analysis (RCA) & Threat Modeling (STRIDE / DREAD)

### 10.1 Multi-Tier Root Cause Dissection

A thorough post-mortem reveals that the Vercel breach cannot be attributed to a single isolated programming error. Instead, it was the catastrophic intersection of failures across four distinct operational tiers:

1. **The Endpoint & Policy Tier (Patient Zero):** A third-party analytics engineer downloaded untrusted software onto a workstation containing sensitive corporate credentials. The absence of strict device isolation, application allowlisting (AppLocker / Windows Defender Application Control), and endpoint segmentation allowed user-level malware to access the browser's DPAPI master key.
2. **The SaaS Governance Tier (Delegation Sprawl):** Vercel employees were permitted to grant high-privilege OAuth 2.0 permissions (`offline_access`, directory read scopes) to third-party tools without automated security review or administrative allowlisting in Google Workspace.
3. **The Protocol Tier (The Bearer Token Flaw):** Standard OAuth 2.0 (RFC 6749 / RFC 6750) treats tokens as bearer credentials. Because automated background token refreshes execute non-interactively without prompting for hardware MFA, possession of a refresh token equals complete identity takeover.
4. **The Platform Architecture Tier (Opt-In Security):** Vercel’s control plane stored customer environment variables in a reversible, plaintext format by default. Treating envelope encryption as an optional opt-in feature meant that the internal API (`GET /v9/projects/:id/env`) became a high-yield exfiltration channel the moment an internal corporate session was compromised.

### 10.2 STRIDE Threat Classification & DREAD Risk Quantification

To evaluate the architectural weaknesses systematically, the incident was mapped across the Microsoft **STRIDE** model and scored using the **DREAD** risk methodology:

| STRIDE Category | Threat Manifestation in Incident | Vulnerable Platform Component | DREAD Score | Residual Risk |
| :--- | :--- | :--- | :---: | :---: |
| **Spoofing** | Adversary presented stolen refresh token from an untrusted IP. | Unbound Bearer Refresh Tokens (RFC 6750) | **8.2** | CRITICAL |
| **Information Disclosure** | Internal REST API returned plaintext customer secrets. | Reversible Database Storage & API Serialization | **9.2** | CRITICAL |
| **Elevation of Privilege**| Engineer's Google identity granted read access across all customer projects. | Over-Privileged Internal Service Roles & Diagnostics | **8.6** | CRITICAL |
| **Repudiation** | Background token refreshes lacked hardware device telemetry. | Missing Continuous Access Evaluation (CAEP) | **7.6** | HIGH |

$$\\text{DREAD Score} = \\frac{\\text{Damage} + \\text{Reproducibility} + \\text{Exploitability} + \\text{Affected Users} + \\text{Discoverability}}{5}$$

The composite DREAD scores confirm that the storage and API serialization flaws represented maximum severity risks (9.2 / 10), as any identity breach in the control plane immediately translated to total customer credential exposure.

---

## Chapter 11: Enterprise Remediation & Zero Trust Architectural Blueprint

![Figure 3: Zero Trust Remediation Blueprint – OAuth DPoP Asymmetric Key Proof-of-Possession and Cloud Envelope Encryption with AWS KMS / HSMs](./assets/zero_trust_remediation.jpg)

### 11.1 Cryptographic Proof-of-Possession via RFC 9449 (DPoP) & CAEP

To permanently close the vector of bearer token replay, cloud identity providers and developer platforms must transition to cryptographic proof-of-possession:

1. **OAuth 2.0 DPoP (Demonstrating Proof-of-Possession - RFC 9449):**
   * Rather than issuing unbound bearer tokens, authorization servers require clients to generate an asymmetric key pair (typically ECDSA using curve P-256). Private keys are held in non-exportable hardware (TPM / Apple Secure Enclave / WebCrypto).
   * For every API interaction, the client signs a discrete `DPoP` proof JWT containing the current HTTP method, destination URI, and timestamp.
   * If a threat actor steals a refresh token or access token from a backend database, the token is completely useless because the attacker does not possess the client's non-exportable private key.
2. **Continuous Access Evaluation Protocol (CAEP / OpenID Shared Signals):**
   * Modern identity fabrics must not rely on static token expiration timers (e.g., 1-hour access tokens). Under CAEP, endpoint detection agents broadcast security events directly to the Identity Provider.
   * If an employee workstation triggers a malware alert, the IdP broadcasts an instant session revocation signal across all integrated SaaS applications, invalidating active access tokens within milliseconds.

### 11.2 Zero-Knowledge Control Planes & AWS KMS Envelope Encryption

Following the incident, Vercel overhauled its secret storage architecture to eliminate the reversible plaintext tier entirely:

* **Mandatory Envelope Encryption:** Every environment variable is encrypted at rest using an ephemeral **Data Encryption Key (DEK)** via AES-256-GCM. The DEK is encrypted using a tenant-specific **Key Encryption Key (KEK)** residing in hardware security modules managed by AWS KMS.
* **Cryptographic Tenant Isolation via AAD:** When encrypting variables, the tenant ID and project ID are injected as **Additional Authenticated Data (AAD)** into the AES-GCM cipher. This ensures that even if an attacker manipulates database pointers, ciphertext cannot be decrypted under another tenant's KMS context.
* **Write-Only Secret Storage (Zero-Knowledge APIs):** The endpoint `GET /v9/projects/:id/env` was refactored to **never return plaintext secrets under any circumstances**. Once saved, secrets can only be updated or deleted. Viewing secrets in the dashboard requires explicit FIDO2 re-authentication and administrative step-up verification.

---

## Chapter 12: Developer Hardening Playbook: Securing Serverless Stacks

### 12.1 Eliminating Static Credentials via OIDC Workload Identity Federation

The root vulnerability of customer exfiltration was that developers were storing long-lived, static cloud credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) inside Vercel environment variables.

In modern cloud engineering, **static credentials should be eliminated entirely**:
* **OIDC Federation:** Vercel serverless runtimes issue a signed OIDC JWT token during execution.
* The function presents this JWT to AWS Security Token Service (STS) via `AssumeRoleWithWebIdentity` (or Google Cloud Workload Identity Federation).
* AWS verifies the cryptographic signature against Vercel's public JWKS endpoint and issues **ephemeral, 15-minute temporary credentials** scoped strictly to the execution role.
* Even if an attacker compromises the deployment control plane, there are no static credentials stored in environment variables to steal.

### 12.2 Automated Secret Scanning & Emergency Rotation Playbooks

Engineering organizations must institute automated detection and emergency containment playbooks:

* **Pre-Commit and CI/CD Quality Gates:** Deploy tools such as TruffleHog and Gitleaks into local pre-commit hooks and GitHub Actions pipelines to block secrets from ever entering source code or deployment configurations.
* **The Dual-Key Zero-Downtime Rotation Pattern:** During an active security incident, teams cannot simply delete existing API keys without bringing down production services. Organizations should execute a phased rotation:
  1. Generate a secondary key in the target service (e.g., Stripe, Supabase).
  2. Inject the secondary key into production deployment variables.
  3. Trigger an atomic zero-downtime blue-green redeployment.
  4. Verify production telemetry confirming traffic is using the secondary key.
  5. Revoke the compromised primary key in the upstream provider.
"""

if __name__ == "__main__":
    print(f"Part 5 loaded. Words: {len(PART5_CONTENT.split())}")
