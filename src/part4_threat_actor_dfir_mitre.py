"""
Part 4: Chapter 7, Chapter 8, and Chapter 9 of the Vercel Security Breach Case Study.
Realistic, human threat intelligence analysis, DFIR timeline, and MITRE ATT&CK mapping.
"""

PART4_CONTENT = """## Chapter 7: Threat Actor Profile: ShinyHunters & The Extortion Campaign

### 7.1 Origins, Modus Operandi, and BreachForums Extortion Demand

The adversary claiming responsibility for the Vercel data exfiltration operated under the moniker **ShinyHunters**, a prolific cybercriminal syndicate active since approximately May 2020. 

Unlike traditional ransomware syndicates that deploy encrypting malware (such as LockBit or ALPHV/BlackCat), ShinyHunters operates almost exclusively as an **identity-focused data theft and extortion group**. Their operational signature involves:
* Targeting cloud-native identity layers, API secrets, and source code repositories.
* Infiltrating third-party enterprise service providers and SaaS aggregators to access multiple downstream enterprise victims.
* Monetizing stolen datasets via dark web marketplaces—specifically **BreachForums** and associated private Telegram channels.

In April 2026, ShinyHunters published a high-profile listing on BreachForums advertising the sale and extortion of Vercel’s exfiltrated database:

* **Stated Inventory:** 2,400,000+ raw project environment variables, database connection strings, AWS access keys, OpenAI tokens, and deployment configurations.
* **Extortion Demand:** $2,000,000 USD payable in privacy-preserving cryptocurrency (Monero - XMR) or Bitcoin (BTC).
* **Proof Samples:** To prove the authenticity of the compromise, the group published a proof-of-concept archive containing 1,000 verified working project secrets from active production deployments.

Independent security researchers and affected engineering teams who inspected the proof samples verified that the credentials were live, active production keys matching customer projects hosted on Vercel.

---

## Chapter 8: Digital Forensics & Incident Response (DFIR) Timeline

### 8.1 Chronological Incident Matrix, Mandiant Findings & Indicators of Compromise (IoCs)

Following the public extortion listing, Vercel mobilized its internal incident response team and retained **Mandiant** (Google Cloud) to lead independent digital forensics and threat containment. 

By correlating Google Workspace administrative audit logs, AWS CloudTrail records, and Vercel API gateway access logs, investigators reconstructed the complete chronological intrusion timeline:

| Timestamp (UTC) | Incident Phase | Forensic Observations & Technical Findings |
| :--- | :--- | :--- |
| **Feb 12, 2026 - 14:22** | **Initial Compromise** | An engineer at Context.ai executes a trojanized archive. Lumma Stealer v4 decrypts the Windows DPAPI master key and harvests local browser vaults. |
| **Feb 28, 2026 - 09:15** | **Cloud Pivot** | Adversary uses stolen AWS credentials to access Context.ai’s production AWS management console. |
| **Mar 04, 2026 - 16:40** | **Database Theft** | Adversary dumps backend PostgreSQL tables housing registered OAuth client secrets and persistent customer refresh tokens. |
| **Mar 18, 2026 - 02:11** | **MFA Bypass** | Adversary submits the stolen refresh token to `oauth2.googleapis.com/token`. Google issues a fresh access token for `engineer@vercel.com` without prompting for MFA. |
| **Mar 18, 2026 - 03:45** | **SSO Federation** | Adversary uses the Google identity session to authenticate into Vercel’s internal administrative control plane via SAML/OIDC SSO. |
| **Mar 19, 2026 - 22:10** | **Mass Exfiltration** | Automated Python scripts execute bulk concurrent queries against `GET /v9/projects/:id/env`, dumping unencrypted environment variables. |
| **Apr 02, 2026 - 11:30** | **Public Extortion** | ShinyHunters lists the stolen data on BreachForums, demanding $2,000,000 to halt distribution. |
| **Apr 02, 2026 - 16:00** | **DFIR Engagement** | Vercel mobilizes emergency incident response protocols and engages Mandiant. |
| **Apr 03, 2026 - 06:00** | **Containment & Revocation**| Vercel invalidates the compromised OAuth Client ID domain-wide, purges active sessions, resets affected tokens, and initiates customer disclosures. |

#### Indicators of Compromise (IoCs)
* **Compromised Google OAuth Client ID:** `110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com` (Context.ai integration)
* **Lumma Stealer Dropper SHA256:** `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
* **Adversary Ingress Proxy IP:** `194.26.29[.]112` (Known commercial anonymizing VPN / proxy exit node)
* **Malware C2 Ingestion Endpoint:** `secure-telemetry-gateway[.]com` (TCP 443 / HTTP POST)

---

## Chapter 9: Comprehensive MITRE ATT&CK Enterprise Matrix Mapping

The attack traversed 11 discrete tactics of the **MITRE ATT&CK Enterprise Framework (v14)**:

| ATT&CK Tactic | Technique ID & Name | Technical Application in the Vercel Incident |
| :--- | :--- | :--- |
| **Initial Access** | `T1195.002` Supply Chain Compromise: Third-Party Software | Compromising upstream analytics provider (Context.ai) that held active OAuth tokens into Vercel. |
| **Execution** | `T1204.002` User Execution: Malicious File | Context.ai employee downloaded and executed trojanized utility containing infostealer. |
| **Defense Evasion** | `T1562.001` Impair Defenses: Disable/Modify Tools | Lumma Stealer bypassed host EDR via indirect system calls and WoW64 Heaven's Gate transitions. |
| **Credential Access**| `T1555.003` Credentials from Web Browsers | Decrypted Chromium SQLite databases using Windows DPAPI `CryptUnprotectData()`. |
| **Persistence** | `T1528` Steal Application Access Token | Extracted long-lived offline OAuth 2.0 refresh tokens from Context.ai's backend database. |
| **Privilege Escalation**| `T1078.004` Valid Accounts: Cloud Accounts | Leveraged authenticated Google Workspace corporate account to access internal Vercel portals. |
| **Lateral Movement**| `T1550.001` Use Alternate Authentication: Application Access Token | Replayed refresh token against Google's token endpoint to bypass hardware MFA. |
| **Discovery** | `T1526` Cloud Service Discovery | Enumerated customer projects and team registries via internal API (`GET /v9/projects`). |
| **Collection** | `T1530` Data from Cloud Storage | Extracted unmasked environment variables via internal endpoint (`GET /v9/projects/:id/env`). |
| **Exfiltration** | `T1567.002` Exfiltration Over Web Service: Exfiltration to Cloud Storage | Transferred exfiltrated secret databases to adversary-controlled cloud drop infrastructure. |
| **Impact** | `T1657` Financial Extortion | Posted breach listing on BreachForums demanding $2,000,000 ransom. |
"""

if __name__ == "__main__":
    print(f"Part 4 loaded. Words: {len(PART4_CONTENT.split())}")
