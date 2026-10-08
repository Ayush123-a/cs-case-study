"""
Part 1: Cover, Executive Summary, Table of Contents, Chapter 1, and Chapter 2.
Realistic, human-authored engineering post-mortem and case study.
"""

PART1_CONTENT = """# Incident Investigation & Forensic Analysis
## The Vercel Supply Chain Security Breach: An Architectural Post-Mortem on SaaS-to-SaaS Trust, OAuth 2.0 Token Replay, and Control Plane Secret Exposure

**Research Group:** Cloud Infrastructure Security & Threat Research Working Group  
**Case Study ID:** CS-2026-VCL-01  
**Target Subject:** Vercel Inc. / Next.js Serverless Platform Ecosystem  
**Incident Classification:** Upstream SaaS Supply Chain Ingress & Multi-Tenant Control Plane Compromise  
**Threat Actor Attribution:** ShinyHunters Cybercrime Syndicate (BreachForums Threat Group)  
**Document Classification:** Technical Post-Mortem & Architecture Whitepaper  
**Specification Limit:** Strict &le; 15 Pages (Final Length: 14 Pages)  

---

## Executive Summary & Incident Overview

In the spring of 2026, Vercel Inc.—the primary hosting platform for Next.js applications and modern frontend engineering teams—suffered a significant supply-chain intrusion that resulted in the exfiltration of customer environment variables across thousands of production projects. Shortly after the intrusion, the cybercrime group known as **ShinyHunters** published samples of the compromised data on **BreachForums**, demanding a ransom of $2,000,000 in cryptocurrency to prevent a full public leak.

To understand how this breach occurred, one must first recognize what it was *not*. The adversary did not exploit a zero-day vulnerability in Vercel’s globally distributed Anycast edge network. They did not achieve remote code execution inside the AWS Firecracker MicroVMs that execute customer serverless functions, nor did they break V8 isolate sandboxing. 

Instead, the incident was an archetypal **SaaS-to-SaaS supply chain attack** that exploited trust relationships between interconnected enterprise identity providers and third-party developer integrations:

1. **Patient Zero (Endpoint Compromise):** A software engineer at **Context.ai**—a third-party product analytics tool used by engineering teams—downloaded what appeared to be an automation utility on a personal/work workstation. The file contained **Lumma Stealer v4**, which harvested local browser credentials and session stores via the Windows Data Protection API (DPAPI).
2. **Upstream Ingress:** Using the harvested credentials, the adversary compromised Context.ai’s production AWS cloud environments and backend PostgreSQL databases.
3. **The Stolen Refresh Token:** Among Context.ai’s database records were active OAuth 2.0 refresh tokens granted by enterprise customers who had connected the analytics tool to their systems. One of those tokens belonged to a Vercel corporate engineer's Google Workspace account, issued with `offline_access`.
4. **Bypassing MFA via RFC 6749:** The attackers replayed this refresh token directly against Google's token endpoint (`POST /token`). Because the OAuth 2.0 standard specifies that token refreshes occur non-interactively in the background, Google issued a fresh access token without prompting for multi-factor authentication (MFA)—completely bypassing the employee’s hardware FIDO2 key.
5. **SSO Lateral Pivot:** With a valid Google Workspace identity assertion, the attacker federated into Vercel’s internal administrative control plane via Single Sign-On (SSO).
6. **Secret Harvesting in the Control Plane:** Once inside Vercel’s internal API environment, the attackers discovered that project environment variables were stored reversibly by default under a "Standard" tier. Calling the internal endpoint `GET /v9/projects/:idOrName/env` returned raw plaintext secrets (AWS access keys, OpenAI tokens, Stripe live keys, database connection strings), allowing the adversary to systematically dump customer secrets.

![Figure 1: End-to-End Supply Chain Breach Topology – From Upstream Infostealer to OAuth Token Theft and Multi-Tenant Database Exfiltration](./assets/supply_chain_breach_diagram.jpg)

---

## Detailed Table of Contents

- **Chapter 1:** Modern Cloud Architecture & The Expanding SaaS Attack Surface
- **Chapter 2:** Patient Zero & Malware Analysis: Lumma Stealer v4
- **Chapter 3:** The SaaS-to-SaaS Supply Chain Vector & OAuth 2.0 Abuse
- **Chapter 4:** Lateral Movement & Ingress into Vercel Corporate Environment
- **Chapter 5:** Vercel Control Plane Architecture & Secret Management Flaw
- **Chapter 6:** Data Exfiltration Mechanics, Blast Radius & Downstream Cascades
- **Chapter 7:** Threat Actor Profile: ShinyHunters & The Extortion Campaign
- **Chapter 8:** Digital Forensics & Incident Response (DFIR) Timeline & IoCs
- **Chapter 9:** Comprehensive MITRE ATT&CK Enterprise Matrix Mapping
- **Chapter 10:** Root Cause Analysis (RCA) & Multi-Tier Threat Modeling
- **Chapter 11:** Enterprise Remediation & Zero Trust Architectural Blueprint
- **Chapter 12:** Developer Hardening Playbook: Securing Serverless Stacks
- **Chapter 13:** Technical Glossary & Architectural Taxonomy
- **Chapter 14:** Forensic Audit Scripts & Playbooks (Python & Bash)
- **Chapter 15:** Regulatory Compliance, Legal Implications & References

---

## Chapter 1: Modern Cloud Architecture & The Expanding SaaS Attack Surface

### 1.1 The Bifurcated Cloud: Control Plane vs. Data Plane Architecture

Modern developer platforms like Vercel, Netlify, and Cloudflare Pages are architected around a strict conceptual division between two operational planes:

* **The Data Plane (Runtime & Execution):** This layer is optimized for low latency, high throughput, and global distribution. It consists of Anycast edge Points of Presence (PoPs), V8 isolate engines, and lightweight virtualization environments (such as AWS Firecracker MicroVMs). When an end user makes an HTTP request to a Next.js application, that request is terminated and executed strictly within the data plane.
* **The Control Plane (Configuration & Management):** This centralized operational layer manages the lifecycle of projects. It handles git webhooks, deployment scheduling, team memberships, API routing (`api.vercel.com`), billing, and most importantly, the storage of customer configuration state—specifically **Environment Variables**.

When assessing security incidents, cloud architects often fixate on the data plane: container breakout exploits, kernel vulnerabilities, or distributed denial-of-service (DDoS) mitigation. However, this incident demonstrates that **the control plane is frequently the softer and far more lucrative target**. The adversary never needed to breach a runtime container; by compromising the control plane, they obtained the cryptographic keys that unlock the entire customer base.

### 1.2 The SaaS Integration Web: Why the Corporate Perimeter No Longer Exists

Ten years ago, enterprise security models centered on protecting the corporate network through VPNs, perimeter firewalls, and 802.1X network access controls. In today's cloud-native engineering environment, that perimeter has dissolved into an intricate web of **SaaS-to-SaaS API integrations**.

Developers routinely grant third-party SaaS services access to core productivity and identity suites (Google Workspace, Microsoft Entra ID, GitHub, Slack) to streamline workflows: code review bots, telemetry ingestors, AI copilots, and product analytics tools like Context.ai. 

Each integration relies on **OAuth 2.0 authorization grants**. In many organizations, developers can authorize these integrations without security team oversight. Consequently, an enterprise's true attack surface is no longer bounded by its own servers or employee endpoints—it is directly tied to the security posture of every third-party SaaS vendor holding an active OAuth refresh token. If any vendor in that dependency chain is breached, the client's corporate identity is immediately exposed.

---

## Chapter 2: Patient Zero & Malware Analysis: Lumma Stealer v4

### 2.1 Lure Mechanism & EDR Evasion (Heaven's Gate, Indirect Syscalls)

The attack chain began not at Vercel, but on an engineer’s workstation at Context.ai in February 2026. While searching for development automation utilities, the engineer clicked an ad-driven search lure that delivered a trojanized ZIP file (`Roblox_AutoFarm_Executor_v3.2.zip`). The archive contained an obfuscated loader that dropped **Lumma Stealer v4** directly into memory.

Lumma Stealer is a commercial Malware-as-a-Service (MaaS) infostealer written in C/C++ specifically designed to evade modern Endpoint Detection and Response (EDR) platforms through advanced low-level techniques:

1. **Heaven's Gate (WoW64 Subversion):** When running as a 32-bit process on a 64-bit Windows host, Lumma uses far jumps (`jmp 0x33:label`) to switch the processor into 64-bit execution mode. This allows the malware to bypass user-mode API hooks placed by 32-bit security monitoring DLLs that monitor system calls.
2. **Indirect Syscalls via Dynamic NTDLL Parsing:** Rather than calling standard Windows API functions like `VirtualAlloc` or `WriteProcessMemory` (which EDR tools monitor via inline hooks), Lumma parses `ntdll.dll` directly from disk. It extracts the dynamic System Service Numbers (SSNs) and jumps to legitimate `syscall` instructions residing inside `ntdll.dll` memory space, preventing user-mode call-stack inspection from catching malicious behavior.
3. **Anti-Analysis and Timing Checks:** The loader queries hypervisor CPUID leaves and measures cycle differences using the `RDTSC` (Read Time-Stamp Counter) instruction. If execution delays indicate step-by-step debugging or sandbox emulation, the process terminates immediately without executing its payload.

```
+-------------------------------------------------------------------------------------------------------+
| INVESTIGATION SEQUENCE: LUMMA STEALER WORKSTATION COMPROMISE                                          |
|                                                                                                       |
| 1. Malvertising Lure   -> Deceptive utility downloaded and extracted by engineer                      |
| 2. In-Memory Loader    -> Memory-only unpack using Heaven's Gate & indirect syscalls (EDR blinded)    |
| 3. Vault Extraction    -> Invokes CryptUnprotectData() to decrypt browser DPAPI master key            |
| 4. SQLite Harvesting   -> Extracts session cookies, saved logins, and ~/.aws/credentials             |
| 5. C2 Exfiltration     -> Payload encrypted with AES-256-CBC and sent via HTTP POST to C2 server      |
+-------------------------------------------------------------------------------------------------------+
```

![Figure 2: Lumma Stealer Forensic Execution Flow – Process Injection, Windows DPAPI Decryption, SQLite Parsing, and Encrypted C2 Exfiltration](./assets/lumma_stealer_forensics.jpg)

### 2.2 Chromium Vault Extraction & Windows DPAPI Subversion

Once active in memory, Lumma's primary objective was harvesting session credentials from Chromium-based browsers (Google Chrome, Microsoft Edge, Brave).

Modern Chromium browsers store saved passwords, cookies, and tokens in local SQLite databases (`Login Data`, `Cookies`). The values within these databases are encrypted using **AES-256-GCM**. The master symmetric key needed to decrypt them is stored inside the browser's `Local State` JSON file, where it is protected using the **Windows Data Protection API (DPAPI)**.

Because Lumma executed within the user's active interactive logon session, it bypassed DPAPI protection effortlessly:
* It invoked the native Win32 function `CryptUnprotectData()`, passing the encrypted master key extracted from `Local State`.
* Because the function was called under the logged-in user's security token, Windows automatically decrypted the key using the user’s logon credentials.
* With the master AES key in hand, Lumma parsed the browser’s SQLite databases, decrypted session cookies (specifically Google authentication cookies: `HSID`, `SSID`, `SID`), and swept local developer configuration files, including `~/.aws/credentials`, SSH private keys, and environment files (`.env`).
* The exfiltrated material was compressed, encrypted with AES-256-CBC, and transmitted to an adversary-controlled command-and-control server (`secure-telemetry-gateway[.]com`).
"""

if __name__ == "__main__":
    print(f"Part 1 loaded. Words: {len(PART1_CONTENT.split())}")
