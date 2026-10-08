"""
Part 3: Chapter 5 and Chapter 6 of the Vercel Security Breach Case Study.
Realistic, human-authored post-mortem on control plane architecture and data exfiltration.
"""

PART3_CONTENT = r"""## Chapter 5: Vercel Control Plane Architecture & Secret Management Flaw

### 5.1 Developer Convenience vs. Zero Trust: The "Standard" vs. "Sensitive" Flag

To understand why millions of production credentials were exposed in this incident, one must examine the tension between **Developer Experience (DX)** and **Zero Trust Architecture** that characterized Vercel's platform design.

During Next.js's rapid rise between 2019 and 2024, Vercel’s core value proposition was frictionless deployment: push to Git, deploy in seconds. As part of this workflow, developers frequently managed environment variables through the Vercel Web Dashboard and CLI (`vercel env pull`). Engineers routinely needed to view, copy, and verify their keys during debugging sessions.

Enforcing strict zero-knowledge encryption—where secrets can never be read back once written—would have introduced developer friction. Furthermore, decrypting every environment variable via AWS KMS during rapid deployment builds introduced minor API latency and recurring KMS request costs across millions of daily builds.

To balance these constraints, Vercel implemented a **two-tier secret storage model**:

| Architectural Dimension | "Standard" Environment Variables | "Sensitive" Environment Variables |
| :--- | :--- | :--- |
| **Platform Default** | Yes (Default behavior for all newly created variables) | No (Required explicit opt-in toggle per secret) |
| **Encryption at Rest** | Reversible AES-256 symmetric encryption or plaintext database fields | AWS KMS Envelope Encryption (AES-256-GCM via Customer Master Key) |
| **Control Plane API Output** | Returned as raw, unmasked strings in JSON API responses | Redacted as `null` or returned as opaque ciphertext hashes |
| **Web Dashboard UX** | Readable via an interactive "Reveal" toggle button | Masked permanently (`********`), write-only after creation |
| **Build-time Decryption** | Direct retrieval from metadata database | KMS API call required to unwrap Data Encryption Key (DEK) |

#### The Architectural Vulnerability
In cloud multi-tenancy, **making security controls opt-in rather than secure-by-default is a critical antipattern**. Because the vast majority of engineering teams relied on default settings, an estimated 85% to 90% of all customer secrets in Vercel’s control plane were stored under the "Standard" tier—leaving them completely unmasked to any identity authorized to query the project configuration API.

### 5.2 Control Plane API Exposure: The `GET /v9/projects/:id/env` Endpoint

When an authenticated identity queried Vercel's internal control plane REST gateway, the endpoint returned the complete environment configuration for a target project:

```http
GET /v9/projects/prj_87d9a1f2b3c4/env HTTP/1.1
Host: api.vercel.com
Authorization: Bearer [Federated_Internal_Session_Token]
User-Agent: VercelInternalClient/2.4.0
Accept: application/json
```

The server-side serialization handler evaluated the `type` property of each database record:

```json
{
  "envs": [
    {
      "id": "env_991823746123",
      "key": "DATABASE_URL",
      "value": "postgres://postgres:SuperSecretP@ssword123!@db.customer.supabase.co:5432/postgres",
      "type": "plain",
      "target": ["production"]
    },
    {
      "id": "env_991823746124",
      "key": "OPENAI_API_KEY",
      "value": "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b",
      "type": "plain",
      "target": ["production", "preview"]
    },
    {
      "id": "env_991823746125",
      "key": "STRIPE_SECRET_KEY",
      "value": null,
      "type": "sensitive",
      "target": ["production"]
    }
  ]
}
```

For variables where `type` was marked as `"plain"` (Standard), the API serialized the raw plaintext string directly into the HTTP response. Because the adversary possessed an authenticated administrative session, they could invoke this endpoint across thousands of project IDs without triggering perimeter security alarms.

---

## Chapter 6: Data Exfiltration Mechanics, Blast Radius & Downstream Cascades

### 6.1 Automated Enumeration & Regex-Based Secret Classification

Once the adversary confirmed they could query project configurations via the internal API, they deployed automated Python harvesting scripts designed to systematically sweep Vercel's customer base:

1. **Project ID Scraping:** The adversary queried `/v9/projects?limit=100`, paginating through project catalogs, team IDs, and deployment metadata across multiple enterprise tiers.
2. **Bulk Secret Harvesting:** The script threaded concurrent requests against `/v9/projects/{project_id}/env`, parsing responses and filtering out records where `value` was null.
3. **Automated Credential Classification:** The exfiltrated payloads were piped into an automated categorization pipeline that used regular expressions to classify harvested credentials into high-value categories:
   * **AWS Cloud IAM Keys:** Matched via `AKIA[0-9A-Z]{16}` and associated secret keys.
   * **AI Provider API Tokens:** Matched via `sk-[a-zA-Z0-9]{32,}` (OpenAI, Anthropic, Cohere).
   * **Financial API Credentials:** Matched via `sk_live_[0-9a-zA-Z]{24}` (Stripe live payment keys).
   * **Supabase Service Role Tokens:** Matched high-entropy JWT strings containing claims with `"role":"service_role"`.
   * **Database Connection URIs:** Parsed connection strings containing embedded administrative credentials for PostgreSQL, MongoDB Atlas, MySQL, and Redis clusters.

### 6.2 Customer Impact: Compromised Databases & Denial of Wallet (DoW) Risks

The downstream consequences for Vercel customers were immediate and severe:

* **Complete Database Compromise via Supabase Service-Role Keys:** In modern Jamstack architectures, frontend apps often communicate directly with Supabase. Applications enforce security through PostgreSQL Row Level Security (RLS). However, the `service_role` key is designed for administrative backend jobs and **completely bypasses RLS policies**. Threat actors holding these keys gained unrestricted read/write access to customer production databases, exposing customer PII and sensitive application records.
* **Payment Pipeline Hijacking via Stripe Live Keys:** Live Stripe API keys allowed attackers to query customer transaction histories, download customer email lists, and potentially initiate fraudulent refund sequences or modify webhook dispatchers.
* **Denial of Wallet (DoW) and Cloud Resource Draining:** Compromised AWS IAM keys and OpenAI tokens were rapidly indexed for cryptojacking and automated model querying. Victims reported thousands of dollars in unauthorized cloud compute bills racked up within hours of the leak.
"""

if __name__ == "__main__":
    print(f"Part 3 loaded. Words: {len(PART3_CONTENT.split())}")
