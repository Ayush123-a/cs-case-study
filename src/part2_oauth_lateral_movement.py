"""
Part 2: Chapter 3 and Chapter 4 of the Vercel Security Breach Case Study.
Realistic, human-authored engineering post-mortem on OAuth delegation and lateral movement.
"""

PART2_CONTENT = """## Chapter 3: The SaaS-to-SaaS Supply Chain Vector & OAuth 2.0 Abuse

### 3.1 Delegated Authorization (RFC 6749) & The Risk of Offline Refresh Tokens

Modern web applications depend heavily on the **OAuth 2.0 Authorization Framework (RFC 6749)**. When it was drafted in 2012, OAuth 2.0 solved a critical security dilemma: it eliminated the need for users to hand over their master passwords to third-party integrations. Instead, an identity provider (such as Google Workspace or Okta) issues a constrained token allowing a third-party client (Context.ai) to access specific resources on the user's behalf.

However, modern developer tooling relies heavily on background automation, requiring continuous API access even when the engineer is offline. During the initial authorization handshake between the Vercel engineer and Context.ai, the OAuth consent request included two crucial parameters:

```http
GET /o/oauth2/v2/auth?
  client_id=110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com&
  redirect_uri=https%3A%2F%2Fapp.context.ai%2Fapi%2Fauth%2Fcallback%2Fgoogle&
  response_type=code&
  scope=openid%20email%20profile%20https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fadmin.directory.user.readonly&
  access_type=offline&
  prompt=consent HTTP/1.1
Host: accounts.google.com
```

The parameter `access_type=offline` changed the risk profile of the entire integration. Rather than issuing only a short-lived **Access Token** (which expires after 60 minutes), Google’s Authorization Server generated a persistent, high-entropy **Refresh Token**. 

To perform recurring analytics sweeps, Context.ai persisted this refresh token in its backend production PostgreSQL database. From that moment forward, the security of the Vercel engineer’s corporate identity was tied directly to the security of Context.ai’s database.

### 3.2 The Bearer Token Dilemma (RFC 6750) & The MFA Bypass Paradox

Under **RFC 6750**, OAuth 2.0 tokens are defined as **Bearer Tokens**. The specification states that any party possessing the token is granted full authorization to use it. The token is not cryptographically bound to the client's TLS session, IP address, or device hardware.

This architectural reality creates what cloud security engineers refer to as the **MFA Bypass Paradox**:

* **Interactive Authentication (Day 0):** The engineer signs in through a web browser. They enter their password and touch a hardware FIDO2 security key (e.g., YubiKey). Google confirms Multi-Factor Authentication (MFA) has succeeded and issues the initial refresh token.
* **Adversary Replay (Day 30):** The adversary steals the stored refresh token from Context.ai’s compromised database. The adversary issues a token refresh request (`POST /token`) directly to Google's OAuth endpoint from a bulletproof proxy server in Eastern Europe.
* **The Failure Mode:** Google’s authorization server checks whether the refresh token is valid and unrevoked. Because RFC 6749 requires background token refreshes to execute non-interactively without user friction, **no MFA prompt is triggered**. Google immediately returns a fresh, valid access token directly to the adversary.

This design exposes a fundamental flaw in modern enterprise identity architecture: organizations invest millions in mandatory hardware-backed MFA, yet an adversary holding an offline refresh token can bypass those controls completely without ever touching a hardware key. 

Furthermore, because neither Google nor Context.ai enforced **Demonstrating Proof-of-Possession (DPoP - RFC 9449)**, the token lacked any asymmetric cryptographic binding to the client endpoint, allowing it to be replayed from an untrusted network with zero friction.

---

## Chapter 4: Lateral Movement & Ingress into Vercel Corporate Environment

### 4.1 Extracting Enterprise Credentials from Context.ai Infrastructure

Armed with the initial credentials stolen by Lumma Stealer from the Context.ai engineer's browser vault, the adversary began their pivot into Context.ai's production infrastructure:

1. **Cloud Environment Takeover:** Using harvested AWS session credentials (`AWS_ACCESS_KEY_ID` and session tokens stored in developer dotfiles), the adversary authenticated to the AWS Management Console and assumed administrative IAM roles (`arn:aws:iam::[ACCOUNT]:role/ProductionAdminRole`).
2. **Database Ingress:** From an administrative bastion host, the adversary connected to Context.ai’s Amazon RDS PostgreSQL cluster housing application secrets and customer accounts.
3. **Targeted Token Harvesting:** The attackers dumped tables storing third-party OAuth integrations. They recovered two critical artifacts: Context.ai’s registered OAuth `client_secret` and thousands of active customer refresh tokens.
4. **Target Identification:** Among the harvested rows was an active Google Workspace refresh token associated with a corporate Vercel email address (`engineer@vercel.com`).

### 4.2 Impersonating Corporate Identities via Google Workspace SSO

With both the OAuth client credentials and the employee's refresh token, the threat actor initiated a programmatic token exchange directly against Google's OAuth endpoints:

```http
POST /token HTTP/1.1
Host: oauth2.googleapis.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)

client_id=110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com&
client_secret=GOCSPX-[REDACTED]&
refresh_token=1//0gX9A_B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0...&
grant_type=refresh_token
```

Google’s Authorization Server validated the parameters and responded with:
* A fresh, valid **OAuth 2.0 Access Token** scoped to Google Workspace user directory APIs.
* A signed **OpenID Connect (OIDC) ID Token** containing identity claims asserting that the holder was indeed `engineer@vercel.com`.

In Vercel’s enterprise infrastructure, Google Workspace served as the primary Single Sign-On (SSO) Identity Provider (IdP). Using the authenticated session:
1. The attacker navigated to Vercel’s internal engineering portals and administrative API gateways.
2. The internal authentication gate redirected to Google for SAML/OIDC federated identity validation.
3. Because the attacker possessed active session tokens for `engineer@vercel.com`, Google’s IdP signed a fresh assertion asserting the employee's identity.
4. Vercel’s internal gateway verified the cryptographic signature against Google’s public JSON Web Key Set (JWKS) and granted the attacker an authenticated internal administrative session.
"""

if __name__ == "__main__":
    print(f"Part 2 loaded. Words: {len(PART2_CONTENT.split())}")
