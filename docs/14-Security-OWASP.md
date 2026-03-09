# Security - OWASP

This document defines a minimum security validation baseline inspired by OWASP for the Metria ecosystem:

- `metria-project` (backend API)
- `metria-web` (frontend)
- `metria-worker` (background worker)

## 1) OWASP Top 10 Coverage (Minimum)

### A01 Broken Access Control

- Verify protected API endpoints require valid JWT
- Ensure user-scoped data is always filtered by authenticated user identity
- Validate admin/debug endpoints are restricted to safe environments

### A02 Cryptographic Failures

- No plaintext secrets in repository
- JWT signing key set through environment variables
- TLS-only public endpoints in production

### A03 Injection

- Use EF Core parameterized queries (avoid raw SQL with concatenation)
- Validate/normalize request inputs
- Ensure structured logs do not concatenate untrusted values into commands

### A04 Insecure Design

- Keep auth, billing, and webhook flows server-authoritative
- Document critical decisions in ADRs

### A05 Security Misconfiguration

- Production env must define required variables
- Swagger in production only via explicit `ENABLE_SWAGGER=true`
- CORS configured with explicit `FRONTEND_ORIGIN`

### A06 Vulnerable and Outdated Components

- Run dependency updates regularly
- Track .NET, npm, and NuGet security advisories

### A07 Identification and Authentication Failures

- Enforce JWT validation (issuer, audience, signature, expiration)
- Verify OAuth redirect URI alignment across backend and Google Console

### A08 Software and Data Integrity Failures

- Protect CI/CD and deployment configuration changes
- Require code review for auth, billing, and infrastructure changes

### A09 Security Logging and Monitoring Failures

- Log auth, webhook, and billing error paths with correlation context
- Keep logs available in Railway for production incident analysis

### A10 Server-Side Request Forgery (SSRF)

- Restrict outbound calls to known providers (Google/Stripe)
- Avoid arbitrary URL fetch based on user input

## 2) Practical Validation Checklist

### Backend (`metria-project`)

- `dotnet list package --vulnerable`
- Validate auth-required endpoints with and without token
- Validate webhook signature rejection on invalid secret
- Verify secrets are environment-only

### Frontend (`metria-web`)

- Check no secret is exposed in `VITE_*` variables
- Validate route guards for authenticated screens
- Validate OAuth callback sanitization/normalization

### Worker (`metria-worker`)

- Validate message idempotency and retry/DLQ controls
- Validate secret/config sourcing from environment only
- Validate dependency vulnerabilities in worker packages

## 3) Recommended Automation

- CI security checks:
  - dependency vulnerability scan
  - lint/static checks
  - build and test gates
- Periodic manual review:
  - OAuth redirect configuration
  - Stripe webhook secrets
  - Railway variable and domain configuration
