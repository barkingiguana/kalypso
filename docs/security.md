# Kalypso Security Model

## Design Principles

Kalypso is designed for **local development only**. It makes HTTPS easy in dev
while minimizing the security risk of running a local CA.

### Short-lived certificates

- Default lifetime: **24 hours**
- Maximum lifetime: **7 days**
- If a dev cert leaks, it expires quickly
- Compare: self-signed certs and mkcert use 10+ year lifetimes

### Constrained root CA

- ECDSA P-256 keys (fast, secure, small)
- `pathLength=0` — the root CA cannot create sub-CAs
- `keyUsage=keyCertSign,crlSign,digitalSignature` — nothing else
- Subject Key Identifier included for chain validation

### Leaf certificate constraints

- `basicConstraints: CA=FALSE` (critical) — certs cannot sign other certs
- `extendedKeyUsage: serverAuth` — only valid for TLS servers
- `authorityKeyIdentifier` — links back to the issuing CA
- Unique serial number per certificate
- Unique key pair per certificate
- Only the domains you specify are covered (no implicit wildcards)

### No authentication on the API

This is intentional. Kalypso is for local dev and should never be exposed to
the internet. Adding auth would make the Docker Compose integration harder
without meaningful security benefit in a local context.

## Threat Model

| Threat | Mitigation |
|---|---|
| Leaked dev cert | Expires in 24 hours (default) |
| Compromised CA key | Rotate: delete `~/.kalypso/`, run `kalypso init`, re-trust |
| CA used to sign malicious certs | Only trust on dev machines, never in production |
| API exposed to internet | Don't do this. Bind to localhost or Docker network only. |
| Man-in-the-middle on API | API runs on local/Docker network. Use firewall rules if concerned. |

## Recommendations

1. **Never use Kalypso in production** — use Let's Encrypt or a real CA
2. **Keep the CA key secret** — treat `ca-key.pem` like a password
3. **Only trust the CA on dev machines** — never add it to production trust stores
4. **Use short cert lifetimes** — the default 24 hours is recommended
5. **Don't expose port 8200** — keep it on localhost or Docker internal networks
