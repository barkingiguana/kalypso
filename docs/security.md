# Kalypso Security Model

## Design Principles

Kalypso is designed for **local development only**. It makes HTTPS easy in dev
while minimizing the security risk of running a local CA.

### Zero external dependencies

Kalypso uses no third-party binaries. Trust store installation, certificate
generation, and key management are all handled natively using Python's
`cryptography` library and OS-native trust store commands.

### Short-lived certificates

- Default lifetime: **24 hours**
- Maximum lifetime: **7 days**
- If a dev cert leaks, it expires quickly
- Compare: self-signed certs and mkcert use 10+ year lifetimes

### Strong cryptography

- **ECDSA P-384** keys — 192-bit security (vs mkcert's P-256 / 128-bit)
- **SHA-384** signatures — matched to P-384 curve strength
- Stronger than what mkcert, minica, and most dev CA tools use

### Constrained root CA

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

### Private key protection

- CA key written with **0600 permissions** (owner read/write only)
- `os.open()` with explicit mode — no window of insecure permissions
- `kalypso status` — verify key permissions and CA fingerprint
- `kalypso load` — warns if key permissions are too open

### Certificate fingerprints

- Every issued cert gets a SHA-256 fingerprint for audit trail
- Displayed on `init`, `issue`, and `status` commands
- Logged by the API server for every issuance

### Native trust store management

- **macOS**: `security add-trusted-cert` (System Keychain)
- **Linux**: `update-ca-certificates` (Debian/Ubuntu) or `trust anchor` (Fedora/Arch)
- **Windows**: `certutil -addstore Root`
- **Firefox/Chrome**: NSS `certutil` for browser-specific databases
- Clean subprocess environment — no env var leakage
- Explicit argument lists — no shell injection
- Command timeouts — no hanging on interactive prompts

### No authentication on the API

This is intentional. Kalypso is for local dev and should never be exposed to
the internet. Adding auth would make the Docker Compose integration harder
without meaningful security benefit in a local context.

## Threat Model

| Threat | Mitigation |
|---|---|
| Leaked dev cert | Expires in 24 hours (default) |
| Compromised CA key | Key stored with 0600 perms. Rotate: delete `~/.kalypso/`, run `kalypso init`, `kalypso trust` |
| CA used to sign malicious certs | Only trust on dev machines, never in production |
| API exposed to internet | Don't do this. Bind to localhost or Docker network only. |
| Man-in-the-middle on API | API runs on local/Docker network. Use firewall rules if concerned. |
| Insecure key permissions | `kalypso status` checks and warns. `kalypso init` uses 0600 by default. |
| Supply chain (malicious CA in repo) | Never commit CA keys. `.gitignore` blocks `*.pem` by default. |

## Recommendations

1. **Never use Kalypso in production** — use Let's Encrypt or a real CA
2. **Keep the CA key secret** — treat `ca-key.pem` like a password
3. **Only trust the CA on dev machines** — never add it to production trust stores
4. **Use short cert lifetimes** — the default 24 hours is recommended
5. **Don't expose port 8200** — keep it on localhost or Docker internal networks
6. **Run `kalypso status`** — verify key permissions after setup
7. **Never commit PEM files** — the `.gitignore` blocks them by default
