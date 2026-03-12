# Kalypso API Reference

Base URL: `http://localhost:8200` (default)

## Endpoints

### `GET /health`

Health check and statistics.

**Response:**

```json
{
  "status": "ok",
  "ca_initialized": true,
  "issued_count": 42
}
```

### `GET /ca.pem`

Download the root CA certificate. Trust this certificate once in your
OS/browser to make all Kalypso-issued certs trusted.

**Response:**

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n..."
}
```

### `POST /certificates`

Issue a new short-lived SSL certificate.

**Request body:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `domains` | `string[]` | Yes | — | Domain names for the cert |
| `hours` | `int` | No | `24` | Lifetime in hours (1–168) |
| `ip_addresses` | `string[]` | No | `[]` | IP SANs |

**Example request:**

```json
{
  "domains": ["myapp.local", "*.myapp.local"],
  "hours": 24,
  "ip_addresses": ["127.0.0.1"]
}
```

**Response:**

```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...",
  "domains": ["myapp.local", "*.myapp.local"],
  "not_after": "2025-01-02T12:00:00Z",
  "ca_certificate": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Error responses:**

- `422` — Invalid request (empty domains, invalid hours, etc.)

## OpenAPI

When the server is running, visit `http://localhost:8200/docs` for interactive
Swagger UI documentation, or `http://localhost:8200/redoc` for ReDoc.

## Security Considerations

- The API has **no authentication** by default — it's designed for local dev only
- Never expose port 8200 to the public internet
- The CA private key is stored at `/data/ca-key.pem` inside the container
- All issued certificates are short-lived (max 7 days)
