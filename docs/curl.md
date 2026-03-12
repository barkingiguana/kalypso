# Kalypso curl Examples

No SDK needed — Kalypso's API is plain HTTP/JSON.

## Check server health

```bash
curl http://localhost:8200/health
```

```json
{"status": "ok", "ca_initialized": true, "issued_count": 5}
```

## Download the CA certificate

```bash
curl -s http://localhost:8200/ca.pem | jq -r .certificate > kalypso-ca.pem
```

## Issue a certificate

### Basic — single domain

```bash
curl -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"]}'
```

### Multiple domains + wildcard

```bash
curl -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local", "*.myapp.local", "api.myapp.local"]}'
```

### Short-lived cert (4 hours)

```bash
curl -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"], "hours": 4}'
```

### With IP addresses

```bash
curl -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"], "ip_addresses": ["127.0.0.1", "::1"]}'
```

## Save cert and key to files

```bash
RESPONSE=$(curl -sf -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"]}')

echo "$RESPONSE" | jq -r .certificate > cert.pem
echo "$RESPONSE" | jq -r .private_key > key.pem
echo "$RESPONSE" | jq -r .ca_certificate > ca.pem
```

## One-liner: issue and save

```bash
curl -sf -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"]}' | \
  jq -r '.certificate' > cert.pem && \
curl -sf -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"]}' | \
  jq -r '.private_key' > key.pem
```

## Auto-refresh with a cron job

```bash
# Add to crontab: refresh cert every 12 hours
0 */12 * * * /path/to/refresh-cert.sh
```

`refresh-cert.sh`:
```bash
#!/bin/bash
set -e
RESPONSE=$(curl -sf -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"], "hours": 24}')

echo "$RESPONSE" | jq -r .certificate > /etc/certs/cert.pem
echo "$RESPONSE" | jq -r .private_key > /etc/certs/key.pem
echo "$(date): Certificate refreshed" >> /var/log/kalypso-refresh.log
```
