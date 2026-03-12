# Getting Started with Kalypso

## Installation

```bash
pip install kalypso
```

Or with Docker:

```bash
docker pull kalypso/kalypso:latest
```

## Step 1: Create Your Root CA

```bash
kalypso init
```

This creates your root CA at `~/.kalypso/`:
- `ca-cert.pem` — the root certificate (share this, it's public)
- `ca-key.pem` — the root private key (**keep this secret**)

## Step 2: Trust the Root CA

You only need to do this once per machine.

### macOS

```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.kalypso/ca-cert.pem
```

### Ubuntu / Debian

```bash
sudo cp ~/.kalypso/ca-cert.pem /usr/local/share/ca-certificates/kalypso.crt
sudo update-ca-certificates
```

### Fedora / RHEL

```bash
sudo trust anchor ~/.kalypso/ca-cert.pem
```

### Firefox (all platforms)

Firefox uses its own trust store:

1. Open `about:preferences#privacy`
2. Click **View Certificates**
3. Click **Import** and select `~/.kalypso/ca-cert.pem`
4. Check **Trust this CA to identify websites**

### Node.js

```bash
export NODE_EXTRA_CA_CERTS=~/.kalypso/ca-cert.pem
```

## Step 3: Issue Certificates

### Via CLI

```bash
# Single domain, valid for 24 hours
kalypso issue myapp.local

# Multiple domains with wildcard
kalypso issue myapp.local "*.myapp.local" api.myapp.local

# Custom lifetime
kalypso issue myapp.local --hours 4

# With IP address (e.g. for localhost)
kalypso issue myapp.local --ip 127.0.0.1 --ip ::1

# Custom output directory
kalypso issue myapp.local --out /path/to/certs
```

### Via API

Start the server:

```bash
kalypso serve
```

Then request certificates:

```bash
curl -X POST http://localhost:8200/certificates \
  -H 'Content-Type: application/json' \
  -d '{"domains": ["myapp.local"]}'
```

### Via SDK

```python
from kalypso_sdk import KalypsoClient

client = KalypsoClient("http://localhost:8200")
cert = client.issue("myapp.local", "*.myapp.local")
cert.save("cert.pem", "key.pem")
```

## Step 4: Use in Your App

### Python (Flask)

```python
app.run(ssl_context=("cert.pem", "key.pem"))
```

### Node.js

```javascript
const https = require('https');
const fs = require('fs');

https.createServer({
  cert: fs.readFileSync('cert.pem'),
  key: fs.readFileSync('key.pem'),
}, app).listen(443);
```

### nginx

```nginx
server {
    listen 443 ssl;
    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
}
```

## Docker Compose

See [examples/docker-compose/](../examples/docker-compose/) for a complete
setup with nginx and auto-issued certs.

For auto-refreshing certs, see
[examples/docker-compose-auto-refresh/](../examples/docker-compose-auto-refresh/).
