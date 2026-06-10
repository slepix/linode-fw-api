# Linode Firewall API

A lightweight Python API that adds inbound TCP/443 allow-rules to a Linode Cloud Firewall for a given IP address and expiration window. Every rule addition is written to a persistent JSON log file for later processing (e.g. scheduled expiry removal).

---

## Requirements

- Python 3.12+ **or** Docker
- A [Linode API token](https://cloud.linode.com/profile/tokens) with **Read/Write** access to *Firewalls*
- An existing Linode Cloud Firewall (note its numeric ID)

---

## Configuration

Copy `.env.example` to `.env` and fill in the three required values:

```env
LINODE_TOKEN=your_linode_api_token_here   # Linode personal access token
API_TOKEN=your_secret_api_token_here      # Token callers must send in the Authorization header
FIREWALL_ID=123456                         # Numeric ID of the target Linode firewall

# Optional — defaults to /data/firewall_log.json inside the container
LOG_FILE=/data/firewall_log.json
```

`API_TOKEN` can be any strong random string. Generate one with:

```bash
openssl rand -hex 32
```

---

## Running locally (without Docker)

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Set environment variables
cp .env.example .env
# edit .env with your values

# 4. Start the server
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

---

## Docker deployment

### Build

```bash
docker build -t linode-firewall-api .
```

### Run

```bash
docker run -d \
  --name firewall-api \
  -p 8000:8000 \
  -v firewall-data:/data \
  --env-file .env \
  --restart unless-stopped \
  linode-firewall-api
```

- `-v firewall-data:/data` mounts a named volume so `firewall_log.json` survives container restarts.
- `--restart unless-stopped` keeps the container running after host reboots.

### View logs

```bash
docker logs -f firewall-api
```

### Stop / remove

```bash
docker stop firewall-api && docker rm firewall-api
```

---

## API reference

All endpoints that modify or read firewall state require a Bearer token header:

```
Authorization: Bearer <API_TOKEN>
```

### `GET /health`

Liveness check. No authentication required.

**Response `200`**
```json
{ "status": "ok" }
```

---

### `POST /api/firewall/allow`

Adds an inbound TCP/443 ACCEPT rule for the given IP address to the configured Linode firewall and appends an entry to the log file.

**Request body**

| Field | Type | Description |
|---|---|---|
| `ip` | string | IPv4 address. `/32` suffix is optional — it will be added automatically. |
| `expires_at` | string (ISO 8601) | When the rule should expire. Must be in the future and no more than **12 hours** from now. |

**Example request**

```bash
curl -s -X POST http://localhost:8000/api/firewall/allow \
  -H "Authorization: Bearer your_secret_api_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.42",
    "expires_at": "2026-06-10T22:00:00Z"
  }'
```

**Response `201`**

```json
{
  "success": true,
  "ip": "203.0.113.42/32",
  "expires_at": "2026-06-10T22:00:00+00:00",
  "label": "auto-203-0-113-42-12345678",
  "message": "Rule added to firewall 123456"
}
```

**Validation rules**

| Rule | Detail |
|---|---|
| `/32` only | Prefix lengths other than `/32` are rejected. |
| No `0.0.0.0` | That address is always rejected. |
| Future timestamp | `expires_at` must be after the current UTC time. |
| Max 12 hours | `expires_at` cannot be more than 12 hours from now. |
| Unique label | A duplicate rule label on the same firewall returns `409`. |

**Error responses**

| Status | Meaning |
|---|---|
| `400` | Validation failure (bad IP, invalid expiry). |
| `401` | Missing or incorrect `Authorization` header. |
| `409` | A rule with the same label already exists on the firewall. |
| `502` | Linode API returned an error or is unreachable. |

---

### `GET /api/firewall/log`

Returns the contents of the JSON log file — every rule that has been added through this API.

**Example request**

```bash
curl -s http://localhost:8000/api/firewall/log \
  -H "Authorization: Bearer your_secret_api_token_here"
```

**Response `200`**

```json
[
  {
    "ip": "203.0.113.42/32",
    "expires_at": "2026-06-10T22:00:00+00:00",
    "added_at": "2026-06-10T12:34:56.789012+00:00",
    "label": "auto-203-0-113-42-12345678",
    "firewall_id": 123456
  }
]
```

---

## Log file

Rules are appended to the JSON file specified by `LOG_FILE`. This file is the source of truth for the expiry scheduler you will build separately. Each entry contains:

| Field | Description |
|---|---|
| `ip` | The `/32` address that was allowed |
| `expires_at` | ISO 8601 UTC timestamp when the rule should be removed |
| `added_at` | ISO 8601 UTC timestamp when the rule was created |
| `label` | Unique Linode firewall rule label (use this to identify the rule for deletion) |
| `firewall_id` | The firewall the rule was added to |

---

## Interactive API docs

FastAPI provides built-in documentation UIs at:

- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

Both UIs include a built-in "Authorize" button where you can enter your `API_TOKEN` and test endpoints directly in the browser.
