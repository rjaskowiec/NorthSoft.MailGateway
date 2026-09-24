# NorthSoft.MailGateway — API Specification

The NorthSoft Mail Gateway (`mail.northsoft.is`) exposes RESTful HTTP endpoints for sending transactional emails.

---

## Service Endpoints

| Method | Endpoint | Auth Required | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | No | Service status check |
| `GET` | `/health` | No | Health check endpoint |
| `POST` | `/v1/send` | **Yes (Bearer)** | Send transactional email |
| `OPTIONS` | `/*` | No | CORS preflight handling |

---

## Authentication

All requests to `/v1/send` require HTTP Bearer Token authentication:

```http
Authorization: Bearer <GATEWAY_TOKEN>
```

Tokens are verified against `env.GATEWAY_TOKEN` using a timing-safe constant-time string comparison (`secureTokenCompare`).

---

## Endpoint Details

### 1. Health Check (`GET /health`)

Returns operational status of the gateway worker.

#### Request

```http
GET /health HTTP/1.1
Host: mail.northsoft.is
```

#### Response (`200 OK`)

```json
{
  "status": "ok",
  "service": "mail-gateway"
}
```

---

### 2. Send Transactional Email (`POST /v1/send`)

Dispatches an email request to the configured Brevo transactional email provider.

#### Request Headers

```http
POST /v1/send HTTP/1.1
Host: mail.northsoft.is
Authorization: Bearer <GATEWAY_TOKEN>
Content-Type: application/json
Content-Length: <bytes>
```

#### Request Payload Specification

```json
{
  "from": {
    "email": "no-reply@example.com",
    "name": "Sender Name"
  },
  "to": [
    {
      "email": "recipient@example.com",
      "name": "Recipient Name"
    }
  ],
  "replyTo": {
    "email": "support@example.com",
    "name": "Support Team"
  },
  "subject": "Email Subject Line",
  "html": "<html><body><h1>Hello World</h1></body></html>"
}
```

#### Field Schema & Constraints

| Field Path | Type | Required | Max Length / Limit | Validation Rules |
| :--- | :--- | :--- | :--- | :--- |
| `from.email` | `string` | Yes | 320 chars | Valid email format. Must match authorized sender (`no-reply@northsoft.is`). No CRLF (`\r`, `\n`). |
| `from.name` | `string` | No | 200 chars | Sender display name. |
| `to` | `array` | Yes | 1 – 10 items | Array of recipient objects. |
| `to[].email` | `string` | Yes | 320 chars | Valid email format. No CRLF. |
| `to[].name` | `string` | No | 200 chars | Recipient display name. |
| `replyTo.email` | `string` | No | 320 chars | Valid email format. No CRLF. |
| `replyTo.name` | `string` | No | 200 chars | Reply-To display name. |
| `subject` | `string` | Yes | 998 chars | Non-empty string. CRLF characters prohibited to prevent header injection. |
| `html` | `string` | Yes | 150 KB | Non-empty HTML string. Active scripts and event handlers are automatically sanitized. |

#### Body Size Limit

The gateway enforces a strict payload limit of **200 KB** (`200,000 bytes`). Requests exceeding this size receive `413 Payload Too Large`.

---

## Response Formats & HTTP Status Codes

### Successful Response (`200 OK`)

```json
{
  "success": true,
  "messageId": "<20260924120000.1234567890@smtp-relay.brevo.com>"
}
```

### Error Responses Table

| Status | Error Key | Description |
| :--- | :--- | :--- |
| `400` | `Request body must be an object` | Body is null, array, or non-JSON object. |
| `400` | `Invalid JSON` | Request body cannot be parsed as valid JSON. |
| `400` | `Missing from` / `Invalid from.email` | Sender configuration missing or invalid email format. |
| `400` | `to must be an array` / `Maximum 10 recipients allowed` | Recipient array missing, empty, or exceeds 10 items. |
| `400` | `Missing subject` / `Invalid subject` | Subject line is empty, too long (>998), or contains CRLF injection. |
| `400` | `Missing html` / `HTML content is too large` | HTML body is empty or exceeds 150 KB. |
| `400` | `Invalid HTML content` | HTML content failed sanitization check. |
| `403` | `Forbidden` | Authorization header missing, invalid prefix, or invalid token. |
| `403` | `Sender is not authorized` | `from.email` is not the authorized sender (`no-reply@northsoft.is`). |
| `405` | `Method not allowed` | Non-POST HTTP method used on `/v1/send`. |
| `413` | `Request body too large` | Payload exceeds 200 KB maximum body size. |
| `415` | `Content-Type must be application/json` | Missing or non-JSON `Content-Type` header. |
| `502` | `Email provider unavailable` | Upstream network failure connecting to Brevo API endpoint. |
| `502` | `Email provider rejected the request` | Upstream Brevo API returned an error response. |
| `503` | `Service unavailable` | Cloudflare Worker runtime is missing required secrets (`GATEWAY_TOKEN`, etc.). |

---

## Security Headers & CORS

Every API response includes the following security headers:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Cache-Control: no-store`

Cross-Origin Resource Sharing (CORS) is restricted to explicitly allowed origins (`northsoft.is`, `www.northsoft.is`, `mail.northsoft.is`, `photo.northsoft.is`, and `localhost:3000`). Unrecognized origins receive `403 Forbidden` on CORS preflight `OPTIONS` requests.
