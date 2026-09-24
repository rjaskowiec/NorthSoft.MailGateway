# NorthSoft.MailGateway

A secure transactional email gateway for NorthSoft applications.

Cloudflare Workers · TypeScript · Brevo API

---

## Overview

NorthSoft.MailGateway is a transactional email gateway deployed on Cloudflare Workers. It acts as an internal API proxy for NorthSoft services, routing outbound emails to the Brevo API while enforcing authentication, sender validation, request size bounds, and HTML sanitization.

Centralizing transactional email logic shields client applications from email provider specifics and prevents unauthorized email dispatching across NorthSoft domains.

---

## Technology Stack

| Component | Technology |
| :--- | :--- |
| Runtime | Cloudflare Workers |
| Language | TypeScript |
| Email Provider | Brevo REST API |
| HTML Sanitizer | sanitize-html |
| Tooling | Wrangler |

---

## Architecture

```text
NorthSoft Application
        |
        | HTTPS POST /v1/send
        v
NorthSoft.MailGateway
(Cloudflare Worker)
        |
        | HTTPS POST /v3/smtp/email
        v
    Brevo API
```

Client microservices submit email requests via HTTPS to the `/v1/send` endpoint. The gateway validates the request payload, verifies the bearer token and sender authorization, sanitizes the HTML content, and dispatches the formatted request to Brevo.

---

## Features

- **Bearer Authentication**: Verifies request tokens using constant-time string comparison.
- **Sender Authorization**: Restricts senders to a configured domain allowlist.
- **Payload Validation**: Enforces schema limits for recipients, subject length, and content sizes.
- **Header Injection Protection**: Rejects subject lines and email fields containing CRLF characters.
- **HTML Sanitization**: Filters HTML content using an allowlist-based parser before forwarding.
- **CORS Support**: Enforces origin restrictions for allowed NorthSoft web applications, including development subdomains.
- **Security Headers**: Returns standard HTTP security response headers.
- **Provider Isolation**: Isolates third-party API details and returns standardized status codes.

---

## API

### Send Email (`POST /v1/send`)

#### Example Request

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
  "subject": "Account Verification",
  "html": "<p>Hello! Please verify your account.</p>"
}
```

#### Example Response (`200 OK`)

```json
{
  "success": true,
  "messageId": "<20260924120000.1234567890@smtp-relay.brevo.com>"
}
```

Complete API specifications and status code mappings are documented in [docs/API.md](docs/API.md).

---

## Configuration

| Binding | Type | Purpose |
| :--- | :--- | :--- |
| `GATEWAY_TOKEN` | Secret | API Bearer token authentication |
| `BREVO_API_KEY` | Secret | Brevo API key |
| `AUTHORIZED_SENDERS` | Variable | Allowed sender email addresses |

Secrets are managed using Cloudflare Worker environment secret bindings and are never stored in repository configuration files.

---

## Development

### Prerequisites

- Node.js (v18+)
- Wrangler CLI

### Setup & Commands

```bash
# Install dependencies
npm install

# Copy example environment configuration
cp .dev.vars.example .dev.vars

# Type check
npm run typecheck

# Run unit and integration tests
npm test

# Start local Wrangler dev server
npm run dev
```

---

## Deployment

Deploy the gateway to Cloudflare Workers:

```bash
# Configure production secret bindings (first-time setup)
npx wrangler secret put GATEWAY_TOKEN
npx wrangler secret put BREVO_API_KEY

# Deploy to Cloudflare
npm run deploy
```

---

## Project Structure

```text
NorthSoft.MailGateway/
├── .dev.vars.example    Example local environment configuration
├── .gitignore           Git ignore rules
├── LICENSE              Proprietary software license
├── README.md            Project documentation
├── SECURITY.md          Security policy and vulnerability reporting
├── package.json         Package configuration and dependencies
├── tsconfig.json        TypeScript compiler configuration
├── wrangler.json        Cloudflare Worker deployment configuration
├── docs/
│   └── API.md           REST API specification
├── src/
│   ├── index.ts         Worker entrypoint and HTTP routing
│   ├── auth.ts          Bearer authentication and timing-safe checks
│   ├── brevo.ts         Brevo REST API integration
│   ├── config.ts        Gateway bounds and CORS whitelist
│   ├── response.ts      HTTP responses, CORS, and security headers
│   ├── sanitizer.ts     Allowlist HTML sanitization
│   ├── types.ts         TypeScript type definitions
│   └── validation.ts    Request schema and header injection validation
└── tests/
    └── gateway.test.ts  Unit and integration test suite
```

---

## Security

Security controls include secret binding isolation, bearer token authentication with constant-time comparison, sender allowlists, payload boundary checks, parser-based HTML sanitization, and security response headers.

Vulnerability reporting procedures are detailed in [SECURITY.md](SECURITY.md).

---

## Testing

The automated test suite contains 21 unit and integration tests covering authentication, request validation, CRLF header injection detection, allowlist HTML sanitization, CORS, security headers, routing, and end-to-end Worker response handling.

---

## Author

[Robert Jaśkowiec (rjaskowiec)](https://github.com/rjaskowiec)

---

## License

Proprietary software. All rights reserved.

The source code is publicly available for review and evaluation, but no license is granted to use, reproduce, modify, distribute, sublicense, or commercially exploit the software without prior written permission.

For commercial licensing or other usage rights, contact the author.
