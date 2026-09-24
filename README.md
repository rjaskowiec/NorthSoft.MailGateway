# NorthSoft.MailGateway

A secure transactional email gateway for NorthSoft applications.

---

## Overview

**NorthSoft.MailGateway** is a production transactional email gateway deployed on [Cloudflare Workers](https://workers.cloudflare.com/) and powered by [Brevo](https://www.brevo.com/) (formerly Sendinblue) as the transactional email infrastructure provider.

The service is deployed at `mail.northsoft.is` and serves as a centralized, secure intermediary for internal NorthSoft microservices requiring transactional email capabilities (such as authentication notifications, password resets, and system alerts).

---

## Technology Decision

### Runtime Platform
**Cloudflare Workers** (V8 isolate edge runtime).

### Language
**TypeScript 5.x** (Strict Mode).

### Transactional Email Provider
**Brevo REST API** (`https://api.brevo.com/v3/smtp/email`).

### HTML Sanitization Engine
**Parser-Based Allowlist Sanitization via [`sanitize-html`](https://github.com/apostrophecms/sanitize-html)**.

### Why Parser-Based HTML Sanitization Was Selected

Rather than relying on fragile regex string replacement rules, the gateway integrates **`sanitize-html`**—a robust, AST/tree parser-based sanitizer built on `htmlparser2`.

- **Strict Tag Allowlist**: Only safe layout tags (`<p>`, `<div>`, `<table>`, `<a>`, `<img>`, `<h1>`-`<h6>`, `<span>`, `<b>`, `<i>`, `<ul>`, etc.) are permitted. Executable elements (`<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `<input>`, `<base>`, `<applet>`, `<frame>`, `<svg>`, `<math>`) and their contents are discarded.
- **Strict Attribute Allowlist**: Permits only essential styling and layout attributes (`style`, `class`, `id`, `src`, `href`, `width`, `height`, `align`, `valign`, `border`, `alt`). All inline event attributes (`onclick`, `onload`, `onerror`, etc.) are unconditionally stripped.
- **Strict Protocol Filtering**: Enforces scheme allowlisting (`http`, `https`, `mailto`, `tel`, `cid`). Malicious URI schemes (`javascript:`, `vbscript:`, `data:`) are completely removed from `href` and `src` attributes.
- **Cloudflare Workers Compatibility**: Operates natively in V8 isolates without DOM dependencies or native C++ bindings.

---

## Architecture

```text
NorthSoft Application
        |
        | HTTPS POST /v1/send
        v
+---------------------------+
| NorthSoft.MailGateway     |
| Cloudflare Worker         |
|                           |
| Authentication            |
| Validation                |
| Authorization             |
| Parser-Based Sanitization |
| Provider Integration      |
+-------------+-------------+
              |
              | HTTPS API
              v
          +-------+
          | Brevo |
          +-------+
```

When a NorthSoft service needs to send an email, it dispatches an authenticated HTTPS `POST` request to `https://mail.northsoft.is/v1/send`. The gateway validates authentication, payload boundaries, sender authorization, and HTML safety before forwarding the payload to the Brevo REST API.

---

## Key Features

- **Bearer Token Authentication**: Enforces HTTP Bearer token authentication verified via constant-time string comparison (`secureTokenCompare`) to eliminate timing side-channel attacks.
- **Authorized Sender Verification**: Enforces a strict whitelist check against `AUTHORIZED_SENDERS` to prevent address spoofing.
- **Strict Payload Boundary Limits**: Enforces input type validation, max email/name lengths, subject bounds, recipient array limits, and early 200 KB request body rejection.
- **Header Injection Protection**: Neutralizes CRLF (`\r`, `\n`) characters in subject lines and email fields to prevent SMTP header injection vulnerabilities.
- **Parser-Based HTML Sanitization**: Uses `sanitize-html` to parse HTML tokens and enforce a strict tag, attribute, and protocol allowlist.
- **CORS Protection**: Enforces an origin whitelist (`northsoft.is`, `www.northsoft.is`, `mail.northsoft.is`, `photo.northsoft.is`, `localhost:3000`) for cross-origin browser requests.
- **Security Headers**: Injects defense headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`).
- **Provider Error Isolation**: Logs detailed upstream error responses internally while returning safe, sanitized error messages to client applications.

---

## API Summary

Detailed API documentation is available in [docs/API.md](docs/API.md).

### Send Email

```http
POST /v1/send HTTP/1.1
Host: mail.northsoft.is
Authorization: Bearer <GATEWAY_TOKEN>
Content-Type: application/json

{
  "from": {
    "email": "no-reply@example.com",
    "name": "Example Sender"
  },
  "to": [
    {
      "email": "recipient@example.com",
      "name": "Example Recipient"
    }
  ],
  "replyTo": {
    "email": "support@example.com",
    "name": "Support Team"
  },
  "subject": "Welcome to NorthSoft",
  "html": "<p>Hello!</p><p>Thank you for creating an account.</p>"
}
```

---

## Configuration

The gateway relies on three Cloudflare Worker environment bindings:

| Binding Name | Type | Classification | Description |
| :--- | :--- | :--- | :--- |
| `GATEWAY_TOKEN` | Secret | **Secret** | Bearer token required to authenticate requests. |
| `BREVO_API_KEY` | Secret | **Secret** | API key for Brevo transactional email endpoint. |
| `AUTHORIZED_SENDERS` | Variable | Configuration | Comma-separated list of permitted sender email addresses. |

> [!IMPORTANT]
> `GATEWAY_TOKEN` and `BREVO_API_KEY` are secrets and must **NEVER** be committed to source code or version control. Configure them in production using `wrangler secret put <KEY>`.

---

## Development & Testing

### Prerequisites

- [Node.js](https://nodejs.org/) (v18 or higher)
- [Cloudflare Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)

### Setup & Testing Commands

```bash
# Install dependencies
npm install

# Run TypeScript type check
npm run typecheck

# Run unit tests
npm run test

# Copy example environment file for local dev
cp .dev.vars.example .dev.vars

# Start local Wrangler dev server
npm run dev
```

---

## Deployment

Deploy to Cloudflare Workers using Wrangler:

```bash
# Set production secrets (first time only)
npx wrangler secret put GATEWAY_TOKEN
npx wrangler secret put BREVO_API_KEY

# Deploy Worker
npm run deploy
```

---

## Project Structure

```text
NorthSoft.MailGateway/
├── .dev.vars.example    # Example local environment bindings
├── .gitignore           # Git ignore rules
├── package.json         # Package configuration and scripts
├── tsconfig.json        # Strict TypeScript configuration
├── wrangler.json        # Cloudflare Worker deployment configuration
├── README.md            # Project overview and documentation
├── SECURITY.md          # Security policy and disclosure guide
├── docs/
│   └── API.md           # Complete REST API specification
├── src/
│   ├── index.ts         # Worker fetch entrypoint and route handler
│   ├── auth.ts          # Bearer authentication and timing-safe checks
│   ├── brevo.ts         # Upstream Brevo API client integration
│   ├── config.ts        # Gateway limits and CORS origin whitelist
│   ├── response.ts      # HTTP response helpers, headers, and CORS
│   ├── sanitizer.ts     # Parser-based allowlist HTML sanitization (sanitize-html)
│   ├── types.ts         # TypeScript interfaces and contracts
│   └── validation.ts    # Request schema, email, and header injection validation
└── tests/
    └── gateway.test.ts  # Automated unit test suite
```

---

## Author

**[Robert Jaśkowiec (rjaskowiec)](https://github.com/rjaskowiec)**

---

## License

*License decision pending.* (Contact author before distributing or reusing repository contents).
