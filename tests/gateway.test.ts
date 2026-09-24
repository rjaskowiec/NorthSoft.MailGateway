import assert from "node:assert";
import { describe, test } from "node:test";
import { extractBearerToken, secureTokenCompare } from "../src/auth.ts";
import worker from "../src/index.ts";
import { getCorsOrigin, isAllowedOrigin, json, securityHeaders } from "../src/response.ts";
import { sanitizeEmailHtml } from "../src/sanitizer.ts";
import type { Env } from "../src/types.ts";
import { containsHeaderInjection, isAuthorizedSender, isValidEmail, validatePayload } from "../src/validation.ts";

const mockEnv: Env = {
  GATEWAY_TOKEN: "test-gateway-token-12345",
  BREVO_API_KEY: "test-brevo-api-key-67890"
};

describe("Auth Module", () => {
  test("extractBearerToken parses valid bearer tokens", () => {
    assert.strictEqual(extractBearerToken("Bearer valid-token-123"), "valid-token-123");
    assert.strictEqual(extractBearerToken("Bearer   spaced-token  "), "spaced-token");
  });

  test("extractBearerToken rejects missing or malformed headers", () => {
    assert.strictEqual(extractBearerToken(null), null);
    assert.strictEqual(extractBearerToken("Basic user:pass"), null);
    assert.strictEqual(extractBearerToken("Bearer"), null);
    assert.strictEqual(extractBearerToken("Bearer "), null);
  });

  test("secureTokenCompare compares tokens in constant time", () => {
    assert.strictEqual(secureTokenCompare("secret123", "secret123"), true);
    assert.strictEqual(secureTokenCompare("secret123", "secret124"), false);
    assert.strictEqual(secureTokenCompare("short", "longer-token"), false);
  });
});

describe("Validation Module", () => {
  test("containsHeaderInjection detects CRLF characters", () => {
    assert.strictEqual(containsHeaderInjection("normal subject"), false);
    assert.strictEqual(containsHeaderInjection("subject\r\nBcc: hacker@example.com"), true);
    assert.strictEqual(containsHeaderInjection("subject\nContent-Type: text/html"), true);
  });

  test("isValidEmail validates standard addresses", () => {
    assert.strictEqual(isValidEmail("user@example.com"), true);
    assert.strictEqual(isValidEmail("no-reply@northsoft.is"), true);
    assert.strictEqual(isValidEmail("invalid-email"), false);
    assert.strictEqual(isValidEmail("user@domain\n.com"), false);
  });

  test("isAuthorizedSender validates single code-defined sender no-reply@northsoft.is", () => {
    assert.strictEqual(isAuthorizedSender("no-reply@northsoft.is"), true);
    assert.strictEqual(isAuthorizedSender("NO-REPLY@NORTHSOFT.IS"), true);
    assert.strictEqual(isAuthorizedSender("info@northsoft.is"), false);
    assert.strictEqual(isAuthorizedSender("unauthorized@evil.com"), false);
  });

  test("validatePayload enforces structural payload rules", () => {
    const validPayload = {
      from: { email: "no-reply@example.com", name: "Sender" },
      to: [{ email: "recipient@example.com", name: "Recipient" }],
      subject: "Test Subject",
      html: "<p>Hello</p>"
    };

    assert.strictEqual(validatePayload(validPayload).valid, true);

    const invalidFrom = { ...validPayload, from: { email: "invalid" } };
    assert.strictEqual(validatePayload(invalidFrom).valid, false);

    const emptyRecipients = { ...validPayload, to: [] };
    assert.strictEqual(validatePayload(emptyRecipients).valid, false);

    const injectionSubject = { ...validPayload, subject: "Test\r\nInjection" };
    assert.strictEqual(validatePayload(injectionSubject).valid, false);
  });
});

describe("Sanitizer Module - Security & Vector Tests", () => {
  test("strips dangerous tags: script, iframe, object, embed, form, svg, math", () => {
    const dirty = `
      <div>
        <script>alert('xss')</script>
        <script src="https://evil.com/xss.js"></script>
        <iframe src="https://evil.com"></iframe>
        <object data="evil.swf"></object>
        <embed src="evil.swf">
        <form action="https://evil.com/phish"><input type="text"></form>
        <svg onload="alert('svg')"><circle r="10"/></svg>
        <math><maction actiontype="statusline"></maction></math>
        <p>Safe Content</p>
      </div>
    `;
    const clean = sanitizeEmailHtml(dirty);
    assert.ok(!clean.includes("script"));
    assert.ok(!clean.includes("iframe"));
    assert.ok(!clean.includes("object"));
    assert.ok(!clean.includes("embed"));
    assert.ok(!clean.includes("form"));
    assert.ok(!clean.includes("svg"));
    assert.ok(!clean.includes("math"));
    assert.ok(clean.includes("<p>Safe Content</p>"));
  });

  test("strips inline event handlers: onerror, onclick, onload, onmouseover", () => {
    const dirty = '<img src="valid.png" onerror="alert(1)" onclick="steal()" onload="doBad()"><div onmouseover="xss()">Hover</div>';
    const clean = sanitizeEmailHtml(dirty);
    assert.ok(!clean.includes("onerror"));
    assert.ok(!clean.includes("onclick"));
    assert.ok(!clean.includes("onload"));
    assert.ok(!clean.includes("onmouseover"));
  });

  test("strips malicious URI schemes: javascript:, vbscript:, data:", () => {
    const dirty = `
      <a href="javascript:alert(1)">Link 1</a>
      <a href="java&#115;cript:alert(1)">Link 2</a>
      <a href=" JAVASCRIPT:alert(1)">Link 3</a>
      <a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Link 4</a>
      <img src="vbscript:msgbox(1)">
    `;
    const clean = sanitizeEmailHtml(dirty);
    assert.ok(!clean.includes("javascript:"));
    assert.ok(!clean.includes("vbscript:"));
    assert.ok(!clean.includes("data:text/html"));
  });

  test("strips HTML comments containing dangerous markup", () => {
    const dirty = '<!-- <script>alert(1)</script> --><p>Clean Text</p>';
    const clean = sanitizeEmailHtml(dirty);
    assert.strictEqual(clean, "<p>Clean Text</p>");
  });

  test("preserves legitimate transactional email HTML and international characters", () => {
    const validEmailHtml = `
      <html lang="pl">
        <head><title>Witaj w NorthSoft</title></head>
        <body>
          <h1 style="color: #333333;">Witaj, Robert!</h1>
          <p>Dziękujemy za rejestrację w serwisie. Twoje konto jest aktywne.</p>
          <table border="0" cellpadding="10" cellspacing="0" width="100%">
            <tr>
              <td align="center" bgcolor="#f8f9fa">
                <a href="https://northsoft.is/login" style="background-color: #007bff; color: white; padding: 10px 20px;">Zaloguj się</a>
              </td>
            </tr>
          </table>
          <p>Icelandic: Þóra & Jón - Ísland. Polish: Zażółć gęślą jaźń.</p>
        </body>
      </html>
    `;
    const clean = sanitizeEmailHtml(validEmailHtml);
    assert.ok(clean.includes("Witaj, Robert!"));
    assert.ok(clean.includes("Zażółć gęślą jaźń"));
    assert.ok(clean.includes("Þóra &amp; Jón - Ísland"));
    assert.ok(clean.includes("href=\"https://northsoft.is/login\""));
    assert.ok(clean.includes("<table"));
  });
});

describe("Response & CORS Module", () => {
  test("securityHeaders returns standard security headers", () => {
    const headers = securityHeaders();
    assert.strictEqual(headers["X-Content-Type-Options"], "nosniff");
    assert.strictEqual(headers["X-Frame-Options"], "DENY");
  });

  test("isAllowedOrigin validates explicit production, local dev, and preview origins", () => {
    const passOrigins = [
      "https://northsoft.is",
      "https://www.northsoft.is",
      "https://mail.northsoft.is",
      "https://photo.northsoft.is",
      "https://app.northsoft.is",
      "https://anything.northsoft.is",
      "http://localhost:3000",
      "https://feature-mail-gateway-migration-northsoft.robert-jaskowiec.workers.dev",
      "https://arbitrary.robert-jaskowiec.workers.dev"
    ];
    for (const origin of passOrigins) {
      assert.strictEqual(isAllowedOrigin(origin), true, `Should accept valid origin: ${origin}`);
    }

    const rejectOrigins = [
      "https://robert-jaskowiec.workers.dev",
      "http://feature-test.robert-jaskowiec.workers.dev",
      "https://robert-jaskowiec.workers.dev.evil.com",
      "https://northsoft.is.evil.com",
      "https://evil.example.com",
      "ftp://northsoft.is",
      "http://northsoft.is",
      "http://sub.northsoft.is"
    ];
    for (const origin of rejectOrigins) {
      assert.strictEqual(isAllowedOrigin(origin), false, `Should reject invalid origin: ${origin}`);
    }
  });

  test("getCorsOrigin verifies whitelisted origins", () => {
    const reqAllowed = new Request("https://mail.northsoft.is/v1/send", {
      headers: { Origin: "https://northsoft.is" }
    });
    assert.strictEqual(getCorsOrigin(reqAllowed), "https://northsoft.is");

    const reqDenied = new Request("https://mail.northsoft.is/v1/send", {
      headers: { Origin: "https://malicious-site.com" }
    });
    assert.strictEqual(getCorsOrigin(reqDenied), null);
  });

  test("json helper returns no-store and correct content type", () => {
    const res = json({ success: true });
    assert.strictEqual(res.headers.get("Content-Type"), "application/json; charset=utf-8");
    assert.strictEqual(res.headers.get("Cache-Control"), "no-store");
  });
});

describe("End-to-End Worker Fetch Handler", () => {
  const ctx = {} as ExecutionContext;

  test("GET / and GET /health return 200 status ok", async () => {
    const reqRoot = new Request("https://mail.northsoft.is/");
    const resRoot = await worker.fetch(reqRoot, mockEnv, ctx);
    assert.strictEqual(resRoot.status, 200);
    const bodyRoot = await resRoot.json() as Record<string, string>;
    assert.strictEqual(bodyRoot.status, "ok");

    const reqHealth = new Request("https://mail.northsoft.is/health");
    const resHealth = await worker.fetch(reqHealth, mockEnv, ctx);
    assert.strictEqual(resHealth.status, 200);
  });

  test("POST /v1/send rejects request missing Authorization header (403)", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ from: { email: "no-reply@example.com" } })
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    assert.strictEqual(res.status, 403);
  });

  test("POST /v1/send rejects invalid Bearer token (403)", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: {
        "Authorization": "Bearer wrong-token",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ from: { email: "no-reply@example.com" } })
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    assert.strictEqual(res.status, 403);
  });

  test("POST /v1/send rejects non-JSON Content-Type (415)", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: {
        "Authorization": "Bearer test-gateway-token-12345",
        "Content-Type": "text/plain"
      },
      body: "hello"
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    assert.strictEqual(res.status, 415);
  });

  test("POST /v1/send rejects unauthorized sender (403)", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: {
        "Authorization": "Bearer test-gateway-token-12345",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: { email: "unauthorized@evil.com" },
        to: [{ email: "user@example.com" }],
        subject: "Hello",
        html: "<p>Test</p>"
      })
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    assert.strictEqual(res.status, 403);
    const body = await res.json() as Record<string, string>;
    assert.strictEqual(body.error, "Sender is not authorized");
  });

  test("POST /v1/send accepts valid token with no-reply@northsoft.is", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: {
        "Authorization": "Bearer test-gateway-token-12345",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: { email: "no-reply@northsoft.is", name: "NorthSoft" },
        to: [{ email: "user@example.com" }],
        subject: "Gateway Test",
        html: "<p>Gateway Test</p>"
      })
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    // Since fetch to Brevo is mocked/failed or live mock, status should be 502 (rejected by Brevo/network) rather than 403 authorization failure
    assert.ok(res.status === 200 || res.status === 502);
  });

  test("POST /v1/send rejects non-authorized sender info@northsoft.is (403)", async () => {
    const req = new Request("https://mail.northsoft.is/v1/send", {
      method: "POST",
      headers: {
        "Authorization": "Bearer test-gateway-token-12345",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: { email: "info@northsoft.is", name: "NorthSoft Info" },
        to: [{ email: "user@example.com" }],
        subject: "Gateway Test Info",
        html: "<p>Gateway Test Info</p>"
      })
    });
    const res = await worker.fetch(req, mockEnv, ctx);
    assert.strictEqual(res.status, 403);
    const body = await res.json() as Record<string, string>;
    assert.strictEqual(body.error, "Sender is not authorized");
  });

  test("OPTIONS /v1/send returns 204 for allowed origin and 403 for disallowed origin", async () => {
    const reqAllowed = new Request("https://mail.northsoft.is/v1/send", {
      method: "OPTIONS",
      headers: { Origin: "https://northsoft.is" }
    });
    const resAllowed = await worker.fetch(reqAllowed, mockEnv, ctx);
    assert.strictEqual(resAllowed.status, 204);
    assert.strictEqual(resAllowed.headers.get("Access-Control-Allow-Origin"), "https://northsoft.is");

    const reqDenied = new Request("https://mail.northsoft.is/v1/send", {
      method: "OPTIONS",
      headers: { Origin: "https://malicious-site.com" }
    });
    const resDenied = await worker.fetch(reqDenied, mockEnv, ctx);
    assert.strictEqual(resDenied.status, 403);
  });
  test("OPTIONS /v1/send allows development subdomain and rejects invalid origins", async () => {
    const devOrigin = "https://test.robert-jaskowiec.workers.dev";
    const reqDevAllowed = new Request("https://mail.northsoft.is/v1/send", {
      method: "OPTIONS",
      headers: { Origin: devOrigin }
    });
    const resDevAllowed = await worker.fetch(reqDevAllowed, mockEnv, ctx);
    assert.strictEqual(resDevAllowed.status, 204);
    assert.strictEqual(resDevAllowed.headers.get("Access-Control-Allow-Origin"), devOrigin);

    const badOrigins = [
      "https://robert-jaskowiec.workers.dev",
      "http://test.robert-jaskowiec.workers.dev",
      "https://evil.workers.dev",
      "https://evil.robert-jaskowiec.workers.dev.attacker.com",
      "https://robert-jaskowiec.workers.dev.attacker.com"
    ];
    for (const o of badOrigins) {
      const req = new Request("https://mail.northsoft.is/v1/send", {
        method: "OPTIONS",
        headers: { Origin: o }
      });
      const res = await worker.fetch(req, mockEnv, ctx);
      assert.strictEqual(res.status, 403);
    }
  });
});
