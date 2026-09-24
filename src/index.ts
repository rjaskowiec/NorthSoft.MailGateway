import { extractBearerToken, secureTokenCompare } from "./auth.ts";
import { sendViaBrevo } from "./brevo.ts";
import { CONFIG } from "./config.ts";
import { handleOptions, json } from "./response.ts";
import { sanitizeEmailHtml } from "./sanitizer.ts";
import type { Env, SendEmailPayload } from "./types.ts";
import { parseAuthorizedSenders, validatePayload } from "./validation.ts";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error("Unhandled gateway error:", error);
      return json({ success: false, error: "Internal server error" }, 500, request);
    }
  }
};

async function handleRequest(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return handleOptions(request);
  }

  if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
    return json({ status: "ok", service: "mail-gateway" }, 200, request);
  }

  if (url.pathname === "/v1/send") {
    if (request.method !== "POST") {
      return json({ success: false, error: "Method not allowed" }, 405, request);
    }
    return handleSend(request, env);
  }

  return json({ success: false, error: "Not found" }, 404, request);
}

async function handleSend(request: Request, env: Env): Promise<Response> {
  if (!env.GATEWAY_TOKEN || !env.BREVO_API_KEY || !env.AUTHORIZED_SENDERS) {
    console.error("Missing required environment secret bindings");
    return json({ success: false, error: "Service unavailable" }, 503, request);
  }

  const token = extractBearerToken(request.headers.get("Authorization"));
  if (!token || !secureTokenCompare(token, env.GATEWAY_TOKEN)) {
    return json({ success: false, error: "Forbidden" }, 403, request);
  }

  const contentType = request.headers.get("Content-Type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ success: false, error: "Content-Type must be application/json" }, 415, request);
  }

  const contentLengthHeader = request.headers.get("Content-Length");
  if (contentLengthHeader) {
    const contentLength = Number(contentLengthHeader);
    if (Number.isFinite(contentLength) && contentLength > CONFIG.maxBodyBytes) {
      return json({ success: false, error: "Request body too large" }, 413, request);
    }
  }

  let payload: SendEmailPayload;
  try {
    payload = (await request.json()) as SendEmailPayload;
  } catch {
    return json({ success: false, error: "Invalid JSON" }, 400, request);
  }

  const validation = validatePayload(payload);
  if (!validation.valid) {
    return json({ success: false, error: validation.error }, 400, request);
  }

  const authorizedSenders = parseAuthorizedSenders(env.AUTHORIZED_SENDERS);
  const senderEmail = payload.from.email.toLowerCase();

  if (!authorizedSenders.includes(senderEmail)) {
    return json({ success: false, error: "Sender is not authorized" }, 403, request);
  }

  const sanitizedHtml = sanitizeEmailHtml(payload.html);
  if (!sanitizedHtml) {
    return json({ success: false, error: "Invalid HTML content" }, 400, request);
  }

  const result = await sendViaBrevo(payload, sanitizedHtml, env.BREVO_API_KEY);

  if (!result.ok) {
    return json({ success: false, error: result.error }, 502, request);
  }

  return json({ success: true, messageId: result.messageId }, 200, request);
}
