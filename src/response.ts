import { CONFIG } from "./config.ts";
import type { ApiResponse } from "./types.ts";

export function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  };
}

export function getCorsOrigin(request: Request): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) {
    return null;
  }

  if ((CONFIG.corsAllowedOrigins as readonly string[]).includes(origin)) {
    return origin;
  }

  return null;
}

export function handleOptions(request: Request): Response {
  const origin = getCorsOrigin(request);

  if (!origin) {
    return new Response(null, {
      status: 403,
      headers: securityHeaders()
    });
  }

  return new Response(null, {
    status: 204,
    headers: {
      ...securityHeaders(),
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    }
  });
}

export function json(data: ApiResponse, status = 200, request: Request | null = null): Response {
  const headers: Record<string, string> = {
    ...securityHeaders(),
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  };

  const origin = request ? getCorsOrigin(request) : null;

  if (origin) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Vary"] = "Origin";
  }

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}
