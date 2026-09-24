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

export function isAllowedOrigin(origin: string): boolean {
  if (!origin || typeof origin !== "string") {
    return false;
  }

  // 1. Explicit static allowed origins (e.g. http://localhost:3000)
  if ((CONFIG.corsAllowedOrigins as readonly string[]).includes(origin)) {
    return true;
  }

  try {
    const url = new URL(origin);
    if (url.protocol !== "https:") {
      return false;
    }
    const hostname = url.hostname;

    // 2. Allow https://northsoft.is and any HTTPS subdomain https://*.northsoft.is
    if (hostname === "northsoft.is" || hostname.endsWith(".northsoft.is")) {
      return true;
    }

    // 3. Cloudflare Worker preview subdomains: https://<SUBDOMAIN>.robert-jaskowiec.workers.dev
    const cfSuffix = ".robert-jaskowiec.workers.dev";
    if (hostname.endsWith(cfSuffix)) {
      const prefix = hostname.slice(0, -cfSuffix.length);
      if (prefix && !prefix.endsWith(".")) {
        return true;
      }
    }

    return false;
  } catch {
    return false;
  }
}

export function getCorsOrigin(request: Request): string | null {
  const origin = request.headers.get("Origin");
  if (!origin || !isAllowedOrigin(origin)) {
    return null;
  }
  return origin;
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
