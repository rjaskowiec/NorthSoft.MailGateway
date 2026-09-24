import { CONFIG } from "./config.ts";
import type { BrevoPayload, BrevoResponse, SendEmailPayload } from "./types.ts";

export async function sendViaBrevo(
  payload: SendEmailPayload,
  sanitizedHtml: string,
  apiKey: string
): Promise<{ ok: boolean; messageId?: string | null; error?: string }> {
  const brevoPayload: BrevoPayload = {
    sender: {
      email: payload.from.email,
      name: payload.from.name || undefined
    },
    to: payload.to.map((recipient) => ({
      email: recipient.email,
      name: recipient.name || undefined
    })),
    subject: payload.subject,
    htmlContent: sanitizedHtml
  };

  if (payload.replyTo) {
    brevoPayload.replyTo = {
      email: payload.replyTo.email,
      name: payload.replyTo.name || undefined
    };
  }

  let brevoResponse: Response;

  try {
    brevoResponse = await fetch(CONFIG.brevoEndpoint, {
      method: "POST",
      headers: {
        "accept": "application/json",
        "api-key": apiKey,
        "content-type": "application/json"
      },
      body: JSON.stringify(brevoPayload)
    });
  } catch (error) {
    console.error("Brevo request failed:", error);
    return { ok: false, error: "Email provider unavailable" };
  }

  const brevoText = await brevoResponse.text();
  let brevoData: BrevoResponse | null = null;

  try {
    brevoData = brevoText ? (JSON.parse(brevoText) as BrevoResponse) : null;
  } catch {
    brevoData = null;
  }

  if (!brevoResponse.ok) {
    console.error("Brevo API error:", {
      status: brevoResponse.status,
      response: brevoData
    });

    return { ok: false, error: "Email provider rejected the request" };
  }

  return {
    ok: true,
    messageId: brevoData?.messageId || null
  };
}
