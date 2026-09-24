import { CONFIG } from "./config.ts";
import type { ValidationResult } from "./types.ts";

export function containsHeaderInjection(value: string): boolean {
  return /[\r\n]/.test(value);
}

export function isValidEmail(email: string): boolean {
  if (typeof email !== "string") {
    return false;
  }

  const value = email.trim();

  if (!value || value.length > CONFIG.maxEmailLength) {
    return false;
  }

  if (containsHeaderInjection(value)) {
    return false;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(value);
}

export function parseAuthorizedSenders(value: string): string[] {
  return value
    .split(",")
    .map((email) => email.trim().toLowerCase())
    .filter(Boolean);
}

export function validatePayload(payload: unknown): ValidationResult {
  if (!payload || typeof payload !== "object") {
    return { valid: false, error: "Request body must be an object" };
  }

  const data = payload as Record<string, unknown>;

  // Sender validation
  if (!data.from || typeof data.from !== "object") {
    return { valid: false, error: "Missing from" };
  }

  const fromObj = data.from as Record<string, unknown>;

  if (typeof fromObj.email !== "string" || !isValidEmail(fromObj.email)) {
    return { valid: false, error: "Invalid from.email" };
  }

  if (fromObj.email.length > CONFIG.maxEmailLength) {
    return { valid: false, error: "from.email is too long" };
  }

  if (
    fromObj.name !== undefined &&
    (typeof fromObj.name !== "string" || fromObj.name.length > CONFIG.maxNameLength)
  ) {
    return { valid: false, error: "Invalid from.name" };
  }

  // Recipients validation
  if (!Array.isArray(data.to)) {
    return { valid: false, error: "to must be an array" };
  }

  if (data.to.length === 0) {
    return { valid: false, error: "At least one recipient is required" };
  }

  if (data.to.length > CONFIG.maxRecipients) {
    return { valid: false, error: `Maximum ${CONFIG.maxRecipients} recipients allowed` };
  }

  for (const recipient of data.to) {
    if (!recipient || typeof recipient !== "object") {
      return { valid: false, error: "Invalid recipient" };
    }

    const recObj = recipient as Record<string, unknown>;

    if (typeof recObj.email !== "string" || !isValidEmail(recObj.email)) {
      return { valid: false, error: "Invalid recipient email" };
    }

    if (recObj.email.length > CONFIG.maxEmailLength) {
      return { valid: false, error: "Recipient email is too long" };
    }

    if (
      recObj.name !== undefined &&
      (typeof recObj.name !== "string" || recObj.name.length > CONFIG.maxNameLength)
    ) {
      return { valid: false, error: "Invalid recipient name" };
    }
  }

  // Reply-To validation
  if (data.replyTo !== undefined) {
    if (!data.replyTo || typeof data.replyTo !== "object") {
      return { valid: false, error: "Invalid replyTo" };
    }

    const replyObj = data.replyTo as Record<string, unknown>;

    if (typeof replyObj.email !== "string" || !isValidEmail(replyObj.email)) {
      return { valid: false, error: "Invalid replyTo.email" };
    }

    if (replyObj.email.length > CONFIG.maxEmailLength) {
      return { valid: false, error: "replyTo.email is too long" };
    }

    if (
      replyObj.name !== undefined &&
      (typeof replyObj.name !== "string" || replyObj.name.length > CONFIG.maxNameLength)
    ) {
      return { valid: false, error: "Invalid replyTo.name" };
    }
  }

  // Subject validation
  if (typeof data.subject !== "string" || data.subject.trim().length === 0) {
    return { valid: false, error: "Missing subject" };
  }

  if (data.subject.length > CONFIG.maxSubjectLength) {
    return { valid: false, error: "Subject is too long" };
  }

  if (containsHeaderInjection(data.subject)) {
    return { valid: false, error: "Invalid subject" };
  }

  // HTML content validation
  if (typeof data.html !== "string" || data.html.trim().length === 0) {
    return { valid: false, error: "Missing html" };
  }

  if (new TextEncoder().encode(data.html).length > CONFIG.maxHtmlBytes) {
    return { valid: false, error: "HTML content is too large" };
  }

  return { valid: true };
}
