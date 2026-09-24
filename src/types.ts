export interface Env {
  BREVO_API_KEY: string;
  GATEWAY_TOKEN: string;
}

export interface EmailContact {
  email: string;
  name?: string;
}

export interface SendEmailPayload {
  from: EmailContact;
  to: EmailContact[];
  replyTo?: EmailContact;
  subject: string;
  html: string;
}

export interface ValidationResult {
  valid: boolean;
  error?: string;
}

export interface ApiResponse {
  success?: boolean;
  messageId?: string | null;
  error?: string;
  status?: string;
  service?: string;
}

export interface BrevoRecipient {
  email: string;
  name?: string;
}

export interface BrevoPayload {
  sender: BrevoRecipient;
  to: BrevoRecipient[];
  replyTo?: BrevoRecipient;
  subject: string;
  htmlContent: string;
}

export interface BrevoResponse {
  messageId?: string;
  code?: string;
  message?: string;
}
