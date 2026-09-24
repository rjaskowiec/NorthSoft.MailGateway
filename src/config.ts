export const CONFIG = {
  maxBodyBytes: 200_000,
  maxHtmlBytes: 150_000,
  maxSubjectLength: 998,
  maxRecipients: 10,
  maxNameLength: 200,
  maxEmailLength: 320,

  brevoEndpoint: "https://api.brevo.com/v3/smtp/email",

  authorizedSenders: [
    "no-reply@northsoft.is"
  ],

  corsAllowedOrigins: [
    "https://northsoft.is",
    "https://www.northsoft.is",
    "https://mail.northsoft.is",
    "https://photo.northsoft.is",
    "http://localhost:3000"
  ]
} as const;
