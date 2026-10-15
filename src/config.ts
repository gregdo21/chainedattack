// Central config. Flip SECURE_MODE to patch all three vulnerabilities at once.
//
//   npm run dev      -> vulnerable (default), the chain works
//   npm run secure   -> SECURE_MODE=true, every // FIX is active, the chain fails
//
export const SECURE_MODE = process.env.SECURE_MODE === "true";

export const PORT = 3000;
export const HOST = "127.0.0.1"; // GUARDRAIL: localhost only, never exposed externally.

// Reset tokens are valid for this many seconds after issue.
export const RESET_TOKEN_TTL_SECONDS = 900; // 15 minutes
