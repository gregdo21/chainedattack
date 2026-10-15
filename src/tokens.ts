import crypto from "crypto";
import { SECURE_MODE } from "./config";

// ---------------------------------------------------------------------------
// VULN 3: Predictable password-reset token.
//
// The token is derived from a weak, fully guessable source: the SHA-1 hash of
// the username concatenated with the current UNIX time in *seconds*. Both
// inputs are known or controllable by an attacker:
//   - the username is discovered via VULN 1 (enumeration)
//   - the second-precision timestamp is known because the attacker themselves
//     triggered the reset via VULN 2 (no rate limit) at a moment they control.
//
// So an attacker can regenerate the exact same token offline. Rated Low in
// isolation only because "you'd need to know the precise instant a reset was
// triggered" -- which stops being a barrier the moment the attacker is the one
// triggering it.
//
// FIX: use crypto.randomBytes (128 bits of CSPRNG output). The token is then
// unguessable regardless of what the attacker knows about username or timing.
// ---------------------------------------------------------------------------

/** Weak, predictable token generator (the vulnerable path). */
export function weakToken(username: string, unixSeconds: number): string {
  return crypto
    .createHash("sha1")
    .update(username + unixSeconds)
    .digest("hex");
}

/** Strong, unpredictable token generator (the fixed path). */
export function strongToken(): string {
  // FIX: 128 bits of cryptographically secure randomness.
  return crypto.randomBytes(16).toString("hex");
}

/**
 * Issue a reset token for a user.
 * Returns the token string. In vulnerable mode it is derived from username+time;
 * in secure mode it is random.
 */
export function issueResetToken(username: string, nowMs: number): string {
  if (SECURE_MODE) {
    return strongToken(); // FIX active
  }
  // VULN 3 active: predictable.
  return weakToken(username, Math.floor(nowMs / 1000));
}
