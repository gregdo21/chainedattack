import { Router, Request, Response } from "express";
import crypto from "crypto";
import { SECURE_MODE, RESET_TOKEN_TTL_SECONDS } from "./config";
import { getUser, userExists } from "./store";
import { issueResetToken } from "./tokens";

export const api = Router();

// Small helper so timing-based demos are visible.
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Tracks how many reset requests each username has received (used only to
// visibly demonstrate the presence/absence of rate limiting).
const resetRequestLog = new Map<string, number[]>(); // username -> epoch ms list

// ===========================================================================
// VULN 1: Username enumeration via the login response.
//
// The endpoint returns a DIFFERENT message (and a different HTTP status, and a
// measurable timing difference) depending on whether the username exists. That
// lets an attacker map out valid accounts one probe at a time.
//
// Low in isolation: on its own it only reveals which usernames are real -- no
// access is gained. It becomes dangerous only as the first link of the chain,
// telling the attacker exactly which account to target next.
//
// FIX (SECURE_MODE): return one identical message + status for every failure,
// and perform the same constant-time work in all branches so response time
// cannot be used as an oracle either.
// ===========================================================================
api.post("/login", async (req: Request, res: Response) => {
  const { username, password } = req.body ?? {};
  const user = getUser(String(username ?? ""));

  if (SECURE_MODE) {
    // FIX: uniform response + constant-time comparison, regardless of branch.
    const known = user?.password ?? "\0".repeat(32);
    const supplied = String(password ?? "");
    // Always compare against a same-length buffer to avoid length/timing leaks.
    const a = Buffer.from(known.padEnd(64, "\0").slice(0, 64));
    const b = Buffer.from(supplied.padEnd(64, "\0").slice(0, 64));
    const match = user ? crypto.timingSafeEqual(a, b) && supplied === user.password : false;
    if (match) {
      return res.json({ ok: true, session: fakeSession(user!.username), message: "Logged in." });
    }
    // Same message + same status whether or not the user exists.
    return res.status(401).json({ ok: false, message: "Invalid username or password." });
  }

  // ---- VULNERABLE PATH ----
  if (!user) {
    // Distinguishable "unknown user" response (fast path, 404).
    return res.status(404).json({ ok: false, message: `No account found for username "${username}".` });
  }
  // Existing user: do a little extra "work", creating a measurable timing gap
  // on top of the distinguishable message.
  await sleep(120);
  if (password !== user.password) {
    return res.status(401).json({ ok: false, message: "Incorrect password for that account." });
  }
  return res.json({ ok: true, session: fakeSession(user.username), message: "Logged in." });
});

// ===========================================================================
// VULN 2: No rate limiting on password-reset requests.
//
// POST /api/reset/request can be called an unlimited number of times, from the
// same client, with no throttle, lockout, backoff, or CAPTCHA.
//
// Low in isolation: without another weakness this just lets an attacker spam
// reset emails to a user -- annoying, not a breach.
//
// In the chain it is the enabler: it lets the attacker fire a reset at an exact
// instant THEY choose (and repeat freely), which is precisely what makes the
// predictable token (VULN 3) reconstructable.
//
// FIX (SECURE_MODE): throttle per-username (and in real life per-IP) and return
// 429 once the limit is exceeded.
// ===========================================================================
const RESET_RATE_LIMIT = 3; // allowed requests
const RESET_RATE_WINDOW_MS = 60_000; // per 60s

api.post("/reset/request", (req: Request, res: Response) => {
  const username = String(req.body?.username ?? "");
  const now = Date.now();

  // Record the attempt (for the "requests fired / blocked" counter in the UI).
  const log = resetRequestLog.get(username) ?? [];
  const recent = log.filter((t) => now - t < RESET_RATE_WINDOW_MS);

  if (SECURE_MODE) {
    // FIX: enforce a per-username throttle.
    if (recent.length >= RESET_RATE_LIMIT) {
      resetRequestLog.set(username, recent);
      return res.status(429).json({
        ok: false,
        blocked: true,
        message: "Too many reset requests. Try again later.",
      });
    }
  }

  recent.push(now);
  resetRequestLog.set(username, recent);

  // Only issue a real token for real users, but ALWAYS return the same generic
  // message so this endpoint itself doesn't leak account existence.
  const user = getUser(username);
  if (user) {
    user.resetToken = issueResetToken(username, now); // VULN 3 lives here
    user.resetExpiresAt = now + RESET_TOKEN_TTL_SECONDS * 1000;
    user.resetTokenUsed = false;
    // NOTE: a real app emails this token; it is never returned in the response.
  }

  return res.json({
    ok: true,
    blocked: false,
    requestsInWindow: recent.length,
    message: "If that account exists, a password reset link has been sent.",
  });
});

// ===========================================================================
// Complete a password reset. Validates the token, then sets the new password.
// This endpoint is not itself the vulnerability -- it's the payoff: because the
// token (VULN 3) is predictable, the attacker can call this with a token they
// regenerated themselves and never received by email.
//
// Single-use + expiry are enforced in BOTH modes (good practice); they simply
// aren't enough on their own when the token is guessable.
// ===========================================================================
api.post("/reset/confirm", (req: Request, res: Response) => {
  const username = String(req.body?.username ?? "");
  const token = String(req.body?.token ?? "");
  const newPassword = String(req.body?.newPassword ?? "");
  const user = getUser(username);

  if (!user || !user.resetToken) {
    return res.status(400).json({ ok: false, message: "No active reset for that account." });
  }
  if (user.resetTokenUsed) {
    return res.status(400).json({ ok: false, message: "That reset token has already been used." });
  }
  if (user.resetExpiresAt && Date.now() > user.resetExpiresAt) {
    return res.status(400).json({ ok: false, message: "That reset token has expired." });
  }
  // Constant-time token comparison (correct in both modes).
  const expected = Buffer.from(user.resetToken);
  const provided = Buffer.from(token.padEnd(user.resetToken.length, "\0").slice(0, user.resetToken.length));
  const tokenOk = expected.length === provided.length && crypto.timingSafeEqual(expected, provided);
  if (!tokenOk) {
    return res.status(400).json({ ok: false, message: "Invalid reset token." });
  }

  user.password = newPassword;
  user.resetTokenUsed = true;
  user.resetToken = null;
  user.resetExpiresAt = null;
  return res.json({ ok: true, message: `Password for "${username}" has been changed.` });
});

// Reports current mode so the UI can label itself accurately.
api.get("/mode", (_req: Request, res: Response) => {
  res.json({ secureMode: SECURE_MODE });
});

// A fake, non-sensitive session marker. Not a real credential.
function fakeSession(username: string): string {
  return `demo-session-for-${username}`;
}
