# Chained Attack Demo — three Lows become one Critical

> ⚠️ **Intentionally vulnerable — for security education only. Do not deploy.**
> Runs on `127.0.0.1` only, with fake seeded data, and makes no outbound network calls.
> In the spirit of OWASP Juice Shop / DVWA / WebGoat.

This is a tiny Node + TypeScript + Express app that demonstrates **vulnerability chaining**:
three weaknesses that are each plausibly rated **Low** in isolation combine into a **Critical**
full **account takeover**.

The single-page UI shows a normal-looking app on the left and a guided **Attacker Console** on the
right that runs the exploit live against it, logging every HTTP request/response and a severity
meter that flips from *Low* to **CRITICAL** once all three links connect.

---

## Setup

```bash
npm install
npm run dev          # vulnerable mode — the chain works
```

Then open **http://localhost:3000**.

To watch the same chain **fail** once every issue is fixed:

```bash
npm run secure       # sets SECURE_MODE=true — all three // FIX paths active
```

Seeded fake accounts: `alice` / `alice-password-1`, `bob` / `bob-password-2`, `carol` / `carol-password-3`.
(Data lives in memory and resets when the server restarts.)

---

## Walkthrough

Run the three buttons in the Attacker Console top to bottom:

1. **Step 1 — Enumerate users.** Logs in with a bad password as `alice` (real) and `ghost` (fake).
   The responses differ (`401 "Incorrect password…"` vs `404 "No account found…"`, plus a timing
   gap), confirming `alice` is a real account. Target acquired.
2. **Step 2 — Spam the reset endpoint.** Fires 8 `POST /api/reset/request` for `alice`.
   None are blocked — so the attacker can mint a reset token at an instant *they* choose.
3. **Step 3 — Predict token & take over.** Triggers one reset at a recorded instant, reconstructs
   the token `sha1("alice" + unixSeconds)` offline (brute-forcing a ~4-second window),
   calls `POST /api/reset/confirm` to set a new password, and logs in as `alice`.
   → **Account takeover.** The severity meter turns red: **CRITICAL**.

In `npm run secure`, Step 1 shows identical responses, Step 2 gets throttled with `429`, and Step 3
cannot reconstruct the now-random token — the chain breaks at every link.

---

## The three vulnerabilities

Look for `// VULN 1/2/3` and `// FIX` comments in the source (`src/routes.ts`, `src/tokens.ts`).

| # | Vulnerability | Individual severity — and why it's Low | Contribution to the chain | Fix |
|---|---------------|----------------------------------------|---------------------------|-----|
| **1** | **Username enumeration** via login response (`src/routes.ts`, `POST /api/login`). Different message + HTTP status + response time for "unknown user" vs "wrong password". | **Low.** On its own it only reveals *which usernames exist*; no access is gained. | Names the victim — tells the attacker exactly which account to target with steps 2 and 3. | Return one **uniform** message and status for every failure (`401 "Invalid username or password."`) and do the **same constant-time work** in all branches (`crypto.timingSafeEqual`) so timing can't be used as an oracle. |
| **2** | **No rate limiting** on password reset (`src/routes.ts`, `POST /api/reset/request`). Unlimited calls, no throttle, lockout, backoff, or CAPTCHA. | **Low.** Alone it only lets an attacker spam reset emails — a nuisance, not a breach. | Lets the attacker trigger a reset **at an instant they control**, repeatedly and unobserved — the precondition for reconstructing a time-based token. | **Throttle** per-username *and* per-IP (e.g. max 3 / 60s → `429`), add exponential backoff / lockout, and CAPTCHA on repeated attempts. |
| **3** | **Predictable reset token** (`src/tokens.ts`). Token = `sha1(username + Math.floor(Date.now()/1000))`. | **Low.** Argued Low because "you'd need to know the exact second a reset was triggered *and* the username." | With (1) supplying the username and (2) letting the attacker pick the trigger instant, both inputs are known — so the token is fully **reconstructable offline**. | Generate tokens from a **CSPRNG** (`crypto.randomBytes(16)`), and enforce **short expiry + single use** and constant-time comparison (expiry/single-use are already on; randomness is the essential fix). |

### Why the chain escalates

Each weakness assumes the *other* weaknesses don't exist. The predictable token was rated Low
because an attacker "couldn't know the exact moment of a reset" — but the missing rate limit hands
them control of that moment, and enumeration hands them the username. Remove **any one** link and the
takeover fails (that's exactly what `SECURE_MODE` demonstrates). Chaining turns three "acceptable"
Lows into a Critical. **Severity must be assessed in combination, not just in isolation.**

---

## Safety guardrails

- Server binds to **`127.0.0.1`** only (`src/config.ts`) — never reachable from other machines.
- Persistent **"intentionally vulnerable"** banner in the UI.
- All data is **fake and seeded**; no real secrets; **no outbound network calls**.
- `SECURE_MODE=true` patches all three vulnerabilities so you can show the chain failing.

## Project layout

```
src/
  config.ts    SECURE_MODE flag, host/port, token TTL
  store.ts     in-memory seeded fake users
  tokens.ts    // VULN 3 weak token  +  // FIX random token
  routes.ts    // VULN 1 enumeration, // VULN 2 no rate limit, reset confirm
  server.ts    express app, binds 127.0.0.1
public/
  index.html   single-page UI: app + attacker console + severity meter + HTTP log
```

## Verifying the behavior

The security logic was validated with a standalone harness that runs the full chain in both modes
and asserts: vulnerable mode → enumeration leaks, no rate limit, token predicted, **takeover
achieved (CRITICAL)**; secure mode → uniform responses, throttled, random token, **takeover
blocked**. All checks pass. The equivalent live demo is what the Attacker Console runs in the browser.
