export async function onRequest(context) {
  const { request, env } = context;

  // Only POST
  if (request.method !== "POST") {
    return json(
      { ok: false, error: "METHOD_NOT_ALLOWED", version: "api2-verify-email-v3" },
      405
    );
  }

  try {
    if (!env || !env.DB) {
      return json(
        { ok: false, error: "NO_DB_BINDING", version: "api2-verify-email-v3" },
        500
      );
    }

    const body = await safeJson(request);
    const email = (body.email || "").toString().trim().toLowerCase();
    const otp = (body.otp || body.code || "").toString().trim();

    if (!email || !otp) {
      return json(
        { ok: false, error: "MISSING_FIELDS", version: "api2-verify-email-v3" },
        400
      );
    }

    // Fetch latest OTP row for this email
    const row = await env.DB.prepare(
      `
      SELECT id, email, otp_hash, created_at, expires_at, used_at, attempts
      FROM email_otps
      WHERE email = ?
      ORDER BY created_at DESC
      LIMIT 1
    `
    )
      .bind(email)
      .first();

    if (!row) {
      return json(
        { ok: false, error: "OTP_NOT_FOUND", version: "api2-verify-email-v3" },
        400
      );
    }

    const now = new Date();
    const nowIso = now.toISOString();

    // used?
    if (row.used_at) {
      return json(
        { ok: false, error: "OTP_ALREADY_USED", version: "api2-verify-email-v3" },
        400
      );
    }

    // expired?
    const exp = row.expires_at ? new Date(row.expires_at) : null;
    if (exp && exp.getTime() <= now.getTime()) {
      return json(
        { ok: false, error: "OTP_EXPIRED", version: "api2-verify-email-v3" },
        400
      );
    }

    const attempts = Number(row.attempts || 0);
    if (attempts >= 6) {
      return json(
        { ok: false, error: "OTP_LOCKED", version: "api2-verify-email-v3" },
        429
      );
    }

    // Compare with multiple compatible hashing styles (حتى لو تغيّر الأسلوب سابقًا)
    const pepper = (env.OTP_PEPPER || "SANDOQ_OTP_v1").toString();
    const candidate1 = otp; // in case stored plaintext (not recommended but compatible)
    const candidate2 = await sha256Hex(otp + pepper);
    const candidate3 = await sha256Hex(email + "|" + otp + "|" + pepper);

    const stored = (row.otp_hash || "").toString();

    const ok =
      safeEq(stored, candidate1) ||
      safeEq(stored, candidate2) ||
      safeEq(stored, candidate3);

    if (!ok) {
      // increment attempts
      await env.DB.prepare(
        `UPDATE email_otps SET attempts = COALESCE(attempts,0) + 1 WHERE id = ?`
      )
        .bind(row.id)
        .run();

      return json(
        { ok: false, error: "OTP_INVALID", version: "api2-verify-email-v3" },
        400
      );
    }

    // Mark OTP used
    await env.DB.prepare(`UPDATE email_otps SET used_at = ? WHERE id = ?`)
      .bind(nowIso, row.id)
      .run();

    // Ensure user exists
    const user = await env.DB.prepare(
      `SELECT email FROM users WHERE email = ? LIMIT 1`
    )
      .bind(email)
      .first();

    if (!user) {
      return json(
        { ok: false, error: "USER_NOT_FOUND", version: "api2-verify-email-v3" },
        400
      );
    }

    // Mark email verified (حدّث الاثنين لأن عندك عمودين)
    await env.DB.prepare(
      `
      UPDATE users
      SET
        is_email_verified = 1,
        email_verified = 1,
        email_verified_at = ?
      WHERE email = ?
    `
    )
      .bind(nowIso, email)
      .run();

    // Create session token (مثل تدفق activate.html)
    const token = base64url(crypto.getRandomValues(new Uint8Array(32)));
    const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 days

    await env.DB.prepare(
      `INSERT INTO sessions (token, email, created_at, expires_at) VALUES (?,?,?,?)`
    )
      .bind(token, email, nowIso, expiresAt)
      .run();

    return json(
      { ok: true, token, email, version: "api2-verify-email-v3" },
      200
    );
  } catch (e) {
    console.error("verify-email error:", e);
    return json(
      { ok: false, error: "DB_SCHEMA_ERROR", detail: String(e), version: "api2-verify-email-v3" },
      500
    );
  }
}

// ---------- helpers ----------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

async function safeJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function safeEq(a, b) {
  // constant-ish time compare for strings
  a = (a ?? "").toString();
  b = (b ?? "").toString();
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function sha256Hex(input) {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
