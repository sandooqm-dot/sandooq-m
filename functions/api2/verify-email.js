export async function onRequest(context) {
  const { request, env } = context;

  // Only POST
  if (request.method !== "POST") {
    return json({ ok: false, error: "METHOD_NOT_ALLOWED" }, 405);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "BAD_JSON" }, 400);
  }

  let email = (body?.email ?? "").toString().trim().toLowerCase();
  let otpRaw = body?.otp;

  // otp may come as number, string, etc.
  let otp = (otpRaw ?? "").toString().trim();
  // keep digits only (prevents spaces or formatting issues)
  otp = otp.replace(/[^\d]/g, "");

  if (!email || !otp || otp.length !== 6) {
    return json({ ok: false, error: "BAD_INPUT" }, 400);
  }

  if (!env?.DB) {
    return json({ ok: false, error: "NO_DB_BINDING" }, 500);
  }

  const nowIso = new Date().toISOString();
  const pepper = (env?.OTP_PEPPER ?? "").toString();

  try {
    // ✅ ALWAYS take the latest OTP that is not used yet
    const row = await env.DB
      .prepare(
        `
        SELECT id, otp_hash, expires_at, used_at, attempts
        FROM email_otps
        WHERE email = ? AND used_at IS NULL
        ORDER BY id DESC
        LIMIT 1
      `
      )
      .bind(email)
      .first();

    if (!row) {
      return json({ ok: false, error: "OTP_NOT_FOUND" }, 400);
    }

    // Expiry check (expires_at is TEXT ISO)
    const exp = Date.parse(row.expires_at);
    if (!Number.isFinite(exp) || exp < Date.now()) {
      return json({ ok: false, error: "OTP_EXPIRED" }, 400);
    }

    const stored = (row.otp_hash ?? "").toString().trim();

    // Some deployments might store with prefixes like "sha256:<hash>"
    const storedClean = stored.includes(":") ? stored.split(":").pop().trim() : stored;

    // Generate multiple candidate hashes to match whatever register.js stored
    const candidates = [];

    // raw comparisons (just in case someone stored raw OTP – shouldn’t happen but we support it)
    candidates.push(otp);

    // sha256 candidates (hex + base64)
    for (const s of [
      otp,
      otp + pepper,
      `${otp}:${pepper}`,
      `${email}:${otp}`,
      `${email}:${otp}:${pepper}`,
      `${email}|${otp}`,
      `${email}|${otp}|${pepper}`,
    ]) {
      const hHex = await sha256Hex(s);
      const hB64 = await sha256B64(s);
      candidates.push(hHex, hB64);
    }

    const ok = candidates.some((c) => safeEqual((c ?? "").toString(), storedClean));

    if (!ok) {
      // Increment attempts
      await env.DB
        .prepare(`UPDATE email_otps SET attempts = COALESCE(attempts,0) + 1 WHERE id = ?`)
        .bind(row.id)
        .run();

      return json({ ok: false, error: "OTP_INVALID" }, 400);
    }

    // Mark user verified + consume otp
    await env.DB
      .prepare(`UPDATE users SET is_email_verified = 1 WHERE email = ?`)
      .bind(email)
      .run();

    await env.DB
      .prepare(`UPDATE email_otps SET used_at = ? WHERE id = ?`)
      .bind(nowIso, row.id)
      .run();

    return json({ ok: true }, 200);
  } catch (e) {
    console.error("verify-email error:", e);
    return json({ ok: false, error: "SERVER_ERROR" }, 500);
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

function safeEqual(a, b) {
  // constant-ish time compare
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}

async function sha256Hex(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(buf);
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}

async function sha256B64(str) {
  const data = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  // btoa expects latin1
  return btoa(bin);
}
