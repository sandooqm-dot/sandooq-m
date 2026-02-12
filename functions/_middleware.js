// functions/_middleware.js
// يحمي /app فقط، ويترك /activate و /api2 تشتغل بدون تحويل
// إصدار 2

function getCookie(req, name) {
  const cookie = req.headers.get("Cookie") || "";
  const parts = cookie.split(";");
  for (const p of parts) {
    const [k, ...rest] = p.trim().split("=");
    if (k === name) return rest.join("=") || "";
  }
  return "";
}

function redirect(to) {
  return Response.redirect(to, 302);
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ✅ لا نحمي API أبداً (عشان لا يصير Loop)
  if (path.startsWith("/api2/")) {
    return context.next();
  }

  // ✅ لا نحمي صفحة التفعيل أبداً (عشان لا يصير Loop)
  if (path === "/activate" || path === "/activate/" || path === "/activate.html") {
    return context.next();
  }

  // ✅ الحماية فقط على /app و /app/*
  if (!path.startsWith("/app")) {
    return context.next();
  }

  // 1) لازم يكون عنده جلسة (Cookie)
  const token = (getCookie(request, "sandooq_session_v1") || "").trim();
  const deviceId = (getCookie(request, "sandooq_device_id_v1") || "").trim();

  if (!token) {
    const next = encodeURIComponent(path + url.search);
    return redirect(`${url.origin}/activate?next=${next}`);
  }

  // 2) نتحقق من /api2/me
  const meRes = await fetch(`${url.origin}/api2/me`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${token}`,
      "x-device-id": deviceId,
    },
    body: "{}",
  });

  if (!meRes.ok) {
    const next = encodeURIComponent(path + url.search);
    return redirect(`${url.origin}/activate?next=${next}`);
  }

  const me = await meRes.json().catch(() => null);

  // لازم يكون مسجل + بريد مؤكد
  if (!me?.ok || !me?.verified) {
    const next = encodeURIComponent(path + url.search);
    return redirect(`${url.origin}/activate?next=${next}`);
  }

  // لازم يكون مفعل
  if (!me?.activated) {
    const next = encodeURIComponent(path + url.search);
    return redirect(`${url.origin}/activate?next=${next}`);
  }

  // ✅ كله تمام → يكمل للعبة
  return context.next();
}
