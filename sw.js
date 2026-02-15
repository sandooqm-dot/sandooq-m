/* Service Worker — Sabaq Alhorof
   - Precaches core files (maps/questions/font/logo)
   - Fast offline + safer updates (iOS-friendly)
   - Cache versioning: غيّر CACHE_VERSION لأي تحديث بالملفات
*/

const CACHE_PREFIX  = "sabaq-alhorof";
const CACHE_VERSION = "2026-02-15-2"; // ✅ جديد لأننا عدّلنا sw.js
const PRECACHE_NAME = `${CACHE_PREFIX}-precache-${CACHE_VERSION}`;
const RUNTIME_NAME  = `${CACHE_PREFIX}-runtime-${CACHE_VERSION}`;

// لو فتح صفحة غير موجودة بالكاش وهو أوفلاين، نرجعه لهذي
const OFFLINE_FALLBACK_PAGE = "index.html";

// الملفات الأساسية اللي نبغاها تشتغل أوفلاين
const PRECACHE_URLS = [
  "./",
  "index.html",
  "join.html",
  "game_full.html",
  "game.html",              // إذا موجود (احتياط)
  "questions_bank.js",
  "AA-GALAXY.otf",
  "logo.png",
  "maps/map1.jpeg",
  "maps/map2.jpeg",
  "maps/map3.jpeg"
];

// ✅ لا نخلي install يفشل لو ملف غير موجود
async function safePrecache(cache, urls){
  await Promise.all(urls.map(async (url) => {
    try{
      // نخزن بمفتاح URL ثابت (string) عشان match يكون مضمون
      const res = await fetch(url, { cache: "no-store" });
      if(res && res.ok){
        await cache.put(url, res);
      }
    }catch(e){}
  }));
}

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(PRECACHE_NAME);
    await safePrecache(cache, PRECACHE_URLS);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    // تنظيف أي كاش قديم
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => {
      if(k.startsWith(CACHE_PREFIX) && k !== PRECACHE_NAME && k !== RUNTIME_NAME){
        return caches.delete(k);
      }
    }));

    // Navigation Preload (يساعد iOS/سفاري أحيانًا)
    try{
      if(self.registration.navigationPreload){
        await self.registration.navigationPreload.enable();
      }
    }catch(e){}

    await self.clients.claim();
  })());
});

// (اختياري) لو بغينا لاحقًا نرسل رسالة من الصفحة لتحديث فوري
self.addEventListener("message", (event) => {
  if(event.data && event.data.type === "SKIP_WAITING"){
    self.skipWaiting();
  }
});

async function cachePut(cacheName, requestKey, response){
  try{
    if(!response || !response.ok) return;
    const cache = await caches.open(cacheName);
    await cache.put(requestKey, response);
  }catch(e){}
}

async function fromCache(request){
  // ignoreSearch عشان لو صار ?v=xx مستقبلاً ما يخرب
  const hit = await caches.match(request, { ignoreSearch: true });
  return hit || null;
}

function withTimeout(promise, ms){
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then((v)=>{ clearTimeout(t); resolve(v); })
           .catch((e)=>{ clearTimeout(t); reject(e); });
  });
}

// للصفحات (HTML): Network-first لكن إذا النت بطيء نعطي الكاش بسرعة
async function navigateStrategy(event){
  const req = event.request;

  const cached = await fromCache(req);

  const networkPromise = (async () => {
    // لو فيه preload response استخدمه
    try{
      const preloaded = await event.preloadResponse;
      if(preloaded){
        await cachePut(RUNTIME_NAME, req, preloaded.clone());
        return preloaded;
      }
    }catch(e){}

    const res = await fetch(req);
    await cachePut(RUNTIME_NAME, req, res.clone());
    return res;
  })();

  // إذا ما عندنا كاش: حاول شبكة، وإذا فشل رجّع fallback
  if(!cached){
    try{
      return await networkPromise;
    }catch(e){
      return (await fromCache(OFFLINE_FALLBACK_PAGE)) || new Response("Offline", { status: 503 });
    }
  }

  // إذا عندنا كاش: نعطي الشبكة فرصة قصيرة ثم نرجع الكاش لو تأخرت/فشلت
  try{
    return await withTimeout(networkPromise, 2500);
  }catch(e){
    return cached;
  }
}

// للملفات الثابتة: Cache-first
async function cacheFirst(request){
  const cached = await fromCache(request);
  if(cached) return cached;

  const res = await fetch(request);
  await cachePut(RUNTIME_NAME, request, res.clone());
  return res;
}

// لباقي الطلبات: Network-first مع fallback للكاش
async function networkFirst(request){
  try{
    const res = await fetch(request);
    await cachePut(RUNTIME_NAME, request, res.clone());
    return res;
  }catch(e){
    const cached = await fromCache(request);
    if(cached) return cached;
    throw e;
  }
}

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // فقط GET
  if(req.method !== "GET") return;

  const url = new URL(req.url);

  // نخلي أي طلب خارج الدومين يروح طبيعي بدون تدخل
  if(url.origin !== self.location.origin) return;

  // تفادي خطأ (only-if-cached) لبعض المتصفحات
  if(req.cache === "only-if-cached" && req.mode !== "same-origin") return;

  // صفحات HTML (navigation أو Accept: text/html)
  const accept = req.headers.get("accept") || "";
  if(req.mode === "navigate" || accept.includes("text/html")){
    event.respondWith(navigateStrategy(event));
    return;
  }

  // Static assets: Cache-first
  const dest = req.destination; // "image" | "script" | "style" | "font" | ...
  if(dest === "image" || dest === "font" || dest === "script" || dest === "style"){
    event.respondWith(cacheFirst(req));
    return;
  }

  // باقي الطلبات: Network-first
  event.respondWith(networkFirst(req));
});
