/* Service Worker — Sabaq Alhorof
   - Precaches core files (maps/questions/font/logo)
   - Fast offline + safer updates (iOS-friendly)
   - Cache versioning: يقرأها تلقائيًا من ?v= في رابط sw.js (أفضل)
*/

const CACHE_PREFIX = "sabaq-alhorof";

// ✅ يقرأ الإصدار من رابط sw.js نفسه: sw.js?v=ASSET_VERSION
const SW_URL = new URL(self.location.href);
const CACHE_VERSION = SW_URL.searchParams.get("v") || "2026-02-15-2";

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
      // نخلي التحميل "مكسور كاش" من الطرف (CDN/Browser) بدون ما نخزن المفتاح بالـ query
      const fetchUrl =
        (typeof url === "string" && !/^https?:\/\//i.test(url) && url !== "./")
          ? `${url}${url.includes("?") ? "&" : "?"}v=${encodeURIComponent(CACHE_VERSION)}`
          : url;

      const res = await fetch(fetchUrl, { cache: "no-store" });

      // نسمح بتخزين OPAQUE (للصور/بعض الطلبات) + OK
      if(res && (res.ok || res.type === "opaque")){
        // نخزن بمفتاح URL ثابت (بدون v=) عشان match يكون مضمون داخل نفس إصدار الـ SW
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
    if(!response) return;
    if(!(response.ok || response.type === "opaque")) return;
    const cache = await caches.open(cacheName);
    await cache.put(requestKey, response);
  }catch(e){}
}

async function fromCache(request, opts){
  // افتراضيًا: لا نتجاهل query (لكن نقدر نفعلها بالـ opts لو احتجنا)
  const hit = await caches.match(request, opts || undefined);
  return hit || null;
}

function withTimeout(promise, ms){
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then((v)=>{ clearTimeout(t); resolve(v); })
           .catch((e)=>{ clearTimeout(t); reject(e); });
  });
}

// Stale-While-Revalidate (مفيد لملفات ثقيلة مثل بنك الأسئلة وملفات الـ modules)
async function staleWhileRevalidate(event, request){
  const cached = await fromCache(request);
  const fetchPromise = (async () => {
    const res = await fetch(request);
    await cachePut(RUNTIME_NAME, request, res.clone());
    return res;
  })();

  if(cached){
    event.waitUntil(fetchPromise.catch(()=>{}));
    return cached;
  }

  return fetchPromise;
}

// للصفحات (HTML): Network-first لكن إذا النت بطيء نعطي الكاش بسرعة
async function navigateStrategy(event){
  const req = event.request;

  // هنا نتجاهل query لأن بعض الروابط قد تجي بباراميترات، ونبغى نفس الصفحة تنفتح أوفلاين
  const cached = await fromCache(req, { ignoreSearch: true });

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
      return (await fromCache(OFFLINE_FALLBACK_PAGE, { ignoreSearch: true })) || new Response("Offline", { status: 503 });
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
  const cached = await fromCache(request, { ignoreSearch: true });
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
    const cached = await fromCache(request, { ignoreSearch: true });
    if(cached) return cached;
    throw e;
  }
}

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // فقط GET
  if(req.method !== "GET") return;

  const url = new URL(req.url);

  // تفادي خطأ (only-if-cached) لبعض المتصفحات
  if(req.cache === "only-if-cached" && req.mode !== "same-origin") return;

  // ✅ (تقوية مهمة) اسمح بكاش Firebase Modules من gstatic عشان الأوفلاين ما يطلع بياض
  const isGstaticFirebase =
    url.origin === "https://www.gstatic.com" &&
    url.pathname.startsWith("/firebasejs/");

  // ✅ QR (اختياري): ما هو ضروري للأوفلاين، بس ما يضر نخليه SWR إذا تبغى
  const isQrServer =
    url.origin === "https://api.qrserver.com" &&
    url.pathname.startsWith("/v1/create-qr-code/");

  // لو خارج الدومين وماهو ضمن القائمة: خلّه طبيعي
  const isSameOrigin = (url.origin === self.location.origin);
  if(!isSameOrigin && !isGstaticFirebase && !isQrServer) return;

  // صفحات HTML (navigation أو Accept: text/html)
  const accept = req.headers.get("accept") || "";
  if(req.mode === "navigate" || accept.includes("text/html")){
    event.respondWith(navigateStrategy(event));
    return;
  }

  // بنك الأسئلة: SWR (سريع + يحدّث نفسه)
  if(isSameOrigin && url.pathname.endsWith("/questions_bank.js")){
    event.respondWith(staleWhileRevalidate(event, req));
    return;
  }

  // Firebase Modules: SWR (عشان أول مرة يخزنها، وبعدها تفتح أوفلاين بدون بياض)
  if(isGstaticFirebase){
    event.respondWith(staleWhileRevalidate(event, req));
    return;
  }

  // QR: Cache-first أو SWR (اختياري)
  if(isQrServer){
    event.respondWith(staleWhileRevalidate(event, req));
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
