/* Service Worker — Sabaq Alhorof
   - Precaches core files (maps/questions/font/logo)
   - Fast offline + safer updates (iOS-friendly)
   - ✅ NEW: Force Network on ?v / ?fresh / ?nocache so cache-buster links REALLY work
*/

const CACHE_PREFIX  = "sabaq-alhorof";
const CACHE_VERSION = "2026-02-28-1"; // ✅ غيّرناه عشان يضمن تحديث SW عند العملاء
const PRECACHE_NAME = `${CACHE_PREFIX}-precache-${CACHE_VERSION}`;
const RUNTIME_NAME  = `${CACHE_PREFIX}-runtime-${CACHE_VERSION}`;

const OFFLINE_FALLBACK_PAGE = "index.html";

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
    const keys = await caches.keys();
    await Promise.all(keys.map((k) => {
      if(k.startsWith(CACHE_PREFIX) && k !== PRECACHE_NAME && k !== RUNTIME_NAME){
        return caches.delete(k);
      }
    }));

    try{
      if(self.registration.navigationPreload){
        await self.registration.navigationPreload.enable();
      }
    }catch(e){}

    await self.clients.claim();
  })());
});

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

function scopeBasePath(){
  try{
    return new URL(self.registration.scope).pathname; // ends with "/"
  }catch(e){
    return "/";
  }
}

// يحوّل URL مطلق إلى مفتاح نسبي مثل: "maps/map1.jpeg" (بدون ?v=)
function toCanonicalKey(urlObj){
  const base = scopeBasePath();
  let p = urlObj.pathname || "";
  if(p.startsWith(base)) p = p.slice(base.length);
  if(p.startsWith("/")) p = p.slice(1);
  return p; // no search
}

// نطابق من RUNTIME أولاً ثم PRECACHE (عشان التحديثات الجديدة تغلب القديمة)
async function matchKeyFirstRuntime(key, ignoreSearch=false){
  try{
    const runtime = await caches.open(RUNTIME_NAME);
    const rHit = await runtime.match(key, { ignoreSearch });
    if(rHit) return rHit;
  }catch(e){}

  try{
    const pre = await caches.open(PRECACHE_NAME);
    const pHit = await pre.match(key, { ignoreSearch });
    if(pHit) return pHit;
  }catch(e){}

  return null;
}

function withTimeout(promise, ms){
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    promise.then((v)=>{ clearTimeout(t); resolve(v); })
           .catch((e)=>{ clearTimeout(t); reject(e); });
  });
}

function hasCacheBuster(url){
  try{
    return url.searchParams.has("v") || url.searchParams.has("fresh") || url.searchParams.has("nocache");
  }catch(e){
    return false;
  }
}

// HTML: Network-first لكن لو الشبكة تأخرت يرجع الكاش بسرعة
async function navigateStrategy(event){
  const req = event.request;
  const url = new URL(req.url);

  // ✅ إذا فيه cache-buster نخليها Network 100% (عشان يحل مشاكل “بعض الأجهزة”)
  const forceFresh = hasCacheBuster(url);

  const cached = forceFresh ? null : await matchKeyFirstRuntime(req, true);

  const networkPromise = (async () => {
    try{
      const preloaded = await event.preloadResponse;
      if(preloaded){
        await cachePut(RUNTIME_NAME, req, preloaded.clone());
        return preloaded;
      }
    }catch(e){}

    const res = await fetch(req, { cache: "no-store" });
    await cachePut(RUNTIME_NAME, req, res.clone());
    return res;
  })();

  // ✅ Force fresh: لا نرجّع كاش إلا إذا الشبكة فشلت تماماً
  if(forceFresh){
    try{
      return await networkPromise;
    }catch(e){
      return (await matchKeyFirstRuntime(req, true)) ||
             (await matchKeyFirstRuntime(OFFLINE_FALLBACK_PAGE, true)) ||
             new Response("Offline", { status: 503 });
    }
  }

  // سلوكنا القديم
  if(!cached){
    try{
      return await networkPromise;
    }catch(e){
      return (await matchKeyFirstRuntime(OFFLINE_FALLBACK_PAGE, true)) || new Response("Offline", { status: 503 });
    }
  }

  try{
    return await withTimeout(networkPromise, 2500);
  }catch(e){
    return cached;
  }
}

// ✅ للملفات الثقيلة/المهمة (مع ?v=): Stale-While-Revalidate بمفتاح ثابت بدون query
async function swrCanonical(event){
  const req = event.request;
  const url = new URL(req.url);
  const key = toCanonicalKey(url);

  const cached = await matchKeyFirstRuntime(key, false);

  const fetchPromise = (async () => {
    const res = await fetch(req); // نفس الطلب (مع ?v=) عشان يكسر كاش المتصفح/CDN
    await cachePut(RUNTIME_NAME, key, res.clone()); // نخزّن تحت مفتاح ثابت بدون query
    return res;
  })().catch(() => null);

  if(cached){
    event.waitUntil(fetchPromise);
    return cached;
  }

  const net = await fetchPromise;
  if(net) return net;

  return new Response("Offline", { status: 503 });
}

// لباقي الملفات الثابتة: Cache-first
async function cacheFirst(req){
  const cached = await matchKeyFirstRuntime(req, true);
  if(cached) return cached;

  const res = await fetch(req);
  await cachePut(RUNTIME_NAME, req, res.clone());
  return res;
}

// لباقي الطلبات: Network-first
async function networkFirst(req){
  try{
    const res = await fetch(req);
    await cachePut(RUNTIME_NAME, req, res.clone());
    return res;
  }catch(e){
    const cached = await matchKeyFirstRuntime(req, true);
    if(cached) return cached;
    throw e;
  }
}

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if(req.method !== "GET") return;

  const url = new URL(req.url);
  if(url.origin !== self.location.origin) return;

  // تفادي خطأ (only-if-cached)
  if(req.cache === "only-if-cached" && req.mode !== "same-origin") return;

  // ✅ لا نتدخل أبدًا في ملفات الـ SW نفسها (عشان ما نعطل التحديث)
  const path = url.pathname || "";
  if(path.endsWith("/sw.js") || path.endsWith("/service-worker.js") || path.endsWith("/service-worker")){
    return;
  }

  const accept = req.headers.get("accept") || "";
  if(req.mode === "navigate" || accept.includes("text/html")){
    event.respondWith(navigateStrategy(event));
    return;
  }

  // ✅ ملفات نبيها تتحدث حتى لو كانت Cache موجودة (maps/logo/font/questions)
  const canonKey = toCanonicalKey(url);
  const isHeavy =
    canonKey === "questions_bank.js" ||
    canonKey === "logo.png" ||
    canonKey === "AA-GALAXY.otf" ||
    canonKey.startsWith("maps/");

  if(isHeavy){
    event.respondWith(swrCanonical(event));
    return;
  }

  // باقي الـ static: Cache-first
  const dest = req.destination; // image | script | style | font | ...
  if(dest === "image" || dest === "font" || dest === "script" || dest === "style"){
    event.respondWith(cacheFirst(req));
    return;
  }

  event.respondWith(networkFirst(req));
});
