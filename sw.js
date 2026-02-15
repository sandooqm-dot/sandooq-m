/* Service Worker — Sabaq Alhorof
   - Cache maps + questions bank + font/logo
   - Cache versioning: غيّر CACHE_VERSION لأي تحديث كبير لتجديد الكاش
*/

const CACHE_PREFIX = "sabaq-alhorof";
const CACHE_VERSION = "2026-02-15-1"; // غيّره عند أي تعديل بالملفات
const PRECACHE_NAME = `${CACHE_PREFIX}-precache-${CACHE_VERSION}`;
const RUNTIME_NAME  = `${CACHE_PREFIX}-runtime-${CACHE_VERSION}`;

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
      const req = new Request(url, { cache: "reload" });
      const res = await fetch(req);
      if(res && res.ok){
        await cache.put(req, res);
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
    await self.clients.claim();
  })());
});

async function cachePut(cacheName, request, response){
  try{
    if(!response || !response.ok) return;
    const cache = await caches.open(cacheName);
    await cache.put(request, response);
  }catch(e){}
}

async function fromCache(request){
  // ignoreSearch عشان لو صار عندك ?v=xx مستقبلاً ما يخرب
  const hit = await caches.match(request, { ignoreSearch: true });
  return hit || null;
}

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

async function cacheFirst(request){
  const cached = await fromCache(request);
  if(cached) return cached;

  const res = await fetch(request);
  await cachePut(RUNTIME_NAME, request, res.clone());
  return res;
}

self.addEventListener("fetch", (event) => {
  const req = event.request;

  // فقط GET
  if(req.method !== "GET") return;

  const url = new URL(req.url);

  // نخلي أي طلب خارج الدومين (Firebase CDN / QR API) يروح طبيعي بدون تدخل
  if(url.origin !== self.location.origin) return;

  // صفحات HTML (navigation): Network-first
  if(req.mode === "navigate"){
    event.respondWith(networkFirst(req));
    return;
  }

  // Static assets: Cache-first
  const dest = req.destination; // "image" | "script" | "style" | "font" | ...
  if(dest === "image" || dest === "font" || dest === "script" || dest === "style"){
    event.respondWith(cacheFirst(req));
    return;
  }

  // باقي الطلبات: Network-first (آمن)
  event.respondWith(networkFirst(req));
});
