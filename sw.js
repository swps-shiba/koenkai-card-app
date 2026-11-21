/* 後援会カード管理 サービスワーカー（アプリ本体のキャッシュのみ。データは扱わない） */
const CACHE = "koenkai-cards-v2";
const ASSETS = ["./", "./index.html", "./styles.css?v=2", "./app.js?v=2", "./manifest.webmanifest", "./icon.svg"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});
self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return; /* 郵便番号API等は素通し */
  e.respondWith(
    caches.match(e.request, { ignoreSearch: false }).then((hit) => hit || fetch(e.request))
  );
});
