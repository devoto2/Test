// Guarda la app para abrirla sin señal; la agenda siempre intenta bajar la última versión primero.
const CACHE='equipo-v1';
const BASE=['./','index.html','app.css','app.js','manifest.webmanifest','icons/icon-192.png','icons/icon-512.png','icons/apple-touch-icon.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(BASE)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET'||u.origin!==location.origin)return;
  // Red primero para todo lo propio: así los cambios llegan enseguida y sin señal se usa la copia.
  e.respondWith(fetch(e.request).then(r=>{
    if(r.ok){const copia=r.clone();caches.open(CACHE).then(c=>c.put(u.pathname.endsWith('agenda.enc.json')?new Request(u.pathname):e.request,copia))}
    return r;
  }).catch(()=>caches.match(u.pathname.endsWith('agenda.enc.json')?new Request(u.pathname):e.request,{ignoreSearch:true})));
});
