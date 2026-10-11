(function(){
'use strict';
const TZ='America/Argentina/Buenos_Aires';
const REPO='devoto2/Test', ARCHIVO='agenda.enc.json', ITER=310000;
// Hoja de Google de Pablo que recibe las llegadas (Apps Script, solo agrega filas).
const REGISTRO_URL='https://script.google.com/macros/s/AKfycbxJyFxYtxpFDxBllGxZJBe3BIJaneVgdDO8CUGvwSQL92g5GBvCxig6wtvSDMEg5m64/exec';
const $=s=>document.querySelector(s);
const ls={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{v==null?localStorage.removeItem(k):localStorage.setItem(k,v)}catch(e){}}};

let S=null, codigo=ls.get('eq_codigo'), me=ls.get('eq_yo'), tab=ls.get('eq_tab')||'dia';
let agVista=ls.get('eq_agvista')||'semana', agQuien=null, agCursor=null, agDia=null, pos=null, precision=null, geoEstado='no', errYo='', diaSel=null, verMes=ls.get('eq_vermes')==='1', mdCursor=null;
let editId=null, dirty=false, token=ls.get('eq_token'), owner=!!token, nuevoCodigo=null, errLock='', instalar=null;

/* ---------- cifrado: PBKDF2-SHA256 + AES-GCM ---------- */
const enc=new TextEncoder(), dec=new TextDecoder();
const b64=u=>btoa(String.fromCharCode(...new Uint8Array(u)));
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const norm=c=>String(c||'').trim().toLowerCase().replace(/\s+/g,'-');
async function clave(cod,salt,iter){
  const base=await crypto.subtle.importKey('raw',enc.encode(norm(cod)),'PBKDF2',false,['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2',salt,iterations:iter,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);
}
async function descifrar(f,cod){
  const k=await clave(cod,unb64(f.salt),f.iter||ITER);
  const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(f.iv)},k,unb64(f.ct));
  return JSON.parse(dec.decode(pt));
}
async function cifrar(obj,cod){
  const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
  const k=await clave(cod,salt,ITER);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,enc.encode(JSON.stringify(obj)));
  return {v:1,kdf:'PBKDF2-SHA256',iter:ITER,salt:b64(salt),iv:b64(iv),ct:b64(ct)};
}

/* ---------- fechas ---------- */
const hoyISO=()=>new Intl.DateTimeFormat('en-CA',{timeZone:TZ,year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
const ahoraHM=()=>new Intl.DateTimeFormat('es-AR',{timeZone:TZ,hour:'2-digit',minute:'2-digit',hour12:false}).format(new Date());
const fechaLarga=iso=>new Intl.DateTimeFormat('es-AR',{timeZone:TZ,weekday:'long',day:'numeric',month:'long'}).format(new Date(iso+'T12:00:00-03:00'));
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const addDias=(iso,n)=>{const [y,m,d]=iso.split('-').map(Number);return new Date(Date.UTC(y,m-1,d+n)).toISOString().slice(0,10)};
const diaSem=iso=>{const [y,m,d]=iso.split('-').map(Number);return (new Date(Date.UTC(y,m-1,d)).getUTCDay()+6)%7};
const lunes=iso=>addDias(iso,-diaSem(iso));
const DIAS=['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'];
const MESES=['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
const sinTilde=t=>String(t||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim().toLowerCase();
function fmtActualizado(a){
  if(!a) return '';
  const [f,h]=String(a).split('T'); const fecha=f.split('-').reverse().join('/');
  return h?`${fecha} a las ${h.slice(0,5)}`:fecha;
}
const ord=(a,b)=>(a.fecha+(a.llegada||a.funcion||'99')).localeCompare(b.fecha+(b.llegada||b.funcion||'99'));
const futuros=()=>S.eventos.filter(e=>e.fecha>=hoyISO()).sort(ord);
const mios=()=>futuros().filter(e=>me&&(e.equipo||[]).includes(me));
const ordT=(a,b)=>(a.fecha+(a.hasta||'99')).localeCompare(b.fecha+(b.hasta||'99'));
const tareasDe=()=>(S.tareas||[]).filter(t=>t.fecha>=hoyISO()).sort(ordT);
const misTareas=()=>tareasDe().filter(t=>me&&(t.equipo||[]).includes(me));

const I={
 map:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s-7-6.2-7-11.5A7 7 0 0 1 19 9.5C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/></svg>',
 ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
 sun:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
 cal:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>',
 list:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M9 6h11M9 12h11M9 18h11"/><circle cx="4.5" cy="6" r="1.2"/><circle cx="4.5" cy="12" r="1.2"/><circle cx="4.5" cy="18" r="1.2"/></svg>',
 team:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-5.5 6-5.5s6 2.2 6 5.5"/><circle cx="17" cy="9" r="2.4"/><path d="M16 14.6c2.8.2 5 2 5 5"/></svg>',
 clock:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>',
 edit:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/></svg>'
};
/* ---------- ubicación y distancias ---------- */
const geoCache=(()=>{try{return JSON.parse(ls.get('eq_geo')||'{}')}catch(e){return {}}})();
const dirDe=e=>[e.direccion,e.lugar].filter(Boolean).join(', ');
function coordsDe(e){
  if(e.lat!=null&&e.lng!=null) return [+e.lat,+e.lng];
  const c=geoCache[sinTilde(e.direccion||e.lugar)]; return c&&c.length?c:null;
}
function km(a,b){
  const R=6371,r=x=>x*Math.PI/180,dl=r(b[0]-a[0]),dn=r(b[1]-a[1]);
  const h=Math.sin(dl/2)**2+Math.cos(r(a[0]))*Math.cos(r(b[0]))*Math.sin(dn/2)**2;
  return 2*R*Math.asin(Math.sqrt(h));
}
const fmtDist=d=>d<1?`${Math.max(10,Math.round(d*100)*10)} m`:`${d<10?d.toFixed(1).replace('.',','):Math.round(d)} km`;
function distDe(e){const c=coordsDe(e);return pos&&c?km(pos,c):null}
function distHTML(e,corto){
  const d=distDe(e);
  if(d==null) return '';
  const cerca=d<0.6;
  return corto?`<span class="dist${cerca?' cerca':''}">${fmtDist(d)}</span>`:
   `<div class="dist${cerca?' cerca':''}">${I.map}${cerca?'Estás acá cerca':'Estás a '+fmtDist(d)} <span class="sub">(en línea recta)</span></div>`;
}
async function geocodificar(q){
  const r=await fetch('https://nominatim.openstreetmap.org/search?format=json&limit=1&countrycodes=ar&accept-language=es&q='+encodeURIComponent(q));
  if(!r.ok) throw new Error('geo');
  const j=await r.json(); return j[0]?{c:[+j[0].lat,+j[0].lon],txt:j[0].display_name}:null;
}
let geoCola=[], geoCorriendo=false;
function ubicarFaltantes(){
  if(!S) return;
  futuros().forEach(e=>{const k=sinTilde(e.direccion||e.lugar);if(k&&!coordsDe(e)&&!(k in geoCache)&&!geoCola.includes(k))geoCola.push(k)});
  if(geoCorriendo||!geoCola.length) return;
  geoCorriendo=true;
  (async()=>{
    while(geoCola.length){
      const k=geoCola.shift(), e=S.eventos.find(x=>sinTilde(x.direccion||x.lugar)===k);
      try{const g=e?await geocodificar(dirDe(e)):null;geoCache[k]=g?g.c:[]}catch(err){}
      await new Promise(r=>setTimeout(r,1100));
    }
    ls.set('eq_geo',JSON.stringify(geoCache)); geoCorriendo=false; if(pos&&tab!=='form')render();
  })();
}
function actualizarKm(){
  if(!S) return;
  document.querySelectorAll('[data-km]').forEach(el=>{const e=S.eventos.find(x=>x.id===el.dataset.km),d=e&&distDe(e);if(d!=null)el.textContent=fmtDist(d)});
}
function seguirUbicacion(){
  if(!navigator.geolocation||geoEstado==='si') return;
  geoEstado='pidiendo';
  navigator.geolocation.watchPosition(p=>{
    const nuevo=!pos; pos=[p.coords.latitude,p.coords.longitude]; precision=p.coords.accuracy||null; geoEstado='si'; ls.set('eq_geo_ok','1');
    const marco=revisarLlegadas(); actualizarKm();
    if((nuevo||marco||Date.now()-(seguirUbicacion.t||0)>60000)&&tab!=='form'){seguirUbicacion.t=Date.now();render()}
  },err=>{geoEstado=err.code===1?'negado':'no';if(tab!=='form')render()},{enableHighAccuracy:true,maximumAge:30000,timeout:20000});
}
function bannerUbicacion(){
  if(geoEstado==='si'||geoEstado==='pidiendo'||!navigator.geolocation) return '';
  if(geoEstado==='negado') return `<div class="aviso warn">${I.map}<div><strong>La app no puede ver tu ubicación</strong><span>Sin eso no se marca sola tu llegada. Permitila en los ajustes del navegador para este sitio.</span></div></div>`;
  return `<div class="aviso">${I.map}<div><strong>Activá tu ubicación</strong><span>Tu llegada se marca sola cuando estás en el teatro, y ves a cuántos km estás.</span></div><button class="btn small primary" data-geo>Activar</button></div>`;
}

/* ---------- tareas de producción ---------- */
let hechas=(()=>{try{return JSON.parse(ls.get('eq_hechas')||'{}')}catch(e){return {}}})();
function encolar(x){let cola=[];try{cola=JSON.parse(ls.get('eq_cola')||'[]')}catch(err){}cola.push(x);ls.set('eq_cola',JSON.stringify(cola.slice(-200)))}
function marcarHecha(t,si){
  if(si){hechas[t.id]={hora:ahoraHM()};toast('Tarea hecha')}else delete hechas[t.id];
  ls.set('eq_hechas',JSON.stringify(hechas));
  encolar({id:`${me}|${t.id}|${si?'hecha':'deshecha'}|${Date.now()}`,tipo:si?'tarea_hecha':'tarea_deshecha',ts:new Date().toISOString(),quien:me,evento_id:t.id,lugar:t.que,fecha:t.fecha,gps:null,dist_m:null,manual:true});
  enviarCola();
}
const ramosTxt=r=>{r=r||{};return [r.c?`${r.c} chicos`:'',r.m?`${r.m} medianos`:'',r.g?`${r.g} grandes`:''].filter(Boolean).join(' · ')};
function plazoTarea(t){
  if(t.hasta) return `Hasta las ${esc(t.hasta)}`;
  const f=S.eventos.filter(e=>e.fecha===t.fecha&&(e.equipo||[]).some(n=>(t.equipo||[]).includes(n))).sort(ord)[0];
  return f?`Antes de salir a ${esc(f.lugar)}${f.llegada?` (llegás ${esc(f.llegada)})`:''}`:'En el día';
}
function tarjetaTarea(t){
  const eq=t.equipo||[], comp=eq.filter(n=>n!==me), h=hechas[t.id], rt=ramosTxt(t.ramos);
  return `<article class="card tarea${h?' hecha':''}">
   <div class="row"><span class="pill prod">Producción</span></div>
   <div><div class="place">${esc(t.que||'Tarea')}</div>${rt?`<div class="ramos-t">${rt}</div>`:''}</div>
   <div class="plazo">${I.clock}<span>${plazoTarea(t)}</span></div>
   <dl class="facts">${t.donde?`<dt>Dónde</dt><dd>${esc(t.donde)}</dd>`:''}<dt>Con</dt><dd>${comp.length?esc(comp.join(', ')):(eq.length?'Sola/o':'Sin asignar')}</dd></dl>
   ${t.nota?`<div class="nota">${esc(t.nota)}</div>`:''}
   ${h?`<div class="estado ok">${I.ok}<span>Hecha a las <b>${esc(h.hora)}</b></span><button class="link" data-deshacer="${t.id}">Deshacer</button></div>`:`<button class="btn" data-hecha="${t.id}">${I.ok}Marcar como hecha</button>`}
  </article>`;
}
function miniTarea(t,attr){
  const eq=t.equipo||[];
  return `<button class="card mini tarea-m" ${attr}="${t.id}">
   <span class="t">${t.hasta?'≤'+esc(t.hasta):'—'}</span>
   <span style="min-width:0"><span class="place">${esc(t.que||'Tarea')}</span><span class="prod-l">Producción${ramosTxt(t.ramos)?' · '+ramosTxt(t.ramos):''}</span>
   <span class="who-l">${eq.length?esc(eq.join(', ')):'Sin asignar'}${hechas[t.id]?' · hecha':''}</span></span></button>`;
}

/* ---------- llegadas: se marcan solas por cercanía ---------- */
const RADIO_KM=0.15;
let llegadas=(()=>{try{return JSON.parse(ls.get('eq_llegadas')||'{}')}catch(e){return {}}})();
function registrarLlegada(e,manual){
  const d=distDe(e);
  llegadas[e.id]={hora:ahoraHM(),ts:hoyISO()+'T'+ahoraHM(),manual:!!manual,dist_m:d==null?null:Math.round(d*1000)};
  ls.set('eq_llegadas',JSON.stringify(llegadas));
  // Cola para mandar al panel cuando esté conectado (formato acordado con el panel central).
  let cola=[];try{cola=JSON.parse(ls.get('eq_cola')||'[]')}catch(x){}
  cola.push({id:`${me}|${e.id}|llegada`,tipo:'llegada',ts:new Date().toISOString(),quien:me,evento_id:e.id,lugar:e.lugar,fecha:e.fecha,gps:pos?{lat:+pos[0].toFixed(5),lng:+pos[1].toFixed(5)}:null,dist_m:llegadas[e.id].dist_m,manual:!!manual});
  ls.set('eq_cola',JSON.stringify(cola.slice(-200)));
  toast(`Llegaste a ${e.lugar} a las ${llegadas[e.id].hora}`);
  enviarCola();
}
// Manda lo pendiente a la hoja; lo que la hoja confirma sale de la cola. Sin señal, reintenta al volver.
async function enviarCola(){
  if(!REGISTRO_URL||enviarCola.yendo) return;
  let cola=[];try{cola=JSON.parse(ls.get('eq_cola')||'[]')}catch(x){}
  if(!cola.length) return;
  enviarCola.yendo=true;
  try{
    const r=await fetch(REGISTRO_URL,{method:'POST',headers:{'Content-Type':'text/plain;charset=utf-8'},body:JSON.stringify(cola.slice(0,50))});
    const j=await r.json(), ok=new Set(j.ok||[]);
    let ahora=[];try{ahora=JSON.parse(ls.get('eq_cola')||'[]')}catch(x){}
    ls.set('eq_cola',JSON.stringify(ahora.filter(x=>!ok.has(x.id))));
  }catch(err){}
  enviarCola.yendo=false;
}
function revisarLlegadas(){
  if(!S||!me||!pos) return false;
  const hoy=hoyISO(), radio=Math.max(RADIO_KM,Math.min(precision||0,250)/1000);
  let marco=false;
  mios().filter(e=>e.fecha===hoy&&!llegadas[e.id]).forEach(e=>{const d=distDe(e);if(d!=null&&d<=radio){registrarLlegada(e,false);marco=true}});
  return marco;
}
function estadoLlegada(e){
  const l=llegadas[e.id], hoy=hoyISO(), mia=me&&(e.equipo||[]).includes(me), d=distDe(e);
  if(l) return `<div class="estado ok">${I.ok}<span>Llegaste a las <b>${esc(l.hora)}</b></span></div>`;
  if(d!=null) return `<div class="estado">${I.map}<span>Estás a <b data-km="${e.id}">${fmtDist(d)}</b></span></div>`;
  if(e.fecha!==hoy||!mia) return '';
  if(geoEstado==='si'&&!coordsDe(e)) return `<div class="estado off"><span>Este teatro todavía no tiene ubicación cargada.</span><button class="link" data-marcar="${e.id}">Marcar llegada a mano</button></div>`;
  if(geoEstado==='negado') return `<div class="estado off"><span>Sin permiso de ubicación.</span><button class="link" data-marcar="${e.id}">Marcar llegada a mano</button></div>`;
  if(geoEstado==='si'||geoEstado==='pidiendo') return `<div class="estado off"><span>Buscando tu ubicación…</span></div>`;
  return `<div class="estado off"><span>Activá la ubicación y tu llegada se marca sola.</span><button class="btn small primary" data-geo>Activar</button></div>`;
}
function mapsIr(e){
  const dest=e.lat!=null?`${e.lat},${e.lng}`:dirDe(e);
  return 'https://www.google.com/maps/dir/?api=1&travelmode=transit&destination='+encodeURIComponent(dest);
}

function toast(t){const el=$('#toast');el.textContent=t;el.hidden=false;clearTimeout(toast.h);toast.h=setTimeout(()=>el.hidden=true,2800)}

/* ---------- carga ---------- */
async function bajar(){
  const r=await fetch(ARCHIVO+'?t='+Date.now(),{cache:'no-store'});
  if(!r.ok) throw new Error('red');
  return r.json();
}
async function abrir(cod){
  let f;
  try{f=await bajar()}catch(e){errLock='No se pudo bajar la agenda. Revisá la conexión.';return false}
  try{S=await descifrar(f,cod);codigo=cod;ls.set('eq_codigo',cod);errLock='';return true}
  catch(e){errLock='Ese código no es correcto.';return false}
}

/* ---------- vistas ---------- */
function vistaLock(){
  return `<section class="card lock" style="align-items:center;text-align:center">
   <img class="logo" src="icons/logo.png" alt="Blanco Flor">
   <h1>Equipo de ramos</h1>
   <p class="sub">Ingresá el código del equipo.</p>
   <form id="f-codigo" style="width:100%">
    <input id="codigo" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="Código del equipo" aria-label="Código del equipo" required>
    ${errLock?`<p class="err" role="alert">${esc(errLock)}</p>`:''}
    <button class="btn primary" type="submit">Entrar</button>
   </form></section>`;
}
function horaBloque(e){
  if(e.llegada) return `<span class="label">Llegar a las</span><div class="when"><span class="big">${esc(e.llegada)}</span>${e.funcion?`<span class="sub">la función empieza ${esc(e.funcion)}</span>`:''}</div>`;
  if(e.funcion) return `<span class="label">La función empieza</span><div class="when"><span class="big">${esc(e.funcion)}</span></div>`;
  return `<div class="when"><span class="big tbd">Horario a confirmar</span></div><p class="sub">Pablo carga la hora apenas la tenga. Volvé a abrir la app antes de salir.</p>`;
}
const pills=e=>`<div class="row">${e.prio==='ir'?'<span class="pill ir">Ir seguro</span>':'<span class="pill probar">De prueba</span>'}${e.confirmado?'':'<span class="pill conf">Datos a confirmar</span>'}</div>`;
function tarjeta(e,hero){
  const eq=e.equipo||[], comp=eq.filter(n=>n!==me), r=e.ramos||{}, tr=(r.c||0)+(r.m||0)+(r.g||0);
  const conQuien=comp.length?esc(comp.join(', ')):(eq.length?'Vas solo/a':'<span style="color:var(--warn);font-weight:700">Sin asignar</span>');
  const ramos=tr?[r.c?`${r.c} chicos`:'',r.m?`${r.m} medianos`:'',r.g?`${r.g} grandes`:''].filter(Boolean).join(' · '):'<span class="sub">Pablo carga la cantidad antes de salir</span>';
  return `<article class="card fn${hero?' hero':''}${llegadas[e.id]?' llegado':''}">
   ${pills(e)}<div>${horaBloque(e)}</div>
   <div><div class="place">${esc(e.lugar)}</div><div class="addr">${esc(e.direccion)}</div></div>
   ${estadoLlegada(e)}
   <a class="btn primary" href="${mapsIr(e)}" target="_blank" rel="noopener">${I.map}Cómo llegar</a>
   <dl class="facts"><dt>Vas con</dt><dd>${conQuien}</dd><dt>Ramos</dt><dd>${ramos}</dd>${e.que?`<dt>Qué es</dt><dd>${esc(e.que)}</dd>`:''}</dl>
   ${e.nota?`<div class="nota">${esc(e.nota)}</div>`:''}
  </article>`;
}
function mini(e,attr){
  const eq=e.equipo||[], sin=!eq.length;
  return `<button class="card mini${sin?' unassigned':''}" ${attr}="${e.id}">
   <span class="t">${esc(e.llegada||e.funcion||'¿?')}</span>
   <span style="min-width:0"><span class="place">${esc(e.lugar)}</span>${llegadas[e.id]?`<span class="dist cerca">Llegaste ${esc(llegadas[e.id].hora)}</span>`:(distDe(e)!=null?`<span class="dist" data-km="${e.id}">${fmtDist(distDe(e))}</span>`:'')}
   <span class="who-l">${sin?'Sin asignar':esc(eq.join(', '))}${e.confirmado?'':' · a confirmar'}</span></span></button>`;
}
function porDia(list,fn){
  const g={};list.forEach(e=>(g[e.fecha]=g[e.fecha]||[]).push(e));
  return Object.keys(g).sort().map(d=>`<section class="daygroup"><div class="dayhead">${d===hoyISO()?'Hoy, ':''}${fechaLarga(d)}</div>${g[d].map(fn).join('')}</section>`).join('');
}
function bannerInstalar(){
  const standalone=matchMedia('(display-mode: standalone)').matches||navigator.standalone;
  if(standalone||ls.get('eq_noinst')) return '';
  const ios=/iphone|ipad|ipod/i.test(navigator.userAgent);
  const txt=ios?'En Safari: Compartir y después "Agregar a inicio".':(instalar?'Abrila con un toque, como cualquier app.':'En Chrome: los tres puntos y "Instalar app".');
  return `<div class="aviso"><div><strong>Instalá la app</strong><span>${txt}</span></div>${instalar&&!ios?'<button class="btn small primary" data-instalar>Instalar</button>':''}<button class="x" data-noinst aria-label="Ocultar">×</button></div>`;
}
function vistaQuien(){
  return `${bannerInstalar()}<section class="card"><h2>¿Quién sos?</h2><p class="sub">Escribí tu nombre. El celular se acuerda la próxima vez.</p>
  <form id="f-yo"><input id="yo" autocomplete="given-name" autocapitalize="words" placeholder="Tu nombre" aria-label="Tu nombre" required>
  ${errYo?`<p class="err" role="alert">${esc(errYo)}</p>`:''}
  <button class="btn primary" type="submit">Listo</button></form></section>`;
}
function vistaDia(){
  if(!me) return vistaQuien();
  const hoy=hoyISO(), m=mios(), mt=misTareas();
  if(!diaSel||diaSel<hoy) diaSel=hoy;
  const del=m.filter(e=>e.fecha===diaSel), tdel=mt.filter(t=>t.fecha===diaSel);
  let h=`<div class="marca">Blanco<span>Flor</span><small>Equipo</small></div>${bannerInstalar()}${bannerUbicacion()}
  <div class="top"><div><h1>Hola, ${esc(me)}</h1><div class="hoy">Hoy es ${fechaLarga(hoy)}</div></div><button class="chip" data-cambiar>Cambiar</button></div>`;
  h+=`<div class="top"><div class="dayhead">${diaSel===hoy?'Tu día':fechaLarga(diaSel)}</div>${diaSel!==hoy?'<button class="chip" data-dia-sel="hoy">Volver a hoy</button>':''}</div>`;
  if(del.length) h+=del.map((e,i)=>tarjeta(e,diaSel===hoy&&i===0)).join('');
  if(tdel.length) h+=`<span class="label">Producción</span>`+tdel.map(tarjetaTarea).join('');
  if(!del.length&&!tdel.length){
    const prox=m.find(e=>e.fecha>diaSel);
    h+=`<div class="card empty"><strong>${diaSel===hoy?'Hoy no tenés nada asignado.':'Ese día estás libre.'}</strong>${prox?`<button class="link" data-dia-sel="${prox.fecha}">La próxima función es el ${fechaLarga(prox.fecha)}</button>`:'<span>Cuando Pablo te asigne algo, aparece acá.</span>'}</div>`;
  }
  h+=`<section class="cal"><div class="top"><div class="dayhead">${verMes?'Tu mes':'Tu semana'}</div><button class="chip" data-ver-mes>${verMes?'Ver semana':'Ver mes'}</button></div>`;
  h+=verMes?gridMes(m,mt,mdCursor||hoy,diaSel,'md'):tiraSemana(m,mt);
  return h+`</section>`;
}
function cuenta(d,evs,tars){return {n:evs.filter(e=>e.fecha===d).length,t:tars.filter(t=>t.fecha===d).length}}
function gridMes(evs,tars,cursor,sel,pref){
  const hoy=hoyISO(), m1=cursor.slice(0,8)+'01', ini=lunes(m1), mes=m1.slice(0,7);
  let h=`<div class="nav"><button class="chip" data-${pref}-mes="-1" aria-label="Mes anterior">‹</button><strong class="mest">${MESES[+mes.slice(5)-1]} ${mes.slice(0,4)}</strong><button class="chip" data-${pref}-mes="1" aria-label="Mes siguiente">›</button></div>`;
  h+=`<div class="mes" role="grid">${DIAS.map(d=>`<span class="mh">${d[0]}</span>`).join('')}`;
  for(let i=0;i<42;i++){const d=addDias(ini,i); if(i>=35&&!d.startsWith(mes))break;
    const c=cuenta(d,evs,tars), fuera=!d.startsWith(mes);
    h+=`<button class="md${fuera?' fuera':''}${d===hoy?' hoyd':''}${d===sel?' sel':''}${d<hoy?' pasado':''}" data-${pref}-dia="${d}" aria-label="${fechaLarga(d)}: ${c.n} funciones, ${c.t} tareas"><b>${+d.slice(8)}</b>${c.n?`<i>${c.n}</i>`:''}${c.t?'<u></u>':''}</button>`}
  return h+`</div><div class="leyenda"><span class="lf">Funciones</span><span class="lt">Producción</span></div>`;
}
function tiraSemana(list,tars){
  const hoy=hoyISO(), dias=[...Array(7)].map((_,i)=>addDias(hoy,i));
  return `<div class="tira" aria-label="Tus próximos 7 días">${dias.map(d=>{const c=cuenta(d,list,tars);
   return `<button class="tdia${c.n?' con':''}${d===hoy?' hoyd':''}" data-dia-sel="${d}" aria-pressed="${d===(diaSel||hoy)}"><span>${d===hoy?'Hoy':DIAS[diaSem(d)]}</span><b>${+d.slice(8)}</b><i>${c.n?c.n+' func.':(c.t?'prod.':'libre')}</i>${c.t?'<u></u>':''}</button>`}).join('')}</div>`;
}
function vistaAgenda(){
  const hoy=hoyISO();
  if(!agCursor) agCursor=hoy;
  const base=S.eventos.slice().sort(ord), tb=(S.tareas||[]).slice().sort(ordT);
  const f=futuros(), sin=f.filter(e=>!(e.equipo||[]).length).length;
  const seg=(v,l)=>`<button class="seg-b" data-ag-vista="${v}" aria-pressed="${agVista===v}">${l}</button>`;
  const delDia=d=>{const ev=base.filter(e=>e.fecha===d), tt=tb.filter(t=>t.fecha===d);
    return ev.length||tt.length?ev.map(e=>mini(e,'data-ver')).join('')+tt.map(t=>miniTarea(t,owner?'data-editar-t':'data-ver-t')).join(''):'<div class="libre">Libre</div>'};
  let h=`<h1>Equipo</h1><div class="hoy">${f.length} funciones por delante${sin?` · <strong style="color:var(--warn)">${sin} sin asignar</strong>`:''}</div>
  <div class="row ctrl"><div class="seg">${seg('semana','Semana')}${seg('mes','Mes')}</div></div>`;
  if(agVista==='semana'){
    const l=lunes(agCursor), dias=[...Array(7)].map((_,i)=>addDias(l,i));
    const tit=`${+l.slice(8)} de ${MESES[+l.slice(5,7)-1]} al ${+dias[6].slice(8)} de ${MESES[+dias[6].slice(5,7)-1]}`;
    h+=`<div class="nav"><button class="chip" data-ag-mover="-7" aria-label="Semana anterior">‹</button><strong>${tit}</strong><button class="chip" data-ag-mover="7" aria-label="Semana siguiente">›</button></div>`;
    h+=dias.map(d=>`<section class="daygroup${d<hoy?' pasado':''}"><div class="dayhead">${d===hoy?'Hoy, ':''}${fechaLarga(d)}</div>${delDia(d)}</section>`).join('');
  }else{
    const mes=agCursor.slice(0,7), sel=agDia&&agDia.startsWith(mes)?agDia:(hoy.startsWith(mes)?hoy:mes+'-01');
    h+=gridMes(base,tb,agCursor,sel,'ag');
    h+=`<section class="daygroup"><div class="dayhead">${sel===hoy?'Hoy, ':''}${fechaLarga(sel)}</div>${delDia(sel)}</section>`;
  }
  return h+`<div class="row" style="justify-content:center">${owner?'':'<button class="link" data-modo-pablo>Soy Pablo: armar la agenda</button>'}<button class="link" data-salir>Cerrar sesión en este celular</button></div>`;
}
function vistaDetalleT(){
  const t=(S.tareas||[]).find(x=>x.id===editId); if(!t) return vistaAgenda();
  return `<div class="top"><button class="chip" data-tab="agenda">← Volver</button></div><div class="dayhead">${fechaLarga(t.fecha)}</div>`+tarjetaTarea(t);
}
function vistaDetalle(){
  const e=S.eventos.find(x=>x.id===editId); if(!e) return vistaAgenda();
  return `<div class="top"><button class="chip" data-tab="agenda">← Volver</button>${owner?`<button class="chip" data-editar="${e.id}">Editar</button>`:''}</div>
  <div class="dayhead">${fechaLarga(e.fecha)}</div>`+tarjeta(e,true);
}
function vistaPablo(){
  return `<div class="top"><button class="chip" data-tab="agenda">← Volver</button></div>
  <section class="card"><h2>Modo Pablo</h2>
  <p>Para guardar cambios, la app necesita una clave de GitHub con permiso para escribir solo en el repositorio de la app. Se guarda únicamente en este celular.</p>
  <form id="f-token"><div class="field"><label for="token">Clave de GitHub</label><input id="token" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="github_pat_…" required></div>
  ${errLock?`<p class="err" role="alert">${esc(errLock)}</p>`:''}
  <button class="btn primary" type="submit">Activar</button></form></section>`;
}
function vistaArmar(){
  if(!owner) return vistaAgenda();
  const f=futuros();
  return `<h1>Armar la agenda</h1>
  ${dirty?`<div class="banner"><strong>Tenés cambios sin publicar.</strong><span>El equipo los ve recién cuando publicás.</span><button class="btn primary" data-publicar>Publicar para el equipo</button></div>`:''}
  <section class="card"><h2>Equipo</h2>
   <div class="who">${S.equipo.map(n=>`<span class="chip" style="cursor:default;display:inline-flex;align-items:center;gap:6px">${esc(n)}<button class="btn small danger" style="min-height:28px;padding:2px 9px" data-quitar="${esc(n)}" aria-label="Quitar a ${esc(n)}">×</button></span>`).join('')}</div>
   <form id="f-persona" class="row" style="flex-direction:row"><input id="nueva-persona" placeholder="Nombre" style="flex:1 1 160px" autocomplete="off" aria-label="Nombre de la persona"><button class="btn small primary" type="submit">Sumar</button></form>
   <div class="field"><label for="nuevo-codigo">Cambiar el código del equipo</label><input id="nuevo-codigo" autocomplete="off" autocapitalize="none" placeholder="Dejalo vacío para mantener el actual"><span class="hint">Si lo cambiás, pasáselo de nuevo a todos.</span></div>
  </section>
  <div class="row"><button class="btn primary" data-editar="nuevo">+ Nueva función</button><button class="btn" data-editar-t="nueva">+ Nueva tarea de producción</button></div>
  ${porDia([...f.map(e=>({...e,_k:'f'})),...tareasDe().map(t=>({...t,_k:'t'}))],x=>x._k==='f'?mini(x,'data-editar'):miniTarea(x,'data-editar-t'))}
  <div class="row" style="justify-content:center"><button class="link" data-sin-pablo>Desactivar modo Pablo en este celular</button></div>`;
}
function vistaFormT(){
  const nuevo=editId==='nueva';
  const t=nuevo?{id:'t'+Date.now().toString(36),fecha:hoyISO(),que:'Armar ramos',ramos:{c:0,m:0,g:0},donde:'',hasta:'',equipo:[],nota:''}:(S.tareas||[]).find(x=>x.id===editId);
  const r=t.ramos||{};
  return `<div class="top"><button class="chip" data-tab="armar">← Volver</button><h2>${nuevo?'Nueva tarea de producción':'Editar tarea'}</h2></div>
  <form id="f-tarea" class="card" data-id="${t.id}">
   <div class="grid2"><div class="field"><label for="ta-fecha">Día</label><input id="ta-fecha" type="date" value="${esc(t.fecha)}" required></div>
   <div class="field"><label for="ta-hasta">Hasta qué hora</label><input id="ta-hasta" type="time" value="${esc(t.hasta)}"><span class="hint">Vacío: antes de salir a la función de ese día.</span></div></div>
   <div class="field"><label for="ta-que">Qué hay que hacer</label><input id="ta-que" value="${esc(t.que)}" required></div>
   <div class="field"><span class="label">Ramos</span><div class="grid3">
    <div class="field"><label for="ta-c">Chicos</label><input id="ta-c" type="number" min="0" inputmode="numeric" value="${r.c||0}"></div>
    <div class="field"><label for="ta-m">Medianos</label><input id="ta-m" type="number" min="0" inputmode="numeric" value="${r.m||0}"></div>
    <div class="field"><label for="ta-g">Grandes</label><input id="ta-g" type="number" min="0" inputmode="numeric" value="${r.g||0}"></div></div></div>
   <div class="field"><label for="ta-donde">Dónde</label><input id="ta-donde" value="${esc(t.donde)}" placeholder="Ej. el taller"></div>
   <div class="field"><span class="label">Quién</span><div class="who">${S.equipo.map(n=>`<button type="button" class="chip" data-asignar="${esc(n)}" aria-pressed="${(t.equipo||[]).includes(n)}">${esc(n)}</button>`).join('')}</div></div>
   <div class="field"><label for="ta-nota">Cómo hacerlo (nota)</label><textarea id="ta-nota">${esc(t.nota)}</textarea></div>
   <div class="row"><button class="btn primary" type="submit">Guardar</button>${nuevo?'':`<button class="btn danger" type="button" data-borrar-t="${t.id}">Borrar</button>`}</div>
  </form>`;
}
function guardarTarea(f){
  const id=f.dataset.id; S.tareas=S.tareas||[]; let t=S.tareas.find(x=>x.id===id);
  if(!t){t={id};S.tareas.push(t)}
  const v=k=>document.getElementById(k).value.trim();
  Object.assign(t,{fecha:v('ta-fecha'),hasta:v('ta-hasta'),que:v('ta-que'),donde:v('ta-donde'),nota:v('ta-nota'),
   ramos:{c:+v('ta-c')||0,m:+v('ta-m')||0,g:+v('ta-g')||0},
   equipo:[...f.querySelectorAll('[data-asignar]')].filter(b=>b.getAttribute('aria-pressed')==='true').map(b=>b.dataset.asignar)});
  dirty=true; ir('armar'); toast('Guardado. Falta publicar.');
}
function vistaForm(){
  const nuevo=editId==='nuevo';
  const e=nuevo?{id:'e'+Date.now().toString(36),fecha:hoyISO(),funcion:'',llegada:'',lugar:'',direccion:'',que:'',prio:'ir',confirmado:false,equipo:[],ramos:{c:0,m:0,g:0},nota:''}:S.eventos.find(x=>x.id===editId);
  const r=e.ramos||{};
  return `<div class="top"><button class="chip" data-tab="armar">← Volver</button><h2>${nuevo?'Nueva función':'Editar función'}</h2></div>
  <form id="f-evento" class="card" data-id="${e.id}">
   <div class="grid2"><div class="field"><label for="ev-fecha">Fecha</label><input id="ev-fecha" type="date" value="${esc(e.fecha)}" required></div>
   <div class="field"><label for="ev-prio">Prioridad</label><select id="ev-prio"><option value="ir"${e.prio==='ir'?' selected':''}>Ir seguro</option><option value="probar"${e.prio==='probar'?' selected':''}>De prueba</option></select></div></div>
   <div class="grid2"><div class="field"><label for="ev-llegada">Hora de llegada</label><input id="ev-llegada" type="time" value="${esc(e.llegada)}"></div>
   <div class="field"><label for="ev-funcion">Empieza la función</label><input id="ev-funcion" type="time" value="${esc(e.funcion)}"></div></div>
   <div class="field"><label for="ev-lugar">Lugar</label><input id="ev-lugar" value="${esc(e.lugar)}" required></div>
   <div class="field"><label for="ev-dir">Dirección (calle, número y localidad)</label><input id="ev-dir" value="${esc(e.direccion)}"></div>
   <div class="field"><label for="ev-ubic">Ubicación exacta</label><input id="ev-ubic" inputmode="decimal" value="${e.lat!=null?esc(e.lat+', '+e.lng):''}" placeholder="Se completa sola con la dirección">
    <span class="hint" id="ev-ubic-txt">${e.lat!=null?`Ubicado. <a href="https://www.google.com/maps?q=${e.lat},${e.lng}" target="_blank" rel="noopener">Ver en el mapa</a>`:'Si la dirección es ambigua, pegá acá un link de Google Maps o las coordenadas (en Maps, mantené apretado el lugar y copiá los números).'}</span>
    <button type="button" class="btn small" data-ubicar>Ubicar con la dirección</button></div>
   <div class="field"><label for="ev-que">Qué es</label><input id="ev-que" value="${esc(e.que)}"></div>
   <div class="field"><span class="label">Quién va</span><div class="who">${S.equipo.map(n=>`<button type="button" class="chip" data-asignar="${esc(n)}" aria-pressed="${(e.equipo||[]).includes(n)}">${esc(n)}</button>`).join('')}</div></div>
   <div class="field"><span class="label">Ramos a llevar</span><div class="grid3">
    <div class="field"><label for="ev-c">Chicos</label><input id="ev-c" type="number" min="0" inputmode="numeric" value="${r.c||0}"></div>
    <div class="field"><label for="ev-m">Medianos</label><input id="ev-m" type="number" min="0" inputmode="numeric" value="${r.m||0}"></div>
    <div class="field"><label for="ev-g">Grandes</label><input id="ev-g" type="number" min="0" inputmode="numeric" value="${r.g||0}"></div></div></div>
   <div class="field"><label for="ev-nota">Nota para el equipo</label><textarea id="ev-nota">${esc(e.nota)}</textarea></div>
   <label class="check"><input id="ev-conf" type="checkbox"${e.confirmado?' checked':''}> Horario y lugar confirmados</label>
   <div class="row"><button class="btn primary" type="submit">Guardar</button>${nuevo?'':`<button class="btn danger" type="button" data-borrar="${e.id}">Borrar</button>`}</div>
  </form>`;
}
function tabs(){
  const t=[['dia','Mi día',I.sun],['agenda','Equipo',I.team]];
  if(owner)t.push(['armar','Armar',I.edit]);
  return `<nav class="tabs" role="tablist"><div class="tabs-in">${t.map(([k,l,ic])=>`<button class="tab" role="tab" data-tab="${k}" aria-selected="${tab===k}">${ic}${l}</button>`).join('')}</div></nav>`;
}
function render(){
  if(!S){$('#app').innerHTML=vistaLock();return}
  const V={detalle:vistaDetalle,detallet:vistaDetalleT,form:vistaForm,formt:vistaFormT,armar:vistaArmar,agenda:vistaAgenda,pablo:vistaPablo};
  $('#app').innerHTML=(V[tab]||vistaDia)()+`<p class="foot">Agenda actualizada el ${esc(fmtActualizado(S.actualizado))}</p>`+tabs();
  ubicarFaltantes();
}
function ir(t){tab=t;errLock='';if(['dia','agenda','armar'].includes(t))ls.set('eq_tab',t);render();window.scrollTo(0,0)}

/* ---------- acciones ---------- */
function leerCoords(t){
  const m=String(t||'').match(/(-?\d{1,2}\.\d+)\s*,\s*(-?\d{1,3}\.\d+)/);
  return m?[+(+m[1]).toFixed(6),+(+m[2]).toFixed(6)]:null;
}
async function ubicarForm(btn){
  const q=[$('#ev-dir').value.trim(),$('#ev-lugar').value.trim()].filter(Boolean).join(', ');
  if(!q){toast('Primero cargá la dirección');return}
  btn.disabled=true; btn.textContent='Buscando…';
  try{
    const g=await geocodificar(q);
    if(g){$('#ev-ubic').value=g.c.join(', ');$('#ev-ubic-txt').innerHTML=`Encontrado: ${esc(g.txt)}. <a href="https://www.google.com/maps?q=${g.c[0]},${g.c[1]}" target="_blank" rel="noopener">Revisalo en el mapa</a>`}
    else $('#ev-ubic-txt').textContent='No encontré esa dirección. Pegá un link de Google Maps o las coordenadas.';
  }catch(e){toast('No se pudo buscar. Revisá la conexión.')}
  btn.disabled=false; btn.textContent='Ubicar con la dirección';
}
function guardarForm(f){
  const id=f.dataset.id; let e=S.eventos.find(x=>x.id===id);
  if(!e){e={id};S.eventos.push(e)}
  const v=k=>document.getElementById(k).value.trim();
  Object.assign(e,{fecha:v('ev-fecha'),llegada:v('ev-llegada'),funcion:v('ev-funcion'),lugar:v('ev-lugar'),direccion:v('ev-dir'),que:v('ev-que'),prio:v('ev-prio'),nota:v('ev-nota'),
   confirmado:document.getElementById('ev-conf').checked,
   equipo:[...f.querySelectorAll('[data-asignar]')].filter(b=>b.getAttribute('aria-pressed')==='true').map(b=>b.dataset.asignar),
   ramos:{c:+v('ev-c')||0,m:+v('ev-m')||0,g:+v('ev-g')||0}});
  const c=leerCoords(v('ev-ubic'));
  if(c){e.lat=c[0];e.lng=c[1]}else{delete e.lat;delete e.lng}
  dirty=true; ir('armar'); toast('Guardado. Falta publicar.');
}
async function gh(path,opt={}){
  const r=await fetch('https://api.github.com/repos/'+REPO+'/'+path,{...opt,headers:{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(opt.headers||{})}});
  if(!r.ok){const err=new Error('gh '+r.status);err.status=r.status;throw err}
  return r.json();
}
async function publicar(btn){
  btn.disabled=true; btn.textContent='Publicando…';
  const nc=$('#nuevo-codigo'); const cod=(nc&&nc.value.trim())?nc.value.trim():codigo;
  S.actualizado=hoyISO()+'T'+ahoraHM();
  try{
    const sobre=await cifrar(S,cod);
    let sha; try{sha=(await gh('contents/'+ARCHIVO)).sha}catch(e){if(e.status!==404)throw e}
    const content=btoa(JSON.stringify(sobre,null,1));
    await gh('contents/'+ARCHIVO,{method:'PUT',body:JSON.stringify({message:'Actualizar agenda del equipo',content,sha})});
    const cambio=cod!==codigo;
    codigo=cod; ls.set('eq_codigo',cod); dirty=false; render();
    toast(cambio?'Publicado con el código nuevo: pasáselo al equipo':'Publicado. El equipo lo ve en un minuto.');
  }catch(e){
    btn.disabled=false; btn.textContent='Publicar para el equipo';
    toast(e.status===401||e.status===403?'La clave de GitHub no sirve o no tiene permiso de escritura':'No se pudo publicar. Revisá la conexión y probá de nuevo.');
  }
}

document.addEventListener('click',ev=>{
  const b=ev.target.closest('button'); if(!b)return;
  const d=b.dataset;
  if(d.tab) ir(d.tab);
  else if(d.diaSel){diaSel=d.diaSel==='hoy'?hoyISO():d.diaSel;if(tab!=='dia')ir('dia');else{render();window.scrollTo({top:0,behavior:'smooth'})}}
  else if('verMes' in d){verMes=!verMes;ls.set('eq_vermes',verMes?'1':null);render()}
  else if(d.mdMes){const [y,m]=(mdCursor||hoyISO()).split('-').map(Number);mdCursor=new Date(Date.UTC(y,m-1+(+d.mdMes),1)).toISOString().slice(0,10);render()}
  else if(d.mdDia){diaSel=d.mdDia<hoyISO()?hoyISO():d.mdDia;render();window.scrollTo({top:0,behavior:'smooth'})}
  else if(d.hecha){const t=(S.tareas||[]).find(x=>x.id===d.hecha);if(t){marcarHecha(t,true);render()}}
  else if(d.deshacer){const t=(S.tareas||[]).find(x=>x.id===d.deshacer);if(t){marcarHecha(t,false);render()}}
  else if(d.verT){editId=d.verT;ir('detallet')}
  else if(d.editarT){editId=d.editarT;ir('formt')}
  else if(d.borrarT){if(b.dataset.seguro){S.tareas=(S.tareas||[]).filter(t=>t.id!==d.borrarT);dirty=true;ir('armar')}else{b.dataset.seguro='1';b.textContent='Tocá de nuevo para borrar'}}
  else if(d.marcar){const e=S.eventos.find(x=>x.id===d.marcar);if(e){registrarLlegada(e,true);render()}}
  else if('geo' in d){seguirUbicacion();render()}
  else if('ubicar' in d) ubicarForm(b);
  else if(d.agVista){agVista=d.agVista;ls.set('eq_agvista',agVista);render()}
  else if(d.agMover){agCursor=addDias(agCursor||hoyISO(),+d.agMover);render()}
  else if(d.agMes){const [y,m]=(agCursor||hoyISO()).split('-').map(Number);agCursor=new Date(Date.UTC(y,m-1+(+d.agMes),1)).toISOString().slice(0,10);agDia=null;render()}
  else if(d.agDia){agDia=d.agDia;render()}

  else if('cambiar' in d){me=null;ls.set('eq_yo',null);render()}
  else if(d.ver){editId=d.ver;ir('detalle')}
  else if(d.editar){editId=d.editar;ir('form')}
  else if(d.asignar) b.setAttribute('aria-pressed',b.getAttribute('aria-pressed')==='true'?'false':'true');
  else if(d.quitar){S.equipo=S.equipo.filter(n=>n!==d.quitar);S.eventos.forEach(e=>e.equipo=(e.equipo||[]).filter(n=>n!==d.quitar));(S.tareas||[]).forEach(t=>t.equipo=(t.equipo||[]).filter(n=>n!==d.quitar));dirty=true;render()}
  else if(d.borrar){if(b.dataset.seguro){S.eventos=S.eventos.filter(e=>e.id!==d.borrar);dirty=true;ir('armar')}else{b.dataset.seguro='1';b.textContent='Tocá de nuevo para borrar'}}
  else if('publicar' in d) publicar(b);
  else if('modoPablo' in d) ir('pablo');
  else if('sinPablo' in d){token=null;owner=false;ls.set('eq_token',null);ir('agenda')}
  else if('salir' in d){if(b.dataset.seguro){['eq_codigo','eq_yo','eq_token','eq_tab','eq_agvista','eq_vermes'].forEach(k=>ls.set(k,null));location.reload()}else{b.dataset.seguro='1';b.textContent='Tocá de nuevo para cerrar sesión'}}
  else if('instalar' in d&&instalar){instalar.prompt();instalar=null}
  else if('noinst' in d){ls.set('eq_noinst','1');render()}
});
document.addEventListener('submit',async ev=>{
  ev.preventDefault(); const f=ev.target;
  if(f.id==='f-codigo'){const btn=f.querySelector('button');btn.disabled=true;btn.textContent='Abriendo…';await abrir($('#codigo').value);render()}
  else if(f.id==='f-yo'){
    const t=sinTilde($('#yo').value), n=S.equipo.find(x=>sinTilde(x)===t)||S.equipo.find(x=>sinTilde(x).split(' ')[0]===t.split(' ')[0]);
    if(n){me=n;errYo='';ls.set('eq_yo',me);render()}else{errYo='No encontramos ese nombre en el equipo. Revisá cómo lo escribiste.';render()}
  }
  else if(f.id==='f-persona'){const n=$('#nueva-persona').value.trim();if(n&&!S.equipo.includes(n)){S.equipo.push(n);dirty=true}render()}
  else if(f.id==='f-evento') guardarForm(f);
  else if(f.id==='f-tarea') guardarTarea(f);
  else if(f.id==='f-token'){
    token=$('#token').value.trim();
    try{const r=await gh('');if(!r.permissions||!r.permissions.push)throw Object.assign(new Error(),{status:403});ls.set('eq_token',token);owner=true;ir('armar');toast('Modo Pablo activado')}
    catch(e){token=null;errLock=e.status===401?'Esa clave no es válida.':'Esa clave no tiene permiso para escribir en el repositorio.';render()}
  }
});
window.addEventListener('online',()=>enviarCola());
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();instalar=e;if(S)render()});
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue=''}});
document.addEventListener('visibilitychange',async()=>{
  if(document.visibilityState==='visible')enviarCola();
  if(document.visibilityState!=='visible'||!S||!codigo||dirty||tab==='form'||tab==='formt')return;
  try{const n=await descifrar(await bajar(),codigo);if(n.actualizado!==S.actualizado||JSON.stringify(n)!==JSON.stringify(S)){S=n;render();toast('Agenda actualizada')}}catch(e){}
});
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});

(async()=>{
  if(tab==='equipo')tab='agenda';
  if(!['dia','agenda','armar'].includes(tab))tab='dia';
  if(ls.get('eq_geo_ok'))seguirUbicacion();
  else if(navigator.permissions&&navigator.permissions.query)navigator.permissions.query({name:'geolocation'}).then(p=>{if(p.state==='granted')seguirUbicacion();else if(p.state==='denied'){geoEstado='negado';if(S)render()}}).catch(()=>{});
  if(tab==='armar'&&!owner)tab='dia';
  if(codigo&&await abrir(codigo)){if(me&&!S.equipo.includes(me))me=null}else{S=null;if(codigo)errLock=errLock||'Ingresá de nuevo el código del equipo.'}
  render();
  enviarCola();
})();
})();
