(function(){
'use strict';
const TZ='America/Argentina/Buenos_Aires';
const REPO='devoto2/Test', ARCHIVO='agenda.enc.json', ITER=310000;
const $=s=>document.querySelector(s);
const ls={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{v==null?localStorage.removeItem(k):localStorage.setItem(k,v)}catch(e){}}};

let S=null, codigo=ls.get('eq_codigo'), me=ls.get('eq_yo'), tab=ls.get('eq_tab')||'dia';
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
const mapsURL=e=>'https://www.google.com/maps/dir/?api=1&travelmode=transit&destination='+encodeURIComponent(e.direccion||e.lugar);
const ord=(a,b)=>(a.fecha+(a.llegada||a.funcion||'99')).localeCompare(b.fecha+(b.llegada||b.funcion||'99'));
const futuros=()=>S.eventos.filter(e=>e.fecha>=hoyISO()).sort(ord);
const mios=()=>futuros().filter(e=>me&&(e.equipo||[]).includes(me));

const I={
 map:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 21s-7-6.2-7-11.5A7 7 0 0 1 19 9.5C19 14.8 12 21 12 21z"/><circle cx="12" cy="9.5" r="2.5"/></svg>',
 ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
 copy:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>',
 sun:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
 cal:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/></svg>',
 team:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="9" cy="8" r="3.2"/><path d="M3 20c0-3.3 2.7-5.5 6-5.5s6 2.2 6 5.5"/><circle cx="17" cy="9" r="2.4"/><path d="M16 14.6c2.8.2 5 2 5 5"/></svg>',
 edit:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/></svg>'
};
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
   <img class="logo" src="icons/icon-192.png" alt="">
   <h1>Equipo Ramos</h1>
   <p class="sub">Ingresá el código del equipo. Te lo pasa Pablo.</p>
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
function ramosHTML(r){
  r=r||{}; const t=(r.c||0)+(r.m||0)+(r.g||0);
  if(!t) return '<span class="sub">Pablo carga la cantidad antes de salir.</span>';
  return `<div class="ramos"><span class="ramo"><b>${r.c||0}</b> chicos</span><span class="ramo"><b>${r.m||0}</b> medianos</span><span class="ramo"><b>${r.g||0}</b> grandes</span></div>`;
}
const pills=e=>`<div class="row">${e.prio==='ir'?'<span class="pill ir">Ir seguro</span>':'<span class="pill probar">De prueba</span>'}${e.confirmado?'':'<span class="pill conf">Datos a confirmar</span>'}</div>`;
function tarjeta(e,hero){
  const eq=e.equipo||[], comp=eq.filter(n=>n!==me);
  return `<article class="card${hero?' hero':''}">
   ${pills(e)}<div>${horaBloque(e)}</div>
   <div><div class="place">${esc(e.lugar)}</div><div class="addr">${esc(e.direccion)}</div></div>
   <div class="row">
    <a class="btn primary" href="${mapsURL(e)}" target="_blank" rel="noopener">${I.map}Cómo llegar</a>
    <button class="btn" data-llegue="${e.id}">${I.ok}Avisar que llegué</button>
   </div>
   <dl class="facts"><dt>Qué es</dt><dd>${esc(e.que)}</dd>
    <dt>Vas con</dt><dd>${comp.length?esc(comp.join(', ')):(eq.length?'Vas solo/a':'<span class="err" style="color:var(--warn)">Sin asignar</span>')}</dd></dl>
   <div class="field"><span class="label">Ramos que se llevan</span>${ramosHTML(e.ramos)}</div>
   ${e.nota?`<div class="nota">${esc(e.nota)}</div>`:''}
   <div class="row"><button class="btn small" data-copiar="${e.id}">${I.copy}Copiar dirección</button></div>
  </article>`;
}
function mini(e,attr){
  const eq=e.equipo||[], sin=!eq.length;
  return `<button class="card mini${sin?' unassigned':''}" ${attr}="${e.id}">
   <span class="t">${esc(e.llegada||e.funcion||'¿?')}</span>
   <span style="min-width:0"><span class="place">${esc(e.lugar)}</span>
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
  const txt=ios?'En Safari, tocá el botón Compartir (el cuadrado con la flecha) y después "Agregar a inicio".':(instalar?'Instalala para abrirla con un toque, como cualquier app.':'En Chrome, tocá los tres puntos y después "Instalar app" o "Agregar a pantalla principal".');
  return `<div class="install"><strong>Poné la app en tu pantalla de inicio</strong><span>${txt}</span><div class="row">${instalar&&!ios?'<button class="btn small primary" data-instalar>Instalar</button>':''}<button class="btn small" data-noinst>Listo</button></div></div>`;
}
function vistaQuien(){
  return `${bannerInstalar()}<section class="card"><h2>¿Quién sos?</h2><p class="sub">Tocá tu nombre. El celular se acuerda la próxima vez.</p>
  <div class="who">${S.equipo.map(n=>`<button class="chip" data-yo="${esc(n)}" aria-pressed="${n===me}">${esc(n)}</button>`).join('')}</div>
  <p class="hint">Si tu nombre no está, pedile a Pablo que te sume.</p></section>`;
}
function vistaDia(){
  if(!me) return vistaQuien();
  const hoy=hoyISO(), m=mios(), deHoy=m.filter(e=>e.fecha===hoy);
  let h=`${bannerInstalar()}<div class="top"><div><h1>Hola, ${esc(me)}</h1><div class="hoy">Hoy es ${fechaLarga(hoy)}</div></div><button class="chip" data-cambiar>Cambiar</button></div>`;
  if(deHoy.length) h+=`<span class="label">Tu día</span>`+deHoy.map((e,i)=>tarjeta(e,i===0)).join('');
  else if(m.length) h+=`<div class="card empty" style="padding:18px"><strong>Hoy no tenés funciones.</strong><span>La próxima es el ${fechaLarga(m[0].fecha)}:</span></div>`+tarjeta(m[0],true);
  else h+=`<div class="card empty"><strong>Todavía no tenés funciones asignadas.</strong><span>Cuando Pablo te asigne una, aparece acá con la hora y cómo llegar.</span></div>`;
  return h;
}
function vistaSemana(){
  if(!me) return vistaQuien();
  const m=mios();
  return `<div class="top"><h1>Mis funciones</h1><button class="chip" data-cambiar>${esc(me)}</button></div>`+
   (m.length?porDia(m,e=>tarjeta(e,false)):`<div class="card empty">No tenés funciones asignadas por ahora.</div>`);
}
function vistaEquipo(){
  const f=futuros(), sin=f.filter(e=>!(e.equipo||[]).length).length;
  return `<h1>Todo el equipo</h1><div class="hoy">${f.length} funciones por delante${sin?` · <strong style="color:var(--warn)">${sin} sin asignar</strong>`:''}</div>`+
   (f.length?porDia(f,e=>mini(e,'data-ver')):`<div class="card empty">No hay funciones cargadas.</div>`)+
   `<div class="row" style="justify-content:center">${owner?'':'<button class="link" data-modo-pablo>Soy Pablo: armar la agenda</button>'}<button class="link" data-salir>Cerrar sesión en este celular</button></div>`;
}
function vistaDetalle(){
  const e=S.eventos.find(x=>x.id===editId); if(!e) return vistaEquipo();
  return `<div class="top"><button class="chip" data-tab="equipo">← Volver</button>${owner?`<button class="chip" data-editar="${e.id}">Editar</button>`:''}</div>
  <div class="dayhead">${fechaLarga(e.fecha)}</div>`+tarjeta(e,true);
}
function vistaPablo(){
  return `<div class="top"><button class="chip" data-tab="equipo">← Volver</button></div>
  <section class="card"><h2>Modo Pablo</h2>
  <p>Para guardar cambios, la app necesita una clave de GitHub con permiso para escribir solo en el repositorio de la app. Se guarda únicamente en este celular.</p>
  <form id="f-token"><div class="field"><label for="token">Clave de GitHub</label><input id="token" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="github_pat_…" required></div>
  ${errLock?`<p class="err" role="alert">${esc(errLock)}</p>`:''}
  <button class="btn primary" type="submit">Activar</button></form></section>`;
}
function vistaArmar(){
  if(!owner) return vistaEquipo();
  const f=futuros();
  return `<h1>Armar la agenda</h1>
  ${dirty?`<div class="banner"><strong>Tenés cambios sin publicar.</strong><span>El equipo los ve recién cuando publicás.</span><button class="btn primary" data-publicar>Publicar para el equipo</button></div>`:''}
  <section class="card"><h2>Equipo</h2>
   <div class="who">${S.equipo.map(n=>`<span class="chip" style="cursor:default;display:inline-flex;align-items:center;gap:6px">${esc(n)}<button class="btn small danger" style="min-height:28px;padding:2px 9px" data-quitar="${esc(n)}" aria-label="Quitar a ${esc(n)}">×</button></span>`).join('')}</div>
   <form id="f-persona" class="row" style="flex-direction:row"><input id="nueva-persona" placeholder="Nombre" style="flex:1 1 160px" autocomplete="off" aria-label="Nombre de la persona"><button class="btn small primary" type="submit">Sumar</button></form>
   <div class="field"><label for="wa">Tu WhatsApp para recibir "Llegué"</label><input id="wa" inputmode="tel" value="${esc(S.whatsapp)}" placeholder="Ej. 5491122334455"><span class="hint">Con código de país y sin el 15. Si lo dejás vacío, cada uno elige el chat.</span></div>
   <div class="field"><label for="nuevo-codigo">Cambiar el código del equipo</label><input id="nuevo-codigo" autocomplete="off" autocapitalize="none" placeholder="Dejalo vacío para mantener el actual"><span class="hint">Si lo cambiás, pasáselo de nuevo a todos.</span></div>
  </section>
  <button class="btn primary" data-editar="nuevo">+ Nueva función</button>
  ${porDia(f,e=>mini(e,'data-editar'))}
  <div class="row" style="justify-content:center"><button class="link" data-sin-pablo>Desactivar modo Pablo en este celular</button></div>`;
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
   <div class="field"><label for="ev-dir">Dirección (para Google Maps)</label><input id="ev-dir" value="${esc(e.direccion)}"></div>
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
  const t=[['dia','Mi día',I.sun],['semana','Mis funciones',I.cal],['equipo','Equipo',I.team]];
  if(owner)t.push(['armar','Armar',I.edit]);
  return `<nav class="tabs" role="tablist"><div class="tabs-in">${t.map(([k,l,ic])=>`<button class="tab" role="tab" data-tab="${k}" aria-selected="${tab===k}">${ic}${l}</button>`).join('')}</div></nav>`;
}
function render(){
  if(!S){$('#app').innerHTML=vistaLock();return}
  const V={detalle:vistaDetalle,form:vistaForm,armar:vistaArmar,semana:vistaSemana,equipo:vistaEquipo,pablo:vistaPablo};
  $('#app').innerHTML=(V[tab]||vistaDia)()+`<p class="foot">Agenda actualizada el ${esc((S.actualizado||'').split('-').reverse().join('/'))}</p>`+tabs();
}
function ir(t){tab=t;errLock='';if(['dia','semana','equipo','armar'].includes(t))ls.set('eq_tab',t);render();window.scrollTo(0,0)}

/* ---------- acciones ---------- */
function llegue(id){
  const e=S.eventos.find(x=>x.id===id); if(!e)return;
  const mandar=pos=>{
    let txt=`Llegué a ${e.lugar} a las ${ahoraHM()}.${me?' '+me:''}`;
    if(pos) txt+=`\nUbicación: https://maps.google.com/?q=${pos.coords.latitude.toFixed(5)},${pos.coords.longitude.toFixed(5)}`;
    const n=(S.whatsapp||'').replace(/\D/g,'');
    location.href=(n?`https://wa.me/${n}`:'https://wa.me/')+'?text='+encodeURIComponent(txt);
  };
  if(!navigator.geolocation){mandar(null);return}
  toast('Buscando tu ubicación…');
  navigator.geolocation.getCurrentPosition(mandar,()=>mandar(null),{enableHighAccuracy:true,timeout:8000,maximumAge:60000});
}
function copiar(id){
  const e=S.eventos.find(x=>x.id===id), t=e.direccion||e.lugar;
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>toast('Dirección copiada'),()=>toast(t));
}
function guardarForm(f){
  const id=f.dataset.id; let e=S.eventos.find(x=>x.id===id);
  if(!e){e={id};S.eventos.push(e)}
  const v=k=>document.getElementById(k).value.trim();
  Object.assign(e,{fecha:v('ev-fecha'),llegada:v('ev-llegada'),funcion:v('ev-funcion'),lugar:v('ev-lugar'),direccion:v('ev-dir'),que:v('ev-que'),prio:v('ev-prio'),nota:v('ev-nota'),
   confirmado:document.getElementById('ev-conf').checked,
   equipo:[...f.querySelectorAll('[data-asignar]')].filter(b=>b.getAttribute('aria-pressed')==='true').map(b=>b.dataset.asignar),
   ramos:{c:+v('ev-c')||0,m:+v('ev-m')||0,g:+v('ev-g')||0}});
  dirty=true; ir('armar'); toast('Guardado. Falta publicar.');
}
async function gh(path,opt={}){
  const r=await fetch('https://api.github.com/repos/'+REPO+'/'+path,{...opt,headers:{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28',...(opt.headers||{})}});
  if(!r.ok){const err=new Error('gh '+r.status);err.status=r.status;throw err}
  return r.json();
}
async function publicar(btn){
  btn.disabled=true; btn.textContent='Publicando…';
  const wa=$('#wa'); if(wa)S.whatsapp=wa.value.trim();
  const nc=$('#nuevo-codigo'); const cod=(nc&&nc.value.trim())?nc.value.trim():codigo;
  S.actualizado=hoyISO();
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
  else if(d.yo!==undefined){me=d.yo;ls.set('eq_yo',me);render()}
  else if('cambiar' in d){me=null;ls.set('eq_yo',null);render()}
  else if(d.llegue) llegue(d.llegue);
  else if(d.copiar) copiar(d.copiar);
  else if(d.ver){editId=d.ver;ir('detalle')}
  else if(d.editar){editId=d.editar;ir('form')}
  else if(d.asignar) b.setAttribute('aria-pressed',b.getAttribute('aria-pressed')==='true'?'false':'true');
  else if(d.quitar){S.equipo=S.equipo.filter(n=>n!==d.quitar);S.eventos.forEach(e=>e.equipo=(e.equipo||[]).filter(n=>n!==d.quitar));dirty=true;render()}
  else if(d.borrar){if(b.dataset.seguro){S.eventos=S.eventos.filter(e=>e.id!==d.borrar);dirty=true;ir('armar')}else{b.dataset.seguro='1';b.textContent='Tocá de nuevo para borrar'}}
  else if('publicar' in d) publicar(b);
  else if('modoPablo' in d) ir('pablo');
  else if('sinPablo' in d){token=null;owner=false;ls.set('eq_token',null);ir('equipo')}
  else if('salir' in d){if(b.dataset.seguro){['eq_codigo','eq_yo','eq_token','eq_tab'].forEach(k=>ls.set(k,null));location.reload()}else{b.dataset.seguro='1';b.textContent='Tocá de nuevo para cerrar sesión'}}
  else if('instalar' in d&&instalar){instalar.prompt();instalar=null}
  else if('noinst' in d){ls.set('eq_noinst','1');render()}
});
document.addEventListener('submit',async ev=>{
  ev.preventDefault(); const f=ev.target;
  if(f.id==='f-codigo'){const btn=f.querySelector('button');btn.disabled=true;btn.textContent='Abriendo…';await abrir($('#codigo').value);render()}
  else if(f.id==='f-persona'){const n=$('#nueva-persona').value.trim();if(n&&!S.equipo.includes(n)){S.equipo.push(n);dirty=true}render()}
  else if(f.id==='f-evento') guardarForm(f);
  else if(f.id==='f-token'){
    token=$('#token').value.trim();
    try{const r=await gh('');if(!r.permissions||!r.permissions.push)throw Object.assign(new Error(),{status:403});ls.set('eq_token',token);owner=true;ir('armar');toast('Modo Pablo activado')}
    catch(e){token=null;errLock=e.status===401?'Esa clave no es válida.':'Esa clave no tiene permiso para escribir en el repositorio.';render()}
  }
});
window.addEventListener('beforeinstallprompt',e=>{e.preventDefault();instalar=e;if(S)render()});
window.addEventListener('beforeunload',e=>{if(dirty){e.preventDefault();e.returnValue=''}});
document.addEventListener('visibilitychange',async()=>{
  if(document.visibilityState!=='visible'||!S||!codigo||dirty||tab==='form')return;
  try{const n=await descifrar(await bajar(),codigo);if(n.actualizado!==S.actualizado||JSON.stringify(n)!==JSON.stringify(S)){S=n;render();toast('Agenda actualizada')}}catch(e){}
});
if('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(()=>{});

(async()=>{
  if(!['dia','semana','equipo','armar'].includes(tab))tab='dia';
  if(tab==='armar'&&!owner)tab='dia';
  if(codigo&&await abrir(codigo)){if(me&&!S.equipo.includes(me))me=null}else{S=null;if(codigo)errLock=errLock||'Ingresá de nuevo el código del equipo.'}
  render();
})();
})();
