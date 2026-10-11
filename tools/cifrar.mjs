// Uso: CODIGO="..." node tools/cifrar.mjs agenda.json > agenda.enc.json
// Cifra la agenda igual que la app (PBKDF2-SHA256 + AES-GCM). La agenda sin cifrar nunca va al repositorio.
import {readFileSync} from 'node:fs';
const {subtle}=globalThis.crypto, ITER=310000;
const norm=c=>String(c||'').trim().toLowerCase().replace(/\s+/g,'-');
const b64=u=>Buffer.from(u).toString('base64');
const obj=JSON.parse(readFileSync(process.argv[2],'utf8'));
const salt=crypto.getRandomValues(new Uint8Array(16)), iv=crypto.getRandomValues(new Uint8Array(12));
const base=await subtle.importKey('raw',new TextEncoder().encode(norm(process.env.CODIGO)),'PBKDF2',false,['deriveKey']);
const k=await subtle.deriveKey({name:'PBKDF2',salt,iterations:ITER,hash:'SHA-256'},base,{name:'AES-GCM',length:256},false,['encrypt']);
const ct=await subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode(JSON.stringify(obj)));
process.stdout.write(JSON.stringify({v:1,kdf:'PBKDF2-SHA256',iter:ITER,salt:b64(salt),iv:b64(iv),ct:b64(ct)},null,1));
