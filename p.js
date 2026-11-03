const WASM_SHA='e6fc166a85fc6aef11d67228768a2d61f964e22e37d218f237ce13641c76522d', WASM_SIZE=7805486;
const out=document.getElementById('out');const R=[];
function rec(n,ok,d){R.push({n,ok,d});const li=document.createElement('li');li.className=ok?'ok':'bad';li.textContent=(ok?'PASS ':'FAIL ')+n+(d?' : '+d:'');out.appendChild(li);}
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
function idb(){return new Promise((res,rej)=>{const r=indexedDB.open('tfp-probe',1);r.onupgradeneeded=()=>r.result.createObjectStore('kv');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
function put(db,k,v){return new Promise((res,rej)=>{const t=db.transaction('kv','readwrite');t.objectStore('kv').put(v,k);t.oncomplete=res;t.onerror=()=>rej(t.error);});}
function get(db,k){return new Promise((res,rej)=>{const t=db.transaction('kv','readonly');const q=t.objectStore('kv').get(k);q.onsuccess=()=>res(q.result);q.onerror=()=>rej(q.error);});}
const ev=[];['visibilitychange','pagehide','pageshow','freeze','resume'].forEach(e=>addEventListener(e,()=>{ev.push(e+':'+document.visibilityState+'@'+Math.round(performance.now()/1000)+'s');document.getElementById('hdr').textContent=navigator.userAgent+' | events '+ev.join(', ');}),true);
(async()=>{
 document.getElementById('hdr').textContent=navigator.userAgent;
 rec('secure context',isSecureContext,location.protocol);
 rec('WebCrypto subtle',!!(crypto&&crypto.subtle));
 let db; try{db=await idb();rec('IndexedDB open',true);}catch(e){rec('IndexedDB open',false,String(e));}
 try{const prev=db&&await get(db,'visits');const n=(prev||0)+1;await put(db,'visits',n);rec('IndexedDB persists across loads',n>1,'visit #'+n+(n>1?'':' (tap Reload test, then close the tab and reopen the link)'));}catch(e){rec('IndexedDB write/read',false,String(e));}
 try{let k=db&&await get(db,'key');let fresh=false;if(!k){k=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);await put(db,'key',k);fresh=true;}
  const iv=crypto.getRandomValues(new Uint8Array(12));const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},k,new TextEncoder().encode('probe'));const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv},k,ct);
  let exp='blocked';try{await crypto.subtle.exportKey('raw',k);exp='EXPORTED';}catch(_){}
  rec('non-extractable key stored in IndexedDB and usable'+(fresh?' (new)':' (reused after reload)'),new TextDecoder().decode(pt)==='probe'&&exp==='blocked','export '+exp);}catch(e){rec('non-extractable key in IndexedDB',false,String(e));}
 try{const p=navigator.storage&&navigator.storage.persist?await navigator.storage.persist():'n/a';const e=navigator.storage&&navigator.storage.estimate?await navigator.storage.estimate():{};rec('storage.persist()',p===true,String(p)+' quota '+Math.round((e.quota||0)/1048576)+' MB');}catch(e){rec('storage.persist()',false,String(e));}
 rec('BroadcastChannel',typeof BroadcastChannel==='function');
 rec('Web Locks',!!(navigator.locks&&navigator.locks.request));
 try{const r=await fetch('c.wasm',{cache:'no-store'});const ct=r.headers.get('content-type');const b=await r.arrayBuffer();const h=hex(await crypto.subtle.digest('SHA-256',b));rec('wasm served as application/wasm',ct==='application/wasm',ct);rec('wasm hash matches pinned build',h===WASM_SHA&&b.byteLength===WASM_SIZE,h.slice(0,12)+' '+b.byteLength+' bytes');
  const m=await WebAssembly.compile(b);rec('wasm compiles under CSP (wasm-unsafe-eval)',!!m,WebAssembly.Module.imports(m).length+' imports');}catch(e){rec('wasm fetch/verify/compile',false,String(e));}
 try{eval('1');rec('CSP blocks eval (expected)',false,'eval ran');}catch(e){rec('CSP blocks eval (expected)',true);}
 document.title='probe done '+R.filter(x=>x.ok).length+'/'+R.length;
})();
document.getElementById('re').onclick=()=>location.reload();
