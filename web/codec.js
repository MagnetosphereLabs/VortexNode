/* Shared, dependency-free client crypto and bounded-memory ZIP64 output. */
window.VortexWire=(()=>{
 'use strict';
 const encoder=new TextEncoder(),decoder=new TextDecoder('utf-8',{fatal:true});
 const CHUNK=1024*1024;
 const encode=s=>encoder.encode(s);
 const b64=bytes=>{let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')};
 const unb64=s=>{if(typeof s!=='string'||!/^[A-Za-z0-9_-]*$/.test(s)||s.length>12*1024*1024)throw Error('Invalid encrypted encoding');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0))};
 const random=n=>crypto.getRandomValues(new Uint8Array(n));
 const hex=b=>Array.from(b,x=>x.toString(16).padStart(2,'0')).join('');
 const sha=async b=>hex(new Uint8Array(await crypto.subtle.digest('SHA-256',b)));
 const nonce=(prefix,n)=>{if(!Number.isSafeInteger(n)||n<0||n>=0xffffffff)throw Error('Chunk counter exceeded');const v=new Uint8Array(12);v.set(prefix);new DataView(v.buffer).setUint32(8,n,false);return v};
 async function key(secret,id,label){const raw=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveKey']);return crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:encode(id),info:encode('Vortex Node / '+label)},raw,{name:'AES-GCM',length:256},false,['encrypt','decrypt'])}
 async function seal(k,plain,aad){const iv=random(12);const c=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:encode(aad)},k,plain));const out=new Uint8Array(12+c.length);out.set(iv);out.set(c,12);return out}
 async function open(k,bytes,aad){if(bytes.length<28)throw Error('Encrypted data is incomplete');return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes.subarray(0,12),additionalData:encode(aad)},k,bytes.subarray(12)))}
 async function proof(secret){const prefix=encode('Vortex Node receive authority\0'),v=new Uint8Array(prefix.length+secret.length);v.set(prefix);v.set(secret,prefix.length);return sha(v)}
 const chunkAad=(share,file,index,size)=>encode(JSON.stringify(['Vortex Share',share,file,index,size]));
 async function encryptChunk(k,prefix,plain,share,file,index,size){return new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce(prefix,index),additionalData:chunkAad(share,file,index,size)},k,plain))}
 async function decryptChunk(k,prefix,cipher,share,file,index,size){return new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce(prefix,index),additionalData:chunkAad(share,file,index,size)},k,cipher))}
 function safePath(path){if(typeof path!=='string'||!path||path.length>4096||path.startsWith('/')||/[\\\x00-\x1f\x7f:]/.test(path))throw Error('Unsafe transfer path');const pieces=path.split('/');if(pieces.length>64||pieces.some(p=>!p||p==='.'||p==='..'))throw Error('Unsafe transfer path');return path.normalize('NFC')}
 function validateManifest(m){
  if(!m||m.format!=='Vortex Share'||!Array.isArray(m.entries)||m.entries.length>10000||!Number.isSafeInteger(m.bytes)||m.bytes<0||m.bytes>100*1024**3)throw Error('Unsupported transfer manifest');
  let bytes=0,piece=0;const seen=new Set();
  for(const e of m.entries){e.path=safePath(e.path);const collision=e.path.toLocaleLowerCase('en-US');if(seen.has(collision))throw Error('The transfer contains conflicting file names');seen.add(collision);
   if(e.folder){if(e.size!==0)throw Error('Invalid folder');continue}
   if(!Number.isSafeInteger(e.size)||e.size<0||!Number.isSafeInteger(e.start)||e.start!==piece||!Number.isSafeInteger(e.count)||e.count!==Math.ceil(e.size/CHUNK)||typeof e.id!=='string'||!/^[A-Za-z0-9_-]{16,64}$/.test(e.id)||unb64(e.prefix).length!==8)throw Error('Invalid transfer layout');
   bytes+=e.size;piece+=e.count;
  }
  if(bytes!==m.bytes||m.pieces!==piece)throw Error('Transfer manifest totals do not match');return m;
 }
 const crcTable=Uint32Array.from({length:256},(_,n)=>{for(let j=0;j<8;j++)n=(n&1)?0xedb88320^(n>>>1):n>>>1;return n>>>0});
 function crcUpdate(crc,b){for(const x of b)crc=crcTable[(crc^x)&255]^(crc>>>8);return crc>>>0}
 function packet(n,fill){const b=new Uint8Array(n),v=new DataView(b.buffer);fill(v,b);return b}
 const u64=(v,o,n)=>v.setBigUint64(o,BigInt(n),true);
 function dosTime(){const d=new Date();return {time:(d.getHours()<<11)|(d.getMinutes()<<5)|(d.getSeconds()>>1),date:((Math.max(1980,d.getFullYear())-1980)<<9)|((d.getMonth()+1)<<5)|d.getDate()}}
 function localHeader(name,size,dt){return packet(30+name.length+20,(v,b)=>{v.setUint32(0,0x04034b50,true);v.setUint16(4,45,true);v.setUint16(6,0x0808,true);v.setUint16(10,dt.time,true);v.setUint16(12,dt.date,true);v.setUint32(18,0xffffffff,true);v.setUint32(22,0xffffffff,true);v.setUint16(26,name.length,true);v.setUint16(28,20,true);b.set(name,30);const p=30+name.length;v.setUint16(p,1,true);v.setUint16(p+2,16,true);u64(v,p+4,size);u64(v,p+12,size)})}
 function centralHeader(r,dt){return packet(46+r.name.length+28,(v,b)=>{v.setUint32(0,0x02014b50,true);v.setUint16(4,45,true);v.setUint16(6,45,true);v.setUint16(8,0x0808,true);v.setUint16(12,dt.time,true);v.setUint16(14,dt.date,true);v.setUint32(16,r.crc,true);v.setUint32(20,0xffffffff,true);v.setUint32(24,0xffffffff,true);v.setUint16(28,r.name.length,true);v.setUint16(30,28,true);v.setUint32(38,r.folder?0x10:0,true);v.setUint32(42,0xffffffff,true);b.set(r.name,46);const p=46+r.name.length;v.setUint16(p,1,true);v.setUint16(p+2,24,true);u64(v,p+4,r.size);u64(v,p+12,r.size);u64(v,p+20,r.offset)})}
 async function* zip(entries,readFile){
  const records=[],dt=dosTime();let offset=0;
  for(const e of entries){const name=encode(e.path+(e.folder?'/':''));if(name.length>65535)throw Error('File path is too long');const rec={name,size:e.size,offset,crc:0,folder:!!e.folder};const h=localHeader(name,e.size,dt);yield h;offset+=h.length;let crc=0xffffffff,got=0;
   if(!e.folder)for await(const b of readFile(e)){if(!(b instanceof Uint8Array)||got+b.length>e.size)throw Error('File length mismatch');crc=crcUpdate(crc,b);got+=b.length;offset+=b.length;yield b;}
   if(got!==e.size)throw Error('File was truncated');rec.crc=(crc^0xffffffff)>>>0;const tail=packet(24,v=>{v.setUint32(0,0x08074b50,true);v.setUint32(4,rec.crc,true);u64(v,8,got);u64(v,16,got)});yield tail;offset+=tail.length;records.push(rec);
  }
  const centralStart=offset;for(const r of records){const h=centralHeader(r,dt);yield h;offset+=h.length}
  const centralSize=offset-centralStart,endStart=offset;
  yield packet(56,v=>{v.setUint32(0,0x06064b50,true);u64(v,4,44);v.setUint16(12,45,true);v.setUint16(14,45,true);u64(v,24,records.length);u64(v,32,records.length);u64(v,40,centralSize);u64(v,48,centralStart)});
  yield packet(20,v=>{v.setUint32(0,0x07064b50,true);u64(v,8,endStart);v.setUint32(16,1,true)});
  yield packet(22,v=>{v.setUint32(0,0x06054b50,true);v.setUint16(8,0xffff,true);v.setUint16(10,0xffff,true);v.setUint32(12,0xffffffff,true);v.setUint32(16,0xffffffff,true)});
 }
 function zipSize(entries){return entries.reduce((n,e)=>n+e.size+148+encode(e.path+(e.folder?'/':'')).length*2,98)}
 function stream(iterable){const iterator=iterable[Symbol.asyncIterator]();return new ReadableStream({async pull(c){try{const {value,done}=await iterator.next();done?c.close():c.enqueue(value)}catch(e){c.error(e)}},async cancel(){await iterator.return?.()}})}
 async function request(url,options={}){if(window.VortexSession)options={...options,signal:VortexSession.requestSignal(options.signal)};const response=await fetch(url,{...options,credentials:'omit',cache:'no-store',redirect:'error'});if(!response.ok){let message='Request failed';try{message=(await response.json()).error||message}catch{}const e=Error(message);e.status=response.status;throw e;}return response}
 async function json(url,body,token,method='POST'){return (await request(url,{method,headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},...(body===undefined?{}:{body:JSON.stringify(body)})})).json()}
 async function download(readable,name,size,{worker='/receive/worker.js',signal}={}){
  const fallback=async()=>{
   if(window.showSaveFilePicker){const h=await showSaveFilePicker({suggestedName:name}),out=await h.createWritable();await readable.pipeTo(out,{signal});return}
   if(size>128*1024**2)throw Error('This browser cannot stream this download. Open this link in an up-to-date Firefox, Chrome or Safari browser.');
   const blob=await new Response(readable).blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),60000);return;
  };
  if(!('serviceWorker' in navigator))return fallback();
  let registration;try{registration=await navigator.serviceWorker.register(worker,{scope:'/receive/'})}catch{return fallback()}const sw=registration.active||await new Promise((resolve,reject)=>{const w=registration.installing||registration.waiting;if(!w)return reject(Error('Download worker unavailable'));const timer=setTimeout(()=>reject(Error('Download worker did not start')),15000);w.addEventListener('statechange',()=>{if(w.state==='activated'){clearTimeout(timer);resolve(w)}})});
  const id=b64(random(24)),channel=new MessageChannel();let reader;
  await new Promise((resolve,reject)=>{const t=setTimeout(()=>reject(Error('Download worker did not respond')),15000);channel.port1.onmessage=e=>{if(e.data?.ready){clearTimeout(t);resolve()}};sw.postMessage({begin:id,name,size},[channel.port2])});
  return new Promise((resolve,reject)=>{
   let finished=false;const end=(error)=>{if(finished)return;finished=true;signal?.removeEventListener('abort',abort);channel.port1.close();error?reject(error):resolve()};
   const abort=()=>{reader?.cancel();channel.port1.postMessage({error:'Download cancelled'});end(Error('Download cancelled'))};signal?.addEventListener('abort',abort,{once:true});
   channel.port1.onmessage=async e=>{try{if(e.data?.error){await reader?.cancel();end(Error(e.data.error));return}if(e.data?.complete){end();return}if(e.data?.cancel){await reader?.cancel();end(Error('Download cancelled'));return}if(e.data?.pull){reader??=readable.getReader();const r=await reader.read();if(r.done){channel.port1.postMessage({done:true});return}const b=r.value instanceof Uint8Array?r.value:new Uint8Array(r.value);const out=b.byteOffset===0&&b.byteLength===b.buffer.byteLength?b:b.slice();channel.port1.postMessage({bytes:out.buffer},[out.buffer])}}catch(error){channel.port1.postMessage({error:'Encrypted download failed'});end(error)}};
   const frame=document.createElement('iframe');frame.hidden=true;frame.setAttribute('aria-hidden','true');frame.src='/receive/download/'+id;document.body.append(frame);setTimeout(()=>frame.remove(),7*60*60*1000);
  });
 }
 return {CHUNK,encode,b64,unb64,random,sha,nonce,key,seal,open,proof,encryptChunk,decryptChunk,validateManifest,safePath,zip,zipSize,stream,request,json,download,decoder};
})();
