'use strict';
const pending=new Map();
self.addEventListener('install',event=>event.waitUntil(self.skipWaiting()));
self.addEventListener('activate',event=>event.waitUntil(self.clients.claim()));
self.addEventListener('message',event=>{
 const {begin,name,size}=event.data||{},port=event.ports[0];
 if(!port||typeof begin!=='string'||!/^[A-Za-z0-9_-]{32}$/.test(begin)||typeof name!=='string'||name.length>4096||!Number.isSafeInteger(size)||size<0)return;
 if(pending.size>=8){port.postMessage({error:'Finish a download before starting another.'});port.close();return;}
 const clean=name.replace(/[\x00-\x1f\x7f\"\\/]/g,'_'),dot=clean.lastIndexOf('.'),suffix=dot>0&&clean.length-dot<=16?clean.slice(dot):'',short=clean.length>200?clean.slice(0,200-suffix.length)+suffix:clean;
 const timer=setTimeout(()=>{pending.delete(begin);port.postMessage({error:'Your browser did not start the download. Allow downloads and retry.'});port.close()},60000);
 pending.set(begin,{port,name:short,size,timer});port.postMessage({ready:true});
});
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);if(url.origin!==self.location.origin||!url.pathname.startsWith('/receive/download/'))return;
 const id=url.pathname.slice('/receive/download/'.length),p=pending.get(id);if(!p)return;
 pending.delete(id);clearTimeout(p.timer);
 let waiting=false,controller;
 const stream=new ReadableStream({start(c){controller=c;p.port.onmessage=e=>{waiting=false;if(e.data?.bytes instanceof ArrayBuffer)c.enqueue(new Uint8Array(e.data.bytes));else if(e.data?.done){c.close();p.port.postMessage({complete:true});p.port.close()}else{c.error(Error('Download interrupted'));p.port.close()}}},pull(){if(!waiting){waiting=true;p.port.postMessage({pull:true})}},cancel(){p.port.postMessage({cancel:true});p.port.close()}},{highWaterMark:0});
 const headers={'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="${p.name.replace(/[^\x20-\x7e]/g,'_')}"; filename*=UTF-8''${encodeURIComponent(p.name).replace(/['()*]/g,c=>'%'+c.charCodeAt(0).toString(16).toUpperCase())}`,'Content-Length':String(p.size),'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'};
 event.respondWith(new Response(stream,{headers}));
});
