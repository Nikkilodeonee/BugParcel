// Synthetic fixtures derived from the fictional checkout. No network requests.
import fs from 'node:fs';
import crypto from 'node:crypto';
const sample='src/main/resources/samples/', cache='.cache/tier4-samples/';
fs.mkdirSync(cache,{recursive:true});
const har=JSON.parse(fs.readFileSync(sample+'checkout.har','utf8'));
const logs=fs.readFileSync(sample+'checkout.ndjson','utf8').trim().split(/\r?\n/).map(JSON.parse);
const xml=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&apos;'}[c]));
const headers=h=>'<headers>'+h.map(v=>`<header><name>${xml(v.name)}</name><value>${xml(v.value)}</value></header>`).join('')+'</headers>';
let charles='<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE charles-session SYSTEM "https://www.charlesproxy.com/dtd/charles-session-1_0.dtd">\n<charles-session>\n';
const executions=[],flows=[];
for(const [i,e] of har.log.entries.entries()){
 const url=new URL(e.request.url),start=Date.parse(e.startedDateTime);
 charles+=`<transaction method="${xml(e.request.method)}" protocolVersion="HTTP/1.1" protocol="${url.protocol.slice(0,-1)}" host="${xml(url.hostname)}" port="${url.port||443}" path="${xml(url.pathname)}" query="${xml(url.search.slice(1))}" startTimeMillis="${start}" endTimeMillis="${start+e.time}"><request>${headers(e.request.headers)}<body encoding="text">${xml(e.request.postData?.text||'')}</body></request><response status="${e.response.status}" mime-type="${xml(e.response.content.mimeType)}">${headers(e.response.headers)}<body encoding="text">${xml(e.response.content.text||'')}</body></response></transaction>\n`;
 executions.push({id:`request-${i+1}`,request:{method:e.request.method,url:{raw:e.request.url},header:e.request.headers.map(h=>({key:h.name,value:h.value})),body:e.request.postData?{mode:'raw',raw:e.request.postData.text}:undefined},response:{code:e.response.status,status:e.response.statusText,header:e.response.headers.map(h=>({key:h.name,value:h.value})),responseTime:e.time,stream:Buffer.from(e.response.content.text||'').toJSON()}});
 const pairs=h=>h.map(v=>[Buffer.from(v.name),Buffer.from(v.value)]);
 flows.push({version:21,type:'http',request:{host:url.hostname,port:Number(url.port||443),scheme:Buffer.from(url.protocol.slice(0,-1)),method:Buffer.from(e.request.method),path:Buffer.from(url.pathname+url.search),headers:pairs(e.request.headers),content:Buffer.from(e.request.postData?.text||''),timestamp_start:start/1000,timestamp_end:start/1000},response:{status_code:e.response.status,reason:Buffer.from(e.response.statusText||''),headers:pairs(e.response.headers),content:Buffer.from(e.response.content.text||''),timestamp_start:start/1000,timestamp_end:(start+e.time)/1000}});
}
fs.writeFileSync(sample+'charles-checkout.xml',charles+'</charles-session>\n');
fs.writeFileSync(sample+'newman-checkout.json',JSON.stringify({run:{executions}},null,2)+'\n');
fs.writeFileSync(sample+'postman-checkout.json',JSON.stringify({results:har.log.entries.map(e=>({url:e.request.url,method:e.request.method,time:e.time,responseCode:{code:e.response.status,name:e.response.statusText}}))},null,2)+'\n');
function net(value){
 let body,type;
 if(Buffer.isBuffer(value)){body=value;type=',';}
 else if(value===null){body=Buffer.alloc(0);type='~';}
 else if(typeof value==='string'){body=Buffer.from(value);type=';';}
 else if(typeof value==='number'){body=Buffer.from(String(value));type=Number.isInteger(value)?'#':'^';}
 else if(Array.isArray(value)){body=Buffer.concat(value.map(net));type=']';}
 else {body=Buffer.concat(Object.entries(value).flatMap(([k,v])=>[net(k),net(v)]));type='}';}
 return Buffer.concat([Buffer.from(body.length+':'),body,Buffer.from(type)]);
}
fs.writeFileSync(sample+'mitmproxy-checkout.mitm',Buffer.concat(flows.map(net)));
const resources=new Map(),network=[];
for(const original of har.log.entries){
 const e=structuredClone(original);
 for(const part of [e.request.postData,e.response.content])if(part?.text){const bytes=Buffer.from(part.text);const sha=crypto.createHash('sha1').update(bytes).digest('hex');resources.set('resources/'+sha,bytes);part._sha1=sha;delete part.text;}
 network.push(JSON.stringify({type:'resource-snapshot',snapshot:e}));
}
const traceFiles=[['trace.network',Buffer.from(network.join('\n')+'\n')],['trace.trace',Buffer.from(JSON.stringify({version:10,type:'context-options',wallTime:Date.parse(har.log.entries[0].startedDateTime)})+'\n')],...resources.entries()];
const manifest={trace:[],logs:[]};
for(const [index,[name,bytes]] of traceFiles.entries()){const file=`trace-part-${index}`;fs.writeFileSync(cache+file,bytes);manifest.trace.push({name,file});}
fs.writeFileSync(cache+'logs-api',logs.slice(0,4).map(JSON.stringify).join('\n')+'\n');
const {gzipSync}=await import('node:zlib');fs.writeFileSync(cache+'logs-worker',gzipSync(Buffer.from(JSON.stringify(logs.slice(4)))));
fs.writeFileSync(cache+'logs-notes','Fictional samples only.');
manifest.logs=[{name:'logs/api.ndjson',file:'logs-api'},{name:'logs/worker.log.gz',file:'logs-worker'},{name:'notes.md',file:'logs-notes'}];
fs.writeFileSync(cache+'manifest.json',JSON.stringify(manifest));
console.log('Generated fictional Charles, Postman/Newman, mitmproxy and Playwright input samples.');
