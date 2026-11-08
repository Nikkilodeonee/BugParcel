import { requestIdGuides } from './request-id-guides.js';
import { createReportFeatures } from './reports.js';
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const escape = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
const state = {har:'', logs:'', title:'Untitled incident', files:{har:null,logs:null}, sample:false, analysis:null, tab:'requests', filter:'all', logFilter:'all', search:'', logSearch:'', selected:null, detailTab:'evidence', enabled:new Set(['CREDENTIAL','EMAIL','IP','PHONE','CUSTOM']), custom:[], exclusions:new Set(), forced:new Set(), reviewSearch:'', reviewPage:0, includeBodies:false, timestampHints:false, busy:false};
Object.assign(state,{profile:null,policyYaml:null,policyName:'',decodeContent:null,samplePolicy:null});
state.enabled.add('POLICY');
const matchLabels = {'request-id':'Request ID match','shared-request':'Shared request ID context','trace-id':'Trace ID match','shared-trace':'Shared trace context','correlation-id':'Correlation ID match','shared-correlation':'Shared correlation context',unmatched:'No shared identifier'};
Object.assign(matchLabels, {'cf-ray':'Cloudflare Ray ID match','shared-ray':'Shared Cloudflare Ray context','aws-trace-id':'AWS trace match','shared-aws-trace':'Shared AWS trace context','azure-root-id':'Azure root context','shared-azure-root':'Shared Azure root context'});
let pending, revision = 0, toastTimer;
const reports=createReportFeatures({state,payload,api,escape,renderLogCard,downloadBlob,toast,message,switchTab,renderLogs,loadSample});

function payload() { return {har:state.har,logs:state.logs,title:state.title,enabledCategories:state.enabled?[...state.enabled]:null,customValues:state.custom,includeBodies:state.includeBodies,excludedFindingIds:[...state.exclusions],redactFindingIds:[...state.forced],timestampHints:state.timestampHints,profile:state.profile,policyYaml:state.policyYaml,decodeContent:state.decodeContent,reportTheme:state.reportTheme}; }
function message(text='') { $('#feedback').textContent=text; $('#feedback').hidden=!text; }
function toast(text) { clearTimeout(toastTimer); $('#toast').textContent=text; $('#toast').hidden=false; toastTimer=setTimeout(()=>$('#toast').hidden=true,4500); }
function setBusy(busy) {
  reports.busy(busy);
  state.busy=busy;$('#busy-line').hidden=!busy;$('#export-button').disabled=busy||!state.analysis;$('#reset-review').disabled=busy||(state.exclusions.size===0&&state.forced.size===0);$$('[data-action="sample"],[data-action="security-sample"],#apply-sample-policy').forEach(b=>b.disabled=busy);
  for(const id of ['redaction-profile','decode-content','policy-file','clear-policy','include-bodies','custom-value'])$(`#${id}`).disabled=busy;
  $$('[data-finding],#custom-form button').forEach(b=>b.disabled=busy);
  $$('[data-category]').forEach(b=>b.disabled=busy||(['CARD','IBAN','PESEL','SUSPECT'].includes(b.dataset.category)&&state.analysis?.incident.security.profile!=='paranoid'));
}
function fileSize(bytes) { return bytes<1024?`${bytes} B`:`${(bytes/1024).toFixed(1)} KB`; }
function failure(r) {return r.status===0||r.status>=400;}
function time(value) {if(!value)return 'No timestamp';if(!/\d{4}-\d{2}-\d{2}[T ].*(Z|[+-]\d{2}:?\d{2})$/i.test(value))return value+' (zone/date unspecified)';const date=new Date(value.replace(',', '.'));return Number.isNaN(date.valueOf())?value:date.toISOString().substring(11,23)+' UTC';}
function duration(ms) {return ms>=1000?`${(ms/1000).toFixed(2)} s`:`${Math.round(ms)} ms`;}
function urlParts(value) {try {const url=new URL(value);return {path:url.pathname+url.search+url.hash,host:url.host};}catch{return {path:value,host:''};}}
function method(r) {const type=['POST','PUT','PATCH','DELETE'].includes(r.method)?r.method.toLowerCase():'';return `<span class="method ${type}">${escape(r.method)}</span>`;}
function status(r) {return `<span class="status-badge ${failure(r)?'failure':r.status>=300?'redirect':''}">${r.status===0?'ERR':escape(r.status)}</span>`;}
function levelClass(value) {return ['ERROR','FATAL','WARN','DEBUG','TRACE'].includes(value)?value.toLowerCase():'';}
function level(value) {return `<span class="level ${levelClass(value)}">${escape(value||'LOG')}</span>`;}
function replacements(value) {return escape(value).replace(/\[REDACTED_[A-Z]+_\d+\]/g,token=>`<span class="redacted">${token}</span>`);}
function updateFiles() {
  for(const key of ['har','logs']) {
    const file=state.files[key];$(`#${key}-drop`).classList.toggle('loaded',!!file);
    $(`#${key}-name`).textContent=file?file.name:key==='har'?'Browser recording':'Server logs';
    $(`#${key}-hint`).textContent=file?`${fileSize(file.size)} · ${state.sample?'Synthetic sample':'In memory'} · Click to replace`:key==='har'?'Drop a .har file or browse files':'Drop JSON, text, logfmt, access or Docker logs';
    $(`#${key}-status`).innerHTML=icon(file?'check':'plus');
  }
  $('#sample-badge').hidden=!state.sample;$('#clear-button').hidden=!state.har&&!state.logs;
}
async function api(path,input,signal) {
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input),signal});
  if(!response.ok) {let error;try{error=(await response.json()).error;}catch{}throw new Error(error||`The local engine returned HTTP ${response.status}.`);}
  return response;
}
async function analyze() {
  reports.invalidate();
  pending?.abort();const current=++revision;
  message();updateFiles();
  if(!state.har) {state.analysis=null;render();return;}
  pending=new AbortController();setBusy(true);
  try {
    const response=await api('/api/analyze',payload(),pending.signal);const result=await response.json();
    if(current!==revision)return;
    state.analysis=result;
    state.enabled=new Set(result.incident.redactions.filter(c=>c.enabled).map(c=>c.category));
    if(!state.selected||!result.incident.requests.some(r=>r.id===state.selected)) state.selected=result.incident.requests.find(r=>r.status>=500)?.id||result.incident.requests.find(failure)?.id||result.incident.requests[0]?.id;
    render();
  }catch(error) {
    if(error.name!=='AbortError'&&current===revision){state.analysis=null;message(error.message);render();}
  }finally {if(current===revision)setBusy(false);}
}
async function loadSample(variant='checkout') {
  if(state.busy)return;
  if(state.har&&!state.sample) {toast('Clear the current session before loading the sample, so your imported evidence stays available.');return;}
  setBusy(true);message();
  try {
    const response=await fetch(variant==='security'?'/api/sample/security':variant==='fixed'?'/api/sample/fixed':'/api/sample');if(!response.ok)throw new Error('The sample files could not be loaded. Is the local engine running?');
    const sample=await response.json();clearSession(false,true);state.har=sample.har;state.logs=sample.logs;state.title=sample.title;state.sample=true;state.samplePolicy=sample.policyYaml||null;
    state.files={har:{name:`${variant}.har`,size:new Blob([sample.har]).size},logs:{name:`${variant}.ndjson`,size:new Blob([sample.logs]).size}};
    state.selected=null;state.search='';$('#request-search').value='';state.filter='all';state.tab='requests';
    await analyze();
  }catch(error){message(error.message);}finally{setBusy(false);}
}
async function importFile(key,file) {
  if(!file)return;
  if(file.size>10*1024*1024){message(`${file.name} is larger than 10 MB. Export a shorter recording around the incident.`);return;}
  try {
    const input=await file.text();if(!input.trim())throw new Error('This file is empty. Choose a recording with some evidence.');
    if(state.sample){clearSession(false,true);}
    state[key]=input;state.files[key]={name:file.name,size:file.size};state.sample=false;state.selected=null;
    if(key==='har'&&state.title==='Untitled incident')state.title=file.name.replace(/\.(har|json)$/i,'').substring(0,160)||'Untitled incident';
    await analyze();
    if(!state.har)toast('Logs added. Add a HAR file to connect the evidence.');
  }catch(error){message(error.message);}finally{$(`#${key}-file`).value='';}
}
function clearSession(notify=true,preserveBaseline=false) {
  const saved=preserveBaseline&&state.baseline?Object.fromEntries(['baseline','baselineLabel','profile','policyYaml','policyName','decodeContent','enabled','custom','exclusions','forced','includeBodies','reportTheme','timestampHints'].map(key=>[key,state[key] instanceof Set?new Set(state[key]):Array.isArray(state[key])?[...state[key]]:state[key]])):null;
  reports.clear();
  state.profile=null;state.policyYaml=null;state.policyName='';state.decodeContent=null;state.samplePolicy=null;$('#policy-file').value='';
  state.timestampHints=false;$('#timestamp-hints').checked=false;
  pending?.abort();revision++;state.har='';state.logs='';state.title='Untitled incident';state.files={har:null,logs:null};state.sample=false;state.analysis=null;state.selected=null;state.custom=[];state.exclusions.clear();state.forced.clear();state.reviewSearch='';state.reviewPage=0;state.enabled=new Set(['CREDENTIAL','EMAIL','IP','PHONE','CUSTOM']);state.includeBodies=false;state.filter='all';state.logFilter='all';state.tab='requests';state.detailTab='evidence';state.search='';state.logSearch='';
  $('#request-search').value='';$('#log-search').value='';$('#har-file').value='';$('#logs-file').value='';
  $('#incident-title').value='Untitled incident';$('#custom-value').value='';$('#include-bodies').checked=false;
  $('#review-search').value='';
  $('#self-check').replaceChildren();$('#policy-status').textContent='No team policy loaded';$('#redaction-profile').value='standard';$('#decode-content').checked=true;
  state.enabled.add('POLICY');
  if(saved)Object.assign(state,saved);
  for(const id of ['stats','request-rows','request-detail','log-list','redaction-options','custom-chips','notes-list','export-summary','review-rows','correlation-diagnostics','detected-formats'])$(`#${id}`).replaceChildren();
  $('#export-status').textContent='';setBusy(false);message();render();if(notify)toast('Session cleared. Your original files are untouched.');
}
function render() {
  updateFiles();const result=state.analysis;
  $('#workspace').hidden=!result;$('#empty-state').hidden=!!result;$('#export-button').disabled=!result||state.busy;
  if(!result)return;
  const incident=result.incident;
  // Keep the original editable title in memory; the preview and export use the redacted title.
  if(document.activeElement!==$('#incident-title'))$('#incident-title').value=state.title;
  $('#incident-meta').textContent=`${incident.requests.length} requests · ${incident.logs.length} log entries`;
  $('#stats').innerHTML=[
    ['requests',incident.requests.length,'From the browser recording',''],
    ['failed',result.failedRequests,'HTTP errors and network failures',result.failedRequests?'error':''],
    ['linked to logs',result.matchedRequests,'Connected by a shared identifier','blue'],
    ['values redacted',result.redactedOccurrences,'Consistent across the evidence','']
  ].map(([label,value,note,color])=>`<div class="stat ${color}" title="${escape(note)}"><b>${value}</b><span>${label}</span></div>`).join('');
  $('#requests-count').textContent=incident.requests.length;$('#logs-count').textContent=incident.logs.length;$('#redactions-count').textContent=result.redactedOccurrences;
  renderSecurity();renderCorrelation();renderTabs();renderRequests();renderLogs();renderRedactions();reports.render();
  $('#notes-label').textContent=`Analysis notes${incident.warnings.length?` · ${incident.warnings.length}`:''}`;
  $('#notes-list').innerHTML=incident.warnings.length?incident.warnings.map(w=>`<li>${escape(w)}</li>`).join(''):'<li>No additional format or correlation warnings.</li>';
}
function checkLabel(incident) {
  const security=incident.security, check=security.selfCheck;
  const limited=!check.completed||security.scanLimited||!security.decodeContent;
  return `${limited?'Limited check · ':''}${check.remainingValues} remaining pattern/known-value ${check.remainingValues===1?'match':'matches'}`;
}
function renderSecurity() {
  const incident=state.analysis.incident, security=incident.security;
  const warning=security.selfCheck.remainingValues>0||!security.selfCheck.completed||security.scanLimited||!security.decodeContent;
  $('#self-check').classList.toggle('warning',warning);
  $('#self-check').innerHTML=`<strong>${escape(checkLabel(incident))}</strong><small>Included evidence · ${escape(security.profile)} profile · bounded detectors. This check does not guarantee all sensitive data was found.${warning?' Review Redactions and Analysis notes before sharing.':''}</small>`;
  $('#redaction-profile').value=security.profile;
  $('#decode-content').checked=security.decodeContent;
  $('#policy-status').textContent=security.policyApplied?`${state.policyName||'Team policy'} · ${security.policyRules} rules · ${security.allowlistRules} allowlists`:'No team policy loaded';
  $('#clear-policy').hidden=!security.policyApplied;
  $('#apply-sample-policy').hidden=!state.samplePolicy;
}
async function importPolicy(file) {
  if(!file)return;
  if(file.size>65536){message('Policy files must be at most 64 KiB.');return;}
  reports.invalidate();
  pending?.abort();const current=++revision;pending=new AbortController();setBusy(true);message();
  try{
    const text=await file.text();
    if(!text.trim())throw new Error('The policy file is empty.');
    const response=await api('/api/analyze',{...payload(),policyYaml:text,profile:null,enabledCategories:null,decodeContent:null},pending.signal);
    const result=await response.json();if(current!==revision)return;
    state.policyYaml=text;state.policyName=file.name;state.profile=null;state.decodeContent=null;
    state.analysis=result;state.enabled=new Set(result.incident.redactions.filter(c=>c.enabled).map(c=>c.category));
    render();toast('Team policy applied. Review its allowlists before sharing.');
  }catch(error){if(error.name!=='AbortError'&&current===revision)message(`Policy was not applied: ${error.message}`);}
  finally{if(current===revision)setBusy(false);$('#policy-file').value='';}
}
function renderCorrelation() {
  const review=state.analysis.incident.correlation;
  const panel=$('#correlation-diagnostics');
  panel.hidden=!review.diagnostics.length;
  const formatNames=review.logFormats.map(f=>f.name).join(' ');
  const guide=formatNames.includes('Python')?'django':formatNames.includes('access')?'nginx':'spring';
  panel.innerHTML=review.diagnostics.length?`<div class="diagnostic-heading"><h2 id="diagnostics-title">No requests linked</h2><button class="button button-secondary" data-action="add-ids" data-guide="${guide}">Add request IDs ${icon('arrow')}</button></div>${review.diagnostics.map(d=>`<div class="diagnostic-reason"><strong>${escape(d.message)}</strong><p>${escape(d.nextStep)}</p></div>`).join('')}`:'';
  $('#detected-formats').textContent=review.logFormats.length?`Detected ${review.logFormats.length>1?'mixed formats':'format'}: ${review.logFormats.map(f=>`${f.name} · ${f.entries}`).join(' / ')}`:'No server logs imported';
  $('#timestamp-hints').checked=review.timestampHintsEnabled;
}
function renderGuide() {
  const guide=requestIdGuides.find(g=>g.id===$('#guide-stack').value)||requestIdGuides[0];
  $('#guide-snippet-note').textContent=guide.note;
  $('#guide-snippet').textContent=guide.code;
  $('#guide-source').href=guide.source;
  $('#guide-copy-status').textContent='';
}
function showGuide(id) {
  if(id)$('#guide-stack').value=id;
  renderGuide();$('#guide-dialog').showModal();
  if(id)$('#add-ids-title').scrollIntoView({block:'start'});
}
function renderTabs() {
  $$('[data-tab]').forEach(button=>{const selected=button.dataset.tab===state.tab;button.classList.toggle('active',selected);button.setAttribute('aria-selected',selected);button.tabIndex=selected?0:-1;$(`#panel-${button.dataset.tab}`).hidden=!selected;});
  $('#value-review').hidden=state.tab!=='redactions';
  $('#policy-panel').hidden=state.tab!=='redactions';
}
function renderRequests() {
  if(!state.analysis)return;
  const all=state.analysis.incident.requests;
  const rows=all.filter(r=>(state.filter==='all'||(state.filter==='failed'?failure(r):!r.logIds.length))&&`${r.method} ${r.url} ${r.status} ${Object.values(r.correlationIds).join(' ')}`.toLowerCase().includes(state.search.toLowerCase()));
  $('#visible-count').textContent=`${rows.length} of ${all.length}`;
  $$('[data-filter]').forEach(b=>{b.classList.toggle('selected',b.dataset.filter===state.filter);b.setAttribute('aria-pressed',b.dataset.filter===state.filter);});
  if(rows.length&&!rows.some(r=>r.id===state.selected))state.selected=rows[0].id;
  $('#request-rows').innerHTML=rows.length?rows.map(r=>{const parts=urlParts(r.url);return `<tr class="${r.id===state.selected?'selected':''}"><td><button class="request-button" data-request="${escape(r.id)}" aria-label="Inspect ${escape(r.method)} ${escape(parts.path)}" aria-pressed="${r.id===state.selected}"><span class="request-primary">${method(r)}<span class="request-path" title="${escape(r.url)}">${escape(parts.path)}</span></span><span class="request-host">${escape(parts.host)}</span></button></td><td>${status(r)}</td><td><span class="duration ${r.durationMs>=1000?'slow':''}">${duration(r.durationMs)}</span></td><td><span class="link-count ${r.logIds.length?'':'zero'}" title="${r.logIds.length} linked log entries">${icon('link')}${r.logIds.length||'—'}</span></td></tr>`;}).join(''):'<tr><td colspan="4"><div class="no-results">No requests match this view.<br>Try another filter or search.</div></td></tr>';
  renderDetail(rows.length?all.find(r=>r.id===state.selected):null);
}
function renderLogCard(log) {
  return `<div class="log-card ${levelClass(log.level)}"><div class="log-line-top">${level(log.level)}<span class="log-time">${escape(time(log.timestamp))}</span></div><div class="log-message">${replacements(log.message)}</div><div class="log-logger">${escape(log.logger||'Text log')} · line ${log.sourceLine}</div>${log.stackTrace?`<details class="stack-details"><summary>Inspect stack trace</summary><pre>${replacements(log.stackTrace)}</pre></details>`:''}</div>`;
}
function headerTable(headers) {const entries=Object.entries(headers);return entries.length?`<table class="header-table"><tbody>${entries.map(([key,value])=>`<tr><td>${escape(key)}</td><td>${replacements(value)}</td></tr>`).join('')}</tbody></table>`:'<p class="detail-note">None recorded.</p>';}
function renderDetail(request) {
  const panel=$('#request-detail');
  if(!request){panel.innerHTML='<div class="empty-evidence">Choose a request to view its evidence.</div>';return;}
  const r=request;const parts=urlParts(r.url);const logs=state.analysis.incident.logs.filter(l=>r.logIds.includes(l.id));
  let content='';
  if(state.detailTab==='evidence') {
    const kind=r.matchKind;
    content=`<div class="match-banner ${kind==='unmatched'?'unmatched':kind.startsWith('shared')?'shared':''}">${icon(kind==='unmatched'?'help':'link')}<span>${escape(matchLabels[kind]||kind)}${logs.length?` · ${logs.length} log ${logs.length===1?'entry':'entries'}`:''}</span></div><div class="correlation-chip">${Object.entries(r.correlationIds).map(([key,value])=>`<span>${escape(key)}: ${replacements(value)}</span>`).join('')}</div>`;
    if(Object.values(r.correlationIds).some(value=>value.includes('[REDACTED_')))content+='<p class="detail-note">Displayed IDs are redacted. These links were matched using the original IDs before redaction.</p>';
    if(kind.startsWith('shared'))content+='<p class="detail-note">This identifier is shared by multiple requests. These logs describe shared context, not an exclusive match.</p>';
    content+=logs.length?`<h3 class="mini-heading">Linked server logs</h3>${reports.grouped(logs,renderLogCard)}`:`<div class="empty-evidence">${icon('link')}${state.logs?'No log entries share a supported identifier with this request.':'Add server logs to connect the other side of this request.'}<br><span class="detail-note">Time alone is not treated as proof.</span></div>`;
    const review=state.analysis.incident.correlation;
    if(review.timestampHintsEnabled&&!logs.length) {
      const hints=review.timestampHints.filter(h=>h.requestId===r.id);
      content+=`<section class="time-hints"><h3>Time hints · unconfirmed</h3><p>Guesses from unlinked logs within ±2 seconds of request start. Clocks can differ. These entries remain unlinked.</p>${hints.length?hints.map(h=>{const log=state.analysis.incident.logs.find(l=>l.id===h.logId);return log?`<div class="hint-distance">${h.distanceMs} ms from request start · guess</div>${renderLogCard(log)}`:'';}).join(''):'<p>No eligible entries in this time window. Hints require a complete date and explicit UTC offset; conflicting IDs are excluded.</p>'}</section>`;
    }
  }else if(state.detailTab==='headers')content=`<h3 class="mini-heading">Request headers</h3>${headerTable(r.requestHeaders)}<h3 class="mini-heading">Response headers</h3>${headerTable(r.responseHeaders)}`;
  else content=state.includeBodies?`<h3 class="mini-heading">Request body</h3>${r.requestBody?`<pre class="body-code">${replacements(r.requestBody)}</pre>`:'<p class="detail-note">No text request body recorded.</p>'}<h3 class="mini-heading">Response body</h3>${r.responseBody?`<pre class="body-code">${replacements(r.responseBody)}</pre>`:'<p class="detail-note">No supported text response body recorded.</p>'}`:`<div class="empty-evidence">${icon('shield')}Bodies are excluded from this report.<br><button class="text-button" data-action="redactions">Manage in Redactions ${icon('arrow')}</button></div>`;
  panel.innerHTML=`<div class="detail-header"><div class="detail-eyebrow">Request details<span>${escape(r.id)}</span></div><div class="detail-path">${method(r)}${escape(parts.path)}</div><div class="detail-meta">${status(r)}<span>${escape(r.statusText)}</span><span>·</span><span>${duration(r.durationMs)}</span><span>·</span><span>${escape(time(r.timestamp))}</span></div>${reports.snippetTools(r.id)}</div><div class="detail-nav" aria-label="Request detail view">${[['evidence','Evidence'],['headers','Headers'],['bodies','Bodies']].map(([key,label])=>`<button class="${state.detailTab===key?'active':''}" data-detail="${key}" aria-pressed="${state.detailTab===key}">${label}</button>`).join('')}</div><div class="detail-content">${content}</div>`;
}
function renderLogs() {
  const incident=state.analysis?.incident;if(!incident)return;
  $('#unmatched-log-count').textContent=`${state.analysis.unmatchedLogs} unlinked`;
  $$('[data-log-filter]').forEach(b=>{b.classList.toggle('selected',b.dataset.logFilter===state.logFilter);b.setAttribute('aria-pressed',b.dataset.logFilter===state.logFilter);});
  const linked=new Set(incident.requests.flatMap(r=>r.logIds));
  const logs=incident.logs.filter(l=>(state.logFilter==='all'||(state.logFilter==='unmatched'?!linked.has(l.id):state.logFilter==='ERROR'?['ERROR','FATAL','CRITICAL'].includes(l.level):l.level===state.logFilter))&&`${l.id} ${l.message} ${l.logger} ${l.stackTrace} ${Object.values(l.correlationIds).join(' ')}`.toLowerCase().includes(state.logSearch.toLowerCase()));
  $('#log-list').innerHTML=logs.length?reports.grouped(logs,l=>`<article class="logbook-entry"><div><div class="log-line-top">${level(l.level)}<span class="log-time">${escape(time(l.timestamp))}</span></div>${incident.requests.filter(r=>r.logIds.includes(l.id)).map(r=>`<button class="logbook-link" data-go-request="${escape(r.id)}">${escape(r.method)} ${escape(urlParts(r.url).path)}</button>`).join('')||'<span class="unlinked-label">No matching browser request</span>'}</div><div><div class="log-message">${replacements(l.message)}</div><div class="log-logger">${escape(l.logger||'Text log')} · source line ${l.sourceLine}</div>${l.stackTrace?`<details class="stack-details"><summary>Inspect stack trace</summary><pre>${replacements(l.stackTrace)}</pre></details>`:''}</div></article>`):`<div class="no-results">${incident.logs.length?'No log entries match this view.':'No server logs imported yet. Add a log file above.'}</div>`;
}
function renderRedactions() {
  if(!state.analysis)return;
  const descriptions={CREDENTIAL:'Provider tokens, JWTs, private-key blocks, URL credentials & labeled secrets',EMAIL:'Including encoded email addresses and decoded text',IP:'IPv4 & IPv6; ambiguous contexts are listed for review',PHONE:'Labeled numbers in supported groups; date-like spans are rejected',CUSTOM:'Literal substrings, including inside displayed identifiers',POLICY:'Custom regexes scoped to fields by the loaded YAML policy',CARD:'Paranoid profile · 13–19 digits with a valid Luhn checksum',IBAN:'Paranoid profile · recognized country length and MOD-97 checksum',PESEL:'Paranoid profile · valid encoded birth date and checksum',SUSPECT:'Paranoid profile · entropy heuristic; hashes and harmless tokens can match'};
  $('#redaction-options').innerHTML=state.analysis.incident.redactions.map(c=>`<div class="redaction-row">${icon(c.category==='CUSTOM'?'plus':'shield')}<div class="redaction-copy"><strong>${escape(c.label)}</strong><small>${descriptions[c.category]}</small></div><span class="redaction-count">${c.uniqueValues} ${c.uniqueValues===1?'value':'values'}</span><label class="switch"><input type="checkbox" data-category="${c.category}" aria-label="Redact ${escape(c.label.toLowerCase())}" ${['CARD','IBAN','PESEL','SUSPECT'].includes(c.category)&&state.analysis.incident.security.profile!=='paranoid'?'disabled':''} ${state.enabled.has(c.category)?'checked':''}><span class="switch-track" aria-hidden="true"></span></label></div>`).join('');
  $('#include-bodies').checked=state.includeBodies;
  $('#custom-chips').innerHTML=state.custom.map((value,index)=>`<span class="custom-chip">${escape(value)}<button data-remove-custom="${index}" aria-label="Remove custom value ${escape(value)}">${icon('close')}</button></span>`).join('');
  renderReview();
}
function renderReview() {
  if(!state.analysis)return;
  const all=state.analysis.findings||[];
  const query=state.reviewSearch.toLowerCase();
  const filtered=all.filter(f=>`${f.value} ${f.categories.join(' ')} ${f.locations.join(' ')} ${(f.detectors||[]).join(' ')} ${f.ambiguous?'ambiguous':''} ${(f.ambiguityReasons||[]).join(' ')}`.toLowerCase().includes(query));
  const pageSize=25;
  const pages=Math.max(1,Math.ceil(filtered.length/pageSize));
  state.reviewPage=Math.min(state.reviewPage,pages-1);
  const page=filtered.slice(state.reviewPage*pageSize,(state.reviewPage+1)*pageSize);
  const ambiguous=all.filter(f=>f.ambiguous).length;
  $('#review-count').textContent=`${filtered.length} of ${all.length} detected values${ambiguous?` · ${ambiguous} ambiguous`:''}`;
  $('#review-rows').innerHTML=page.length?page.map(f=>{
    const mode=f.excluded?'KEEP':f.forced?'REDACT':'AUTO';
    const categoryEnabled=f.categories.some(category=>state.enabled.has(category));
    const substitutions=`${f.replacements} ${f.replacements===1?'substitution':'substitutions'}`;
    const status=f.excluded?'Kept by your choice':f.allowlistedOccurrences>=f.occurrences?'Kept by policy allowlist':!categoryEnabled?'Category disabled':f.ambiguousKeptOccurrences>0?`${substitutions} · ${f.ambiguousKeptOccurrences} ambiguous kept automatically`:f.replacements?substitutions:'Covered by another match or context kept';
    const ambiguity=f.ambiguous?`<details class="finding-ambiguity"><summary>Ambiguous address context</summary><ul>${f.ambiguityReasons.map(reason=>`<li>${escape(reason)}</li>`).join('')}</ul><p>Automatic rules keep these occurrences. Choose Redact all occurrences to hide this value, or Keep value to leave it visible. Category switches still apply.</p></details>`:'';
    return `<tr><td><select data-finding="${escape(f.id)}" aria-label="Redaction decision for ${escape(f.replacement)}"><option value="AUTO" ${mode==='AUTO'?'selected':''}>Automatic</option><option value="REDACT" ${mode==='REDACT'?'selected':''}>Redact all occurrences</option><option value="KEEP" ${mode==='KEEP'?'selected':''}>Keep value</option></select></td><td><code class="finding-placeholder">${escape(f.replacement)}</code><details class="finding-original"><summary>Reveal original · ${f.value.length} characters</summary><code>${escape(f.value)}</code></details><span class="finding-state ${f.excluded||f.ambiguousKeptOccurrences||f.allowlistedOccurrences?'kept':''}">${escape(status)}${f.fieldOnly?' · field-scoped':''}${f.allowlistedOccurrences&&f.allowlistedOccurrences<f.occurrences?` · ${f.allowlistedOccurrences} allowlisted occurrences`:''}</span>${ambiguity}<span class="detector-notes">${(f.detectors||[]).map(escape).join(' · ')}</span></td><td><span class="finding-categories">${f.categories.map(escape).join(' · ')}</span></td><td><details class="finding-locations"><summary>${f.occurrences} detected ${f.occurrences===1?'occurrence':'occurrences'}</summary><ul>${f.locations.map(location=>`<li>${escape(location)}</li>`).join('')}</ul></details></td></tr>`;
  }).join(''):'<tr><td colspan="4"><div class="no-results">No detected values match this view.</div></td></tr>';
  $('#review-page').textContent=`Page ${state.reviewPage+1} of ${pages}`;
  $('#review-prev').disabled=state.reviewPage===0;
  $('#review-next').disabled=state.reviewPage>=pages-1;
  $('#reset-review').disabled=(state.exclusions.size===0&&state.forced.size===0)||state.busy;
}
function switchTab(tab,focus=false) {state.tab=tab;renderTabs();if(focus)$(`#tab-${tab}`).focus();}
function showExport() {
  if(!state.analysis||state.busy)return;
  $('#report-theme').value=state.reportTheme;
  const a=state.analysis;const disabled=a.incident.redactions.filter(c=>!c.enabled&&c.occurrences>0);
  $('#export-summary').innerHTML=`<div><strong>${a.incident.requests.length}</strong><small>browser requests</small></div><div><strong>${a.incident.logs.length}</strong><small>server log entries</small></div><div><strong>${a.redactedOccurrences}</strong><small>values redacted</small></div>${disabled.length?`<div class="export-warning">Disabled categories: ${disabled.map(c=>escape(c.label.toLowerCase())).join(', ')}. Their values may remain visible.</div>`:''}${a.incident.excludedValues?`<div class="export-warning">You chose to keep ${a.incident.excludedValues} detected ${a.incident.excludedValues===1?'value':'values'}. Another overlapping rule can still hide them. The review list and its IDs are excluded from the report; kept values can appear in the evidence.</div>`:''}`;
  if(a.incident.ambiguousValuesKept)$('#export-summary').insertAdjacentHTML('beforeend',`<div class="export-warning">${a.incident.ambiguousValuesKept} address ${a.incident.ambiguousValuesKept===1?'value has':'values have'} ambiguous occurrences kept by automatic rules. Inspect these in Redactions before sharing.</div>`);
  $('#export-summary').insertAdjacentHTML('beforeend',`<div class="export-warning">Self-check: ${escape(checkLabel(a.incident))}. Scope: included evidence, ${escape(a.incident.security.profile)} profile. Kept and allowlisted values can remain. Review before sharing.</div>`);
  $('#export-status').textContent='';$('#export-dialog').showModal();
}
function downloadBlob(blob,name) {const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}
async function download() {
  if(!state.analysis||state.busy)return;
  const format=$('#export-format').value;const button=$('#download-button');const input=payload();
  button.disabled=true;$('#export-status').textContent='Preparing your report…';
  try {const response=await api(`/api/export/${format}`,input);downloadBlob(await response.blob(),`bugparcel-report.${format==='markdown'?'md':format}`);$('#export-status').textContent='Report downloaded. Your original files remain on your machine.';toast('Report ready. Review it before sharing.');}
  catch(error){$('#export-status').textContent=error.message;}finally{button.disabled=false;}
}
async function sampleFiles() {
  try {const response=await fetch('/api/sample');if(!response.ok)throw new Error('Sample files are unavailable.');const data=await response.json();downloadBlob(new Blob([data.har],{type:'application/json'}),'checkout.har');downloadBlob(new Blob([data.logs],{type:'application/x-ndjson'}),'checkout.ndjson');toast('Two synthetic sample files downloaded.');}catch(error){message(error.message);}
}
document.addEventListener('click',async event=>{
  const action=event.target.closest('[data-action]')?.dataset.action;
  if(action==='sample')await loadSample();
  else if(action==='security-sample')await loadSample('security');
  else if(action==='apply-sample-policy'&&state.samplePolicy)await importPolicy(new File([state.samplePolicy],'bugparcel.example.yml',{type:'application/yaml'}));
  else if(action==='download-policy'){
    try{const response=await fetch('/api/sample/security');if(!response.ok)throw new Error('Policy example unavailable.');const sample=await response.json();downloadBlob(new Blob([sample.policyYaml],{type:'application/yaml'}),'bugparcel.example.yml');}catch(error){message(error.message);}
  }
  else if(action==='guide')showGuide();
  else if(action==='add-ids')showGuide(event.target.closest('[data-guide]').dataset.guide);
  else if(action==='copy-guide'){
    try{await navigator.clipboard.writeText($('#guide-snippet').textContent);$('#guide-copy-status').textContent='Snippet copied.';}
    catch{$('#guide-copy-status').textContent='Clipboard access was unavailable. Select and copy the code below.';}
  }
  else if(action==='sample-files')await sampleFiles();
  else if(action==='clear')clearSession();
  else if(action==='clear-policy'){state.policyYaml=null;state.policyName='';state.profile=null;state.decodeContent=null;state.enabled=null;await analyze();}
  else if(action==='export')showExport();
  else if(action==='download')await download();
  else if(action==='reset-review'){state.exclusions.clear();state.forced.clear();await analyze();}
  else if(action==='review-prev'){state.reviewPage--;renderReview();}
  else if(action==='review-next'){state.reviewPage++;renderReview();}
  else if(action==='redactions')switchTab('redactions');
  else if(action==='preview-request'||action==='workspace'){switchTab('requests');$('#main').focus();}
  const close=event.target.closest('[data-close]');if(close)$(`#${close.dataset.close}`).close();
  const tab=event.target.closest('[data-tab]');if(tab)switchTab(tab.dataset.tab);
  const filter=event.target.closest('[data-filter]');if(filter){state.filter=filter.dataset.filter;renderRequests();}
  const logFilter=event.target.closest('[data-log-filter]');if(logFilter){state.logFilter=logFilter.dataset.logFilter;renderLogs();}
  const request=event.target.closest('[data-request]');if(request){state.selected=request.dataset.request;state.detailTab='evidence';renderRequests();}
  const detail=event.target.closest('[data-detail]');if(detail){state.detailTab=detail.dataset.detail;renderDetail(state.analysis.incident.requests.find(r=>r.id===state.selected));}
  const go=event.target.closest('[data-go-request]');if(go){state.selected=go.dataset.goRequest;state.filter='all';state.search='';$('#request-search').value='';state.detailTab='evidence';switchTab('requests');renderRequests();$('#request-detail').scrollIntoView({behavior:'smooth',block:'nearest'});}
  const remove=event.target.closest('[data-remove-custom]');if(remove){state.custom.splice(Number(remove.dataset.removeCustom),1);await analyze();}
});
$('#request-search').addEventListener('input',event=>{state.search=event.target.value;renderRequests();});
$('#log-search').addEventListener('input',event=>{state.logSearch=event.target.value;renderLogs();});
$('#incident-title').addEventListener('change',async event=>{state.title=event.target.value.trim()||'Untitled incident';await analyze();});
$('#include-bodies').addEventListener('change',async event=>{state.includeBodies=event.target.checked;await analyze();});
$('#redaction-profile').addEventListener('change',async event=>{state.profile=event.target.value;state.enabled=null;await analyze();});
$('#decode-content').addEventListener('change',async event=>{state.decodeContent=event.target.checked;await analyze();});
$('#policy-file').addEventListener('change',event=>importPolicy(event.target.files[0]));
$('#timestamp-hints').addEventListener('change',async event=>{state.timestampHints=event.target.checked;await analyze();});
$('#guide-stack').innerHTML=requestIdGuides.map(g=>`<option value="${g.id}">${escape(g.name)}</option>`).join('');
$('#guide-stack').addEventListener('change',renderGuide);
$('#redaction-options').addEventListener('change',async event=>{if(!event.target.dataset.category)return;const category=event.target.dataset.category;event.target.checked?state.enabled.add(category):state.enabled.delete(category);await analyze();});
$('#review-rows').addEventListener('change',async event=>{
  const id=event.target.dataset.finding;
  if(!id)return;
  state.exclusions.delete(id);state.forced.delete(id);
  if(event.target.value==='KEEP')state.exclusions.add(id);
  if(event.target.value==='REDACT')state.forced.add(id);
  await analyze();
});
$('#review-search').addEventListener('input',event=>{state.reviewSearch=event.target.value;state.reviewPage=0;renderReview();});
$('#custom-form').addEventListener('submit',async event=>{event.preventDefault();const value=$('#custom-value').value.trim();if(value.length<2){toast('Use at least two characters for a custom value.');return;}if(state.custom.length>=50){toast('Use up to 50 custom values per incident.');return;}if(state.custom.includes(value)){toast('That value is already included.');return;}state.custom.push(value);state.enabled.add('CUSTOM');$('#custom-value').value='';await analyze();});
for(const key of ['har','logs']) {
  $(`#${key}-file`).addEventListener('change',event=>importFile(key,event.target.files[0]));
  const drop=$(`#${key}-drop`);
  for(const name of ['dragenter','dragover'])drop.addEventListener(name,event=>{event.preventDefault();drop.classList.add('drag-over');});
  for(const name of ['dragleave','drop'])drop.addEventListener(name,event=>{event.preventDefault();drop.classList.remove('drag-over');});
  drop.addEventListener('drop',event=>{const files=[...event.dataTransfer.files];if(files.length>1)toast('Add one file to each evidence box.');importFile(key,files[0]);});
}
document.addEventListener('keydown',event=>{
  const editing=event.target.matches('input,textarea,select,[contenteditable="true"]');
  if(event.key==='/'&&!editing&&!$('dialog[open]')&&state.analysis){event.preventDefault();switchTab('requests');$('#request-search').focus();}
  if(event.target.matches('[role="tab"]')&&['ArrowLeft','ArrowRight','Home','End'].includes(event.key)){
    event.preventDefault();const tabs=$$('[role="tab"][data-tab]').map(t=>t.dataset.tab);let next=tabs.indexOf(state.tab);if(event.key==='Home')next=0;else if(event.key==='End')next=tabs.length-1;else next=(next+(event.key==='ArrowRight'?1:tabs.length-1))%tabs.length;switchTab(tabs[next],true);
  }
});
for(const dialog of $$('dialog'))dialog.addEventListener('click',event=>{if(event.target===dialog){const box=dialog.getBoundingClientRect();if(event.clientX<box.left||event.clientX>box.right||event.clientY<box.top||event.clientY>box.bottom)dialog.close();}});
async function health() {try{const response=await fetch('/api/health');if(!response.ok)throw new Error();$('#connection').innerHTML='<span></span>Local engine connected';}catch{$('#connection').innerHTML='<span></span>Local engine unavailable';$('#connection').classList.add('offline');message('The local Java engine is not responding. Start BugParcel, then refresh this page.');}}
render();await health();if(new URLSearchParams(location.search).get('sample')==='1')await loadSample();
