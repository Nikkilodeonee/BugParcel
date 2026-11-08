export function createReportFeatures({state,payload,api,escape,renderLogCard,downloadBlob,toast,message,switchTab,renderLogs,loadSample}) {
  const $=s=>document.querySelector(s), duration=n=>n>=1e12?`${n.toExponential(2)} ms`:`${Math.round(n)} ms`;
  Object.assign(state,{reportTheme:'paper',baseline:null,baselineLabel:'',comparison:null,groupErrors:true});
  let generation=0,controller,compareBusy=false,timelinePage=0,comparisonPage=0,snippetFormat='curl';
  const incident=()=>state.analysis?.incident;
  const maps=i=>({requests:new Map(i.requests.map(r=>[r.id,r])),logs:new Map(i.logs.map(l=>[l.id,l]))});
  const chartLabel=q=>q.id+' '+q.method+' '+q.url.replace(/^https?:\/\/[^/?#]+/i,'').split(/[?#]/,1)[0];
  function invalidate(){generation++;controller?.abort();compareBusy=false;state.comparison=null;$('#comparison-results').hidden=true;$('#comparison-status').textContent='';}
  function clear(){
    invalidate();state.baseline=null;state.baselineLabel='';state.reportTheme='paper';state.groupErrors=true;timelinePage=0;comparisonPage=0;snippetFormat='curl';
    for(const id of ['report-ribbon','timeline-summary','waterfall-chart','timeline-events','comparison-summary','comparison-differences','comparison-errors','before-request','after-request'])$('#'+id).replaceChildren();
    $('#baseline-status').textContent='No baseline captured.';$('#group-errors').checked=true;$('#comparison-mode').value='incidents';$('#ignore-volatile').checked=true;$('#timeline-filter').value='all';$('#report-theme').value='paper';
  }
  function busy(value){
    $('#run-comparison').disabled=value||compareBusy||($('#comparison-mode').value==='incidents'&&!state.baseline);
    for(const action of ['comparison-demo','baseline','clear-baseline','comparison-download'])document.querySelector(`[data-report-action="${action}"]`).disabled=value||compareBusy;
  }
  function render() {
    const i=incident();if(!i)return;
    const m=maps(i),r=i.report,slow=m.requests.get(r.slowestRequestId);
    $('#report-ribbon').innerHTML=`<span>Slowest: <b>${escape(slow?`${slow.method} · ${duration(slow.durationMs)}`:'—')}</b></span><span>${Object.values(r.errorsByLogger).reduce((a,b)=>a+b,0)} error entries · ${r.errorGroups.length} signatures</span><button data-report-action="timeline">Open timeline &amp; waterfall →</button>`;
    $('#timeline-summary').innerHTML=`<h2>Incident brief</h2><div class="brief-grid"><div><h3>Failed requests · ${r.failedRequestIds.length}</h3><ul>${r.failedRequestIds.slice(0,25).map(id=>{const q=m.requests.get(id);return `<li><button class="text-button" data-go-request="${escape(id)}">${q.status} ${escape(q.method+' '+q.url)}</button></li>`;}).join('')||'<li>No failures recorded.</li>'}</ul></div><div><h3>Slowest request</h3><p>${escape(slow?slow.method+' '+slow.url:'—')}<br>${slow?duration(slow.durationMs):''}</p><h3>Error entries by logger</h3><ul>${Object.entries(r.errorsByLogger).map(([logger,count])=>`<li>${escape(logger)} · ${count}</li>`).join('')||'<li>None recorded.</li>'}</ul></div></div>${r.firstStackLogId?`<details class="brief-stack"><summary>${r.firstStackTimed?'First timed error stack':'First error stack in file order; time unspecified'}</summary><pre>${escape(m.logs.get(r.firstStackLogId).stackTrace)}</pre></details>`:''}`;
    drawWaterfall(i,m);renderTimeline();renderComparisonControls();if(state.comparison)renderComparison();
  }
  function drawWaterfall(i,m) {
    const rows=i.report.waterfall.slice(0,200),range=Math.max(1,i.report.waterfallDurationMs);let charts='';
    for(let at=0;at<rows.length;at+=24){const part=rows.slice(at,at+24),height=50+part.length*26;
      charts+=`<svg viewBox="0 0 960 ${height}" role="img" aria-label="Request timings in milliseconds"><title>Relative request starts and HAR durations</title>${[0,1,2,3,4].map(t=>{const x=230+t*165;return `<line class="axis" x1="${x}" x2="${x}" y1="30" y2="${height-6}"/><text x="${x}" y="20" text-anchor="middle">${duration(range*(t/4))}</text>`;}).join('')}${part.map((row,index)=>{const q=m.requests.get(row.requestId),y=40+index*26,label=chartLabel(q);return `<g><title>${escape(q.method+' '+q.url+' · '+duration(row.durationMs)+' · offset '+duration(row.startMs))}</title><text x="10" y="${y+12}">${escape(label.length>31?label.slice(0,30)+'…':label)}</text><rect class="bar ${q.status===0||q.status>=400?'failed':''}" x="${230+row.startMs/range*660}" y="${y}" width="${Math.max(2,row.durationMs/range*660)}" height="16" rx="2"/><text x="940" y="${y+12}" text-anchor="end">${q.status}</text></g>`;}).join('')}</svg>`;
    }
    $('#waterfall-chart').innerHTML=charts||'<p class="report-note">No complete request dates with explicit UTC offsets.</p>';
    $('#waterfall-note').textContent=`${i.report.untimedRequests} requests have no absolute start. ${i.report.waterfall.length>200?'First 200 requests shown; JSON retains all timings.':'Charts split every 24 rows for readable printing.'}`;
  }
  function renderTimeline() {
    const i=incident();if(!i)return;const m=maps(i),all=i.report.timeline,filter=$('#timeline-filter').value;
    let rows=all;if(filter==='errors')rows=all.filter(e=>e.error);if(filter==='leadup'){const first=all.findIndex(e=>e.firstError);rows=first<0?[]:all.slice(Math.max(0,first-5),Math.min(all.length,first+3));}
    const pages=Math.max(1,Math.ceil(rows.length/50));timelinePage=Math.min(timelinePage,pages-1);
    $('#timeline-note').textContent=`${i.report.untimedEvents} events without absolute time`;
    $('#timeline-events').innerHTML=rows.slice(timelinePage*50,timelinePage*50+50).map(e=>{const q=m.requests.get(e.refId),l=m.logs.get(e.refId),detail=e.kind==='log'?l.level+' '+l.message:q.status+' '+q.method+' '+q.url;
      return `<article class="timeline-event ${e.firstError?'first-error':''}"><div class="timeline-clock">${escape(e.timestamp||'Time unspecified')}<br>${e.offsetMs===null?'Outside chronological order':'+'+duration(e.offsetMs)}</div><button ${e.kind==='log'?`data-report-log="${escape(e.refId)}"`:`data-go-request="${escape(e.refId)}"`}><span class="timeline-kind">${e.firstError?'FIRST TIMED ERROR · ':''}${escape(e.kind+' · '+e.refId)}</span>${escape(detail.length>500?detail.slice(0,500)+'…':detail)}</button></article>`;}).join('')||'<p class="report-note">No events in this view.</p>';
    $('#timeline-page').textContent=`Page ${timelinePage+1} of ${pages} · ${rows.length} events`;$('#timeline-prev').disabled=timelinePage===0;$('#timeline-next').disabled=timelinePage>=pages-1;
  }
  function grouped(logs,renderer) {
    if(!state.groupErrors)return logs.map(renderer).join('');
    const membership=new Map();for(const group of incident().report.errorGroups)for(const id of group.logIds)membership.set(id,group);
    const included=new Set(logs.map(l=>l.id)),seen=new Set(),byId=new Map(logs.map(l=>[l.id,l]));let html='';
    for(const log of logs){if(seen.has(log.id))continue;const group=membership.get(log.id),ids=group?group.logIds.filter(id=>included.has(id)):[log.id];ids.forEach(id=>seen.add(id));
      if(ids.length<2){html+=renderer(log);continue;}
      html+=`<details class="error-cluster"><summary>Repeated error · ${ids.length} occurrences in this view</summary>${renderer(log)}<p class="report-note">Representative stack shown once. Every timestamp/message is retained below.</p>${ids.map(id=>{const l=byId.get(id);return `<div class="error-occurrence">${escape(l.timestamp+' · line '+l.sourceLine+' · '+l.message)}</div>`;}).join('')}</details>`;
    }return html;
  }
  function snippetTools(id){return `<div class="snippet-tools"><label class="sr-only" for="snippet-format">Copy or export request</label><select id="snippet-format">${[['curl','cURL replay'],['httpie','HTTPie replay'],['github','GitHub issue'],['jira','Jira wiki'],['slack','Slack'],['markdown','Markdown']].map(([value,label])=>`<option value="${value}" ${value===snippetFormat?'selected':''}>${label}</option>`).join('')}</select><button class="button button-secondary" data-report-action="copy-snippet" data-snippet-id="${escape(id)}">Copy</button><button class="button button-secondary" data-report-action="download-snippet" data-snippet-id="${escape(id)}">Download</button></div><p class="snippet-note">Reviewed evidence only. Replay templates require your BP_* values and never run automatically.</p>`;}
  function renderComparisonControls() {
    const i=incident();if(!i)return;const mode=$('#comparison-mode').value;
    $('#incident-comparison-controls').hidden=mode!=='incidents';$('#request-comparison-controls').hidden=mode!=='requests';
    $('#baseline-status').textContent=state.baseline?`Baseline: ${state.baselineLabel}. Replace the HAR/log files with the new capture, then compare.`:'No baseline captured. Capture this incident first, then load the new HAR/log files.';$('#clear-baseline').hidden=!state.baseline;
    for(const id of ['before-request','after-request']){const old=$('#'+id).value;$('#'+id).innerHTML=i.requests.map(r=>`<option value="${escape(r.id)}">${escape(r.id+' · '+r.status+' '+r.method+' '+r.url)}</option>`).join('');if(i.requests.some(r=>r.id===old))$('#'+id).value=old;else $('#'+id).value=id==='after-request'?state.selected||i.requests.at(-1)?.id:i.requests.find(r=>r.status>=200&&r.status<400)?.id||i.requests[0]?.id;}
    busy(state.busy);
  }
  function comparisonPayload(){return $('#comparison-mode').value==='requests'?{incident:payload(),beforeId:$('#before-request').value,afterId:$('#after-request').value,ignoreVolatileHeaders:$('#ignore-volatile').checked}:{before:state.baseline,after:payload(),ignoreVolatileHeaders:$('#ignore-volatile').checked};}
  async function compare() {
    if(state.busy||compareBusy)return;const mode=$('#comparison-mode').value;if(mode==='incidents'&&!state.baseline){toast('Capture a baseline first.');return;}
    controller?.abort();controller=new AbortController();const current=++generation;compareBusy=true;busy(true);$('#comparison-status').textContent='Comparing sanitized evidence…';
    try{const response=await api(mode==='requests'?'/api/compare/requests':'/api/compare',comparisonPayload(),controller.signal);const result=await response.json();if(current!==generation)return;state.comparison=result;comparisonPage=0;renderComparison();$('#comparison-status').textContent='Comparison ready.';}
    catch(error){if(error.name!=='AbortError'&&current===generation)$('#comparison-status').textContent=error.message;}
    finally{if(current===generation){compareBusy=false;busy(state.busy);}}
  }
  function renderComparison() {
    const result=state.comparison;if(!result)return;$('#comparison-results').hidden=false;const s=result.summary;
    $('#comparison-summary').innerHTML=`<h3>${s.changed} changed · ${s.added} added · ${s.removed} removed · ${s.unchanged} unchanged</h3><p>Failed requests: ${s.beforeFailures} → ${s.afterFailures}. Error entries: ${s.beforeErrors} → ${s.afterErrors}.</p><p>Self-check residuals: before ${result.before.security.selfCheck.remainingValues}, after ${result.after.security.selfCheck.remainingValues}. Review both captures before sharing.</p><ul>${result.notes.map(n=>`<li>${escape(n)}</li>`).join('')}</ul>`;
    const changed=result.requests.filter(d=>d.kind!=='unchanged'),pages=Math.max(1,Math.ceil(changed.length/20));comparisonPage=Math.min(comparisonPage,pages-1);const before=maps(result.before),after=maps(result.after);
    $('#comparison-differences').innerHTML=changed.slice(comparisonPage*20,comparisonPage*20+20).map(d=>{const q=after.requests.get(d.afterId)||before.requests.get(d.beforeId);return `<article class="panel request-difference"><h3>${escape(d.kind+' · '+q.method+' '+q.url)}</h3>${d.fields.map(f=>`<div class="field-difference"><h4>${escape(f.field)}${f.truncated?' · preview truncated':''}</h4><div class="diff-pair"><div><b>Before</b><pre>${escape(f.before)}</pre></div><div><b>After</b><pre>${escape(f.after)}</pre></div></div></div>`).join('')||`<p class="report-note">Request ${escape(d.kind)} in this capture.</p>`}</article>`;}).join('')||'<p class="report-note">No request field differences under the selected comparison rules.</p>';
    $('#comparison-page').textContent=`Page ${comparisonPage+1} of ${pages}`;$('#comparison-prev').disabled=comparisonPage===0;$('#comparison-next').disabled=comparisonPage>=pages-1;
    $('#comparison-errors').innerHTML=`<h3>Repeated error changes</h3>${result.errors.map(e=>{const log=after.logs.get(e.afterLogId)||before.logs.get(e.beforeLogId);return `<p>${e.beforeCount} → ${e.afterCount} occurrences</p>${renderLogCard(log)}`;}).join('')||'<p>No stack-signature count changes.</p>'}`;
  }
  document.addEventListener('click',async event=>{
    const target=event.target.closest('[data-report-action]'),action=target?.dataset.reportAction;
    if(action==='timeline')switchTab('timeline');
    else if(action==='timeline-prev'){timelinePage--;renderTimeline();}else if(action==='timeline-next'){timelinePage++;renderTimeline();}
    else if(action==='baseline'){if(state.busy)return;state.baseline={har:state.har,logs:state.logs,title:state.title,captureEncoding:state.captureEncoding,logsEncoding:state.logsEncoding};state.baselineLabel=incident().title;invalidate();renderComparisonControls();toast('Baseline captured in memory. Replace files to compare the next capture.');}
    else if(action==='clear-baseline'){state.baseline=null;state.baselineLabel='';invalidate();renderComparisonControls();}
    else if(action==='compare')await compare();
    else if(action==='comparison-prev'){comparisonPage--;renderComparison();}else if(action==='comparison-next'){comparisonPage++;renderComparison();}
    else if(action==='comparison-demo'){
      if(state.busy||compareBusy)return;
      if(state.har&&!state.sample){toast('Clear imported evidence before opening the comparison sample.');return;}
      try{const response=await fetch('/api/sample');if(!response.ok)throw new Error('Sample unavailable.');const sample=await response.json();state.baseline={har:sample.har,logs:sample.logs,title:sample.title};state.baselineLabel='Original checkout (synthetic)';await loadSample('fixed');switchTab('compare');await compare();}catch(error){message(error.message);}
    }
    else if(action==='comparison-download'&&state.comparison){const current=generation,format=$('#comparison-format').value,requests=$('#comparison-mode').value==='requests';try{const response=await api(`/api/compare/${requests?'requests/':''}export/${format}`,comparisonPayload());const blob=await response.blob();if(current!==generation)return;downloadBlob(blob,`bugparcel-comparison.${format==='markdown'?'md':format}`);toast('Comparison downloaded.');}catch(error){message(error.message);}}
    else if(action==='copy-snippet'||action==='download-snippet'){
      if(state.busy)return;const current=generation,id=target.dataset.snippetId;snippetFormat=$('#snippet-format').value;
      try{const response=await api(`/api/request/${encodeURIComponent(id)}/snippet/${snippetFormat}`,payload());const text=await response.text();if(current!==generation){toast('Evidence changed. Generate the snippet again.');return;}
        if(action==='copy-snippet'){await navigator.clipboard.writeText(text);toast('Redacted request snippet copied.');}else downloadBlob(new Blob([text],{type:'text/plain'}),`bugparcel-${id}.${['curl','httpie'].includes(snippetFormat)?'sh':'txt'}`);
      }catch(error){toast(error.message||'Clipboard unavailable. Use Download.');}
    }
    const log=event.target.closest('[data-report-log]');if(log){state.logSearch=log.dataset.reportLog;state.logFilter='all';$('#log-search').value=state.logSearch;switchTab('logs');renderLogs();}
  });
  $('#timeline-filter').addEventListener('change',()=>{timelinePage=0;renderTimeline();});
  for(const id of ['comparison-mode','before-request','after-request','ignore-volatile'])$('#'+id).addEventListener('change',()=>{invalidate();renderComparisonControls();});
  $('#group-errors').addEventListener('change',event=>{state.groupErrors=event.target.checked;renderLogs();});
  $('#report-theme').addEventListener('change',event=>{state.reportTheme=event.target.value;});
  return {render,invalidate,clear,busy,snippetTools,grouped};
}
