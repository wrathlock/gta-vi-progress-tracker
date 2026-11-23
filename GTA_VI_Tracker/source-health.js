/* Source Health Monitor — published hourly checks, not browser probes. */
(function(){
let filter='all',search='';
const escapeHtml=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const health=r=>{
 if(r.site_health)return r.site_health;
 const code=r.http_status,err=String(r.error||'');
 if(r.status==='ok'||r.status==='reachable'||(code>=200&&code<400))return 'online';
 if([401,403,407,429,451].includes(code)||/HTTP (401|403|429)/.test(err))return 'restricted';
 if(/github\.com\//.test(r.url||'')&&/HTTP (404|410)/.test(err))return 'missing_or_private';
 if([404,410].includes(code))return 'not_found';
 if(code>=500&&code<=599)return 'server_error';
 return 'unknown';
};
const labels={online:'Online',restricted:'Restricted',missing_or_private:'Missing / private',not_found:'Not found',server_error:'Server error',unknown:'Unknown'};
const colors={online:'#40c9a2',restricted:'#f2bd60',missing_or_private:'#f28c8c',not_found:'#f28c8c',server_error:'#f28c8c',unknown:'#a6b4c7'};
const isProblem=s=>['missing_or_private','not_found','server_error'].includes(s);
function sourceHealthPanel(){
 const live=typeof LIVE!=='undefined'&&LIVE&&Array.isArray(LIVE.source_results)?LIVE:null;
 const records=live?live.source_results:[];
 const names=Array.isArray(db?.sources)?db.sources:[];
 const map=new Map(records.map(r=>[r.name,r]));
 const list=names.length?names:records.map(r=>r.name);
 const totals={online:0,restricted:0,problem:0,unknown:0};
 list.forEach(name=>{const st=health(map.get(name)||{});if(st==='online')totals.online++;else if(st==='restricted')totals.restricted++;else if(isProblem(st))totals.problem++;else totals.unknown++});
 const count=(n,label)=>'<div class="card" style="padding:14px;min-width:0"><small>'+label+'</small><div class="heading">'+n+'</div></div>';
 const time=live?.last_attempt_utc?trackerDate(live.last_attempt_utc,'full'):'No published check';
 const summary='<div class="cols" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px">'+count(list.length,'Total sources')+count(totals.online,'Online')+count(totals.restricted,'Restricted')+count(totals.problem,'Errors / missing')+'</div><p class="desc">Last collector check: '+escapeHtml(time)+' · '+totals.unknown+' unknown or not checked. Status reflects automated access from the collector, not guaranteed global uptime. Refreshed hourly when collection succeeds.</p>';
 const controls='<div class="row" style="gap:10px;flex-wrap:wrap"><input id="source-health-search" aria-label="Search monitored sources" placeholder="Search all sources" value="'+escapeHtml(search)+'" style="flex:1;min-width:160px"><select id="source-health-filter" aria-label="Filter by source status"><option value="all">All statuses</option>'+[['online','Online'],['restricted','Restricted'],['problem','Errors / missing'],['unknown','Unknown']].map(([k,l])=>'<option value="'+k+'" '+(filter===k?'selected':'')+'>'+l+'</option>').join('')+'</select></div>';
 const matching=list.filter(name=>{const r=map.get(name)||{},st=health(r);return name.toLowerCase().includes(search.toLowerCase())&&(filter==='all'||filter==='problem'&&isProblem(st)||st===filter)});
 const cards=matching.map(name=>{
  const r=map.get(name)||{},st=health(r),url=r.url||urls[name]||'',http=r.http_status;
  const desc=r.health_note||({online:'Automated check succeeded',restricted:'Access may be blocked or rate-limited',missing_or_private:'Repository missing or inaccessible',not_found:'Requested page not found',server_error:'Server returned an error',unknown:'No conclusive availability result'}[st]);
  const response=http?'HTTP '+http:r.status==='ok'?'GitHub API: success':r.error?String(r.error):'No response code';
  const href=/^https:\/\//i.test(url)?'<a href="'+escapeHtml(url)+'" target="_blank" rel="noopener noreferrer">Open source ↗</a>':'';
  return '<div class="item" style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap"><div style="min-width:0;flex:1"><b>'+escapeHtml(name)+'</b><div class="desc">'+escapeHtml(desc)+'</div><div class="desc">'+escapeHtml(response)+' · Checked '+escapeHtml(r.checked_at_utc?trackerDate(r.checked_at_utc):'not yet')+'</div>'+href+'</div><span style="border:1px solid '+colors[st]+';color:'+colors[st]+';border-radius:999px;padding:4px 10px;font-size:12px;white-space:nowrap">● '+labels[st]+'</span></div>';
 }).join('')||'<p class="desc">No sources match these filters.</p>';
 return card(summary+controls+'<div id="source-health-results">'+cards+'</div>'+(live?'':'<p class="desc">Live source results unavailable. Showing configured sources as Unknown until the next successful collection.</p>'),'Source Health Monitor');
}
const original=section;
section=function(){return current==='Sources'?sourceHealthPanel():original()};
document.addEventListener('input',e=>{if(e.target.id==='source-health-search'){search=e.target.value;const parent=e.target.closest('.card');const list=parent?.querySelector('#source-health-results');if(list){const fresh=document.createElement('div');fresh.innerHTML=sourceHealthPanel();const updated=fresh.querySelector('#source-health-results');if(updated)list.innerHTML=updated.innerHTML}}});
document.addEventListener('change',e=>{if(e.target.id==='source-health-filter'){filter=e.target.value;if(current==='Sources')render()}});
if(current==='Sources')render();
})();
