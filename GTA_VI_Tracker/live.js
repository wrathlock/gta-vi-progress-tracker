/* Firefox-safe optional live adapter. Original V2.7 stays functional offline. */
let LIVE=null, LIVE_ERROR=null, livePlatform='All', liveType='All';
const liveEsc=x=>String(x??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const liveLink=u=>(/^https:\/\/(github\.com|api\.github\.com)\//.test(u||''))?`<a href="${liveEsc(u)}" target="_blank" rel="noopener noreferrer">Source</a>`:'No source link';
function liveBadge(s){return `<span class="pill">${liveEsc(s)}</span>`;}
function localTime(s){if(!s)return 'Never recorded';return trackerDate(s,'full');}
function liveTable(rows){return `<div class="tablewrap"><table>${rows.join('')}</table></div>`;}
function liveHealth(){
if(!LIVE)return '<div class="empty">No validated live collection is available. '+liveEsc(LIVE_ERROR||'The collector may not have published yet.')+'</div><p class="desc">Historical research remains accessible. A configured schedule is not proof of a successful scan.</p>';
const rs=LIVE.source_results||[];
const valid=LIVE.validation?.source_count_matches_expected&&LIVE.validation?.all_source_records_timestamped&&LIVE.validation?.all_events_have_source_urls;
return '<div class="cols"><div class="card"><small>Last attempted metadata collection</small><div class="heading">'+localTime(LIVE.last_attempt_utc)+'</div></div><div class="card"><small>Last successful partial collection</small><div class="heading">'+localTime(LIVE.last_successful_scan_utc)+'</div></div><div class="card"><small>Sources configured / reachable</small><div class="heading">'+liveEsc(LIVE.listed_sources??'unknown')+' / '+liveEsc(LIVE.reachable_sources??'unknown')+'</div></div><div class="card"><small>Substantive content reviews / independent verification</small><div class="heading">'+liveEsc(LIVE.automated_content_screened_sources??0)+' / '+liveEsc(LIVE.independently_verified_sources??0)+'</div></div></div><div class="card"><h3>Collection integrity</h3><div class="item"><b>Collection result:</b> '+liveBadge(LIVE.status||'unknown')+'</div><div class="item"><b>Schema:</b> '+liveEsc(LIVE.schema_version||'legacy')+'</div><div class="item"><b>Validation:</b> '+(valid?'Basic source-count/timestamp/URL checks passed':'Not validated by current schema')+'</div><div class="item"><b>Unavailable sources:</b> '+liveEsc(LIVE.unavailable_sources??'unknown')+' · <b>Source errors:</b> '+liveEsc(LIVE.last_error_count??'unknown')+'</div><p class="desc">'+liveEsc(LIVE.collector_scope||'Scope not recorded')+'</p><p class="warn">Reachability and repository metadata are NOT full content scans, verification of GTA VI claims, or independent technical tests. Automated README screening is limited to accessible GitHub repositories. Complete substantive content scan: not recorded.</p></div><div class="card"><h3>Per-source health</h3>'+liveTable(['<tr><th>Source</th><th>Status</th><th>Checked (local)</th><th>Method / error</th></tr>',...rs.map(x=>'<tr><td>'+liveEsc(x.name)+'</td><td>'+liveBadge(x.status)+'</td><td>'+liveEsc(trackerDate(x.checked_at_utc))+'</td><td>'+liveEsc(x.method)+(x.error?' · '+liveEsc(x.error):'')+(x.activity_error?' · '+liveEsc(x.activity_error):'')+'</td></tr>')])+'</div>';
}
function filteredEvents(){return (LIVE?.events||[]).filter(e=>(livePlatform==='All'||e.platform===livePlatform)&&(liveType==='All'||e.type===liveType));}
function liveFeed(){if(!LIVE)return liveHealth();
 return `<div class="card"><h3>Public development activity · unverified technical significance</h3><p class="desc">Commit messages and releases are project records (C1); they are not gameplay, C2 developer tests, C3 reproduction, or a confirmed GTA VI executable.</p><div class="filters"><select onchange="livePlatform=this.value;render()">${['All','Xbox','PS5','Research','Unknown'].map(x=>`<option ${x===livePlatform?'selected':''}>${x}</option>`)}</select><select onchange="liveType=this.value;render()">${['All','commit','release','issue','PR'].map(x=>`<option ${x===liveType?'selected':''}>${x}</option>`)}</select></div>${filteredEvents().length?filteredEvents().slice(0,100).map(e=>`<div class="item"><div class="row"><b>${liveEsc(e.project)}</b><span class="tag">${liveEsc(e.type)} · ${liveEsc(e.evidence)}</span></div><p>${liveEsc(e.title)}</p><div class="desc">${liveEsc(trackerDate(e.date))} · ${liveEsc(e.classification)} · ${liveLink(e.url)}</div></div>`).join(''):'<div class="empty">No matching collected records.</div>'}</div>`;
}
function liveChanges(){if(!LIVE)return liveHealth();return `<div class="card"><h3>Latest changes since stored scan</h3><p class="desc">New or changed sampled GitHub metadata only. Record time is the source record timestamp, not the time this change was detected. Last collector attempt: ${liveEsc(trackerDate(LIVE.last_attempt_utc))}. This does NOT compare source-content evidence, independently verified technical milestones, or actual regressions. Missing records are not regressions.</p>${LIVE.changes?.length?LIVE.changes.slice(0,60).map(x=>`<div class="item"><b>${liveEsc(x.event?.project)}:</b> ${liveEsc(x.event?.title)} ${liveLink(x.event?.url)}<div class="desc">Record time: ${liveEsc(trackerDate(x.event?.date))} · ${liveEsc(x.note)}</div></div>`).join(''):'<div class="empty">No new or changed metadata recorded, or no previous successful scan. This does not mean technical progress stopped.</div>'}</div>`;}
function liveAnalytics(){if(!LIVE)return liveHealth();return `<div class="card"><h3>Collected GitHub activity records</h3><p class="desc">Recent samples only. These are not full-interval commit counts or verified GTA VI execution results.</p>${liveTable(['<tr><th>Project</th><th>Last push</th><th>Commit sample</th><th>PR sample</th><th>Merged in sample</th></tr>',...(LIVE.github_analytics||[]).map(x=>`<tr><td>${liveEsc(x.project)}</td><td>${liveEsc(trackerDate(x.last_push_utc))}</td><td>${liveEsc(x.collected_commit_records)}</td><td>${liveEsc(x.sampled_prs)}</td><td>${liveEsc(x.sampled_merged_prs)}</td></tr>`)])}</div>`;}
const originalSection=section;
section=function(){
  if(current==='Live research status')return liveHealth();
  if(current==='Development Activity')return liveFeed();
  if(current==='Latest Changes')return liveChanges();
  if(current==='GitHub analytics')return liveAnalytics();
  if(current==='Overview')return originalSection()+`<div class="card"><div class="row"><b>Hosted source collector</b>${liveBadge(LIVE?LIVE.status:'Not connected')}</div><p class="desc">${LIVE?'Last real collection: '+localTime(LIVE.last_attempt_utc):'No validated live collection available. Historical research baseline remains intact.'}</p><div class="actions"><button onclick="go('Live research status')">Source health</button><button onclick="go('Development Activity')">Development activity</button></div></div>`;
  return originalSection();
};
let liveLoading=false;
async function loadLive(){
 if(liveLoading)return;liveLoading=true;
 try{
  const urls=['https://raw.githubusercontent.com/wrathlock/gta-vi-progress-tracker/main/GTA_VI_Tracker/data/live.json','data/live.json'];
  const results=await Promise.allSettled(urls.map(async url=>{
   const response=await fetch(url+'?cache='+Date.now(),{cache:'no-store'});
   if(!response.ok)throw Error('HTTP '+response.status);
   const obj=await response.json();
   if(!obj||obj.status==='never_collected'||!Array.isArray(obj.source_results)||!Number.isFinite(Date.parse(obj.last_attempt_utc))||obj.source_results.length!==obj.listed_sources)throw Error('Invalid collection payload');
   return obj;
  }));
  const candidates=results.filter(x=>x.status==='fulfilled').map(x=>x.value).sort((a,b)=>Date.parse(b.last_attempt_utc)-Date.parse(a.last_attempt_utc));
  if(!candidates.length)throw Error('Both collection endpoints unavailable');
  const next=candidates[0];
  if(!LIVE||Date.parse(next.last_attempt_utc)>=Date.parse(LIVE.last_attempt_utc))LIVE=next;
  LIVE_ERROR=null;
 }catch(e){LIVE_ERROR=e.message;}
 finally{liveLoading=false;header();render();}
}
loadLive();setInterval(loadLive,60000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)loadLive();});
window.addEventListener('online',loadLive);
