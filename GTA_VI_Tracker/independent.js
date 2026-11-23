/* Public third-party finding viewer. Never treats user claims as verified GTA VI execution. */
(function(){
let data=null,error=null,view='findings',filter='all',selected=null;
const escapeText=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const badge=s=>'<span class="pill">'+escapeText(s.replace(/_/g,' '))+'</span>';
const box=(title,body)=>'<div class="card"><h3>'+escapeText(title)+'</h3>'+body+'</div>';
window.renderIndependentVerification=()=>display();
function display(){
 if(error)return box('Independent Verification','<p class="desc">Monitoring data unavailable: '+escapeText(error)+'</p>');
 if(!data)return box('Independent Verification','<p class="desc">Loading published independent findings…</p>');
 const counts=data.counts||{}, findings=data.findings||[];
 let head='<p class="desc">Public third-party testing claims and limited Reddit account-history checks. A claim is not a verified result; account screening cannot prove a commenter is human. No build number is required for an initial finding.</p>'+
 '<div class="stats" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:12px 0">'+
 [['Findings detected',counts.findings],['Community corroboration',counts.community_corroboration],['Accounts screened',counts.accounts_screened],['Verified GTA VI tests',0]].map(([k,v])=>'<div class="stat" style="min-width:0"><small>'+escapeText(k)+'</small><div class="value">'+escapeText(v??0)+'</div></div>').join('')+'</div>'+
 '<div class="actions">'+[['findings','Findings'],['consensus','Comment assessments'],['reddit','Reddit screening'],['rules','Rules']].map(([v,k])=>'<button type="button" class="btn" data-independent-tab="'+v+'" aria-pressed="'+(view===v)+'">'+k+'</button>').join('')+'</div>';
 if(view==='rules')return box('Community & Independent Findings',head+
 ['Initial finding — one identifiable firsthand report, build number optional.','Community corroboration — multiple distinct firsthand accounts, with at least one lower-bot-risk history assessment; this is not technical verification.','Credible external report — independent publication reporting firsthand testing; planned for future source-specific extraction, not currently scanned.','Reproduced technical result — independently reproducible technical evidence required.','Verified GTA VI execution — GTA VI-specific independently reproducible boot/gameplay evidence required.'].map(x=>'<div class="item">'+escapeText(x)+'</div>').join('')+
 '<p class="desc">Automated coverage: public Reddit search results, accessible comments, and limited public commenter history. Inaccessible sources are not considered reviewed.</p>');
 if(view==='consensus'){
  const monitored=(data.monitored_subreddits||['r/CrackWatch','r/Piracy','r/GTA6','r/GamingLeaksAndRumours','r/emulation','r/ps5homebrew','r/ReverseEngineering']);
  const health='<p class="desc">Monitored: '+monitored.map(escapeText).join(' · ')+'</p><p class="desc">Collection: '+escapeText(data.status||'unknown')+' · Access: '+escapeText(data.reddit_access||'not recorded')+' · Last attempt: '+escapeText(data.collected_at_utc||'not recorded')+'. '+escapeText(data.access_note||'')+'</p>';
  const entries=findings.filter(f=>f.community_assessment);
  return box('Reddit comment claim assessments',head+health+'<p class="desc">Keyword-based classifications are preliminary, not verified sentiment or technical proof. Minimum 20 distinct assessable authors; votes are not counted as authentication. Unavailable comments mean NOT CHECKED.</p>'+
   (entries.length?entries.map(f=>{const a=f.community_assessment;return '<div class="item"><b>'+escapeText(f.title)+'</b> '+badge(a.status||'not_checked')+'<p class="desc">'+escapeText(f.source)+' · '+escapeText(a.distinct_assessable_authors||0)+' distinct assessable authors / '+escapeText(a.sampled_comments||0)+' comments sampled · '+escapeText(f.published_at_utc||'undated')+'</p><p>Supporting: '+escapeText(a.supporting||0)+' · Disputing: '+escapeText(a.disputing||0)+' · Uncertain: '+escapeText(a.uncertain||0)+' · Firsthand candidates: '+escapeText(a.firsthand_candidate_authors||0)+'</p><p class="desc">'+escapeText(a.sample_method||'Limited accessible comments')+'</p><a href="'+escapeText(f.url)+'" target="_blank" rel="noopener noreferrer">Open Reddit discussion</a></div>'}).join(''):'<p class="desc">No comment assessments available. '+(data.errors?.length?'Reddit access or retrieval errors: '+data.errors.length+'. This is NOT a finding of zero relevant claims.':'No qualifying discussions in this limited sample.')+'</p>'));
 }
 if(view==='reddit'){
  let comments=findings.flatMap(f=>(f.comments||[]).map(c=>({...c,project:f.project,source:f.source})));
  if(filter!=='all')comments=comments.filter(c=>c.account_screening?.risk===filter);
  return box('Reddit account-history screening',head+'<div class="filters"><select id="independent-risk-filter">'+[['all','All accounts'],['lower_bot_risk','Lower bot risk'],['higher_bot_risk','Higher bot risk'],['insufficient_history','Insufficient history']].map(([v,t])=>'<option value="'+v+'" '+(filter===v?'selected':'')+'>'+t+'</option>').join('')+'</select></div>'+
   (comments.length?comments.slice(0,100).map(c=>'<div class="item"><b>Account '+escapeText(c.account_id)+'</b> '+badge(c.account_screening?.risk||'insufficient_history')+'<p class="desc">'+escapeText(c.project)+' · '+escapeText(c.account_screening?.reason)+' · Account age '+escapeText(c.account_screening?.account_age_days??'unknown')+' days · '+escapeText(c.account_screening?.sampled_comments??0)+' sampled comments</p><p>'+escapeText(c.excerpt)+'</p><a href="'+escapeText(c.comment_url)+'" target="_blank" rel="noopener noreferrer">Original Reddit comment</a></div>').join(''):'<p class="desc">No accessible qualifying account histories found in this scan.</p>'));
 }
 return box('Community & Independent Findings',head+
 (findings.length?findings.slice(0,60).map(f=>'<div class="item"><b>'+escapeText(f.project)+'</b> '+badge(f.status)+'<p>'+escapeText(f.title)+'</p><p class="desc">Reported stage: '+escapeText(f.reported_stage)+' · '+escapeText(f.firsthand_reports)+' distinct firsthand reports · '+escapeText(f.lower_bot_risk)+' lower-risk · '+escapeText(f.insufficient_history)+' uncertain · '+escapeText(f.higher_bot_risk)+' higher-risk</p><p class="desc">Unverified community claims; no independent GTA VI execution established.</p><a href="'+escapeText(f.url)+'" target="_blank" rel="noopener noreferrer">View source discussion</a></div>').join(''):'<p class="desc">No qualifying firsthand reports discovered in the available samples. This does not mean no reports exist.</p>')+
 (data.errors?.length?'<p class="desc">Some searches were unavailable ('+data.errors.length+' access or retrieval errors). Results are incomplete.</p>':''));
}
const priorSection=section;
function redditIntegration(){
 if(!data)return box('Reddit claim intelligence','<p class="desc">'+(error?'Reddit data unavailable: '+escapeText(error):'Loading Reddit collector data…')+'</p>');
 const findings=Array.isArray(data.findings)?data.findings:[];
 const coverage='<p class="desc">Reddit last attempted: '+escapeText(data.collected_at_utc||'not recorded')+' · '+escapeText(data.status||'unknown')+' · '+escapeText(data.reddit_access||'access method unknown')+' · '+escapeText(data.errors?.length||0)+' retrieval errors. '+escapeText(data.access_note||'')+'</p>';
 const preview=findings.slice(0,5).map(f=>{const a=f.community_assessment||{};return '<div class="item"><b>'+escapeText(f.title)+'</b> '+badge(a.status||'not_checked')+'<p class="desc">'+escapeText(f.source)+' · '+escapeText(f.published_at_utc||'undated')+' · '+escapeText(a.distinct_assessable_authors??'not checked')+' assessable authors · supporting '+escapeText(a.supporting??'—')+' / disputing '+escapeText(a.disputing??'—')+' / uncertain '+escapeText(a.uncertain??'—')+'</p><a href="'+escapeText(f.url)+'" target="_blank" rel="noopener noreferrer">Source discussion</a></div>'}).join('');
 const intro='<p class="desc">Community reports are unverified. 20 distinct assessable authors are required for a provisional community assessment; popularity does not verify a GTA VI milestone.</p>';
 const details=current==='Evidence & Confidence'?'<div class="item"><b>Executable authentication</b><p class="desc">Requires original provenance, build metadata, hashes, executable-format inspection, and independent reproducibility. A hash, comment consensus, or filename alone does not authenticate GTA VI.</p></div>':'';
 return box('Reddit claim intelligence',intro+coverage+details+(preview||'<p class="desc">No assessable posts collected. Inaccessible Reddit data is not evidence that claims do not exist.</p>')+'<button type="button" class="btn" data-open-independent="1">Full comment assessments and screening</button>');
}
section=function(){
 if(current==='Independent Verification')return display();
 const existing=priorSection();
 if(['Development Activity','Evidence & Confidence','Latest Changes','Sources','Breakthroughs'].includes(current))return existing+redditIntegration();
 return existing;
};
document.addEventListener('click',e=>{if(e.target.closest('[data-open-independent]'))go('Independent Verification')});
document.addEventListener('click',e=>{const b=e.target.closest('[data-independent-tab]');if(!b)return;view=b.getAttribute('data-independent-tab');if(current==='Independent Verification')render()});
document.addEventListener('change',e=>{if(e.target.id==='independent-risk-filter'){filter=e.target.value;if(current==='Independent Verification')render()}});
async function refresh(){
 try{const r=await fetch('data/independent.json?cache='+Date.now(),{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const d=await r.json();if(!Array.isArray(d.findings))throw Error('Invalid data format');data=d;error=null}
 catch(e){error=e.message}
 if(current==='Independent Verification'||current==='Evidence & Confidence')render();
}
refresh();setInterval(refresh,5*60*1000);
})();
