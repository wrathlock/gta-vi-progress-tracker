"""Public third-party claim discovery. Heuristic labels are NOT independent verification."""
import json,re,urllib.request,urllib.parse,urllib.error,datetime,hashlib,time
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
SUBS=['emulation','GTA6','GamingLeaksAndRumours','CrackWatch','Piracy']
TERMS=re.compile(r'(?i)gta\s*(?:vi|6)|leonida|xbox2windows|scarlettx|tombox|anyxboxx|\bxcl\b|cyberleek')
FIRST=re.compile(r'(?i)\b(i (?:tested|tried|ran|launched|downloaded|got|installed|booted)|we (?:tested|tried|ran|launched|booted)|works for me|got it (?:working|running)|managed to (?:run|launch|boot))\b')
STAGES=[('gameplay',r'(?i)\b(gameplay|playing gta|controllable)\b'),('game_boot',r'(?i)\b(gta\s*(?:vi|6).{0,40}(?:boot|launch|run))\b'),('initialization',r'(?i)\b(initializ|startup|boot screen)\b'),('application_launch',r'(?i)\b(launch|start|running|opened|run it|works for me)\b'),('files_obtained',r'(?i)\b(downloaded|got the files|obtained|installed)\b')]
def get(url):
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'GtaViSignalTracker/1.0 (public research; contact via repository)','Accept':'application/json'})
  with urllib.request.urlopen(req,timeout=10) as r:return json.load(r),None
 except Exception as e:return None,type(e).__name__+': '+str(e)[:90]
def stage(text):
 for label,pattern in STAGES:
  if re.search(pattern,text):return label
 return 'unspecified'
def project(text):
 for name,pattern in [('Leonida',r'leonida'),('Xbox2Windows',r'xbox2windows'),('ScarlettX',r'scarlettx'),('AnyXboxX',r'anyxboxx'),('TomBox',r'tombox'),('Cyberleek',r'cyberleek'),('XCL',r'\bxcl\b')]:
  if re.search(pattern,text,re.I):return name
 return 'GTA VI (unspecified project)'
def profile(author,cache):
 if author in cache:return cache[author]
 info,err=get('https://www.reddit.com/user/'+urllib.parse.quote(author,safe='')+'/about.json')
 if not isinstance(info,dict) or not isinstance(info.get('data'),dict):
  result={'risk':'insufficient_history','account_age_days':None,'sampled_comments':0,'reason':'Account profile inaccessible'}
 else:
  d=info['data'];age=max(0,int((datetime.datetime.now(datetime.timezone.utc).timestamp()-d.get('created_utc',0))/86400)) if d.get('created_utc') else None
  result={'risk':'insufficient_history','account_age_days':age,'sampled_comments':0,'reason':'Limited public history'}
  history,_=get('https://www.reddit.com/user/'+urllib.parse.quote(author,safe='')+'/comments.json?limit=25')
  items=(history or {}).get('data',{}).get('children',[]) if isinstance(history,dict) else []
  texts=[str(x.get('data',{}).get('body','')) for x in items if isinstance(x,dict)]
  result['sampled_comments']=len(texts)
  duplicates=len(texts)-len(set(t.strip().lower() for t in texts))
  technical=sum(bool(re.search(r'(?i)\b(emulat|shader|debug|driver|kernel|compile|gpu|cpu|reverse.engineer)\b',t)) for t in texts)
  if duplicates>=4 and len(texts)>=5:result.update(risk='higher_bot_risk',reason='Repeated similar public comments')
  elif age is not None and age>=180 and len(texts)>=8 and duplicates<4:result.update(risk='lower_bot_risk',reason='Established account with varied visible activity'+('; technical discussion history' if technical>=2 else ''))
  elif age is not None and age<7 and len(texts)<5:result.update(risk='higher_bot_risk',reason='Very new account with little visible activity; not proof of automation')
 cache[author]=result
 return result
def collect():
 findings=[];errors=[];cache={};seen=set();queries=['gta 6 emulator','leonida xbox2windows','gta 6 files working']
 for sub in SUBS:
  for query in queries:
   url='https://www.reddit.com/r/'+sub+'/search.json?'+urllib.parse.urlencode({'q':query,'restrict_sr':'on','sort':'new','t':'month','limit':12})
   data,err=get(url)
   if err:errors.append({'source':'r/'+sub,'error':err});continue
   posts=(data or {}).get('data',{}).get('children',[])
   for item in posts:
    p=item.get('data',{});pid=p.get('id')
    if not pid or pid in seen:continue
    seen.add(pid)
    title=str(p.get('title',''));body=str(p.get('selftext',''));context=title+' '+body
    if not TERMS.search(context):continue
    thread_url='https://www.reddit.com'+str(p.get('permalink',''))
    comments,ce=get('https://www.reddit.com/comments/'+pid+'.json?limit=60&depth=2&sort=new')
    if ce:errors.append({'source':thread_url,'error':ce})
    nodes=comments[1].get('data',{}).get('children',[]) if isinstance(comments,list) and len(comments)>1 else []
    eligible=[]
    for node in nodes:
     c=node.get('data',{});author=c.get('author');text=str(c.get('body',''))
     if not author or author in ('[deleted]','AutoModerator') or not FIRST.search(text):continue
     if not (TERMS.search(text) or TERMS.search(context)):continue
     if c.get('distinguished')=='moderator' and 'bot' in author.lower():continue
     eligible.append((author,c,text))
    distinct={}
    for author,c,text in eligible:
     if author in distinct:continue
     account=profile(author,cache) if len(distinct)<8 else {'risk':'insufficient_history','reason':'Account history sample limit','account_age_days':None,'sampled_comments':0}
     distinct[author]={'account_id':hashlib.sha256(author.encode()).hexdigest()[:12],'comment_url':'https://www.reddit.com'+str(c.get('permalink','')),'posted_utc':datetime.datetime.fromtimestamp(c.get('created_utc',0),datetime.timezone.utc).isoformat() if c.get('created_utc') else None,'stage':stage(text),'excerpt':re.sub(r'\s+',' ',text)[:220],'account_screening':account}
    if not distinct:continue
    entries=list(distinct.values())
    lower=sum(x['account_screening']['risk']=='lower_bot_risk' for x in entries)
    higher=sum(x['account_screening']['risk']=='higher_bot_risk' for x in entries)
    status='community_corroboration' if len(entries)>=2 and lower>=1 else 'initial_finding'
    findings.append({'id':'reddit:'+pid,'project':project(context),'source':'r/'+sub,'title':title[:180],'url':thread_url,'observed_at_utc':NOW,'published_at_utc':datetime.datetime.fromtimestamp(p.get('created_utc',0),datetime.timezone.utc).isoformat() if p.get('created_utc') else None,'reported_stage':max((x['stage'] for x in entries),key=lambda x:dict(files_obtained=1,application_launch=2,initialization=3,game_boot=4,gameplay=5,unspecified=0).get(x,0)),'status':status,'firsthand_reports':len(entries),'lower_bot_risk':lower,'higher_bot_risk':higher,'insufficient_history':len(entries)-lower-higher,'comments':entries,'verification':'not_independently_verified','note':'Public user claims; account-history signals are heuristic and do not establish authenticity, file safety, GTA VI boot or gameplay'})
   time.sleep(0.2)
 findings.sort(key=lambda x:x.get('published_at_utc') or '',reverse=True)
 return {'collected_at_utc':NOW,'status':'partial' if errors else 'ok','scope':'Public Reddit search/comment samples; public account-history heuristic; no binaries or private data; not proof of human identity or technical verification','findings':findings[:60],'counts':{'findings':len(findings),'community_corroboration':sum(f['status']=='community_corroboration' for f in findings),'accounts_screened':len(cache),'verified_gta_vi_tests':0},'errors':errors[:35]}
