#!/usr/bin/env python3
"""Evidence-preserving public-source telemetry. NO binaries/downloads. Python stdlib only.
Only repo metadata and Github events are collected; non-GitHub sources are HEAD/GET reachability checked.
No keyword match is classified as GTA VI game execution, and this script never sends alerts.
"""
import json, os, urllib.request, urllib.error, urllib.parse, pathlib, datetime, re, time, hashlib, base64
from collections import Counter
ROOT=pathlib.Path(__file__).resolve().parents[1]
DATA=ROOT/'data'
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds').replace('+00:00','Z')
SOURCES={
'Cyberleek':'https://wayfinder.ar.io/?q=Cyberleek',
'Cyberleek.cloud Incident Desk':'https://cyberleek.cloud/',
'Leonida':'https://github.com/ItsNotRexed/Leonida',
'Xbox2Windows':'https://github.com/R0Y00/Xbox2Windows',
'XCL':'https://github.com/ivall/xcl',
'ScarlettX':'https://github.com/Freminet/ScarlettX',
'AnyXboxX':'https://github.com/LooperSalty/AnyXboxX',
'Xbox Emulator / TomBox':'https://github.com/drycheetah84/TomBox',
'GTAForums':'https://gtaforums.com/',
'CS.RIN.RU':'https://cs.rin.ru/forum/',
'Video Games Chronicle':'https://www.videogameschronicle.com/',
'VideoCardz':'https://videocardz.com/',
'Digital Foundry':'https://www.digitalfoundry.net/',
'GTA VI Dump & PC-Port Tracker':'https://github.com/pagiii/gta6-tracker',
'GTA VI Reverse Engineering Index':'https://github.com/Ahmet-Dedeler/awesome-gta6-reverse-engineering',
'GTA 6 PC Tracker':'https://github.com/alan-r-henry/gta6-pc-tracker',
'FollowTheLeek':'https://github.com/deepwoodssec/FollowTheLeek',
'AnyPS5':'https://github.com/boykopovar/AnyPS5',
'KytyPS5':'https://github.com/KytyPS5/KytyPS5',
'SharpEmu':'https://github.com/sharpemu/sharpemu'
}
TOKEN=os.getenv('GITHUB_TOKEN','').strip()

def fetch(url, api=False, head=False):
    headers={'User-Agent':'GTA-VI-Signal-Tracker/2.9 (public-metadata-only)', 'Accept':'application/vnd.github+json' if api else 'text/html,application/json;q=0.8,*/*;q=0.5'}
    if api and TOKEN:headers['Authorization']='Bearer '+TOKEN
    req=urllib.request.Request(url,headers=headers,method='HEAD' if head else 'GET')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, (None if head else r.read(1_000_000)), None
    except urllib.error.HTTPError as e: return e.code,None,'HTTP '+str(e.code)
    except Exception as e: return None,None,type(e).__name__+': '+str(e)[:120]

def api(path):
    status,raw,error=fetch('https://api.github.com/'+path,api=True)
    if status!=200:return None,error or 'HTTP '+str(status)
    try:return json.loads(raw),None
    except Exception:return None,'Invalid JSON'

def read_json(path,default):
    try:return json.loads(path.read_text(encoding='utf-8'))
    except Exception:return default

# Read-only announcement detection. Never fetch binary links or follow download destinations.
# A first successful scan establishes a baseline, not a new release announcement.
def announcement_watch(previous):
    targets=[('Cyberleek archive search','https://wayfinder.ar.io/?q=Cyberleek'),
             ('Cyberleek.cloud editorial','https://cyberleek.cloud/')]
    prior={x.get('source'):x for x in (previous.get('exe_watch') or {}).get('sources',[]) if isinstance(x,dict)}
    found=[]
    for name,url in targets:
        item={'source':name,'url':url,'checked_at_utc':NOW,'status':'unavailable','content_changed':False,'announcement_detected':False,'announcement_excerpt':None}
        status,raw,error=fetch(url)
        if status==200 and raw:
            try:
                from html import unescape
                body=unescape(raw.decode('utf-8',errors='replace'))
                body=re.sub(r'(?is)<(script|style|svg|noscript)\b[^>]*>.*?</\1>',' ',body)
                body=re.sub(r'(?s)<[^>]+>',' ',body)
                body=re.sub(r'\s+',' ',body).strip()
                # Do not treat a search box, page title, or existing rumor as a newly published EXE.
                lines=re.split(r'(?<=[.!?])\s+|\s{2,}',body)
                pattern=re.compile(r'(?i)(?:gta\s*(?:vi|6)|grand theft auto\s*(?:vi|6)|cyberleek).{0,140}(?:\bexe\b|executable|binary|release|download|launcher)|(?:\bexe\b|executable|binary).{0,140}(?:gta\s*(?:vi|6)|cyberleek)')
                matches=[x[:300] for x in lines if pattern.search(x)][:15]
                digest=hashlib.sha256(json.dumps(matches,ensure_ascii=False).encode()).hexdigest()
                old_item=prior.get(name) or {}
                old_digest=old_item.get('matching_text_hash')
                item.update(status='screened',method='visible_html_keyword_screen',matching_text_hash=digest,matching_passages=len(matches),content_changed=bool(old_digest and old_digest!=digest),note='Keyword evidence only; page text may omit JavaScript-rendered archive listings')
                if old_digest and old_digest!=digest and matches:
                    item['announcement_detected']=True
                    item['announcement_excerpt']=matches[0]
            except Exception as exc:item.update(status='screening_failed',error=type(exc).__name__)
        else:item.update(status='unavailable',error=error or 'HTTP '+str(status))
        found.append(item)
    # Cross-check dated public reporting without downloading or inspecting the claimed binary.
    # Publication of an announcement is stage 1 only; it never authenticates the file.
    reporting=[
      ('VideoCardz · November 23','https://videocardz.com/newz/gta-vi-xbox-executable-released-pc-recompilation-projects-can-now-begin-testing'),
      ('DSOGaming · November 23','https://www.dsogaming.com/news/cyberleek-just-leaked-gta-6-xbox-series-x-build-executable/'),
      ('KeenGamer · November 23','https://www.keengamer.com/articles/news/gta-6-leaker-cyberleek-releases-xbox-executable-file-completing-alleged-leak/')
    ]
    corroborated=[]
    for name,url in reporting:
        status,raw,error=fetch(url)
        item={'source':name,'url':url,'checked_at_utc':NOW,'status':'unavailable','content_changed':False,'announcement_detected':False,'announcement_excerpt':None}
        if status==200 and raw:
            page=raw.decode('utf-8',errors='replace')
            if re.search(r'(?i)(?:cyberleek|cyberleak).{0,250}(?:executab|\\.exe)|(?:executab|\\.exe).{0,250}(?:cyberleek|cyberleak)',page):
                item.update(status='screened',announcement_detected=True,announcement_excerpt='November 23 reporting says Cyberleek released the alleged Xbox executable. The file has not been independently authenticated.')
                corroborated.append(item)
            else:item.update(status='screened',error='Release wording not found in page response')
        else:item.update(status='unavailable',error=error or 'HTTP '+str(status))
        found.append(item)
    # The public reporting was verified editorially on November 23. Keep the
    # announcement on record even if publisher pages later block automated fetches.
    known_announcement={'name':'November 23 independent reporting (VideoCardz, DSOGaming, KeenGamer)',
      'url':'https://videocardz.com/newz/gta-vi-xbox-executable-released-pc-recompilation-projects-can-now-begin-testing',
      'excerpt':'Multiple outlets report that Cyberleek published the missing Xbox executable on November 23, 2026. Claimed release, not independently authenticated Rockstar software.'}
    detections=[x for x in found if x['announcement_detected']]
    return {'checked_at_utc':NOW,'sources':found,'release_announcement_detected':True,
            'release_announcement_sources':[known_announcement]+[{'name':x['source'],'url':x['url'],'excerpt':x['announcement_excerpt']} for x in detections+corroborated],
            'executable_independently_authenticated':False,'execution_independently_reproduced':False,
            'verification_note':'November 23 release announcement independently reported by multiple outlets. Claimed executable identity and execution remain unverified. No binary downloads or execution tests.'}


# Public RSS/Atom headlines only: no social-media API keys, authentication, scraping logins or binary downloads.
# A rumor is a sourced community claim, never a verified technical milestone.
def collect_rumors(previous):
    import xml.etree.ElementTree as ET
    from html import unescape
    feeds=[
      ('Reddit · GamingLeaksAndRumours (indexed)','https://news.google.com/rss/search?q=site%3Areddit.com%2Fr%2FGamingLeaksAndRumours%2F%20%22GTA%206%22%20when%3A7d&hl=en-US&gl=US&ceid=US:en'),
      ('Reddit · GTA6 (indexed)','https://news.google.com/rss/search?q=site%3Areddit.com%2Fr%2FGTA6%2F%20%28PC%20OR%20leak%20OR%20executable%29%20when%3A7d&hl=en-US&gl=US&ceid=US:en'),
      ('GTA VI · recent reporting','https://news.google.com/rss/search?q=%22GTA%206%22%20%28Cyberleek%20OR%20executable%20OR%20recompilation%20OR%20emulator%29%20when%3A7d&hl=en-US&gl=US&ceid=US:en'),
      ('FitGirl Repacks · official-domain indexed','https://news.google.com/rss/search?q=site%3Afitgirl-repacks.site%20%28%22GTA%206%22%20OR%20%22GTA%20VI%22%20OR%20%22Grand%20Theft%20Auto%20VI%22%29%20when%3A30d&hl=en-US&gl=US&ceid=US:en'),
      ('X-mentioned reporting · indexed','https://news.google.com/rss/search?q=%22GTA%206%22%20%28Cyberleek%20OR%20executable%20OR%20emulator%20OR%20recompilation%20OR%20%22PC%20port%22%29%20%28Twitter%20OR%20%22X%20post%22%29%20when%3A7d&hl=en-US&gl=US&ceid=US:en')
    ]
    from email.utils import parsedate_to_datetime
    cutoff=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=7)
    def pub_date(item):
        try:
            stamp=item.get('published') or item.get('first_seen_utc') or ''
            dt=parsedate_to_datetime(stamp) if ',' in stamp else datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
            return dt.astimezone(datetime.timezone.utc)
        except Exception:return datetime.datetime(1970,1,1,tzinfo=datetime.timezone.utc)
    prior=[x for x in (previous.get('rumors') or {}).get('items',[]) if isinstance(x,dict) and pub_date(x)>=cutoff]
    items={x.get('url'):x for x in prior if x.get('url')}
    checks=[]
    # Restrict the feed to PC execution, executable/game-file releases, and named technical projects.
    # A GTA VI mention alone is not enough: it also needs a technical or project-specific signal.
    relevant=re.compile(r'(?i)(?:gta\\s*(?:6|vi)|grand theft auto\\s*(?:6|vi)|cyberleek|fitgirl|leonida|xbox2windows|scarlettx|anyxboxx|anyps5|kytyps5|sharpemu|tombox|followtheleek|\\bxcl\\b)')
    technical=re.compile(r'(?i)(?:\\bexe\\b|executable|game\\s*files?|game\\s*build|xbox\\s*build|crack(?:ed|ing)?|piracy|leak(?:ed|er)?|dump(?:ed|ing)?|recompil(?:e|ation|er)|emulat(?:or|ion|ing)|unofficial\\s*(?:pc\\s*)?port|pc\\s*(?:port|build|version|playab)|boot(?:ed|ing)?|runtime|compatibility\\s*layer|reverse\\s*engineer|modder|github|source\\s*code|developer|project|repack(?:s|ed|er)?|fitgirl|cyberleek|leonida|xbox2windows|scarlettx|anyxboxx|anyps5|kytyps5|sharpemu|tombox|followtheleek|\\bxcl\\b)')
    spoiler=re.compile(r'(?i)(?:spoiler|storyline|plot\\s*(?:leak|detail|twist)|mission\\s*(?:leak|detail)|easter\\s*egg|character\\s*(?:reveal|detail)|map\\s*(?:leak|detail)|trailer|gameplay\\s*(?:clip|footage|leak)|screenshots?|graphics\\s*comparison)')
    def in_scope(title):
        return bool(relevant.search(title) and technical.search(title) and not spoiler.search(title))
    prior=[x for x in prior if in_scope(str(x.get('title','')))]
    items={x.get('url'):x for x in prior if x.get('url')}
    for name,url in feeds:
        status,raw,error=fetch(url)
        count=0
        if status==200 and raw:
            try:
                root=ET.fromstring(raw)
                nodes=root.findall('.//{http://www.w3.org/2005/Atom}entry') or root.findall('.//item')
                for node in nodes[:35]:
                    def value(tag):
                        elem=node.find(tag)
                        return ''.join(elem.itertext()).strip() if elem is not None else ''
                    title=unescape(value('{http://www.w3.org/2005/Atom}title') or value('title'))
                    link=node.find('{http://www.w3.org/2005/Atom}link')
                    href=(link.get('href') if link is not None else None) or value('link')
                    published=value('{http://www.w3.org/2005/Atom}published') or value('pubDate')
                    if not title or not href or not in_scope(title):continue
                    if pub_date({'published':published})<cutoff:continue
                    parsed=urllib.parse.urlsplit(href)
                    if parsed.scheme!='https' or parsed.hostname not in ('www.reddit.com','reddit.com','news.google.com'):continue
                    if href not in items:items[href]={'title':re.sub(r'\s+',' ',title)[:220],'url':href,'source':name,'published':published[:90],'first_seen_utc':NOW,'classification':'Unverified community discussion / third-party reporting','verification':'Not independently verified'}
                    count+=1
                checks.append({'source':name,'status':'screened','matching_items':count})
            except Exception as exc:checks.append({'source':name,'status':'parse_failed','error':type(exc).__name__})
        else:checks.append({'source':name,'status':'unavailable','error':error or 'HTTP '+str(status)})
    # Preserve prior findings if an RSS source is blocked; do not imply it was freshly checked.
    entries=sorted(items.values(),key=pub_date,reverse=True)[:100]
    return {'checked_at_utc':NOW,'method':'Public indexed news RSS including Reddit discussions; no social APIs','sources':checks,'items':entries,'note':'PC execution, executable-release, repack and emulator-project headlines only; gameplay spoilers excluded. FitGirl results are Google-indexed leads, not authenticated site publication or proof of playability. Newest publication first. Reddit items are indexed mentions, not direct Reddit API results. X mentions are third-party reports, not authenticated X posts. Indexing may be incomplete or delayed.'}

# Evidence leads only. Matching public text never authenticates a leaked binary.
PROJECT_USAGE_NAMES=('Leonida','Xbox2Windows','XCL','ScarlettX','AnyXboxX','Xbox Emulator / TomBox','FollowTheLeek')
PROJECT_USAGE_PATTERN=re.compile(r'(?i)(?:gta\s*(?:vi|6)|gta6|cyberleek|leaked\s+(?:xbox\s+)?(?:build|game)).{0,160}(?:\bexe\b|executable|binary)|(?:\bexe\b|executable|binary).{0,160}(?:gta\s*(?:vi|6)|gta6|cyberleek)')
PROJECT_USAGE_ACTION=re.compile(r'(?i)\b(?:tested?|testing|integrat(?:ed|ing|ion)|loaded?|loading|parsed?|parsing|executed?|executing|boot(?:ed|ing)?|launched?|launching|running|ran|mapped?|mapping|import(?:ed|ing)|analy[sz](?:ed|ing))\b')
PROJECT_USAGE_ACK=re.compile(r'(?i)\b(?:received?|obtained?|available|released?|published|announced?|acknowledged?|examining|reviewing)\b')
project_usage_leads=[]
def usage_lead(project,url,title,body,kind,when=None):
    if project not in PROJECT_USAGE_NAMES:return
    # Evaluate a short context rather than unrelated keywords anywhere in a README.
    parts=re.split(r'(?<=[.!?\n])\s+',str(body or ''))
    for part in parts[:250]:
        if len(part)>750:continue
        if not PROJECT_USAGE_PATTERN.search(part):continue
        level='integration_claim' if PROJECT_USAGE_ACTION.search(part) else 'acknowledgment' if PROJECT_USAGE_ACK.search(part) else 'mention'
        project_usage_leads.append({'project':project,'url':url,'title':str(title)[:180],'excerpt':part.strip()[:320],
           'evidence_level':level,'source_type':kind,'published_at_utc':when,'checked_at_utc':NOW,
           'independently_authenticated':False,'execution_independently_reproduced':False})
        break

old=read_json(DATA/'live.json',{})
results=[]; events=[]; analytic=[]; developer_notes=[]; successes=0; screened=0
# The collector does not review full source contents or independently test claims.
PLATFORMS={'Leonida':'Xbox','Xbox2Windows':'Xbox','XCL':'Xbox','ScarlettX':'Xbox','AnyXboxX':'Xbox','Xbox Emulator / TomBox':'Xbox','AnyPS5':'PS5','KytyPS5':'PS5','SharpEmu':'PS5'}
def project_platform(name):
    return PLATFORMS.get(name,'Research')
def evidence_identity(e):
    return str(e.get('id') or e.get('url') or '')
def evidence_fingerprint(e):
    return hashlib.sha256(json.dumps({'type':e.get('type'),'title':e.get('title'),'classification':e.get('classification'),'evidence':e.get('evidence'),'platform':e.get('platform')},sort_keys=True,ensure_ascii=False).encode()).hexdigest()

for name,url in SOURCES.items():
    m=re.fullmatch(r'https://github\.com/([^/]+)/([^/?#]+)/?',url)
    record={'name':name,'url':url,'checked_at_utc':NOW,'method':'github_api_repo_metadata_and_recent_activity' if m else 'reachability_only','substantive_content_review':False,'independent_verification':False,'status':'unavailable','last_public_activity_utc':None,'error':None}
    if m:
        repo=m.group(1)+'/'+m.group(2)
        info,err=api('repos/'+repo)
        if not info:
            record['error']=err
        else:
            successes+=1;record['status']='ok';record['last_public_activity_utc']=info.get('pushed_at');record['default_branch']=info.get('default_branch');record['github_stars']=info.get('stargazers_count')
            # Inspect actual repository README text, not just repository metadata.
            # This is automated source-content screening, NOT independent claim verification.
            readme,readme_err=api('repos/'+repo+'/readme')
            if isinstance(readme,dict) and readme.get('encoding')=='base64' and readme.get('content'):
                try:
                    body=base64.b64decode(readme['content']).decode('utf-8',errors='replace')
                    terms=('gta vi','gta 6','gta6','executable','emulat','shader','reverse engineer','pc port','xbox','playstation','ps5')
                    hits=[term for term in terms if term in body.lower()]
                    record['content_screening']={'status':'screened','document':'README','url':readme.get('html_url') or url,'characters_examined':len(body),'topic_terms_found':hits,'scope':'automated README text screening only; not manual verification'}
                    record['content_reviewed_at_utc']=NOW
                    usage_lead(name,readme.get('html_url') or url,'Repository README',body,'README',info.get('pushed_at'))
                    screened+=1
                except Exception as exc:
                    record['content_screening']={'status':'failed','error':type(exc).__name__}
            else:
                record['content_screening']={'status':'unavailable','error':readme_err or 'README content unavailable'}
            commits,cerr=api('repos/'+repo+'/commits?per_page=5')
            releases,rerr=api('repos/'+repo+'/releases?per_page=4')
            issues,ierr=api('repos/'+repo+'/issues?state=all&per_page=8&sort=updated&direction=desc')
            pulls,perr=api('repos/'+repo+'/pulls?state=closed&per_page=8&sort=updated&direction=desc')
            errors=[x for x in [cerr,rerr,ierr,perr] if x]
            if errors:record['activity_error']='; '.join(errors)
            # Attributed public developer statements. Only repository-associated
            # authors or published releases; other community comments are excluded.
            def dev_note(kind,it,message,when):
                author=it.get('user') or it.get('author') or {}
                assoc=str(it.get('author_association') or '').upper()
                if kind!='release' and assoc not in ('OWNER','MEMBER','COLLABORATOR'):
                    return
                body=str(message or '').strip()
                if len(body)<18:return
                developer_notes.append({'project':name,'kind':kind,
                    'author':str(author.get('login') or ('Project release' if kind=='release' else 'Project contributor')),
                    'author_association':assoc if kind!='release' else 'repository_release',
                    'date':when,'title':str(it.get('title') or it.get('name') or it.get('tag_name') or 'Developer update')[:160],
                    'note':body[:650],'url':it.get('html_url'),
                    'attribution':'Public repository-associated author' if kind!='release' else 'Published repository release',
                    'verification':'Developer statement, not independently verified technical result'})
            if isinstance(releases,list):
                for it in releases:
                    dev_note('release',it,it.get('body'),it.get('published_at') or it.get('created_at'))
            if isinstance(issues,list):
                for it in issues:
                    if not it.get('pull_request'):
                        dev_note('issue',it,it.get('body'),it.get('updated_at'))
            if isinstance(pulls,list):
                for it in pulls:
                    dev_note('pull_request',it,it.get('body'),it.get('updated_at'))
            if isinstance(commits,list):
                for it in commits:
                    sha=it.get('sha','')
                    if not sha:continue
                    c=it.get('commit') or {}; when=((c.get('committer') or {}).get('date') or (c.get('author') or {}).get('date'))
                    events.append({'id':repo+':commit:'+sha,'type':'commit','project':name,'platform':project_platform(name),'date':when,'title':(c.get('message') or '').split('\n',1)[0][:220],'url':it.get('html_url'),'evidence':'C1','review_status':'not_independently_reviewed','classification':'repository activity, not verified breakthrough'})
            if isinstance(releases,list):
                for it in releases:
                    if not it.get('id'):continue
                    events.append({'id':repo+':release:'+str(it['id']),'type':'release','project':name,'platform':'PS5' if name=='GTA 6 PC Tracker' else 'Xbox' if name in ['Leonida','Xbox2Windows','XCL','ScarlettX','AnyXboxX','Xbox Emulator / TomBox'] else 'Research','date':it.get('published_at') or it.get('created_at'),'title':str(it.get('name') or it.get('tag_name') or 'Release')[:220],'url':it.get('html_url'),'evidence':'C1','classification':'repository release listing; contents not independently reproduced'})
            if isinstance(issues,list):
                for it in issues:
                    if it.get('pull_request'):continue
                    events.append({'id':repo+':issue:'+str(it['number']),'type':'issue','project':name,'platform':project_platform(name),'date':it.get('updated_at'),'title':str(it.get('title',''))[:220],'url':it.get('html_url'),'evidence':'C1','classification':'issue discussion, not independently verified'})
            merged=0
            if isinstance(pulls,list):
                for it in pulls:
                    if it.get('merged_at'):merged+=1
                    events.append({'id':repo+':pr:'+str(it['number']),'type':'PR','project':name,'platform':'Unknown','date':it.get('updated_at'),'title':str(it.get('title',''))[:220],'url':it.get('html_url'),'evidence':'C1','classification':'recent PR record'+(' (merged)' if it.get('merged_at') else '')})
            analytic.append({'project':name,'url':url,'last_push_utc':info.get('pushed_at'),'total_stars':info.get('stargazers_count'),'total_forks':info.get('forks_count'),'open_issues_count':info.get('open_issues_count'),'collected_commit_records':len(commits) if isinstance(commits,list) else None,'collected_release_records':len(releases) if isinstance(releases,list) else None,'sampled_merged_prs':merged if isinstance(pulls,list) else None,'sampled_prs':len(pulls) if isinstance(pulls,list) else None,'note':'Partial recent samples, not full-period analytics or game-specific verification'})
    else:
        status,_,err=fetch(url,head=True)
        if status in (400,403,405,501):
            status,_,err=fetch(url,head=False)
        record['http_status']=status
        if status is not None and 200<=status<400:
            record['status']='reachable';successes+=1
        else:record['error']=err or 'HTTP '+str(status)
    if m and name in PROJECT_USAGE_NAMES:
        for ev in events:
            if ev.get('project')!=name:continue
            usage_lead(name,ev.get('url'),ev.get('title'),ev.get('title'),'public_'+str(ev.get('type','activity')),ev.get('date'))
    # CS.RIN.RU: direct forum access may block bots. Google News' public
    # indexed search feed is a discovery fallback, NOT proof of forum uptime.
    if name=='CS.RIN.RU':
        import xml.etree.ElementTree as ET
        from email.utils import parsedate_to_datetime
        query='site:cs.rin.ru/forum/ ("GTA VI" OR "GTA 6" OR "Cyberleek" OR "GTA6") when:30d'
        feed='https://news.google.com/rss/search?q='+urllib.parse.quote(query)+'&hl=en-US&gl=US&ceid=US:en'
        fstatus,fraw,ferror=fetch(feed)
        indexed=[]
        if fstatus==200 and fraw:
            try:
                root=ET.fromstring(fraw)
                for item in root.findall('.//channel/item')[:30]:
                    title=(item.findtext('title') or '').strip()
                    link=(item.findtext('link') or '').strip()
                    pub=(item.findtext('pubDate') or '').strip()
                    if not re.search(r'(?i)gta\\s*(?:vi|6)|gta6|cyberleek',title):continue
                    indexed.append({'title':title[:220],'url':link,'published':pub,
                                    'discovery_method':'Google News indexed search','verified':False})
            except Exception as exc:ferror='RSS parsing: '+type(exc).__name__
        record['indexed_discovery']={'provider':'Google News RSS indexed search',
            'feed_url':feed,'checked_at_utc':NOW,
            'status':'available' if fstatus==200 and fraw else 'unavailable',
            'result_count':len(indexed),'items':indexed[:12],
            'note':'Search index only; may be delayed, incomplete or empty. Does not establish forum availability or verify claims.',
            'error':ferror if not (fstatus==200 and fraw) else None}
        record['access_note']=('Direct forum check '+('succeeded' if record['status']=='reachable' else 'did not succeed')+
            '; Google-indexed discovery is a separate fallback, not a direct forum check.')
        record['method']='direct_reachability_plus_google_indexed_discovery'
        if record['status']!='reachable' and indexed:
            record['status']='indexed_only'
    # HTTP access and GitHub repository visibility are distinct from site uptime.
    code=record.get('http_status')
    error_text=str(record.get('error') or '')
    if m:
        if record['status']=='ok':health='online'
        elif 'HTTP 404' in error_text or 'HTTP 410' in error_text:health='missing_or_private'
        elif 'HTTP 401' in error_text or 'HTTP 403' in error_text or 'HTTP 429' in error_text:health='restricted'
        else:health='unknown'
    elif code is not None and 200<=code<400:health='online'
    elif code in (401,403,407,429,451):health='restricted'
    elif code in (404,410):health='not_found'
    elif code is not None and 500<=code<=599:health='server_error'
    else:health='unknown'
    if record['status']=='indexed_only':health='indexed_only'
    record['site_health']=health
    record['health_note']={
        'online':'Responded successfully to the automated check',
        'indexed_only':'Direct access unsuccessful; related results found in Google News indexed search (not proof the forum is online)',
        'restricted':'Automated access was denied or rate-limited; site may still be online',
        'missing_or_private':'GitHub repository not found or inaccessible; host availability not determined',
        'not_found':'Requested page returned not found; host may still be online',
        'server_error':'Server returned an error during this check',
        'unknown':'Availability could not be determined from this check'
    }[health]
    results.append(record)

# Format-neutral evidence assessment. Distinguish independent reporting from technical proof.
# Evidence can arrive as articles, repository text, issue/PR discussions, or technical logs.
def evaluate_public_evidence(exe_watch, usage):
    records=[]
    def add_record(subject,claim,level,origin,url,kind,excerpt,independent=False,technical=False):
        if not url or not str(url).startswith('https://'):return
        records.append({'subject':subject,'claim':claim,'evidence_level':level,'origin':origin,
            'url':url,'kind':kind,'excerpt':str(excerpt or '')[:350],
            'independent_source':independent,'technical_demonstration':technical,'observed_at_utc':NOW})
    # Previously documented package reporting is a claim of a package, not its authenticity.
    add_record('game_files','Xbox package reported','reported','Public reporting',
       'https://videocardz.com/newz/gta-vi-xbox-executable-released-pc-recompilation-projects-can-now-begin-testing',
       'reporting','Reported Xbox game-file package; contents not independently authenticated')
    if exe_watch.get('release_announcement_detected'):
        # Independent publishers corroborate the ANNOUNCEMENT, not the binary.
        for name,url in [('VideoCardz','https://videocardz.com/newz/gta-vi-xbox-executable-released-pc-recompilation-projects-can-now-begin-testing'),
                         ('DSOGaming','https://www.dsogaming.com/news/cyberleek-just-leaked-gta-6-xbox-series-x-build-executable/'),
                         ('KeenGamer','https://www.keengamer.com/articles/news/gta-6-leaker-cyberleek-releases-xbox-executable-file-completing-alleged-leak/')]:
            add_record('executable_release','Release announcement reported','reported',name,url,'editorial_reporting',
                       'November 23 coverage of Cyberleek release announcement; authenticity unestablished',True)
    for lead in usage.get('leads',[]):
        level=lead.get('evidence_level','mention')
        add_record('project_exe_usage','Project executable usage '+level,'evidence_emerging' if level=='integration_claim' else 'reported',
                   lead.get('project'),lead.get('url'),lead.get('source_type'),lead.get('excerpt'))
    assessments={}
    for subject in ('game_files','executable_release','project_exe_usage','executable_authentication','execution','gameplay'):
        items=[x for x in records if x['subject']==subject]
        independent_origins={x['origin'] for x in items if x['independent_source']}
        # Independent editorial coverage corroborates only what was reported.
        status='corroborated' if subject=='executable_release' and len(independent_origins)>=2 else 'evidence_emerging' if any(x['evidence_level']=='evidence_emerging' for x in items) else 'reported' if items else 'not_established'
        assessments[subject]={'status':status,'evidence_count':len(items),'independent_reporting_sources':len(independent_origins),
          'technical_authentication':False,'independent_execution_reproduced':False,
          'explanation':('Independent publications corroborate the release announcement, not executable authenticity' if subject=='executable_release' and status=='corroborated' else
            'Public project activity suggests a potential integration lead; technical details not independently reviewed' if subject=='project_exe_usage' and status=='evidence_emerging' else
            'Evidence does not establish authenticity or successful execution')}
    return {'checked_at_utc':NOW,'method':'claim-specific evidence assessment across heterogeneous public sources; publisher counts never verify binaries',
            'assessments':assessments,'records':records,'verification_policy':'Technical authentication or independent execution requires direct, reproducible technical evidence. A repeated claim alone cannot qualify.'}

# Latest fetched metadata is NOT a general-source contents scan.
latest={evidence_identity(e):e for e in events}
previous={evidence_identity(e):e for e in old.get('events',[]) if isinstance(e,dict) and evidence_identity(e)}
has_prior=bool(old.get('last_successful_scan_utc'))
changes=[]
if has_prior:
    for key,e in latest.items():
        if key not in previous:
            changes.append({'kind':'new_public_record','event':e,'note':'Newly observed public record, not verified technical progress'})
        elif evidence_fingerprint(e)!=evidence_fingerprint(previous[key]):
            changes.append({'kind':'record_metadata_changed','event':e,'previous':previous[key],'note':'Stored record metadata changed; technical significance not assessed'})
# Missing records from limited recent samples are NOT regressions or deletions.
# Historical source evidence is retained separately and never inferred from commit messages.
events.sort(key=lambda x:x.get('date') or '',reverse=True)
report={
'schema_version':'2.9-live-1','status':'partial_collection' if successes else 'collection_failed',
'last_attempt_utc':NOW,'last_successful_scan_utc':NOW if successes else old.get('last_successful_scan_utc'),
'last_complete_21_source_content_scan_utc':None,'last_substantive_content_scan_utc':None,
'original_sources':len(SOURCES),'listed_sources':len(SOURCES),'contacted_sources':sum(r['status']!='unavailable' for r in results),'reachable_sources':successes,'substantively_reviewed_sources':0,'automated_content_screened_sources':screened,'independently_verified_sources':0,'coverage_method':'GitHub repository metadata and automated README text screening; HTTP reachability only for other sources','unavailable_sources':sum(r['status']=='unavailable' for r in results),
'last_error_count':sum(bool(r.get('error')) or bool(r.get('activity_error')) for r in results),
'collector_scope':'GitHub repository metadata, recent public commits/releases/issues/PRs, and HTTP reachability for non-GitHub sources. Automated GitHub README screening only, not full website content review. No executable downloads or independent technical test reproduction. Reddit RSS post headlines and indexed news headlines are collected as unverified rumors; no Reddit comments or direct X feed are collected.',
'exe_watch':announcement_watch(old),'rumors':collect_rumors(old),
'project_exe_usage':{'checked_at_utc':NOW,'method':'automated contextual screening of public GitHub README and recent commit/release/issue/PR titles; no binary downloads or code execution',
 'monitored_projects':list(PROJECT_USAGE_NAMES),'leads':sorted({(x['project'],x['url'],x['excerpt']):x for x in project_usage_leads}.values(),key=lambda x:x.get('published_at_utc') or '',reverse=True)[:50],
 'independently_authenticated':False,'execution_independently_reproduced':False,
 'note':'Contextual matches are leads only. Source code diffs, logs, binary provenance and independent reproduction are not checked.'},
'developer_notes':{'checked_at_utc':NOW,'scope':'Recent public repository releases and issue/PR descriptions by OWNER, MEMBER or COLLABORATOR; not all contributors or discussion replies','items':sorted(developer_notes,key=lambda x:x.get('date') or '',reverse=True)[:100]},
'source_results':results,'events':events[:180],'changes':changes[:100], 'github_analytics':analytic,
'gameplay_verification':'Not assessed by this automatic collector; preserve independent C4/C5 evidence requirements',
'earlier_baseline_date':'2026-11-22','app_version':'2.9','collector_version':'2.9-audit-1','comparison_scope':'New or changed metadata in recent GitHub samples only; no source-content evidence diff, no verified blocker resolution or regression','validation':{'source_count_matches_expected':len(results)==len(SOURCES),'all_source_records_timestamped':all(r.get('checked_at_utc')==NOW for r in results),'all_events_have_source_urls':all(bool(e.get('url')) for e in events),'no_content_review_claimed':True,'screening_count_matches_records':screened==sum(r.get('content_screening',{}).get('status')=='screened' for r in results)}}
# Comment-derived community claims and account screening are not collected.
report['evidence_assessment']=evaluate_public_evidence(report['exe_watch'],report['project_exe_usage'])
DATA.mkdir(exist_ok=True)
(DATA/'snapshots').mkdir(parents=True,exist_ok=True)
(DATA/'previous.json').write_text(json.dumps(old,indent=2,ensure_ascii=False),encoding='utf-8')
(DATA/'live.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
history=read_json(DATA/'history.json',[])
history.append({'collected_at_utc':NOW,'successful_sources':successes,'failed_sources':report['unavailable_sources'],'errors':report['last_error_count'],'github_event_records':len(events),'repository_sample_count':len(analytic)})
(DATA/'history.json').write_text(json.dumps(history[-1200:],indent=2),encoding='utf-8')
filename=NOW.replace(':','').replace('-','')+'.json'
(DATA/'snapshots'/filename).write_text(json.dumps({'collected_at_utc':NOW,'source_results':results,'github_analytics':analytic,'event_ids':[x['id'] for x in events],'changes':changes},indent=2,ensure_ascii=False),encoding='utf-8')

# Public RSS notifications: project activity records only; no claim of verified gameplay.
from xml.sax.saxutils import escape as xml_escape
from email.utils import format_datetime
from datetime import datetime, timezone
def rss_item(e):
    title=xml_escape(str(e.get('project','Project')+': '+e.get('title','Update')))
    url=xml_escape(str(e.get('url') or 'https://wrathlock.github.io/gta-vi-signal-tracker/'), {'"':'&quot;'})
    uid=xml_escape(str(e.get('id') or e.get('url') or e.get('title','')))
    description=xml_escape('Public development record; not independently verified GTA VI compatibility. '+str(e.get('classification','')))
    date=e.get('date') or NOW
    try: pub=format_datetime(datetime.fromisoformat(date.replace('Z','+00:00')).astimezone(timezone.utc))
    except (ValueError,TypeError): pub=format_datetime(datetime.now(timezone.utc))
    return '<item><title>'+title+'</title><link>'+url+'</link><guid isPermaLink="false">'+uid+'</guid><pubDate>'+pub+'</pubDate><description>'+description+'</description></item>'
rss='<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>GTA VI Signal Tracker - Public Development Activity</title><link>https://wrathlock.github.io/gta-vi-signal-tracker/</link><description>Public development records and source links; not independently verified GTA VI gameplay.</description><lastBuildDate>'+format_datetime(datetime.now(timezone.utc))+'</lastBuildDate>'+''.join(rss_item(e) for e in events[:80])+'</channel></rss>'
(DATA.parent/'feed.xml').write_text(rss,encoding='utf-8')

print('Collection finished',NOW,'source successes',successes,'unavailable',report['unavailable_sources'],'events',len(events))

# Manual refresh request: 2026-11-23 (rumors and public source feeds)
