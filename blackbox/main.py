from __future__ import annotations
import hashlib,os,ipaddress,secrets,base64,hmac,time,json,asyncio,subprocess,sys,io
from collections import defaultdict,deque
from pathlib import Path
from fastapi import FastAPI,File,UploadFile,HTTPException,Query,Request
from fastapi.responses import FileResponse,PlainTextResponse,JSONResponse,StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel,Field
from . import storage,accounts,replay,specialists,ml_features,ml_anomaly,report_pdf,trace
from .parser import iter_frames,parse_frame,CaptureError
from .analyze import recompute
from .assistant import answer,OLLAMA_URL
from .config import safe_cloud_status

ROOT=Path(__file__).resolve().parent.parent
MAX_UPLOAD=int(os.environ.get('BLACKBOX_MAX_UPLOAD_MB','100'))*1024*1024
MAX_FRAMES=int(os.environ.get('BLACKBOX_MAX_FRAMES','350000'))
DEPLOY_MODE=os.environ.get('BLACKBOX_DEPLOY_MODE','local').lower()
if DEPLOY_MODE not in ('local','local-auth','local-hybrid','public-demo','private-hosted','multi-user','hybrid'):
    raise RuntimeError('Invalid BLACKBOX_DEPLOY_MODE')
if DEPLOY_MODE=='private-hosted' and (not os.environ.get('BLACKBOX_BASIC_USER') or len(os.environ.get('BLACKBOX_BASIC_PASSWORD',''))<16):
    raise RuntimeError('Private hosting requires BLACKBOX_BASIC_USER and a password of at least 16 characters')
if DEPLOY_MODE in ('public-demo','private-hosted','multi-user','hybrid') and not os.environ.get('BLACKBOX_PUBLIC_HOST','').strip():
    raise RuntimeError('Hosted mode requires BLACKBOX_PUBLIC_HOST')
if DEPLOY_MODE=='public-demo':
    os.environ.pop('BLACKBOX_CLOUD_API_KEY',None)
app=FastAPI(title='BLACKBOX Investigator',version='1.9.0',docs_url=None if DEPLOY_MODE!='local' else '/api/docs',redoc_url=None)
REQUESTS=defaultdict(deque)
AUTH_REQUESTS=defaultdict(deque)
# Single-process concurrency gate; for scale-out replace SQLite and this gate with a shared job queue.
UPLOAD_GATE=asyncio.Semaphore(1)
MAX_CASES_PER_USER=int(os.environ.get('BLACKBOX_MAX_CASES_PER_USER','12'))
MAX_CAPTURES_PER_CASE=int(os.environ.get('BLACKBOX_MAX_CAPTURES_PER_CASE','20'))
MAX_USER_DISK_MB=int(os.environ.get('BLACKBOX_MAX_USER_DISK_MB','500'))
MAX_TOTAL_DISK_MB=int(os.environ.get('BLACKBOX_MAX_TOTAL_DISK_MB','2048'))
WORKER_TIMEOUT=int(os.environ.get('BLACKBOX_WORKER_TIMEOUT_SECONDS','120'))
storage.init_db()

def _limited_login(request):
    # Shared proxy IP in single-container installs: conservative cap, not a distributed limiter.
    ip=request.client.host if request.client else 'unknown'
    bucket=AUTH_REQUESTS[ip]
    now=time.monotonic()
    while bucket and bucket[0]<now-60:bucket.popleft()
    if len(bucket)>=15:return True
    bucket.append(now)
    return False

def _audit(event, request, detail=''):
    """Best-effort minimal audit trail; do not log tokens, passwords, or packet content."""
    try:
        path=storage.DATA/'audit.jsonl'
        row={'utc':__import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(),
             'event':event,'actor':getattr(request.state,'user','anonymous'),
             'path':request.url.path.split('?')[0][:180],'detail':detail[:110]}
        fd=os.open(str(path),os.O_CREAT|os.O_APPEND|os.O_WRONLY,0o600)
        try:os.write(fd,(json.dumps(row)+'\n').encode())
        finally:os.close(fd)
    except (OSError,ValueError):pass

app.mount('/assets',StaticFiles(directory=ROOT/'static'),name='assets')

@app.middleware('http')
async def deployment_guard(request:Request,call_next):
    path=request.url.path
    method=request.method
    if DEPLOY_MODE in ('local-auth','local-hybrid') and request.client and request.client.host not in ('127.0.0.1','::1'):
        return JSONResponse({'detail':'Local authentication is available on loopback only'},status_code=403)
    headers={'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer',
             'Cache-Control':'no-store','X-Permitted-Cross-Domain-Policies':'none','Permissions-Policy':'camera=(), microphone=(), geolocation=()',
             'Cross-Origin-Opener-Policy':'same-origin','Cross-Origin-Resource-Policy':'same-origin',
             'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"}
    if DEPLOY_MODE not in ('local','local-auth','local-hybrid'):headers['Strict-Transport-Security']='max-age=31536000; includeSubDomains'
    def fail(detail,status,extra=None):
        r=JSONResponse({'detail':detail},status_code=status,headers=extra or {})
        r.headers.update(headers)
        return r
    # Public demo has no write actions, LLM calls, or user uploads at all.
    if DEPLOY_MODE=='public-demo' and path.startswith('/api/') and method not in ('GET','HEAD','OPTIONS'):
        _audit('public_write_rejected',request)
        return fail('Read-only public demo: uploading and AI calls are disabled.',403)
    if DEPLOY_MODE=='private-hosted':
        raw=request.headers.get('authorization','')
        expected_user=os.environ['BLACKBOX_BASIC_USER']
        expected_pass=os.environ['BLACKBOX_BASIC_PASSWORD']
        try:
            kind,token=raw.split(' ',1)
            pair=base64.b64decode(token,validate=True).decode('utf-8')
            username,password=pair.split(':',1)
            valid=kind.lower()=='basic' and hmac.compare_digest(username,expected_user) and hmac.compare_digest(password,expected_pass)
        except (ValueError,UnicodeError,base64.binascii.Error):valid=False
        if not valid:
            if _limited_login(request):return fail('Too many failed logins',429)
            _audit('login_denied',request)
            return fail('Authentication required',401,{'WWW-Authenticate':'Basic realm="BLACKBOX Private"'})
    request.state.user=''
    request.state.auth_kind='anonymous'
    request.state.csrf=''
    # Both existing Basic accounts and new browser sessions work in multi-user mode.
    # Hybrid allows anonymous READ-ONLY access to synthetic gallery cases.
    if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid'):
        session=accounts.get_session(request.cookies.get(accounts.SESSION_COOKIE,''))
        if session and session['username'] in accounts.accounts():
            request.state.user=session['username']
            request.state.auth_kind='cookie'
            request.state.csrf=session['csrf']
        else:
            raw=request.headers.get('authorization','')
            try:
                kind,token=raw.split(' ',1)
                pair=base64.b64decode(token,validate=True).decode('utf-8')
                username,password=pair.split(':',1)
                if kind.lower()=='basic' and accounts.verify(username,password):
                    request.state.user=username
                    request.state.auth_kind='basic'
            except (ValueError,UnicodeError,base64.binascii.Error):pass
        auth_public=path in ('/api/health','/api/auth/session','/api/auth/login','/api/auth/register') or path=='/' or path.startswith('/assets/')
        if not request.state.user:
            if DEPLOY_MODE in ('multi-user','local-auth') and not auth_public:
                if _limited_login(request):return fail('Too many failed logins',429)
                return fail('Sign in to access your investigations',401)
            if DEPLOY_MODE in ('hybrid','local-hybrid') and path.startswith('/api/') and method not in ('GET','HEAD','OPTIONS') and path not in ('/api/auth/login','/api/auth/register'):
                return fail('Sign in to create private investigations',401)
        if request.state.auth_kind=='cookie' and path.startswith('/api/') and method not in ('GET','HEAD','OPTIONS') and path not in ('/api/auth/login','/api/auth/register'):
            if not hmac.compare_digest(request.headers.get('x-bb-csrf',''),request.state.csrf):
                return fail('Invalid session verification token; refresh and retry',403)
        # Ownership check applies to every case-specific endpoint, including exports.
        parts=path.split('/')
        if len(parts)>=4 and parts[1:3]==['api','cases']:
            cid=parts[3]
            record=storage.get_case(cid)
            if record is None:return fail('Case not found',404)
            owner=record.get('owner')
            can_read=bool(request.state.user and owner==request.state.user) or (DEPLOY_MODE in ('hybrid','local-hybrid') and owner=='public-demo' and method in ('GET','HEAD','OPTIONS'))
            if not can_read:
                _audit('case_access_denied',request)
                return fail('Case not found',404)
    # Preflight-size guard; upload handler also streams and enforces exact bytes.
    if path.endswith('/captures') and method=='POST':
        content_length=request.headers.get('content-length','')
        if content_length.isdecimal() and int(content_length)>MAX_UPLOAD+1024*1024:
            return fail('Request exceeds upload limit',413)
    # Local mode rejects cross-origin requests. Hosted mode accepts its own HTTPS origin only.
    if path.startswith('/api/') and method not in ('GET','HEAD','OPTIONS'):
        origin=request.headers.get('origin')
        if DEPLOY_MODE not in ('local',) and not origin:
            return fail('Origin required for authenticated write requests',403)
        if origin:
            from urllib.parse import urlsplit
            try:
                uri=urlsplit(origin)
                if DEPLOY_MODE=='local':allowed=uri.scheme=='http' and uri.hostname in ('127.0.0.1','localhost','::1') and uri.port==8765
                elif DEPLOY_MODE in ('local-auth','local-hybrid'):allowed=uri.scheme=='http' and uri.hostname in ('127.0.0.1','localhost','::1') and uri.port==8765 and not uri.username and not uri.password
                else:
                    public_host=os.environ.get('BLACKBOX_PUBLIC_HOST','').lower().strip()
                    allowed=bool(public_host) and uri.hostname==public_host and uri.scheme=='https' and uri.port in (None,443) and not uri.username and not uri.password
                if not allowed:
                    _audit('origin_rejected',request)
                    return fail('Untrusted request origin',403)
            except ValueError:return fail('Malformed request origin',403)
    if DEPLOY_MODE!='local' and path.startswith('/api/'):
        # Simple single-process rate limiter. Supplement with reverse-proxy controls in production.
        ip=request.client.host if request.client else 'unknown'
        bucket=REQUESTS[(ip,'write' if method not in ('GET','HEAD','OPTIONS') else 'read')]
        now=time.monotonic()
        while bucket and bucket[0]<now-60:bucket.popleft()
        cap=30 if method not in ('GET','HEAD','OPTIONS') else 240
        if len(bucket)>=cap:return fail('Rate limit exceeded',429)
        bucket.append(now)
    response=await call_next(request)
    if DEPLOY_MODE!='local' and path.startswith('/api/') and method not in ('GET','HEAD','OPTIONS'):
        _audit('write_request',request,str(response.status_code))
    for k,v in headers.items():response.headers[k]=v
    return response

@app.get('/')
def index():return FileResponse(ROOT/'static'/'index.html')

def _first_run_setup():
    """Allow one initial private user from the local browser; not permitted on hosted servers."""
    return DEPLOY_MODE=='local-hybrid' and not accounts.accounts()

def _invited_registration():
    return len(os.environ.get('BLACKBOX_SIGNUP_INVITE_CODE','').strip())>=20 and DEPLOY_MODE in ('hybrid','multi-user','local-hybrid')

@app.get('/api/health')
def health():return {'ok':True,'version':'1.9.0','mode':DEPLOY_MODE,'ollama_configured':bool(OLLAMA_URL),
  'cloud_ai':safe_cloud_status() if DEPLOY_MODE!='public-demo' else {'configured':False,'provider':None,'model':None},
  'registration_enabled':_invited_registration() or _first_run_setup(),
  'first_run_setup':_first_run_setup(),
  'limits':{'upload_mb':MAX_UPLOAD//(1024*1024),'frames':MAX_FRAMES, 'max_cases_per_user':MAX_CASES_PER_USER, 'max_captures_per_case':MAX_CAPTURES_PER_CASE}}


class LoginIn(BaseModel):
    username:str=Field(min_length=3,max_length=48)
    password:str=Field(min_length=1,max_length=256)

class RegisterIn(LoginIn):
    invite_code:str=Field(default='',max_length=256)

@app.get('/api/auth/session')
def auth_status(request:Request):
    return {'authenticated':bool(getattr(request.state,'user','')),
            'username':getattr(request.state,'user','') or None,
            'csrf':request.state.csrf if getattr(request.state,'auth_kind','')=='cookie' else None,
            'mode':DEPLOY_MODE,
            'registration_enabled':_invited_registration() or _first_run_setup(),
            'first_run_setup':_first_run_setup()}

def _set_login_cookie(response,username):
    token,csrf=accounts.create_session(username)
    response=JSONResponse({'authenticated':True,'username':username,'csrf':csrf})
    response.set_cookie(accounts.SESSION_COOKIE,token,httponly=True,secure=DEPLOY_MODE not in ('local','local-auth','local-hybrid'),
                        samesite='strict',path='/',max_age=accounts.SESSION_LIFETIME_SECONDS)
    return response

@app.post('/api/auth/login')
def login(data:LoginIn,request:Request):
    if DEPLOY_MODE not in ('hybrid','multi-user','local-auth','local-hybrid'):
        raise HTTPException(403,'Browser login is not enabled for this deployment')
    if _limited_login(request):raise HTTPException(429,'Too many sign-in attempts; retry later')
    if not accounts.verify(data.username,data.password):
        _audit('login_denied',request)
        raise HTTPException(401,'Incorrect username or password')
    _audit('login_success',request,data.username)
    return _set_login_cookie(None,data.username)

@app.post('/api/auth/register')
def register(data:RegisterIn,request:Request):
    secret=os.environ.get('BLACKBOX_SIGNUP_INVITE_CODE','').strip()
    initial_setup=_first_run_setup()
    if not initial_setup and (DEPLOY_MODE not in ('hybrid','multi-user','local-auth','local-hybrid') or not secret):
        raise HTTPException(403,'Invitation registration is disabled')
    if _limited_login(request):raise HTTPException(429,'Too many registration attempts; retry later')
    if not initial_setup and (len(secret)<20 or not hmac.compare_digest(secret,data.invite_code)):
        raise HTTPException(403,'Invalid invitation code')
    try:accounts.add(data.username,data.password,first_account_only=initial_setup)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    _audit('register_success',request,data.username)
    return _set_login_cookie(None,data.username)

@app.post('/api/auth/logout')
def logout(request:Request):
    accounts.revoke_session(request.cookies.get(accounts.SESSION_COOKIE,''))
    response=JSONResponse({'logged_out':True})
    response.delete_cookie(accounts.SESSION_COOKIE,path='/',secure=DEPLOY_MODE not in ('local','local-auth','local-hybrid'),httponly=True,samesite='strict')
    return response

class CaseIn(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    description:str=Field(default='',max_length=1000)

class ChatIn(BaseModel):
    question:str=Field(min_length=2,max_length=1400)
    use_local_model:bool=False
    use_cloud_model:bool=False
    history:list[dict]=Field(default_factory=list,max_length=12)
    page:str=Field(default="assistant",max_length=30)

@app.get('/api/cases')
def cases(request:Request):
    if DEPLOY_MODE in ('hybrid','local-hybrid'):
        public=storage.list_cases('public-demo')
        user=storage.list_cases(request.state.user) if request.state.user else []
        return public+user
    return storage.list_cases(request.state.user if DEPLOY_MODE in ('multi-user','local-auth') else 'public-demo' if DEPLOY_MODE=='public-demo' else None)

@app.post('/api/cases',status_code=201)
def add_case(data:CaseIn,request:Request):
    if not data.name.strip():raise HTTPException(422,'Case name cannot be blank')
    owner=request.state.user if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid') else ''
    if DEPLOY_MODE in ('multi-user','private-hosted','hybrid','local-auth','local-hybrid'):
        if storage.count_cases(owner if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid') else None)>=MAX_CASES_PER_USER:
            raise HTTPException(429,'Case quota reached; delete unused cases before creating a new one')
    return storage.create_case(data.name,data.description,owner)


def require_case(cid):
    obj=storage.get_case(cid)
    if obj is None or (DEPLOY_MODE=='public-demo' and obj.get('owner')!='public-demo'):
        raise HTTPException(404,'Case not found')
    return obj

@app.get('/api/cases/{cid}')
def one_case(cid:str):
    return {'case':require_case(cid),'summary':storage.summary(cid), 'captures':storage.list_captures(cid)}

@app.delete('/api/cases/{cid}')
def remove_case(cid:str):
    require_case(cid);storage.delete_case(cid);return {'deleted':True}

# Generated PCAP-format demonstration cases. No third-party collected evidence is distributed.
LAB_CASES=(
    ('DEMO A · SYN port sweep (synthetic)','Generated TCP communication exhibiting sweep-like activity; not a real attack.','SYNTHETIC_01_tcp_sweep.pcap'),
    ('DEMO B · ARP identity conflict (synthetic)','Generated conflicting ARP claims for TRACE; not a real attack.','SYNTHETIC_02_arp_conflict.pcap'),
)

@app.post('/api/demo',status_code=201)
async def create_demo(request:Request):
    """Seed two explicitly synthetic PCAP-format demonstration captures."""
    if DEPLOY_MODE=='public-demo':
        raise HTTPException(403,'Public gallery is read-only; run seed_public_demo.py first.')
    # Avoid creating duplicate cases on every click.
    existing=storage.list_cases(request.state.user if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid') else None)
    first=None
    for name,description,filename in LAB_CASES:
        found=next((row for row in existing if row.get('name')==name),None)
        if found:
            if first is None:first=found['id']
            continue
        source=ROOT/'samples'/'demo_pcaps'/filename
        if not source.is_file():raise HTTPException(503,'Bundled synthetic demo capture unavailable.')
        data=source.read_bytes()
        if len(data)>MAX_UPLOAD:raise HTTPException(413,'Demo capture exceeds upload limit.')
        case=storage.create_case(name,description,request.state.user if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid') else '')
        temp=storage.CAPTURES/(secrets.token_hex(20)+'.capture')
        try:
            temp.write_bytes(data)
            parse=_parse_in_worker if DEPLOY_MODE in ('private-hosted','multi-user','hybrid','local-auth','local-hybrid') else _parse_and_store
            await run_in_threadpool(parse,case['id'],filename,temp,hashlib.sha256(data).hexdigest(),len(data))
            if first is None:first=case['id']
        except Exception:
            storage.delete_case(case['id'])
            raise
        finally:
            if temp.exists() and not storage.capture_path_exists(str(temp)):
                temp.unlink(missing_ok=True)
    return {'case_id':first,'real_format':True,'capture_origin':'generated synthetic demonstration packets; no actual network capture'}

@app.get('/api/cases/{cid}/explain')
def public_evidence_explain(cid:str,question:str=Query(min_length=2,max_length=300)):
    """Read-only offline evidence assistant; never invokes a provider or model."""
    require_case(cid)
    return answer(cid,question,False,False,history=[],page='assistant')

@app.get('/api/cases/{cid}/captures')
def list_caps(cid:str):require_case(cid);return storage.list_captures(cid)

@app.post('/api/cases/{cid}/captures',status_code=201)
async def upload_capture(cid:str,file:UploadFile=File(...)):
    require_case(cid)
    try:
        await asyncio.wait_for(UPLOAD_GATE.acquire(),timeout=1.0)
    except asyncio.TimeoutError:
        raise HTTPException(503,'Capture workers are busy; please retry shortly')
    try:
        return await _upload_unlocked(cid,file)
    finally:
        UPLOAD_GATE.release()

async def _upload_unlocked(cid,file):
    filename=Path((file.filename or 'capture.pcap').replace('\\','/')).name[:200]
    if not filename.lower().endswith(('.pcap','.pcapng','.cap')):
        raise HTTPException(422,'Upload .pcap or .pcapng file')
    temp=storage.CAPTURES/(secrets.token_hex(20)+'.capture')
    size=0;h=hashlib.sha256()
    try:
        with open(temp,'wb') as f:
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>MAX_UPLOAD: raise HTTPException(413,f'Capture too large; limit is {MAX_UPLOAD//(1024*1024)} MB')
                h.update(chunk);f.write(chunk)
        if DEPLOY_MODE in ('multi-user','private-hosted','hybrid','local-auth','local-hybrid'):
            obj=storage.get_case(cid)
            if not obj:raise HTTPException(404,'Case not found')
            quota=storage.capture_usage(cid, obj['owner'] if DEPLOY_MODE in ('multi-user','hybrid','local-auth','local-hybrid') else None)
            if quota['case_captures']>=MAX_CAPTURES_PER_CASE:
                raise HTTPException(429,'Capture count quota exceeded for this case')
            if quota['owner_bytes']+size>MAX_USER_DISK_MB*1024*1024:
                raise HTTPException(413,'Account storage quota exceeded')
            if quota['total_bytes']+size>MAX_TOTAL_DISK_MB*1024*1024:
                raise HTTPException(413,'Server storage quota exceeded')
            return await run_in_threadpool(_parse_in_worker,cid,filename,temp,h.hexdigest(),size)
        return await run_in_threadpool(_parse_and_store,cid,filename,temp,h.hexdigest(),size)
    finally:
        await file.close()
        if temp.exists() and not storage.capture_path_exists(str(temp)):
            temp.unlink(missing_ok=True)


def _parse_in_worker(cid,filename,temp,digest,size):
    """Hosted uploads are parsed in a separate, time- and resource-limited process.

    This reduces parser crash blast radius but is NOT a full OS sandbox; the child still
    has process-user filesystem permissions. Do not advertise independent hardening audit.
    """
    env=os.environ.copy()
    env['BLACKBOX_DATA_DIR']=str(storage.DATA)
    env['BLACKBOX_PARSER_WORKER']='1'
    env.pop('BLACKBOX_CLOUD_API_KEY',None)
    env.pop('BLACKBOX_CLOUD_PROVIDER',None)
    env.pop('BLACKBOX_CLOUD_MODEL',None)
    env.pop('BLACKBOX_BOOTSTRAP_PASSWORD',None)
    env.pop('BLACKBOX_SIGNUP_INVITE_CODE',None)
    env.pop('BLACKBOX_BASIC_PASSWORD',None)
    cmd=[sys.executable,'-m','blackbox.worker',cid,filename,str(temp),digest,str(size)]
    try:
        proc=subprocess.run(cmd,cwd=str(ROOT),env=env,capture_output=True,
               timeout=WORKER_TIMEOUT+12,check=False)
    except subprocess.TimeoutExpired:
        _clean_failed_worker(cid,temp)
        raise HTTPException(503,'Capture analysis timed out in the isolated worker')
    if proc.returncode or not proc.stdout or len(proc.stdout)>65536:
        _clean_failed_worker(cid,temp)
        raise HTTPException(422,'Capture worker could not process the file safely')
    try:result=json.loads(proc.stdout)
    except (ValueError,UnicodeError):
        _clean_failed_worker(cid,temp)
        raise HTTPException(422,'Capture worker returned an invalid response')
    if 'error' in result:
        _clean_failed_worker(cid,temp)
        raise HTTPException(result.get('status',422),str(result['error'])[:200])
    return result


def _clean_failed_worker(cid,temp):
    # Remove incomplete capture rows and re-evaluate remaining evidence.
    with storage.connect() as db:
        rows=db.execute('SELECT id FROM captures WHERE case_id=? AND stored_path=?',(cid,str(temp))).fetchall()
    for row in rows:
        storage.delete_capture(cid,row['id'])
    if rows:recompute(cid)


def _parse_and_store(cid,filename,temp,digest,size):
    # Parse first frame before recording capture to reject bad file format early.
    iterator=iter_frames(str(temp))
    try:first=next(iterator,None)
    except CaptureError as exc:raise HTTPException(422,str(exc)) from exc
    if first is None: raise HTTPException(422,'Capture contains no packets')
    cap=storage.new_capture(cid,filename,temp,digest,size)
    count=0;supported=0;first_ts=None;last_ts=None;batch=[];status='ready';err=''
    try:
        from itertools import chain
        for frame in chain((first,),iterator):
            if count>=MAX_FRAMES:
                status='partial';err=f'Only the first {MAX_FRAMES} frames were ingested. Results are partial.';break
            p=parse_frame(frame)
            count+=1
            if p['proto'] not in ('OTHER','IP-FRAGMENT'):supported+=1
            if p['ts']:
                first_ts=p['ts'] if first_ts is None else min(first_ts,p['ts'])
                last_ts=p['ts'] if last_ts is None else max(last_ts,p['ts'])
            batch.append((cid,cap['id'],p['no'],p['ts'],p['src'],p['dst'],p['proto'],
               p['src_port'],p['dst_port'],p['length'],p['tcp_flags'],p['dns_query'],
               p['dns_qtype'],p['dns_rcode'],int(p['dns_response']),p['dns_answers'],
               p['tls_sni'],p['http_host'],p['http_method'],p['arp_ip'],p['arp_mac'],p['note']))
            if len(batch)>=2000:
                storage.add_packets(batch);batch.clear()
        if batch:storage.add_packets(batch)
    except (CaptureError,ValueError,OverflowError,IndexError,UnicodeError) as exc:
        if batch:storage.add_packets(batch)
        status='partial';err=f'Parsing stopped after {count} frames: {exc}'
    storage.update_capture(cap['id'],status,count,supported,first_ts,last_ts,err)
    result=recompute(cid)
    return {'capture_id':cap['id'],'status':status,'frames':count,'supported_frames':supported,
            'message':err,'case_findings':result['findings'],'sha256':digest}
@app.delete('/api/cases/{cid}/captures/{capid}')
def remove_cap(cid:str,capid:str):
    require_case(cid)
    if not storage.delete_capture(cid,capid):raise HTTPException(404,'Capture not found')
    recompute(cid);return {'deleted':True}

@app.get('/api/cases/{cid}/summary')
def case_summary(cid:str):require_case(cid);return storage.summary(cid)

@app.get('/api/cases/{cid}/packets')
def packets(cid:str,limit:int=Query(100,ge=1,le=500),offset:int=Query(0,ge=0),ip:str='',proto:str='',search:str=''):
    require_case(cid);return storage.query_packets(cid,limit,offset,ip[:55],proto[:20],search)

@app.get('/api/cases/{cid}/packets/{packet_id}')
def single_packet(cid:str,packet_id:int):
    require_case(cid)
    row=storage.get_packet(cid,packet_id)
    if row is None:raise HTTPException(404,'Packet metadata not found in case')
    return row

@app.get('/api/cases/{cid}/flows')
def flows(cid:str,limit:int=Query(250,ge=1,le=1000),ip:str=''):
    require_case(cid);return storage.flows(cid,limit,ip[:55])

@app.get('/api/cases/{cid}/ml/features.csv')
def export_ml_features(cid:str):
    """Export packet-derived directional flows for optional ML integration."""
    require_case(cid)
    rows=ml_features.flows_from_case(cid)
    response=PlainTextResponse(ml_features.as_csv(rows),media_type='text/csv; charset=utf-8')
    response.headers['Content-Disposition']='attachment; filename=BLACKBOX-ml-features.csv'
    return response

@app.get('/api/cases/{cid}/ml/anomalies')
def ml_anomalies(cid:str):
    """Per-case unsupervised outlier detection; never interprets scores as attack probabilities."""
    require_case(cid)
    return ml_anomaly.screen(cid)

@app.get('/api/cases/{cid}/captures/{capid}/download')
def download_original_capture(cid:str,capid:str):
    """Retrieve exactly the source file for an authorized case (never from public gallery)."""
    require_case(cid)
    if DEPLOY_MODE=='public-demo' or (DEPLOY_MODE in ('hybrid','local-hybrid') and storage.get_case(cid)['owner']=='public-demo'):raise HTTPException(403,'Original captures cannot be downloaded from public gallery.')
    cap=storage.get_capture(cid,capid)
    if not cap:raise HTTPException(404,'Capture not found')
    path=Path(cap['stored_path']).resolve()
    if not path.is_relative_to(storage.CAPTURES.resolve()) or not path.is_file():
        raise HTTPException(404,'Original capture unavailable')
    filename=Path(cap['filename']).name
    if not filename.lower().endswith(('.pcap','.pcapng','.cap')):filename += '.pcap'
    return FileResponse(path,media_type='application/octet-stream',filename=filename,content_disposition_type='attachment')

@app.get('/api/cases/{cid}/dns')
def dns(cid:str,limit:int=Query(250,ge=1,le=1000)):
    require_case(cid);return storage.dns_stats(cid,limit)

@app.get('/api/cases/{cid}/dhcp')
def dhcp(cid:str):require_case(cid);return storage.dhcp_stats(cid)

@app.get('/api/cases/{cid}/topology')
def topology(cid:str):require_case(cid);return storage.topology(cid)

@app.get('/api/cases/{cid}/hosts/{ip}')
def hosts(cid:str,ip:str):
    require_case(cid)
    try:ipaddress.ip_address(ip)
    except ValueError:raise HTTPException(422,'Invalid IP address')
    return storage.host_details(cid,ip)

@app.get('/api/cases/{cid}/findings')
def findings(cid:str):require_case(cid);return storage.list_findings(cid)

@app.get('/api/cases/{cid}/findings/{fid}')
def one_finding(cid:str,fid:str):
    require_case(cid)
    f=storage.get_finding(cid,fid)
    if f is None:raise HTTPException(404,'Finding not found')
    return f

@app.get('/api/cases/{cid}/trace/{fid}')
def finding_trace(cid:str,fid:str):
    """Read-only counter-hypothesis analysis with verified case-bound packet links."""
    require_case(cid)
    result=trace.build(cid,fid)
    if result is None:raise HTTPException(404,'Finding not found in this case')
    return result

@app.get('/api/cases/{cid}/trace/{fid}/export')
def export_finding_trace(cid:str,fid:str,format:str='md'):
    require_case(cid)
    result=trace.build(cid,fid)
    if result is None:raise HTTPException(404,'Finding not found in this case')
    if format=='json':return result
    if format!='md':raise HTTPException(422,'format must be md or json')
    response=PlainTextResponse(trace.to_markdown(result),media_type='text/markdown; charset=utf-8')
    response.headers['Content-Disposition']=f'attachment; filename="blackbox-trace-{fid[:18]}.md"'
    return response

@app.get('/api/cases/{cid}/replay')
def case_replay(cid:str):
    require_case(cid)
    return replay.build_replay(cid)

@app.get('/api/cases/{cid}/agent-brief')
def agent_brief(cid:str,question:str=Query('',max_length=180)):
    # Same case ownership check as all other evidence endpoints.
    require_case(cid)
    return specialists.coordinated_brief(cid,question,all_agents=not question)

@app.get('/api/cases/{cid}/timeline')
def timeline(cid:str):require_case(cid);return storage.timeline(cid)

@app.post('/api/cases/{cid}/investigate')
def investigate(cid:str):require_case(cid);return recompute(cid)

@app.post('/api/cases/{cid}/ask')
def ask(cid:str,data:ChatIn):require_case(cid);return answer(cid,data.question,data.use_local_model,data.use_cloud_model,history=[{"role":h.get("role"),"content":str(h.get("content",""))[:1100]} for h in data.history if isinstance(h,dict) and h.get("role") in ("user","assistant")][-8:],page=data.page if data.page in ("overview","captures","investigation","replay","findings","traffic","assistant","report") else "assistant")

class AIReportIn(BaseModel):
    mode:str=Field(pattern='^(cloud|local)$')

@app.post('/api/cases/{cid}/report/ai.pdf')
def ai_explained_pdf(cid:str,data:AIReportIn):
    """Explicit opt-in to an LLM. Cloud mode shares bounded case metadata, not raw PCAP."""
    require_case(cid)
    if DEPLOY_MODE=='public-demo':raise HTTPException(403,'AI calls disabled in public demo')
    summary=storage.summary(cid)
    if not summary['stats']['packet_count']:
        raise HTTPException(422,'Import packets before requesting an AI-assisted report')
    question=('Give a concise, readable investigation summary using only verified packet and rule evidence available in this case. '
              'Explain what was observed, why the findings deserve review, two alternative benign explanations, '
              'relevant packet IDs, checks an analyst should make next, and unknowns. '
              'Do not invent packet counts, IPs, confirmed attacks, malware labels, or attacker identities.')
    result=answer(cid,question,use_local_model=data.mode=='local',use_cloud_model=data.mode=='cloud',page='report')
    if result.get('engine') not in ('cloud-tool-agent','local-tool-agent'):
        raise HTTPException(503,'AI model unavailable. Use the evidence-generated PDF instead.')
    pdf=report_pdf.build(cid,ai_commentary=result['answer'],ai_engine=result['engine'])
    return StreamingResponse(io.BytesIO(pdf),media_type='application/pdf',
      headers={'Content-Disposition':f'attachment; filename="BLACKBOX-{cid[:8]}-AI-explained.pdf"'})

@app.get('/api/cases/{cid}/report')
def report(cid:str,format:str='md'):
    case=require_case(cid);s=storage.summary(cid);fs=storage.list_findings(cid)
    caps=storage.list_captures(cid)
    report={
        'case':case,'capture_integrity':[{'filename':c['filename'],'sha256':c['sha256'],
          'frames':c['frame_count'],'status':c['status'],'error':c['error']} for c in caps],
        'summary':s,'dhcp_activity':storage.dhcp_stats(cid),'findings':fs,
        'specialist_brief':specialists.coordinated_brief(cid,all_agents=True),'limitations':[
            'Only uploaded capture data was analyzed. Missing packets and encrypted content are not visible.',
            'Heuristic findings are leads for investigation, not confirmed intrusions.',
            'Full TCP reassembly, IDS signatures, malware detection and SSL decryption are NOT provided.',
            'Unusual traffic patterns may have legitimate explanations.',
            'This tool is not a substitute for a full forensic suite or human analyst.'
        ]}
    if format=='json':return report
    if format=='pdf':
        pdf=report_pdf.build(cid)
        return StreamingResponse(io.BytesIO(pdf),media_type='application/pdf',
            headers={'Content-Disposition':f'attachment; filename="BLACKBOX-{cid[:8]}-investigation.pdf"',
                     'X-Content-Type-Options':'nosniff'})
    if format!='md':raise HTTPException(422,'format must be pdf, md or json')
    def esc(v):return str(v).replace('\n',' ').replace('\r',' ')
    lines=[f"# BLACKBOX — {esc(case['name'])}", '',f"Case ID: `{case['id']}`", '',
       f"Packets analyzed: **{s['stats']['packet_count']:,}**  ",f"Observed bytes (packet lengths): **{s['stats']['traffic_bytes']:,}**  ",
       f"Heuristic findings: **{len(fs)}**",'', '## Capture evidence (SHA-256)']
    for c in caps:lines.append(f"- {esc(c['filename'])}: `{c['sha256']}` · {c['frame_count']} frames · {c['status']} {esc(c['error'])}")
    if report['dhcp_activity']:
        lines+=['','## DHCP observations']
        for row in report['dhcp_activity']:
            lines.append(f"- {esc(row['event'])}: {row['packets']} packet(s)")
    lines+=['','## Observations requiring review']
    if not fs:lines.append('No configured rule thresholds were exceeded. This is not a clean bill of health.')
    for f in fs:
        lines += ['',f"### [{f['severity'].upper()}] {esc(f['title'])}",
           f"Rule: `{f['rule']}` · heuristic confidence: {f['confidence']}",
           '',esc(f['summary']),'',f"**What to check:** {esc(f['recommendation'])}",
           f"**Packet metadata IDs:** {', '.join(str(x) for x in f['evidence'])}"]
    lines+=['','## Limitations']+['- '+x for x in report['limitations']]
    return PlainTextResponse('\n'.join(lines)+'\n',media_type='text/markdown',
       headers={'Content-Disposition':f'attachment; filename="blackbox-{cid[:8]}.md"'})
