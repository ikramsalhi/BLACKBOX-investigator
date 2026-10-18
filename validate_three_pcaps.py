"""Run three PCAPs as separate BLACKBOX cases and write a factual summary JSON.
Usage: python validate_three_pcaps.py path/to/capture-1.pcap path/to/capture-2.pcap path/to/capture-3.pcap
Run locally. Imports to the configured storage directory; don't point it to live data.
"""
import json,sys,hashlib
from pathlib import Path
from fastapi.testclient import TestClient
from blackbox.main import app

if len(sys.argv)!=4:
    raise SystemExit('Usage: python validate_three_pcaps.py capture-1.pcap capture-2.pcap capture-3.pcap')
if __import__('os').environ.get('BLACKBOX_DEPLOY_MODE','local')!='local':
    raise SystemExit('Run validation in local mode only.')
client=TestClient(app)
results=[]
for index,arg in enumerate(sys.argv[1:],1):
    p=Path(arg).resolve()
    if not p.is_file():
        results.append({'test':index,'file':str(p),'error':'File not found'});continue
    case=client.post('/api/cases',json={'name':f'Validation {index}: {p.name}','description':'Automated analysis of user-supplied capture; conclusions require analyst review.'})
    case.raise_for_status()
    cid=case.json()['id']
    with p.open('rb') as f:
        r=client.post(f'/api/cases/{cid}/captures',files={'file':(p.name,f,'application/octet-stream')})
    if r.status_code!=201:
        results.append({'test':index,'file':p.name,'error':r.text[:500]});continue
    cap=r.json()
    summary=client.get(f'/api/cases/{cid}/summary').json()
    findings=client.get(f'/api/cases/{cid}/findings').json()
    results.append({'test':index,'case_id':cid,'file':p.name,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
                    'ingest_status':cap['status'],'frames':cap['frames'],'supported_frames':cap['supported_frames'],
                    'partial_warning':cap.get('message',''),'protocols':summary.get('protocols',[]),
                    'findings_by_rule':{rule:sum(1 for x in findings if x['rule']==rule) for rule in sorted({x['rule'] for x in findings})},
                    'finding_count':len(findings),'top_findings':[{'title':f['title'],'severity':f['severity'],'summary':f['summary']} for f in findings[:8]]})
out=Path('BLACKBOX_PCAP_VALIDATION.json')
out.write_text(json.dumps({'note':'Heuristic detections are not verified attacks. Partial imports need manual review.','results':results},indent=2),encoding='utf-8')
print(out.resolve())
for r in results:
    print(r['test'],r['file'],r.get('frames','ERROR'),r.get('ingest_status',r.get('error')))
