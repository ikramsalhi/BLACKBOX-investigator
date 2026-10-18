"""Cloud agent uses only configured provider and bounded, read-only case tools."""
import io, json
import pytest
from fastapi.testclient import TestClient
from blackbox import agent, main, storage
from blackbox.config import cloud_settings
from samples.make_sample import build


def test_provider_configuration_private(monkeypatch):
    monkeypatch.setenv('BLACKBOX_CLOUD_PROVIDER','groq')
    monkeypatch.setenv('BLACKBOX_CLOUD_API_KEY','private-fake-key-123')
    monkeypatch.setenv('BLACKBOX_CLOUD_MODEL','llama-3.3-70b-versatile')
    assert cloud_settings()['url']=='https://api.groq.com/openai/v1/chat/completions'
    res=TestClient(main.app).get('/api/health')
    assert res.status_code==200
    assert res.json()['cloud_ai']['configured'] is True
    assert res.json()['cloud_ai']['provider']=='groq'
    assert 'private-fake-key-123' not in res.text
    assert 'BLACKBOX_CLOUD_API_KEY' not in res.text


def test_cloud_request_auth_and_clean_json(monkeypatch):
    monkeypatch.setenv('BLACKBOX_CLOUD_PROVIDER','gemini')
    monkeypatch.setenv('BLACKBOX_CLOUD_API_KEY','private-fake-key-456')
    monkeypatch.setenv('BLACKBOX_CLOUD_MODEL','gemini-2.5-flash')
    calls=[]
    class Response:
        def __enter__(self):return self
        def __exit__(self,*a):return False
        def read(self):return json.dumps({'choices':[{'message':{'content':'{"calls":[]}'}}]}).encode()
    def fake_urlopen(req,timeout):
        calls.append((req,timeout));return Response()
    monkeypatch.setattr(agent.urllib.request,'urlopen',fake_urlopen)
    result=agent._cloud([{'role':'user','content':'Inspect 10.0.0.3'}])
    assert result=='{"calls":[]}'
    assert len(calls)==1
    req,timeout=calls[0]
    assert req.full_url=='https://generativelanguage.googleapis.com/v1beta/openai/chat/completions'
    assert req.get_header('Authorization')=='Bearer private-fake-key-456'
    assert json.loads(req.data)['model']=='gemini-2.5-flash'
    assert 'private-fake-key-456' not in json.dumps(json.loads(req.data))


def test_cloud_agent_evidence_end_to_end(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    client=TestClient(main.app)
    cid=client.post('/api/cases',json={'name':'real case test'}).json()['id']
    capture=tmp_path/'test.pcap';build(capture)
    with capture.open('rb') as f:
        r=client.post(f'/api/cases/{cid}/captures',files={'file':('capture.pcap',f)})
    assert r.status_code==201
    monkeypatch.setenv('BLACKBOX_CLOUD_PROVIDER','openai')
    monkeypatch.setenv('BLACKBOX_CLOUD_API_KEY','private-fake-key-789')
    monkeypatch.setenv('BLACKBOX_CLOUD_MODEL','gpt-4.1-mini')
    output=[]
    def fake_cloud(messages,max_tokens=700):
        output.append(messages)
        if len(output)==1:
            return '```json\n{"calls":[{"name":"list_findings","args":{}}]}\n```'
        f=storage.list_findings(cid)[0]
        return json.dumps({'answer':'Possible suspicious traffic, review packet evidence.','finding_ids':[f['id'],'invented-id']})
    monkeypatch.setattr(agent,'_cloud',fake_cloud)
    data=client.post(f'/api/cases/{cid}/ask',json={'question':'What is suspicious here?','use_cloud_model':True}).json()
    assert data['engine']=='cloud-tool-agent'
    assert 'list_findings' in data['tools_used']
    assert len(data['finding_ids'])==1
    assert data['finding_ids'][0] in {f['id'] for f in storage.list_findings(cid)}
    assert 'raw capture' in data['notice'].lower()
    assert any('tools_executed' in x['content'] for x in output[-1])


def test_cloud_opt_in_and_fallback(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    client=TestClient(main.app)
    cid=client.post('/api/cases',json={'name':'no external'}).json()['id']
    def no_cloud(*args,**kwargs):raise AssertionError('Cloud should not be contacted')
    monkeypatch.setattr(agent,'_cloud',no_cloud)
    d=client.post(f'/api/cases/{cid}/ask',json={'question':'Any findings?'}).json()
    assert d['engine']=='offline-evidence'
    assert 'no external LLM' in d['notice']
