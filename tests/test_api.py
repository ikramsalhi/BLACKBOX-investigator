from fastapi.testclient import TestClient
from blackbox import main,storage
from samples.make_sample import build
import pytest

@pytest.fixture()
def client(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    return TestClient(main.app)

def test_full_investigation(client,tmp_path):
    c=client.post('/api/cases',json={'name':'Real PCAP ingestion E2E'})
    assert c.status_code==201
    cid=c.json()['id']
    p=tmp_path/'sample.pcap';build(p)
    with open(p,'rb') as f:
        r=client.post(f'/api/cases/{cid}/captures',files={'file':('sample.pcap',f,'application/octet-stream')})
    assert r.status_code==201,r.text
    data=r.json()
    assert data['frames']>=30
    summary=client.get(f'/api/cases/{cid}/summary').json()
    assert summary['stats']['packet_count']==data['frames']
    findings=client.get(f'/api/cases/{cid}/findings').json()
    assert any(f['rule']=='port-sweep' for f in findings),findings
    assert all(f['evidence'] for f in findings)
    packets=client.get(f'/api/cases/{cid}/packets?limit=30').json()
    assert packets and packets[0]['src']=='10.0.0.12'
    topology=client.get(f'/api/cases/{cid}/topology').json()
    assert len(topology['nodes'])>=3
    ans=client.post(f'/api/cases/{cid}/ask',json={'question':'What happened in this capture?'}).json()
    assert ans['finding_ids'] and ans['engine']=='offline-evidence'
    assert client.get(f'/api/cases/{cid}/report?format=md').status_code==200
    assert client.get(f'/api/cases/{cid}/report?format=json').json()['capture_integrity'][0]['sha256']==data['sha256']
    assert client.delete(f'/api/cases/{cid}/captures/{data["capture_id"]}').status_code==200
    assert client.get(f'/api/cases/{cid}/summary').json()['stats']['packet_count']==0
    assert client.delete(f'/api/cases/{cid}').json()['deleted']


def test_malformed_and_limits(client):
    c=client.post('/api/cases',json={'name':'Bad file validation'}).json();cid=c['id']
    r=client.post(f'/api/cases/{cid}/captures',files={'file':('fake.pcap',b'should not parse','application/octet-stream')})
    assert r.status_code==422
    assert client.get(f'/api/cases/{cid}/captures').json()==[]
    assert client.post(f'/api/cases/{cid}/ask',json={'question':'Is the network compromised?'}).json()['finding_ids']==[]
    assert client.post('/api/cases',json={'name':'  '}).status_code==422


def test_origin_guard(client):
    response=client.post('/api/cases',headers={'Origin':'https://attacker.example'},json={'name':'blocked'})
    assert response.status_code==403

def test_two_cases_same_capture_do_not_collide(client,tmp_path):
    p=tmp_path/'sample-again.pcap';build(p)
    ids=[]
    for name in ('Case one','Case two'):
        cid=client.post('/api/cases',json={'name':name}).json()['id']
        with open(p,'rb') as f:
            res=client.post(f'/api/cases/{cid}/captures',files={'file':('same.pcap',f)})
        assert res.status_code==201,res.text
        finds=client.get(f'/api/cases/{cid}/findings').json()
        assert finds
        ids.append({f['id'] for f in finds})
    assert not ids[0].intersection(ids[1])
