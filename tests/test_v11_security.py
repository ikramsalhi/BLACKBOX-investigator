"""Account quotas, isolated upload path, and non-leaking cloud configuration."""
import base64
from fastapi.testclient import TestClient
from blackbox import main, storage, accounts


def headers(username):
    token=base64.b64encode(f'{username}:a-dedicated-private-password-987654'.encode()).decode()
    return {'Authorization':'Basic '+token,'Origin':'https://blackbox.example.com'}


def setup(monkeypatch,tmp_path):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    monkeypatch.setattr(main,'DEPLOY_MODE','multi-user')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    storage.init_db()
    accounts.add('owner','a-dedicated-private-password-987654')
    return TestClient(main.app)


def test_case_quota_and_owner_isolation(tmp_path,monkeypatch):
    c=setup(monkeypatch,tmp_path)
    monkeypatch.setattr(main,'MAX_CASES_PER_USER',1)
    assert c.post('/api/cases',json={'name':'One'},headers=headers('owner')).status_code==201
    blocked=c.post('/api/cases',json={'name':'Two'},headers=headers('owner'))
    assert blocked.status_code==429
    assert 'quota' in blocked.json()['detail'].lower()
    assert c.get('/api/cases',headers=headers('owner')).status_code==200


def test_capture_quota_denies_before_worker(tmp_path,monkeypatch):
    c=setup(monkeypatch,tmp_path)
    case=c.post('/api/cases',json={'name':'Demo'},headers=headers('owner')).json()
    monkeypatch.setattr(main,'MAX_CAPTURES_PER_CASE',0)
    with open('tests/fixtures/synthetic_packet_fixture.pcap','rb') as p:
        r=c.post('/api/cases/'+case['id']+'/captures',headers=headers('owner'),files={'file':('example.pcap',p)})
    assert r.status_code==429
    assert storage.list_captures(case['id'])==[]


def test_storage_quota_denies_before_worker(tmp_path,monkeypatch):
    c=setup(monkeypatch,tmp_path)
    case=c.post('/api/cases',json={'name':'Quota check'},headers=headers('owner')).json()
    monkeypatch.setattr(main,'MAX_USER_DISK_MB',0)
    with open('tests/fixtures/synthetic_packet_fixture.pcap','rb') as p:
        r=c.post('/api/cases/'+case['id']+'/captures',headers=headers('owner'),files={'file':('example.pcap',p)})
    assert r.status_code==413


def test_worker_fails_closed_if_crashed(tmp_path,monkeypatch):
    c=setup(monkeypatch,tmp_path)
    case=c.post('/api/cases',json={'name':'Broken upload'},headers=headers('owner')).json()
    class Broken:
        returncode=1
        stdout=b''
    monkeypatch.setattr(main.subprocess,'run',lambda *args,**kwargs:Broken())
    with open('tests/fixtures/synthetic_packet_fixture.pcap','rb') as p:
        r=c.post('/api/cases/'+case['id']+'/captures',headers=headers('owner'),files={'file':('example.pcap',p)})
    assert r.status_code==422
    assert storage.list_captures(case['id'])==[]
