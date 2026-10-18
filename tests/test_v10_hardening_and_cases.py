"""Fast offline integration checks; generated captures are synthetic training samples."""
import base64
from fastapi.testclient import TestClient
from blackbox import main, storage, accounts
from samples.build_scenarios import scenarios


def test_all_three_synthetic_scenarios(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    monkeypatch.setattr(main,'DEPLOY_MODE','local')
    storage.init_db()
    client=TestClient(main.app)
    expected=['port-sweep','arp-conflict','dns-nxdomain']
    for i,(path,rule) in enumerate(zip(scenarios(),expected),start=1):
        r=client.post('/api/cases',json={'name':f'SYNTHETIC TEST {i}'})
        assert r.status_code==201,r.text
        cid=r.json()['id']
        with path.open('rb') as inp:
            res=client.post(f'/api/cases/{cid}/captures',files={'file':(path.name,inp,'application/octet-stream')})
        assert res.status_code==201,res.text
        assert res.json()['status']=='ready'
        assert res.json()['frames']>1
        alerts=client.get(f'/api/cases/{cid}/findings').json()
        assert rule in [f['rule'] for f in alerts],(rule,[f['rule'] for f in alerts])
        assert all(f['evidence'] for f in alerts)
        assert client.get(f'/api/cases/{cid}/report?format=json').status_code==200
        assert client.get(f'/api/cases/{cid}/packets').status_code==200


def test_demo_exposes_only_explicitly_synthetic_cases(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    private_case=storage.create_case('Private evidence',owner='alice')
    demo_case=storage.create_case('SYNTHETIC demo',owner='public-demo')
    monkeypatch.setattr(main,'DEPLOY_MODE','public-demo')
    client=TestClient(main.app)
    listed=client.get('/api/cases').json()
    assert len(listed)==1 and listed[0]['id']==demo_case['id']
    assert client.get(f'/api/cases/{private_case["id"]}').status_code==404
    assert client.get(f'/api/cases/{private_case["id"]}/report?format=json').status_code==404
    assert client.post('/api/cases',json={'name':'No'}).status_code==403
    assert client.get('/assets/app.js').status_code==200
    home=client.get('/')
    assert home.status_code==200
    assert 'aurora.css' in home.text
    assert "frame-ancestors 'none'" in home.headers['Content-Security-Policy']
    assert home.headers['X-Frame-Options']=='DENY'


def test_hosted_write_requires_trusted_https_origin(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','multi-user')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    accounts.add('analyst','A-very-long-password-for-test-123')
    auth='Basic '+base64.b64encode(b'analyst:A-very-long-password-for-test-123').decode()
    c=TestClient(main.app)
    assert c.post('/api/cases',json={'name':'No origin'},headers={'Authorization':auth}).status_code==403
    assert c.post('/api/cases',json={'name':'Wrong'},headers={'Authorization':auth,'Origin':'https://blackbox.example.com:444'}).status_code==403
    assert c.post('/api/cases',json={'name':'Okay'},headers={'Authorization':auth,'Origin':'https://blackbox.example.com'}).status_code==201
    assert (tmp_path/'audit.jsonl').exists()
