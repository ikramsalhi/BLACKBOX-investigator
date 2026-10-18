import base64
from fastapi.testclient import TestClient
from blackbox import main,storage


def test_public_demo_read_only(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','public-demo')
    client=TestClient(main.app)
    assert client.get('/api/cases').status_code==200
    assert client.post('/api/cases',json={'name':'No'}).status_code==403
    assert client.post('/api/cases/fake/ask',json={'question':'hi'}).status_code==403
    assert client.get('/api/health').json()['cloud_ai']['configured'] is False


def test_private_hosted_requires_auth(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','private-hosted')
    monkeypatch.setenv('BLACKBOX_BASIC_USER','analyst')
    monkeypatch.setenv('BLACKBOX_BASIC_PASSWORD','test-only-long-password-999')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    c=TestClient(main.app)
    assert c.get('/api/cases').status_code==401
    assert c.get('/').status_code==401
    auth=base64.b64encode(b'analyst:test-only-long-password-999').decode()
    headers={'Authorization':'Basic '+auth}
    assert c.get('/api/cases',headers=headers).status_code==200
    assert c.post('/api/cases',headers={**headers,'Origin':'https://evil.example'},json={'name':'Reject'}).status_code==403
    assert c.post('/api/cases',headers={**headers,'Origin':'https://blackbox.example.com'},json={'name':'Allowed'}).status_code==201
