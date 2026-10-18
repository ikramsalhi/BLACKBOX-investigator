import base64
from fastapi.testclient import TestClient
from blackbox import main,storage,accounts

def auth(username,password):
    return {'Authorization':'Basic '+base64.b64encode(f'{username}:{password}'.encode()).decode()}

def test_accounts_case_isolation(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','multi-user')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    accounts.add('alice','test-password-alice-12345')
    accounts.add('bob','test-password-bob-1234567')
    client=TestClient(main.app)
    assert client.get('/api/cases').status_code==401
    headers=auth('alice','test-password-alice-12345')
    headers['Origin']='https://blackbox.example.com'
    case=client.post('/api/cases',json={'name':'Alice case'},headers=headers)
    assert case.status_code==201,case.text
    cid=case.json()['id']
    assert len(client.get('/api/cases',headers=auth('alice','test-password-alice-12345')).json())==1
    assert client.get('/api/cases',headers=auth('bob','test-password-bob-1234567')).json()==[]
    assert client.get(f'/api/cases/{cid}',headers=auth('bob','test-password-bob-1234567')).status_code==404
    assert client.delete(f'/api/cases/{cid}',headers=auth('bob','test-password-bob-1234567')).status_code==404
    assert client.get(f'/api/cases/{cid}',headers=auth('alice','test-password-alice-12345')).status_code==200
