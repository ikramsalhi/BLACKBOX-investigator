"""Black-box browser account and authorization regression tests. All data synthetic."""
from fastapi.testclient import TestClient
from blackbox import main,storage,accounts

BASE='https://blackbox.example.com'
ORIGIN={'Origin':BASE}


def test_hybrid_gallery_login_csrf_isolation_logout(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','hybrid')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    monkeypatch.setenv('BLACKBOX_SIGNUP_INVITE_CODE','test-only-superlong-invite-code-0123456789')
    storage.create_case('Synthetic public gallery','','public-demo')
    guest=TestClient(main.app,base_url=BASE)
    assert guest.get('/').status_code==200
    assert guest.get('/api/auth/session').json()['authenticated'] is False
    assert len(guest.get('/api/cases').json())==1
    assert guest.post('/api/cases',json={'name':'Unauthorized'},headers=ORIGIN).status_code==401
    assert guest.post('/api/auth/register',json={'username':'alice','password':'strong-password-1-2-3','invite_code':'wrong'},headers=ORIGIN).status_code==403
    creds={'username':'alice','password':'strong-password-1-2-3','invite_code':'test-only-superlong-invite-code-0123456789'}
    register=guest.post('/api/auth/register',json=creds,headers=ORIGIN)
    assert register.status_code==200,register.text
    assert register.cookies.get('bb_session')
    assert 'httponly' in register.headers['set-cookie'].lower()
    assert 'secure' in register.headers['set-cookie'].lower()
    csrf=register.json()['csrf']
    assert guest.get('/api/auth/session').json()['username']=='alice'
    assert guest.post('/api/cases',json={'name':'No CSRF'},headers=ORIGIN).status_code==403
    assert guest.post('/api/cases',json={'name':'Wrong origin'},headers={**ORIGIN,'X-BB-CSRF':csrf} | {'Origin':'https://evil.example'}).status_code==403
    new=guest.post('/api/cases',json={'name':'Alice evidence'},headers={**ORIGIN,'X-BB-CSRF':csrf})
    assert new.status_code==201,new.text
    case_id=new.json()['id']
    assert {x['owner'] for x in guest.get('/api/cases').json()}=={'alice','public-demo'}
    bob=TestClient(main.app,base_url=BASE)
    assert bob.get(f'/api/cases/{case_id}').status_code==404
    accounts.add('bob','strong-password-bob-4567')
    logged=bob.post('/api/auth/login',json={'username':'bob','password':'strong-password-bob-4567'},headers=ORIGIN)
    assert logged.status_code==200,logged.text
    assert bob.get(f'/api/cases/{case_id}').status_code==404
    assert bob.get(f'/api/cases/{case_id}/report?format=pdf').status_code==404
    assert bob.get('/api/cases').json()[0]['owner']=='public-demo'
    assert len(bob.get('/api/cases').json())==1
    assert bob.delete(f'/api/cases/{case_id}',headers={**ORIGIN,'X-BB-CSRF':logged.json()['csrf']}).status_code==404
    # Even signed-in users cannot edit shared public demo cases.
    public=next(x['id'] for x in bob.get('/api/cases').json() if x['owner']=='public-demo')
    assert bob.delete(f'/api/cases/{public}',headers={**ORIGIN,'X-BB-CSRF':logged.json()['csrf']}).status_code==404
    old=register.cookies['bb_session']
    out=guest.post('/api/auth/logout',json={},headers={**ORIGIN,'X-BB-CSRF':csrf})
    assert out.status_code==200
    assert guest.get('/api/auth/session').json()['authenticated'] is False
    assert guest.get(f'/api/cases/{case_id}').status_code==404
    assert accounts.get_session(old) is None
    assert guest.post('/api/auth/login',json={'username':'alice','password':'wrong-password'},headers=ORIGIN).status_code==401
    assert guest.post('/api/auth/login',json={'username':'alice','password':'strong-password-1-2-3'},headers=ORIGIN).status_code==200
    assert guest.get(f'/api/cases/{case_id}').status_code==200


def test_multi_user_login_ui_requires_auth(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    monkeypatch.setattr(main,'DEPLOY_MODE','multi-user')
    monkeypatch.setenv('BLACKBOX_PUBLIC_HOST','blackbox.example.com')
    monkeypatch.delenv('BLACKBOX_SIGNUP_INVITE_CODE',raising=False)
    accounts.add('private','very-strong-16-character-secret')
    client=TestClient(main.app,base_url=BASE)
    assert client.get('/').status_code==200
    assert client.get('/assets/auth.css').status_code==200
    assert client.get('/api/health').status_code==200
    assert client.get('/api/cases').status_code==401
    assert client.get('/api/auth/session').json()['registration_enabled'] is False
    result=client.post('/api/auth/login',json={'username':'private','password':'very-strong-16-character-secret'},headers=ORIGIN)
    assert result.status_code==200,result.text
    assert client.get('/api/cases').status_code==200
