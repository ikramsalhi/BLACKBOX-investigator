"""1.3 regression: source-verified specialists and coordinator boundaries."""
from fastapi.testclient import TestClient
from blackbox import storage,agent,specialists,main
from samples.make_sample import build
import pytest

@pytest.fixture
def case(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    client=TestClient(main.app)
    cid=client.post('/api/cases',json={'name':'Agent case'}).json()['id']
    p=tmp_path/'packets.pcap'; build(p)
    with open(p,'rb') as f:
        r=client.post(f'/api/cases/{cid}/captures',files={'file':('packets.pcap',f)})
    assert r.status_code==201,r.text
    yield client,cid


def test_three_read_only_specialists_have_real_evidence(case):
    client,cid=case
    response=client.get(f'/api/cases/{cid}/agent-brief')
    assert response.status_code==200,response.text
    brief=response.json()
    assert brief['selected_agents']==['traffic','threat','timeline']
    assert brief['model_used'] is False
    for entry in brief['agents']:
        for ref in entry['packet_refs']:
            data=client.get(f'/api/cases/{cid}/packets/{ref["packet_id"]}').json()
            assert data['id']==ref['packet_id']
            assert data['frame_no']==ref['frame_no']
            assert data['sha256']==ref['sha256']
            assert data['filename']==ref['capture']
        for fid in entry['finding_ids']:
            assert client.get(f'/api/cases/{cid}/findings/{fid}').status_code==200
    assert client.get(f'/api/cases/{cid}/agent-brief?question=show%20dns%20traffic').json()['selected_agents']==['traffic']
    assert client.get(f'/api/cases/{cid}/agent-brief?question=ARP%20spoofing').json()['selected_agents']==['threat']
    assert client.get(f'/api/cases/{cid}/agent-brief?question=Explain%20replay%20step%203').json()['selected_agents']==['timeline']


def test_cross_case_packet_id_is_not_citation(case):
    client,cid=case
    other=client.post('/api/cases',json={'name':'Second case'}).json()['id']
    try:
        real=client.get(f'/api/cases/{cid}/packets?limit=1').json()[0]['id']
        assert specialists._packet_refs(other,[real])==[]
        assert client.get('/api/cases/nonexistent/agent-brief').status_code==404
    finally:
        client.delete(f'/api/cases/{other}')


def test_model_fake_prose_reference_removed_and_not_clickable(case,monkeypatch):
    client,cid=case
    packet=client.get(f'/api/cases/{cid}/packets?limit=1').json()[0]['id']
    replies=iter([
        '{"calls":[{"name":"inspect_packet","args":{"id":'+str(packet)+'}}]}',
        '{"answer":"See packet #999999999 (incorrect) and packet #'+str(packet)+' for evidence.","finding_ids":["invented"],"packet_ids":['+str(packet)+',999999999]}'
    ])
    monkeypatch.setattr(agent,'cloud_settings',lambda:{'provider':'deepseek','url':'https://example.invalid','model':'test','key':'fake'})
    monkeypatch.setattr(agent,'_cloud',lambda messages,max_tokens=700:next(replies))
    result=agent.investigate_with_tools(cid,'Investigate this case','Sample packet',mode='cloud')
    assert result['packet_ids']==[packet]
    assert not result['finding_ids']
    assert result['citation_status']=='verified'
    assert 'packet #999999999' not in result['answer']
    assert 'unverified packet reference removed' in result['answer']
    assert result['specialists_used']==['traffic','threat','timeline']


def test_empty_case_and_unknown_evidence_have_no_fabricated_findings(case):
    client,cid=case
    other=client.post('/api/cases',json={'name':'Empty'}).json()['id']
    try:
        brief=client.get(f'/api/cases/{other}/agent-brief').json()
        assert all(a['packet_refs']==[] for a in brief['agents'])
        assert all(a['finding_ids']==[] for a in brief['agents'])
        assert brief['agents'][0]['status']=='no-evidence'
        assert brief['agents'][2]['status']=='no-evidence'
        assert 'not prove' in brief['agents'][1]['summary'].lower() or 'not mean' in brief['agents'][1]['summary'].lower()
    finally:
        client.delete(f'/api/cases/{other}')
