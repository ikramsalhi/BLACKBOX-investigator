"""v1.7: deterministic replay from openly redistributable synthetic demos."""
import tempfile
from pathlib import Path
from fastapi.testclient import TestClient
from blackbox.main import app
from blackbox import storage
from blackbox.replay import build_replay
from blackbox.agent import run_tool


def test_demo_replay_linkage_and_conversation():
    client=TestClient(app)
    r=client.post('/api/demo')
    assert r.status_code==201,r.text
    data=r.json()
    assert data['real_format'] is True
    assert 'synthetic' in data['capture_origin']
    cid=data['case_id']
    try:
        report=client.get(f'/api/cases/{cid}/report?format=json').json()
        assert report['summary']['stats']['packet_count']>=30
        result=client.get(f'/api/cases/{cid}/replay')
        assert result.status_code==200
        story=result.json()
        assert story['kind']=='observed-network-replay'
        assert len(story['steps'])==20
        assert sum(s['packet_count'] for s in story['steps'])==report['summary']['stats']['packet_count']
        assert any(s['findings'] for s in story['steps'])
        assert any(s['links'] for s in story['steps'])
        evidence=set()
        for step in story['steps']:
            for p in step['packet_samples']:
                evidence.add(p['id'])
                packet=client.get(f'/api/cases/{cid}/packets/{p["id"]}')
                assert packet.status_code==200
                assert packet.json()['frame_no']==p['frame_no']
            assert all(f['packet_ids'] for f in step['findings'])
        assert evidence
        result=client.post(f'/api/cases/{cid}/ask',json={'question':'Explain replay step 1'})
        assert result.status_code==200,result.text
        reply=result.json()
        assert reply['engine']=='offline-replay'
        assert 'packet' in reply['answer'].lower()
        assert reply['packet_ids']
        assert all(client.get(f'/api/cases/{cid}/packets/{n}').status_code==200 for n in reply['packet_ids'])
        assert run_tool(cid,'replay_window',{'step':1})['step']==0
        assert client.get('/api/cases/nonexistent/replay').status_code==404
    finally:
        for row in client.get('/api/cases').json():
            if row['name'].startswith('DEMO '):client.delete(f'/api/cases/{row["id"]}')


def test_replay_without_packets():
    cid=storage.create_case('Empty replay 12',owner='')['id']
    try:
        result=build_replay(cid)
        assert result['steps']==[]
        assert result['total_packets']==0
    finally:
        storage.delete_case(cid)


def test_cloud_citations_are_limited_to_retrieved_case_packets(monkeypatch):
    """Model-created packet IDs may appear in prose, but never become clickable proof."""
    import blackbox.agent as agent
    client=TestClient(app)
    r=client.post('/api/demo')
    assert r.status_code==201
    cid=r.json()['case_id']
    try:
        sample=client.get(f'/api/cases/{cid}/replay').json()['steps'][0]['packet_samples'][0]['id']
        replies=iter([
            '{"calls":[{"name":"replay_window","args":{"step":1}}]}',
            '{"answer":"Observed packets need human review.","finding_ids":[],"packet_ids":['+str(sample)+',999999999]}'
        ])
        monkeypatch.setattr(agent,'cloud_settings',lambda:{'provider':'deepseek','url':'https://example.invalid','model':'test','key':'fake'})
        monkeypatch.setattr(agent,'_cloud',lambda messages,max_tokens=700:next(replies))
        result=agent.investigate_with_tools(cid,'Explain replay step 1','Test',mode='cloud')
        assert result['packet_ids']==[sample]
        assert 'replay_window' in result['tools_used']
    finally:
        for row in client.get('/api/cases').json():
            if row['name'].startswith('DEMO '):client.delete(f'/api/cases/{row["id"]}')
