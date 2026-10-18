"""BLACKBOX TRACE regression: packet provenance, bounded claims, exported dossier."""
from fastapi.testclient import TestClient
from blackbox import main,storage,trace
from samples.make_sample import build
import pytest


@pytest.fixture
def client_case(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, 'DATA', tmp_path)
    monkeypatch.setattr(storage, 'CAPTURES', tmp_path/'captures')
    storage.init_db()
    client = TestClient(main.app)
    cid = client.post('/api/cases', json={'name':'TRACE review'}).json()['id']
    capture = tmp_path/'trace-scan.pcap'
    build(capture)
    with capture.open('rb') as fh:
        result = client.post(f'/api/cases/{cid}/captures', files={'file':('trace-scan.pcap',fh)})
    assert result.status_code == 201, result.text
    fid = next(f['id'] for f in client.get(f'/api/cases/{cid}/findings').json() if f['rule'] == 'port-sweep')
    return client,cid,fid


def test_trace_is_read_only_case_bound_and_source_verified(client_case):
    client,cid,fid=client_case
    old_packets=client.get(f'/api/cases/{cid}/summary').json()['stats']['packet_count']
    response=client.get(f'/api/cases/{cid}/trace/{fid}')
    assert response.status_code==200, response.text
    t=response.json()
    assert t['finding_id']==fid and t['rule']=='port-sweep'
    assert t['ml_model_used'] is False and t['llm_model_used'] is False
    assert 'NOT A CONFIRMED ATTACK' in t['review_status']
    assert len(t['alternatives'])==2
    assert any('Authorized' in a['title'] for a in t['alternatives'])
    assert t['representative_packets']
    assert len(t['representative_packets'])<=16
    timestamps=[p['ts'] for p in t['representative_packets']]
    assert timestamps==sorted(timestamps)
    for p in t['representative_packets']:
        source=client.get(f'/api/cases/{cid}/packets/{p["packet_id"]}').json()
        assert (source['frame_no'],source['sha256'],source['filename'])==(p['frame_no'],p['sha256'],p['capture'])
        assert p['src']==source['src'] and p['dst']==source['dst']
    assert client.get(f'/api/cases/{cid}/summary').json()['stats']['packet_count']==old_packets


def test_trace_does_not_leak_across_cases(client_case):
    client,cid,fid=client_case
    other=client.post('/api/cases',json={'name':'Unrelated case'}).json()['id']
    assert client.get(f'/api/cases/{other}/trace/{fid}').status_code==404
    assert client.get(f'/api/cases/{cid}/trace/invalid').status_code==404
    assert client.get('/api/cases/does-not-exist/trace/invalid').status_code==404
    assert client.get(f'/api/cases/{cid}/trace/{fid}/export?format=nope').status_code==422


def test_trace_report_exports_source_hashes_and_limitations(client_case):
    client,cid,fid=client_case
    response=client.get(f'/api/cases/{cid}/trace/{fid}/export?format=md')
    assert response.status_code==200
    assert 'attachment' in response.headers['content-disposition']
    doc=response.text
    trace_record=client.get(f'/api/cases/{cid}/trace/{fid}').json()
    assert 'Competing interpretations' in doc and 'not' in doc.lower()
    assert 'Representative packet evidence' in doc
    assert trace_record['sources'][0]['sha256'] in doc
    assert trace_record['representative_packets'][0]['frame_no'] is not None
    assert client.get(f'/api/cases/{cid}/trace/{fid}/export?format=json').json()==trace_record


def test_generic_rule_has_safe_alternatives():
    assert 'arp-conflict' in trace.ALTERNATIVES
    assert 'dns-pattern' in trace.ALTERNATIVES
    for k,v in trace.ALTERNATIVES.items():
        assert len(v)==2 and all(len(a)==3 for a in v)


def test_public_gallery_trace_read_allowed_but_mutation_blocked(client_case,monkeypatch):
    client,cid,fid=client_case
    with storage.connect() as db:
        db.execute("UPDATE cases SET owner='public-demo' WHERE id=?",(cid,))
    monkeypatch.setattr(main,'DEPLOY_MODE','public-demo')
    response=client.get(f'/api/cases/{cid}/trace/{fid}')
    assert response.status_code==200
    assert response.json()['explanation_engine']=='deterministic-evidence-trace'
    assert client.get(f'/api/cases/{cid}/trace/{fid}/export?format=md').status_code==200
    assert client.post(f'/api/cases/{cid}/investigate').status_code==403
