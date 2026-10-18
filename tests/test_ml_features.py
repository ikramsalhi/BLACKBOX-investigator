"""Flow CSV integration: extracted from stored packet evidence, not invented labels."""
from fastapi.testclient import TestClient
from blackbox import main,storage,ml_features
from samples.make_sample import build
import csv,io

def test_flow_export_has_evidence_and_no_training_label(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    sample=tmp_path/'sample.pcap';build(sample)
    with TestClient(main.app) as c:
        cid=c.post('/api/cases',json={'name':'ML export test'}).json()['id']
        with sample.open('rb') as fh:
            assert c.post(f'/api/cases/{cid}/captures',files={'file':('sample.pcap',fh)}).status_code==201
        result=c.get(f'/api/cases/{cid}/ml/features.csv')
        assert result.status_code==200
        assert result.headers['content-type'].startswith('text/csv')
        rows=list(csv.DictReader(io.StringIO(result.text)))
        assert rows
        assert set(ml_features.FIELDNAMES)==set(rows[0])
        assert all(r['label']=='' and r['traffic_category']=='' for r in rows)
        assert any(r['tcp_syn_count']!='0' for r in rows)
        assert any(r['evidence_packet_ids'] for r in rows)
        packet_ids={int(i) for row in rows for i in row['evidence_packet_ids'].split('|') if i}
        assert all(c.get(f'/api/cases/{cid}/packets/{i}').status_code==200 for i in list(packet_ids)[:8])

def test_no_case_is_not_exportable(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    with TestClient(main.app) as c:
        assert c.get('/api/cases/does-not-exist/ml/features.csv').status_code==404
