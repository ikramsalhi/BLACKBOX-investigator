"""Regression tests for readable PDFs, saved originals and real (unsupervised) ML screening."""
from pathlib import Path
from fastapi.testclient import TestClient
from blackbox import main,storage
from samples.make_sample import build
from pypdf import PdfReader
import io


def test_pdf_original_and_persistent_history(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    p=tmp_path/'known.pcap';build(p)
    with TestClient(main.app) as c:
        cid=c.post('/api/cases',json={'name':'Readable report | investigation 18','description':'Authorized simulation'}).json()['id']
        with p.open('rb') as fh:
            resp=c.post(f'/api/cases/{cid}/captures',files={'file':('known.pcap',fh)})
        assert resp.status_code==201
        capid=resp.json()['capture_id']
        pdf=c.get(f'/api/cases/{cid}/report?format=pdf')
        assert pdf.status_code==200,pdf.text[:250] if pdf.status_code!=200 else ''
        assert pdf.headers['content-type']=='application/pdf'
        assert pdf.content.startswith(b'%PDF-')
        text=' '.join(page.extract_text() or '' for page in PdfReader(io.BytesIO(pdf.content)).pages)
        assert 'Executive summary' in text
        assert 'Suspicious patterns' in text
        assert 'known.pcap' in text
        assert 'not proof' in text or 'not establish' in text
        assert resp.json()['sha256'] in text
        origin=c.get(f'/api/cases/{cid}/captures/{capid}/download')
        assert origin.status_code==200 and origin.content==p.read_bytes()
        assert c.get(f'/api/cases/{cid}/captures/no-such/download').status_code==404
        assert c.get('/api/cases/other/captures/no-such/download').status_code==404
        # Create a second client to simulate page refresh/restart; SQLite case list remains.
    storage.init_db()
    with TestClient(main.app) as restarted:
        assert any(x['id']==cid for x in restarted.get('/api/cases').json())
        assert restarted.get(f'/api/cases/{cid}/captures/{capid}/download').content==p.read_bytes()
        ml=restarted.get(f'/api/cases/{cid}/ml/anomalies')
        assert ml.status_code==200
        assert ml.json()['kind']=='unsupervised_per_case'
        assert ml.json()['status']=='ready'
        assert ml.json()['anomaly_count']>0
        for anomaly in ml.json()['anomalies']:
            for packet_id in anomaly['evidence_packet_ids']:
                assert restarted.get(f'/api/cases/{cid}/packets/{packet_id}').status_code==200
        ai=restarted.post(f'/api/cases/{cid}/report/ai.pdf',json={'mode':'local'})
        # Model is intentionally unconfigured in CI; never pretend offline fallback was LLM-generated.
        assert ai.status_code==503


def test_empty_case_pdf_and_ml(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    with TestClient(main.app) as c:
        cid=c.post('/api/cases',json={'name':'No source capture'}).json()['id']
        assert c.get(f'/api/cases/{cid}/report?format=pdf').content.startswith(b'%PDF')
        m=c.get(f'/api/cases/{cid}/ml/anomalies').json()
        assert m['status']=='insufficient_data'
        assert m['anomalies']==[]
        assert c.post(f'/api/cases/{cid}/report/ai.pdf',json={'mode':'cloud'}).status_code==422
