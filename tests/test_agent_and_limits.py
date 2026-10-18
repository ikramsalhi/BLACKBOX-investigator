from fastapi.testclient import TestClient
from blackbox import main,storage,agent
from samples.make_sample import build
from tests.test_parser import to_pcapng
import pytest

@pytest.fixture()
def case_with_packets(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    client=TestClient(main.app)
    cid=client.post('/api/cases',json={'name':'case A'}).json()['id']
    p=tmp_path/'data.pcap';ng=tmp_path/'data.pcapng';build(p);to_pcapng(p,ng)
    with open(ng,'rb') as f:
        res=client.post(f'/api/cases/{cid}/captures',files={'file':('data.pcapng',f)})
    assert res.status_code==201,res.text
    return client,cid,res.json()

def test_pcapng_api_and_evidence_lookup(case_with_packets):
    client,cid,ingest=case_with_packets
    assert ingest['frames']==31
    findings=client.get(f'/api/cases/{cid}/findings').json()
    evid=findings[0]['evidence'][0]
    p=client.get(f'/api/cases/{cid}/packets/{evid}').json()
    assert p['id']==evid
    assert p['filename']=='data.pcapng'
    assert p['sha256']==ingest['sha256']
    assert 1<=p['frame_no']<=31

def test_read_only_tools_and_agent(case_with_packets,monkeypatch):
    client,cid,ingest=case_with_packets
    summary=agent.run_tool(cid,'case_summary')
    assert summary['stats']['packet_count']==31
    detail=agent.run_tool(cid,'inspect_host',{'ip':'10.0.0.12'})
    assert detail['frames']>0
    with pytest.raises(ValueError):agent.run_tool(cid,'execute_shell',{'command':'rm -rf /'})
    sent=[]
    def mock_ollama(messages,max_tokens=700):
        sent.append(messages)
        if len(sent)==1:return '{"calls":[{"name":"inspect_host","args":{"ip":"10.0.0.12"}},{"name":"list_findings","args":{}}]}'
        finding=storage.list_findings(cid)[0]
        return '{"answer":"An observed SYN sweep merits human review.","finding_ids":["'+finding['id']+'","nonexistent"]}'
    monkeypatch.setattr(agent,'_ollama',mock_ollama)
    monkeypatch.setenv('BLACKBOX_OLLAMA_URL','http://localhost:11434')
    from blackbox import assistant
    monkeypatch.setattr(assistant,'OLLAMA_URL','http://localhost:11434')
    result=agent.investigate_with_tools(cid,'Review 10.0.0.12','Parsed 31 packets')
    assert result['engine']=='local-tool-agent'
    assert len(result['tools_used'])==2
    assert result['finding_ids']==[storage.list_findings(cid)[0]['id']]
    assert '10.0.0.12' in str(sent[-1])

def test_partial_status(tmp_path,monkeypatch):
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    monkeypatch.setattr(main,'MAX_FRAMES',3)
    storage.init_db();client=TestClient(main.app)
    cid=client.post('/api/cases',json={'name':'partial'}).json()['id']
    p=tmp_path/'many.pcap';build(p)
    with open(p,'rb') as f:res=client.post(f'/api/cases/{cid}/captures',files={'file':('many.pcap',f)})
    assert res.status_code==201,res.text
    assert res.json()['status']=='partial'
    assert res.json()['frames']==3
    assert client.get(f'/api/cases/{cid}/summary').json()['captures']['incomplete']==1
