from blackbox import assistant, agent

def test_greeting_does_not_open_case_tools(monkeypatch):
    monkeypatch.setattr(assistant.storage,'summary',lambda c:{'stats':{'packet_count':0}})
    monkeypatch.setattr(assistant.storage,'list_findings',lambda c:[])
    r=assistant.answer('case','hi',use_cloud_model=True)
    assert r['engine']=='copilot'
    assert 'Hello' in r['answer']
    assert not r['finding_ids']

def test_page_guidance_without_model(monkeypatch):
    monkeypatch.setattr(assistant.storage,'summary',lambda c:{'stats':{'packet_count':0}})
    monkeypatch.setattr(assistant.storage,'list_findings',lambda c:[])
    r=assistant.answer('case','what is this page?',page='report')
    assert 'report' in r['answer'].lower()
    assert r['engine']=='offline-guide'

def test_cloud_conversation_includes_bounded_history(monkeypatch):
    recorded=[]
    def fake_model(messages,max_tokens=700):
        recorded.extend(messages)
        return '{"answer":"Go to Evidence vault and upload a PCAP.","finding_ids":[]}'
    monkeypatch.setattr(agent,'_cloud',fake_model)
    r=agent.conversation_reply('How do I upload?',history=[{'role':'user','content':'Where do I begin?'}],page='captures')
    assert 'Evidence vault' in r['answer']
    assert any('Where do I begin?' in x['content'] for x in recorded)
    assert 'captures' in recorded[0]['content']
