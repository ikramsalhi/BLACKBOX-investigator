"""Evidence-bounded assistant: offline, local Ollama, or opt-in cloud AI.

No evidence = no confident diagnosis. LLM cannot directly mutate stored data.
"""
from __future__ import annotations
import json,os,re,urllib.request,urllib.error,ipaddress
from . import storage

OLLAMA_URL=os.environ.get('BLACKBOX_OLLAMA_URL','').rstrip('/')
OLLAMA_MODEL=os.environ.get('BLACKBOX_OLLAMA_MODEL','qwen2.5:7b')


def _offline(case_id,question,findings,summary):
    q=question.lower()
    if summary['stats']['packet_count']==0:
        return 'This case has no parsed packets. Upload a real PCAP or PCAPNG capture first. I cannot infer an incident without evidence.',[]
    ips=[]
    for part in re.findall(r'[0-9a-fA-F:.]+',question):
        try: ips.append(str(ipaddress.ip_address(part)))
        except ValueError:pass
    if ips:
        ip=ips[0]; details=storage.host_details(case_id,ip)
        related=[f for f in findings if ip in json.dumps(f['indicators'])]
        if not details['frames']:
            return f'I did not observe {ip} in this case. That does not mean it never appeared outside this capture.',[]
        peers=', '.join(f"{p['peer']} ({p['packets']} packets)" for p in details['peers'][:6]) or 'none'
        return (f"Observed {ip} in {details['frames']:,} packet records, {details['bytes'] or 0:,} bytes (packet lengths). "
                f"Leading peers: {peers}. Associated rule findings: {len(related)}. "
                "This is observed activity, not a claim of compromise."),[f['id'] for f in related[:8]]
    if any(w in q for w in ('dhcp','bootp','lease','dhcp request','dhcp offer')):
        rows=storage.dhcp_stats(case_id)
        if not rows:return 'No decoded DHCP message types were found in this capture. This does not prove DHCP traffic was absent.',[]
        events='; '.join(f"{r['event']}: {r['packets']} frames" for r in rows)
        return 'Observed DHCP message types: '+events+'. These are observed network configuration messages, not evidence of a rogue server on their own.',[]
    if any(w in q for w in ('dns','domain','nxdomain')):
        rows=storage.dns_stats(case_id,8)
        if not rows:return 'No parsed DNS questions in this case. DNS-over-HTTPS may not be visible as DNS.',[]
        lines='; '.join(f"{r['domain']} ({r['count']} observations, {r['nxdomain']} NXDOMAIN)" for r in rows)
        selected=[f['id'] for f in findings if 'dns' in f['rule']]
        return 'Most observed DNS names: '+lines+'. NXDOMAIN counts refer only to responses visible in this capture.',selected
    if any(w in q for w in ('top talk','biggest','most traffic','bandwidth','bytes')):
        top=summary['top_talkers'][:8]
        return 'Top packet sources by observed bytes: '+ '; '.join(f"{h['ip']}: {h['bytes']:,} bytes" for h in top)+'. This is observed traffic, not necessarily full flow volume.',[]
    if any(w in q for w in ('flow','connection','port','protocol')):
        data=storage.flows(case_id,10)
        return 'Largest observed unidirectional conversations: '+ '; '.join(f"{r['src']}:{r['src_port'] or '-'} → {r['dst']}:{r['dst_port'] or '-'} ({r['proto']}; {r['packets']} packets)" for r in data)+'.',[]
    if not findings:
        return (f"I parsed {summary['stats']['packet_count']:,} packets and no built-in heuristic rule crossed its threshold. "
                'This does NOT mean the capture is safe; verify scope, decrypted visibility, baseline and host logs.'),[]
    ids=[f['id'] for f in findings[:5]]
    return (f"I reviewed {summary['stats']['packet_count']:,} parsed packets and found {len(findings)} rule-based signals for human review. "
            + ' | '.join(f"[{f['severity'].upper()}] {f['title']}: {f['summary']}" for f in findings[:5])
            + ' Open the Findings tab to inspect exact packet IDs. These are hypotheses, not confirmed compromises.'),ids


# Conversational routing avoids sending greetings and UI-help questions into packet detectors.
def _conversation_intent(question):
    q=question.lower().strip().strip('!?., ')
    if re.fullmatch(r'(hi|hey|hello|yo|salut|bonjour|salam|good morning|good evening|thanks|thank you|bye|hey there)(\s+blackbox)?',q):return 'greeting'
    if any(x in q for x in ('what can you do','who are you','how do i use','how to use','how does blackbox','how does this app',
        'what is this page','explain this page','what does this page','what are the pages','navigate the app',
        'how to upload','where to upload','how to export','what is blackbox','help me use')):return 'guide'
    if any(x in q for x in ('what is arp','explain arp','what is dns','explain dns','what is a pcap','what is tcp',
        'explain tcp','what is a syn','what is spoofing','explain spoofing','what is phishing',
        'teach me','explain the concept','what is cybersecurity')) and not any(x in q for x in ('this capture','my capture','this case','in my network')):return 'education'
    return 'evidence'

_GREET='Hello! I’m BLACKBOX Copilot 👋 I can explain every page, guide you through uploading and investigating a PCAP, teach network security concepts, and help analyze real case evidence. What would you like to explore?'

def _offline_guide(question,page):
    from .agent import APP_GUIDE
    intent=_conversation_intent(question)
    if intent=='greeting':return _GREET
    if intent=='education':return 'I can explain networking and cybersecurity concepts in depth using Cloud AI or local Ollama. Select an AI mode, then ask your question. For packet-specific conclusions, upload evidence first.'
    return ('You are on the '+page.replace('_',' ')+' page. '+APP_GUIDE.replace('\n',' ')+ ' Ask me about any specific tab or upload workflow.')[:2200]

def answer(case_id,question,use_local_model=False,use_cloud_model=False,history=None,page='assistant'):
    summary=storage.summary(case_id)
    findings=storage.list_findings(case_id)
    intent=_conversation_intent(question)
    replay_match=re.search(r'\breplay\s+(?:step|window|moment)\s+(\d{1,3})\b',question,re.IGNORECASE)
    if replay_match and not (use_cloud_model or use_local_model):
        from .replay import build_replay
        windows=build_replay(case_id)['steps']
        ix=int(replay_match.group(1))-1
        if not (0<=ix<len(windows)):
            return {'answer':'That replay moment does not exist for this case. Open Incident replay to see the available windows.',
                    'engine':'offline-replay','finding_ids':[],'packet_ids':[],'tools_used':['replay_window'],
                    'notice':'No cloud AI request was made.'}
        window=windows[ix]
        flows='; '.join(f"{f['src']} → {f['dst']} ({f['packets']} packets)" for f in window['links'][:4]) or 'no observed IP communications'
        description=(f"Replay moment {ix+1}: {window['packet_count']} timestamped packets, "
                     f"{window['bytes']} observed bytes. Leading relationships: {flows}. "
                     + (f"{len(window['findings'])} heuristic finding(s) begin in this window. " if window['findings'] else 'No rule finding begins in this interval. ')
                     + 'These are time-ordered observations, not a proven attack sequence. Open referenced packets in the original capture to investigate further.')
        ids=list(dict.fromkeys([p['id'] for p in window['packet_samples']]+[pid for f in window['findings'] for pid in f['packet_ids']]))[:12]
        return {'answer':description,'engine':'offline-replay','finding_ids':[f['id'] for f in window['findings']],
                'packet_ids':ids,'tools_used':['replay_window'],'notice':'Grounded in stored packet metadata; no external LLM used.'}
    if intent!='evidence':
        if intent=='greeting':
            return {'answer':_GREET,'finding_ids':[],'engine':'copilot','tools_used':[], 'notice':'Welcome to BLACKBOX.'}
        if use_cloud_model or use_local_model:
            try:
                from .agent import conversation_reply
                return conversation_reply(question,history,page,'cloud' if use_cloud_model else 'local')
            except (ValueError,KeyError,TypeError,TimeoutError,OSError,urllib.error.URLError,json.JSONDecodeError) as exc:
                msg=str(exc)[:150] if isinstance(exc,ValueError) else type(exc).__name__
                return {'answer':_offline_guide(question,page),'finding_ids':[],'engine':'offline-guide','tools_used':[],
                    'notice':'AI unavailable ('+msg+'); showing built-in product guidance.'}
        return {'answer':_offline_guide(question,page),'finding_ids':[],'engine':'offline-guide','tools_used':[], 'notice':'Built-in product guidance; no external AI used.'}
    offline,ids=_offline(case_id,question,findings,summary)
    if use_cloud_model or use_local_model:
        mode='cloud' if use_cloud_model else 'local'
        try:
            from .agent import investigate_with_tools
            return investigate_with_tools(case_id,question,offline,mode=mode,history=history,page=page)
        except (ValueError, KeyError, TypeError, TimeoutError, OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            # No secret or provider request body is returned to the browser.
            error=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
            error=error[:190]
            return {'answer':offline,'finding_ids':ids,'engine':'offline-evidence',
                    'tools_used':[],
                    'notice':f'{mode.capitalize()} model unavailable ({error}). Fell back to deterministic evidence.'}

    return {'answer':offline,'finding_ids':ids,'engine':'offline-evidence',
      'notice':'Rule-based evidence explanation; no external LLM was used.'}
