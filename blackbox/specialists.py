"""BLACKBOX v1.3: evidence-first specialized investigation agents.

These are deterministic, read-only specialists. They are *not* additional
LLM API calls: the optional DeepSeek/Ollama Copilot coordinates their output.
The parser/rule engine remains the sole source of detection hypotheses.
All evidence references are resolved against the selected case in SQLite.
"""
from __future__ import annotations
import re
from . import storage
from .replay import build_replay

MAX_FINDINGS=6
MAX_EVENTS=5
MAX_PACKETS_PER_AGENT=10


def _packet_refs(case_id, packet_ids):
    """Drop forged/missing IDs. Never trust model-generated references."""
    refs=[];seen=set()
    for pid in packet_ids:
        if type(pid) is not int or pid<=0 or pid in seen:continue
        seen.add(pid)
        packet=storage.get_packet(case_id,pid)
        if packet:
            refs.append({'packet_id':pid,'frame_no':packet['frame_no'],
                'capture':packet['filename'],'sha256':packet['sha256'],
                'ts':packet['ts'],'src':packet['src'],'dst':packet['dst'],
                'proto':packet['proto']})
        if len(refs)>=MAX_PACKETS_PER_AGENT:break
    return refs


def _flow_packet_ids(case_id, flows):
    """Link each notable flow to an actual packet from THIS case."""
    found=[]
    with storage.connect() as db:
        for f in flows[:6]:
            row=db.execute('''SELECT id FROM packets WHERE case_id=? AND src=? AND dst=?
                AND proto=? AND COALESCE(src_port,-1)=COALESCE(?,-1)
                AND COALESCE(dst_port,-1)=COALESCE(?,-1)
                ORDER BY ts,id LIMIT 1''',
                (case_id,f['src'],f['dst'],f['proto'],f['src_port'],f['dst_port'])).fetchone()
            if row:found.append(row['id'])
    return found


def traffic_agent(case_id):
    """What network communication is actually observable?"""
    stats=storage.summary(case_id)
    flows=storage.flows(case_id,limit=6)
    dns=storage.dns_stats(case_id,limit=5)
    dhcp=storage.dhcp_stats(case_id)
    proto=stats['protocols'][:7]
    count=int(stats['stats']['packet_count'])
    message=(f"Observed {count:,} packet records across {len(proto)} displayed protocol categories. "
        "Top flows show observed unidirectional traffic, not proof of an attack.") if count else 'No packet records. Import authorized PCAP evidence.'
    return {'agent':'traffic','title':'Traffic Agent','status':'observed' if count else 'no-evidence',
        'summary':message,
        'observations':{'packet_count':count,'protocols':proto,
            'top_flows':[{'src':f['src'],'dst':f['dst'],'proto':f['proto'],
                          'src_port':f['src_port'],'dst_port':f['dst_port'],
                          'packets':f['packets'],'bytes':f['bytes']} for f in flows],
            'dns_questions':dns,'dhcp_messages':dhcp[:10]},
        'finding_ids':[], 'packet_refs':_packet_refs(case_id,_flow_packet_ids(case_id,flows)),
        'limitations':['Observed traffic may be partial or encrypted; direction does not imply malicious intent.']}


def threat_agent(case_id):
    """Examine previously computed heuristic findings; NEVER invent detections."""
    findings=storage.list_findings(case_id)[:MAX_FINDINGS]
    items=[{'finding_id':f['id'],'rule':f['rule'],'title':f['title'],
            'severity':f['severity'],'confidence':f['confidence'],
            'summary':f['summary'],'first_seen':f['first_seen'],
            'evidence_packet_ids':[pid for pid in f['evidence'][:6] if type(pid) is int]}
            for f in findings]
    refs=_packet_refs(case_id,(pid for f in findings for pid in f['evidence']))
    return {'agent':'threat','title':'Threat Agent',
        'status':'review-needed' if findings else 'no-rules-triggered',
        'summary':(f"{len(findings)} displayed heuristic finding(s) merit review. "
                   "No finding alone confirms an attack." if findings else
                   'No rule finding crossed its threshold. This does not mean the capture is safe.'),
        'observations':{'findings':items},
        'finding_ids':[x['finding_id'] for x in items], 'packet_refs':refs,
        'limitations':['Rule hits are hypotheses and may be false positives; missing signatures can cause false negatives.']}


def timeline_agent(case_id):
    """Chronology of sampled observed packets, not a causal attack chain."""
    replay=build_replay(case_id)
    windows=[w for w in replay['steps'] if w['packet_count'] or w['findings']]
    # Prefer first & last observations and intervals containing findings, bounded.
    flagged=[w for w in windows if w['findings']]
    chosen={w['step']:w for w in ([windows[0]] if windows else [])+flagged[:MAX_EVENTS]+([windows[-1]] if windows else [])}
    for w in windows:
        if len(chosen)>=MAX_EVENTS:break
        chosen[w['step']]=w
    selected=[chosen[x] for x in sorted(chosen)][:MAX_EVENTS]
    ids=[];finding_ids=[]
    events=[]
    for w in selected:
        packet_ids=[p['id'] for p in w['packet_samples'][:3]]
        ids.extend(packet_ids)
        finding_ids.extend(f['id'] for f in w['findings'])
        events.append({'step':w['step']+1,'start_ts':w['start_ts'],
             'end_ts':w['end_ts'],'packet_count':w['packet_count'],
             'observed_links':w['links'][:3],
             'finding_ids':[f['id'] for f in w['findings']],
             'sample_packet_ids':packet_ids})
    return {'agent':'timeline','title':'Timeline Agent',
        'status':'observed' if windows else 'no-evidence',
        'summary':(f"{replay['total_packets']:,} stored packet records were mapped into replay windows. "
                   'Chronology is observed; attack stages and causality are not inferred.' if windows
                   else 'No timestamped evidence is available for replay.'),
        'observations':{'windows':events,'total_windows':len(replay['steps'])},
        'finding_ids':list(dict.fromkeys(finding_ids)),
        'packet_refs':_packet_refs(case_id,ids),
        'limitations':['Multiple captures can have unrelated time ranges; samples do not show every packet.']}


AGENTS={'traffic':traffic_agent,'threat':threat_agent,'timeline':timeline_agent}


def select_agents(question):
    """Transparent keyword router. Broad questions use all specialists."""
    q=(question or '').lower()
    if not q or re.search(r'\b(incident|what happened|overall|summari[sz]e|investigat|all agents|full analysis)\b',q):
        return ('traffic','threat','timeline')
    chosen=[]
    if re.search(r'\b(traffic|protocol|port|tcp|udp|dns|dhcp|flow|bandwidth|host|device|ip|connection)\b',q):chosen.append('traffic')
    if re.search(r'\b(attack|threat|suspicious|finding|alert|malicious|scan|spoof|arp|intrusion|compromis|anomal)\w*',q):chosen.append('threat')
    if re.search(r'\b(replay|timeline|step|sequence|first|before|after|when|chronolog)\w*',q):chosen.append('timeline')
    return tuple(chosen) if chosen else ('traffic','threat','timeline')


def coordinated_brief(case_id, question='', all_agents=False):
    """Deterministically assemble only requested specialists for this case."""
    if not storage.get_case(case_id):raise ValueError('Unknown case')
    names=tuple(AGENTS) if all_agents else select_agents(question)
    output=[AGENTS[name](case_id) for name in names]
    return {'architecture':'deterministic-analysis -> specialist-agents -> evidence-verified-copilot',
            'case_id':case_id,'selected_agents':list(names),'agents':output,
            'evidence_policy':'Packet references resolve to this case and include capture SHA-256/frame number. No confirmed attack verdict is inferred.',
            'model_used':False}
