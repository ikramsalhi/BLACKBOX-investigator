"""Evidence-grounded incident replay. All events come from stored packet metadata.

It does not infer adversary phases, physical topology or a verified attack path.
Finite-window SQL aggregation bounds the output regardless of capture length.
"""
from __future__ import annotations
from collections import Counter
from . import storage

STEPS = 20


def build_replay(case_id: str) -> dict:
    case=storage.get_case(case_id)
    if case is None:
        raise ValueError('Unknown case')
    with storage.connect() as db:
        range_row=db.execute('''SELECT MIN(NULLIF(ts,0)) lo, MAX(NULLIF(ts,0)) hi,
            COUNT(*) total FROM packets WHERE case_id=?''',(case_id,)).fetchone()
    if not range_row['total']:
        return {'case_id':case_id,'kind':'observed-network-replay','steps':[],
                'total_packets':0,'limits':['Upload a capture to create a replay.']}
    lo=float(range_row['lo'] or 0)
    hi=float(range_row['hi'] or lo)
    # Use a fixed number of bounded time windows; do not make bins narrower than 1 microsecond.
    interval=max((hi-lo)/STEPS,0.000001)
    windows=[]
    findings=storage.list_findings(case_id)
    attached=[[] for _ in range(STEPS)]
    for f in findings:
        ix=min(STEPS-1,max(0,int((float(f['first_seen'])-lo)/interval)))
        attached[ix].append({
            'id':f['id'],'severity':f['severity'],'title':f['title'],
            'summary':f['summary'],'confidence':f['confidence'],
            'packet_ids':[int(x) for x in f['evidence'][:8] if isinstance(x,int)]})
    with storage.connect() as db:
        for index in range(STEPS):
            start=lo+index*interval
            end=lo+(index+1)*interval
            # Inclusive right edge only for final frame.
            upper='<= ?' if index==STEPS-1 else '< ?'
            clause=f'case_id=? AND ts>=? AND ts{upper}'
            params=(case_id,start,end)
            row=db.execute(f'''SELECT COUNT(*) packets,COALESCE(SUM(length),0) bytes,
                  COUNT(DISTINCT CASE WHEN src<>'' THEN src END) sources
                  FROM packets WHERE {clause}''',params).fetchone()
            proto=[dict(r) for r in db.execute(f'''SELECT proto,COUNT(*) packets FROM packets
                  WHERE {clause} GROUP BY proto ORDER BY packets DESC LIMIT 5''',params)]
            links=[dict(r) for r in db.execute(f'''SELECT src,dst,COUNT(*) packets, SUM(length) bytes,
                  MIN(id) packet_id FROM packets WHERE {clause} AND src<>'' AND dst<>'' AND src<>dst
                  GROUP BY src,dst ORDER BY packets DESC,src,dst LIMIT 7''',params)]
            samples=[dict(r) for r in db.execute(f'''SELECT id,frame_no,ts,src,dst,proto,note,
                   src_port,dst_port FROM packets WHERE {clause}
                   ORDER BY ts,id LIMIT 5''',params)]
            windows.append({'step':index,'start_ts':start,'end_ts':end,
                'packet_count':row['packets'],'bytes':row['bytes'],'source_hosts':row['sources'],
                'protocols':proto,'links':links,'packet_samples':samples,
                'findings':attached[index]})
    return {'case_id':case_id,'kind':'observed-network-replay',
        'first_ts':lo,'last_ts':hi,'total_packets':int(range_row['total']),
        'steps':windows,
        'limits':['Replay windows aggregate stored packet metadata, not live traffic.',
                  'Connections show observed conversations, not causal attack progression.',
                  'Rule findings are hypotheses, not proof of an intrusion.',
                  'Only up to seven leading source-destination relationships and five packet samples appear per window.',
                  'Empty time windows are retained; multiple captures may have widely separated timestamps.']}
