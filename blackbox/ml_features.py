"""Export traceable flow features for ML experiments; no attack labels are inferred.

Every row is a single capture, 120-second wall-clock window, directional five-tuple.
The PCAP supplies observations; trained model, labels and calibration are separate.
"""
from __future__ import annotations
import csv
import io
from collections import defaultdict
from . import storage

WINDOW_SECONDS = 120
FIELDNAMES = [
    "flow_id", "capture_id", "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "window_start_epoch", "start_ts", "end_ts", "duration_sec",
    "packet_count", "byte_count", "flow_rate_pps", "byte_rate_bps",
    "avg_packet_size", "unique_dst_ports", "tcp_syn_count", "tcp_rst_count",
    "evidence_packet_ids", "label", "traffic_category"
]
MODEL_INPUT_FIELDS = [
    "src_port", "dst_port", "protocol", "duration_sec", "packet_count", "byte_count",
    "flow_rate_pps", "byte_rate_bps", "avg_packet_size", "unique_dst_ports",
    "tcp_syn_count", "tcp_rst_count"
]

def flows_from_case(case_id):
    """Aggregate parsed observations. No arbitrary public-PCAP labels are fabricated.

    An evidence list references at most 12 packet DB IDs, which can be resolved via
    /api/cases/{case_id}/packets/{packet_id} or their source capture/frame.
    """
    groups = {}
    ports_per_source = defaultdict(set)
    with storage.connect() as db:
        q = db.execute("""SELECT id,capture_id,ts,src,dst,src_port,dst_port,proto,length,tcp_flags
            FROM packets WHERE case_id=? ORDER BY capture_id,ts,id""", (case_id,))
        for p in q:
            ts = float(p['ts'] or 0)
            bucket = int(ts // WINDOW_SECONDS) if ts > 0 else 0
            src = p['src'] or ''
            dst = p['dst'] or ''
            proto = p['proto'] or 'OTHER'
            sp,dp = p['src_port'],p['dst_port']
            key = (p['capture_id'], bucket, src, dst, sp, dp, proto)
            if key not in groups:
                groups[key] = {
                    'capture_id':p['capture_id'],'src_ip':src,'dst_ip':dst,
                    'src_port':sp,'dst_port':dp,'protocol':proto,
                    'window_start_epoch':bucket*WINDOW_SECONDS,
                    'start_ts':ts,'end_ts':ts,'packet_count':0,'byte_count':0,
                    'tcp_syn_count':0,'tcp_rst_count':0,'_ids':[]}
            g = groups[key]
            if ts > 0:
                g['start_ts'] = min(g['start_ts'], ts) if g['start_ts']>0 else ts
                g['end_ts'] = max(g['end_ts'],ts)
            g['packet_count']+=1
            g['byte_count']+=max(0,int(p['length'] or 0))
            flags = p['tcp_flags'] or ''
            if proto=='TCP' and 'S' in flags and 'A' not in flags:g['tcp_syn_count']+=1
            if proto=='TCP' and 'R' in flags:g['tcp_rst_count']+=1
            if len(g['_ids'])<12:g['_ids'].append(str(p['id']))
            if dp is not None and src:
                ports_per_source[(p['capture_id'], bucket, src)].add(dp)
    records = []
    for i,(key,g) in enumerate(sorted(groups.items(),key=lambda pair:(str(pair[0][0]),pair[0][1],str(pair[0][2]),str(pair[0][3]),str(pair[0][4]),str(pair[0][5]),str(pair[0][6]))),1):
        duration=max(0.0,g['end_ts']-g['start_ts'])
        n=g['packet_count']
        record={k:v for k,v in g.items() if k!='_ids'}
        record.update({
            'flow_id':f'FLW-{i:06d}',
            'duration_sec':round(duration,6),
            # A single observed packet has no meaningful temporal rate.
            'flow_rate_pps':round(n/duration,3) if duration>0 else 0,
            'byte_rate_bps':round(g['byte_count']/duration,3) if duration>0 else 0,
            'avg_packet_size':round(g['byte_count']/n,3) if n else 0,
            'unique_dst_ports':len(ports_per_source.get((key[0],key[1],key[2]),())),
            'evidence_packet_ids':'|'.join(g['_ids']),
            'label':'', 'traffic_category':''
        })
        records.append(record)
    return records

def as_csv(rows):
    b=io.StringIO(newline='')
    writer=csv.DictWriter(b,fieldnames=FIELDNAMES,extrasaction='ignore')
    writer.writeheader()
    writer.writerows(rows)
    return b.getvalue()
