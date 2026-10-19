"""Explicitly *unsupervised* per-case Isolation Forest; not a trained attack classifier.

This screening is fit on the uploaded case itself. It ranks unusual *relative*
flow feature patterns. A capture dominated by attacks is not a valid benign
training set; interpretations always require evidence and independent labels.
"""
from __future__ import annotations
import math
from . import ml_features

FEATURES=['src_port','dst_port','duration_sec','packet_count','byte_count','flow_rate_pps',
          'byte_rate_bps','avg_packet_size','unique_dst_ports','tcp_syn_count','tcp_rst_count']
MIN_FLOWS=24


def screen(case_id):
    records=ml_features.flows_from_case(case_id)
    result={'method':'IsolationForest','kind':'unsupervised_per_case','flows':len(records),
       'min_flows':MIN_FLOWS,'status':'insufficient_data','anomalies':[],
       'disclaimer':'Relative statistical outlier screening only. Not a confirmed attack, trained supervised detector, or calibrated compromise probability.'}
    if len(records)<MIN_FLOWS:return result
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
    except ImportError:
        result['status']='dependency_unavailable';return result
    x=[]
    for row in records:
        vec=[math.log1p(max(0,float(row.get(key) or 0))) for key in FEATURES]
        vec.extend(float(row['protocol']==p) for p in ('TCP','UDP','ICMP','ARP'))
        x.append(vec)
    scaler=StandardScaler()
    scaled=scaler.fit_transform(x)
    model=IsolationForest(n_estimators=100,contamination=0.08,random_state=18,max_samples=min(len(records),256))
    marks=model.fit_predict(scaled)
    distances=model.decision_function(scaled)
    hits=[]
    for row,flag,dist in zip(records,marks,distances):
        if flag != -1:continue
        hits.append({'flow_id':row['flow_id'],'src_ip':row['src_ip'],'dst_ip':row['dst_ip'],
           'src_port':row['src_port'],'dst_port':row['dst_port'],'protocol':row['protocol'],
           'packet_count':row['packet_count'],'byte_count':row['byte_count'],
           'anomaly_score':round(float(-dist),5),'evidence_packet_ids':row['evidence_packet_ids'].split('|') if row['evidence_packet_ids'] else [],
           'explanation':'This flow differs statistically from other flows in the same uploaded case. Its cause is not established.'})
    hits.sort(key=lambda x:x['anomaly_score'],reverse=True)
    result['status']='ready';result['anomalies']=hits[:30];result['anomaly_count']=len(hits)
    return result
