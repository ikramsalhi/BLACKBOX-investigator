"""Explainable, conservative heuristic detectors with packet-level evidence references.

Findings are *indicators for human review*, not confirmation of an attack.
All rules are based only on actual packet metadata collected from the capture.
"""
from __future__ import annotations
from collections import defaultdict, Counter
from math import log2
import hashlib,json
from . import storage
from .parser import is_public_ip


def _entropy(s):
    if not s:return 0
    c=Counter(s.lower());n=len(s)
    return -sum((v/n)*log2(v/n) for v in c.values())


def recompute(case_id):
    scans=defaultdict(lambda: {'ports':set(),'ids':[],'start':None,'end':None})
    syns=defaultdict(lambda: {'n':0,'ids':[],'start':None,'end':None})
    resets=defaultdict(lambda: {'n':0,'ids':[],'start':None,'end':None})
    domains=defaultdict(lambda:{'n':0,'lens':[],'entropy':[],'ids':[],'start':None,'end':None})
    nx=defaultdict(lambda:{'requests':0,'failures':0,'ids':[],'start':None,'end':None})
    arps=defaultdict(lambda:defaultdict(list))
    protocols=defaultdict(lambda:{'n':0,'ids':[],'start':None,'end':None})
    large=defaultdict(lambda:{'bytes':0,'ids':[],'start':None,'end':None})
    risky=defaultdict(lambda:{'n':0,'ids':[],'start':None,'end':None})
    total=0
    with storage.connect() as db:
        rows=db.execute('''SELECT id,ts,src,dst,proto,src_port,dst_port,length,tcp_flags,
           dns_query,dns_rcode,dns_response,arp_ip,arp_mac FROM packets
           WHERE case_id=? ORDER BY ts,id''',(case_id,))
        for r in rows:
            total+=1
            t=r['ts']; src=r['src'];dst=r['dst'];proto=r['proto'];dp=r['dst_port'];sp=r['src_port']
            if not t: continue # no timestamp for some PCAPNG simple packet blocks
            bucket=int(t//120)
            def mark(d):
                if d['start'] is None:d['start']=t
                d['end']=t
                if len(d['ids'])<8:d['ids'].append(r['id'])
            if proto=='TCP':
                flags=r['tcp_flags']
                if 'S' in flags and 'A' not in flags:
                    a=syns[(src,dst,bucket)];a['n']+=1;mark(a)
                    if dp is not None:
                        a=scans[(src,dst,bucket)];a['ports'].add(dp);mark(a)
                if 'R' in flags:
                    a=resets[(src,dst,bucket)];a['n']+=1;mark(a)
            if r['dns_query']:
                q=r['dns_query'].lower().rstrip('.')
                if not r['dns_response']:
                    source=r['src'];a=nx[(source,bucket)];a['requests']+=1;mark(a)
                    left=q.split('.')
                    if len(left)>=3:
                        root='.'.join(left[-2:]);prefix='.'.join(left[:-2]);d=domains[(source,root,bucket)]
                        d['n']+=1;d['lens'].append(len(prefix));d['entropy'].append(_entropy(prefix));mark(d)
                elif r['dns_rcode']==3:
                    # response destination is query requester; label is only a heuristic correlation
                    a=nx[(dst,bucket)];a['failures']+=1;mark(a)
            if proto=='ARP' and r['arp_ip'] and r['arp_mac']:
                arps[r['arp_ip']][r['arp_mac']].append((r['id'],t))
            if proto=='TCP' and dp in (21,23,110,143):
                a=protocols[(src,dst,dp)];a['n']+=1;mark(a)
            if proto in ('TCP','UDP') and src and dst and not is_public_ip(src) and is_public_ip(dst):
                a=large[(src,dst)];a['bytes']+=r['length'];mark(a)
            if proto=='TCP' and dp in (3389,445) and is_public_ip(dst):
                a=risky[(src,dst,dp)];a['n']+=1;mark(a)
    results=[]
    def emit(rule,title,severity,confidence,summary,recommendation,indicators,aggregate):
        if not aggregate['ids']:return
        data={'case_id':case_id,'rule':rule,'title':title,'severity':severity,'confidence':confidence,
              'summary':summary,'recommendation':recommendation,'indicators':indicators,
              'evidence':aggregate['ids'],'first_seen':aggregate['start'],'last_seen':aggregate['end']}
        signature=case_id+'|'+rule+'|'+json.dumps(indicators,sort_keys=True)+'|'+str(aggregate['start'])
        data['id']=hashlib.sha256(signature.encode()).hexdigest()[:18]
        results.append(data)
    for (src,dst,bucket),a in scans.items():
        if len(a['ports'])>=12:
            emit('port-sweep',f'Possible port sweep: {src} → {dst}','high','medium',
                f'{len(a["ports"])} destination TCP ports had SYN attempts within a two-minute window. A scan is possible, but legitimate monitoring can look similar.',
                'Verify whether this host is an authorized scanner; inspect the referenced SYN packets and destination host logs.',
                {'source':src,'destination':dst,'distinct_ports':len(a['ports']),'window_seconds':120},a)
    for (src,dst,_),a in syns.items():
        if a['n']>=40:
            emit('syn-burst',f'SYN burst: {src} → {dst}','medium','medium',
                 f'{a["n"]} TCP SYN packets without ACK flag occurred within two minutes. This does not prove unsuccessful connections or a SYN flood.',
                 'Check connection handshake completion and compare with legitimate workload.',
                 {'source':src,'destination':dst,'syn_packets':a['n']},a)
    for (src,dst,_),a in resets.items():
        if a['n']>=35:
            emit('reset-burst',f'TCP reset burst: {src} → {dst}','medium','medium',
                 f'{a["n"]} TCP RST packets observed in two minutes; may reflect service or connection issues.',
                 'Correlate with service logs, firewall policy and recent changes.',
                 {'source':src,'destination':dst,'rst_packets':a['n']},a)
    for (src,root,_),a in domains.items():
        if a['n']>=10 and sum(a['lens'])/a['n']>=45 and sum(a['entropy'])/a['n']>=3.45:
            emit('dns-pattern',f'Long high-entropy DNS names: {src}','medium','low',
                 f'{a["n"]} queries under {root} had unusually long, diverse-looking prefixes. This can indicate tunneling or legitimate encoded tracking data.',
                 'Review queried domains with DNS server logs and check whether they match known business applications.',
                 {'source':src,'domain_suffix':root,'queries':a['n'],'avg_prefix_length':round(sum(a['lens'])/a['n'],1)},a)
    for (src,_),a in nx.items():
        if a['requests']>=15 and a['failures']>=12 and a['failures']/a['requests']>=.7:
            emit('dns-nxdomain',f'Frequent DNS failures: {src}','medium','low',
                f'{a["failures"]} observed NXDOMAIN responses against {a["requests"]} queries in a two-minute bucket. May indicate bad configuration or suspicious generation.',
                'Examine the failed domains, resolver visibility and host DNS configuration.',
                {'host':src,'queries':a['requests'],'nxdomain_responses':a['failures']},a)
    for ip,macs in arps.items():
        if len(macs)>=2:
            obs=[(mac,pairs[0][0],pairs[0][1]) for mac,pairs in macs.items()]
            a={'ids':[i for _,i,_ in obs[:8]],'start':min(t for _,_,t in obs),'end':max(t for _,_,t in obs)}
            emit('arp-conflict',f'Multiple MAC addresses for {ip}','medium','medium',
                 f'{ip} appeared with {len(macs)} different source MAC addresses in ARP frames. Could be spoofing, failover or legitimate reconfiguration.',
                 'Check switch ARP/MAC tables, HSRP/VRRP/failover and host ownership.',
                 {'ip':ip,'mac_addresses':list(macs)[:10]},a)
    for (src,dst,port),a in protocols.items():
        if a['n']>=3:
            emit('cleartext-service',f'Legacy cleartext service: {src} → {dst}:{port}','low','high',
                 f'{a["n"]} TCP packets targeted port {port}, commonly associated with a plaintext service. This does not establish whether credentials were sent.',
                 'Check if the service is used; prefer encrypted alternatives where possible.',
                 {'source':src,'destination':dst,'port':port,'packets':a['n']},a)
    for (src,dst),a in large.items():
        if a['bytes']>=8*1024*1024:
            emit('external-volume',f'Outbound volume: {src} → {dst}','medium','low',
                 f'{a["bytes"]:,} bytes of packet lengths observed from a non-public source to public destination. This is traffic volume, NOT verified exfiltration.',
                 'Verify business purpose, directionality, flow completeness and expected transfer sizes.',
                 {'source':src,'destination':dst,'observed_bytes':a['bytes']},a)
    for (src,dst,port),a in risky.items():
        if a['n']>=5:
            emit('remote-access-public',f'Admin service traffic to public IP: {dst}:{port}','medium','medium',
                 f'{a["n"]} TCP packets aimed at public IP {dst} on admin/file-sharing port {port}.',
                 'Confirm this service is expected and access is appropriately restricted.',
                 {'source':src,'destination':dst,'port':port,'packets':a['n']},a)
    storage.set_findings(case_id,results)
    return {'packet_count':total,'findings':len(results)}
