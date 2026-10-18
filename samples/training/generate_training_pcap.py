"""Generate a self-contained synthetic PCAP for testing BLACKBOX's own heuristic detections.
No packets are transmitted; the bytes are constructed entirely offline.
No real attack or compromised host is represented.
"""
from __future__ import annotations
import datetime as dt
import hashlib
import itertools
import json
from pathlib import Path
import socket
import struct

OUT=Path(__file__).with_name('SYNTHETIC_multi_pattern_training.pcap')
START=int(dt.datetime(2026,10,17,15,0,tzinfo=dt.timezone.utc).timestamp())
SRC_MAC=bytes.fromhex('021122334455')
DST_MAC=bytes.fromhex('02aabbccddee')
records=[]
case_counts={}

def checksum(data):
    if len(data)%2:data+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while s>>16: s=(s&65535)+(s>>16)
    return (~s)&65535

def ip4(addr): return socket.inet_aton(addr)

def ethernet(payload,etype=0x800,srcmac=SRC_MAC,dstmac=DST_MAC):
    return dstmac+srcmac+struct.pack('!H',etype)+payload

def ipv4(src,dst,protocol,segment,ident=0):
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(segment),ident%65536,0,64,protocol,0,ip4(src),ip4(dst))
    header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
    return ethernet(header+segment)

def tcp(src,dst,sport,dport,flags,body=b'',seq=1234):
    header=struct.pack('!HHIIHHHH',sport,dport,seq,0, (5<<12)|flags,4096,0,0)
    pseudo=ip4(src)+ip4(dst)+struct.pack('!BBH',0,6,len(header)+len(body))
    header=header[:16]+struct.pack('!H',checksum(pseudo+header+body))+header[18:]
    return ipv4(src,dst,6,header+body,seq)

def udp(src,dst,sport,dport,body):
    length=8+len(body)
    header=struct.pack('!HHHH',sport,dport,length,0)
    pseudo=ip4(src)+ip4(dst)+struct.pack('!BBH',0,17,length)
    uc=checksum(pseudo+header+body)
    header=struct.pack('!HHHH',sport,dport,length,uc or 0xffff)
    return ipv4(src,dst,17,header+body,114)

def arp(srcip,mac,targetip='10.42.0.20'):
    macraw=bytes.fromhex(mac.replace(':',''))
    dst=b'\xff'*6
    pay=struct.pack('!HHBBH',1,0x800,6,4,2)+macraw+ip4(srcip)+dst+ip4(targetip)
    return ethernet(pay,0x0806,srcmac=macraw,dstmac=dst)

def dns_q(name,answer=False):
    q=b''.join(bytes([len(part)])+part.encode('ascii') for part in name.split('.'))+b'\x00'+struct.pack('!HH',1,1)
    return struct.pack('!HHHHHH',0x1234,0x8183 if answer else 0x0100,1,0,0,0)+q

def add(tag,dt_ms,packet):
    records.append((START+dt_ms/1000,packet,tag))
    case_counts[tag]=case_counts.get(tag,0)+1

# Two related anomaly signals: > 12 distinct ports + > 40 SYN packets in the same 2-minute bucket.
for k in range(55):
    add('TCP port sweep + SYN burst', k*135, tcp('10.42.0.14','10.42.0.20',41000+k,20+k,0x02,seq=4000+k))

# 40 resets as a separate pattern.
for k in range(42):
    add('TCP reset burst',12000+k*95,tcp('10.42.0.25','10.42.0.44',51000+k,443,0x04,seq=8000+k))

# High entropy DNS subdomain and failures (DNS tunnel-like pattern, not proven tunneling).
for k in range(20):
    prefix=hashlib.sha256(f'blackbox-educational-lab-{k}'.encode()).hexdigest()[:56]
    name=prefix+'.example.org'
    t=17500+k*100
    add('Long DNS query + NXDOMAIN',t,udp('10.42.0.22','10.42.0.53',53000+k,53,dns_q(name)))
    add('DNS NXDOMAIN response',t+45,udp('10.42.0.53','10.42.0.22',53,53000+k,dns_q(name,True)))

# ARP conflicting ownership (two senders claim identical IPv4 address).
for k in range(5):
    add('ARP identity conflict',23000+k*130,arp('10.42.0.1','02:12:34:56:78:01'))
    add('ARP identity conflict',23700+k*130,arp('10.42.0.1','02:12:34:56:78:99'))

# FTP port 21 attempts, flagged as legacy protocol - no credentials embedded.
for k in range(7):
    add('Legacy FTP service',28000+k*180,tcp('10.42.0.31','10.42.0.40',42000+k,21,0x18,body=b'NO-CREDENTIALS-IN-THIS-LAB\r\n',seq=8500+k))

# Public IP admin-service ports (no actual packets sent to this IP).
for k in range(7):
    add('Public admin port',32000+k*200,tcp('10.42.0.35','1.1.1.1',43000+k,445,0x02,seq=9500+k))

# Over 8 MiB in outbound UDP frame lengths. Not proof of exfiltration; just the rule threshold.
for k in range(7700):
    # Repeatable 1100-byte inert payload, not credentials or an exploit.
    body=(f'BLACKBOX-LAB-PACKET-{k:06d}---'.encode()*45)[:1100]
    add('Outbound traffic volume',36000+k*7,udp('10.42.0.60','1.1.1.1',40000+(k%1000),443,body))

records.sort(key=lambda row:row[0])
OUT.parent.mkdir(parents=True,exist_ok=True)
with OUT.open('wb') as f:
    f.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiii',2,4,0,0,65535,1))
    for stamp,frame,tag in records:
        sec=int(stamp); micros=int(round((stamp-sec)*1000000))
        f.write(struct.pack('<IIII',sec,micros,len(frame),len(frame)))
        f.write(frame)
meta={'filename':OUT.name,'sha256':hashlib.sha256(OUT.read_bytes()).hexdigest(),'frames':len(records),'bytes':OUT.stat().st_size,'frame_types':case_counts,'synthetic':True,'does_not_contact_any_device':True}
Path(__file__).with_name('training_manifest_generated.json').write_text(json.dumps(meta,indent=2))
print(json.dumps(meta,indent=2))
