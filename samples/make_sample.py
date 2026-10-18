"""Generates a synthetic packet capture for integration testing.

Every address/pattern here is invented. Never present this as a real incident.
"""
from pathlib import Path
import struct,socket,random
BASE=Path(__file__).resolve().parent.parent

def ip(a):return socket.inet_aton(a)
def eth(payload,typ=0x0800):return bytes.fromhex('00 11 22 33 44 55 02 aa bb cc dd ee')+struct.pack('!H',typ)+payload

def ipv4(src,dst,protocol,payload):
    l=20+len(payload)
    return bytes([0x45,0])+struct.pack('!HHHBBH',l,123,0,64,protocol,0)+ip(src)+ip(dst)+payload

def tcp(src,dst,sport,dport,flags=2,payload=b''):
    segment=struct.pack('!HHIIHHHH',sport,dport,1000,0,(5<<12)|flags,4096,0,0)+payload
    return eth(ipv4(src,dst,6,segment))

def udp(src,dst,sport,dport,payload=b''):
    return eth(ipv4(src,dst,17,struct.pack('!HHHH',sport,dport,8+len(payload),0)+payload))

def dns_query(name,rcode=None):
    parts=name.split('.')
    q=b''.join(bytes([len(s)])+s.encode('ascii') for s in parts)+b'\0'+struct.pack('!HH',1,1)
    if rcode is None:return struct.pack('!HHHHHH',4321,0x0100,1,0,0,0)+q
    return struct.pack('!HHHHHH',4321,0x8180|rcode,1,0,0,0)+q

def build(path):
    packets=[];ts=1790000000
    for j in range(18):
        packets.append((ts+j, tcp('10.0.0.12','10.0.0.21',40000+j,20+j), 'SYN probe'))
    for j in range(7):
        packets.append((ts+25+j,udp('10.0.0.12','8.8.8.8',55000+j,53,dns_query(f'app{j}.example.org')),'DNS'))
    for j in range(5):
        packets.append((ts+36+j,tcp('10.0.0.31','10.0.0.40',45000+j,21,24),'FTP protocol'))
    packets.append((ts+42,tcp('10.0.0.12','93.184.215.14',51515,80,24,b'GET / HTTP/1.1\r\nHost: example.org\r\n\r\n'),'HTTP'))
    path.parent.mkdir(parents=True,exist_ok=True)
    with open(path,'wb') as f:
        f.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiii',2,4,0,0,65535,1))
        for timestamp,raw,desc in packets:
            f.write(struct.pack('<IIII',timestamp,0,len(raw),len(raw)));f.write(raw)
    return len(packets)

if __name__=='__main__':
    n=build(BASE/'static'/'sample-incident.pcap')
    print(f'Generated synthetic capture with {n} frames')
