"""Generate synthetic captures for reproducible regression tests and THIRDUNI demos.
Addresses, attacks and results here are invented training scenarios, never real incidents.
"""
from pathlib import Path
import struct, socket
from samples.make_sample import tcp,udp,dns_query,build

ROOT=Path(__file__).resolve().parent
OUT=ROOT/'demo_pcaps'

def save(path,packets):
    path.parent.mkdir(exist_ok=True,parents=True)
    with path.open('wb') as f:
        f.write(b'\xd4\xc3\xb2\xa1'+struct.pack('<HHiiii',2,4,0,0,65535,1))
        for ts,frame in packets:
            f.write(struct.pack('<IIII',ts,0,len(frame),len(frame)))
            f.write(frame)
    return len(packets)

def arp_frame(source_ip,source_mac,target_ip='192.0.2.1'):
    mac=bytes.fromhex(source_mac.replace(':',''))
    dstmac=b'\xff'*6
    arp=struct.pack('!HHBBH',1,0x0800,6,4,2)+mac+socket.inet_aton(source_ip)+dstmac+socket.inet_aton(target_ip)
    return dstmac+mac+struct.pack('!H',0x0806)+arp

def scenarios():
    ts=1790001000
    p1=OUT/'SYNTHETIC_01_tcp_sweep.pcap'
    build(p1)
    p2=OUT/'SYNTHETIC_02_arp_conflict.pcap'
    save(p2,[(ts+i,arp_frame('192.0.2.10','02:11:22:33:44:55')) for i in range(4)]+
            [(ts+10+i,arp_frame('192.0.2.10','02:99:88:77:66:55')) for i in range(4)]+
            [(ts+24,arp_frame('192.0.2.20','02:11:22:33:44:20'))])
    p3=OUT/'SYNTHETIC_03_dns_and_dhcp_ports.pcap'
    rows=[]
    for i in range(18):
        name=f'nohost{i}.invalid.test'
        rows.append((ts+i*2,udp('192.0.2.15','192.0.2.53',50000+i,53,dns_query(name))))
        rows.append((ts+i*2+1,udp('192.0.2.53','192.0.2.15',53,50000+i,dns_query(name,rcode=3))))
    # UDP port 67/68 communications demonstrate DHCP port visibility, not deep DHCP packet decoding.
    rows += [(ts+50+i,udp('0.0.0.0','255.255.255.255',68,67,b'\x01\x01\x06\x00'+bytes(40))) for i in range(3)]
    save(p3,rows)
    return (p1,p2,p3)

if __name__=='__main__':
    for item in scenarios():print('SYNTHETIC TRAINING ONLY:',item)
