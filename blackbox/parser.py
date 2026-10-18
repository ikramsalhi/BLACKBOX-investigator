"""Streaming PCAP/PCAPNG packet parsing. No payload or secrets are persisted.

Recognizes Ethernet, Linux cooked SLL/SLL2, raw IPv4/IPv6 and loopback PCAP
linktypes. Unsupported linktypes are counted and displayed, not guessed.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress
import socket
import struct
from typing import Iterator

class CaptureError(ValueError):
    pass

@dataclass
class Frame:
    number: int
    ts: float
    linktype: int
    recorded_len: int
    wire_len: int
    data: bytes


def _read_exact(stream, n):
    b=stream.read(n)
    if len(b)!=n: raise CaptureError('Truncated capture header or frame')
    return b


def iter_frames(path: str) -> Iterator[Frame]:
    with open(path, 'rb') as f:
        first=f.read(4)
        if first==b'\x0a\x0d\x0d\x0a':
            yield from _pcapng(f, first)
        elif first in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d'):
            yield from _pcap(f,first)
        else:
            raise CaptureError('Not a supported PCAP or PCAPNG file (invalid capture magic)')


def _pcap(f, magic):
    little=magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1')
    ns=magic in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d')
    e='<' if little else '>'
    rest=_read_exact(f,20)
    major,minor,_,_,snaplen,linktype=struct.unpack(e+'HHiIII',rest)
    if major!=2 or minor not in (2,3,4): raise CaptureError('Unsupported PCAP version')
    if snaplen > 128*1024*1024: raise CaptureError('Unreasonable capture snaplen')
    n=0
    while True:
        h=f.read(16)
        if not h: break
        if len(h)<16: raise CaptureError('Truncated PCAP packet record')
        sec,frac,inc,orig=struct.unpack(e+'IIII',h)
        if inc>16*1024*1024: raise CaptureError('Unreasonable captured frame size')
        data=_read_exact(f,inc)
        n+=1
        yield Frame(n, sec+frac/(1e9 if ns else 1e6),linktype&0xffff,inc,orig,data)


def _pcapng(f, first):
    n=0; pending=first; interfaces=[]; endian=None
    while True:
        typeb=pending or f.read(4)
        pending=b''
        if not typeb: break
        if len(typeb)<4: raise CaptureError('Truncated PCAPNG block type')
        lengthb=_read_exact(f,4)
        if typeb==b'\x0a\x0d\x0d\x0a':
            bom=_read_exact(f,4)
            if bom==b'\x4d\x3c\x2b\x1a': endian='<'
            elif bom==b'\x1a\x2b\x3c\x4d': endian='>'
            else: raise CaptureError('Invalid PCAPNG section byte order')
            size=struct.unpack(endian+'I',lengthb)[0]
            if size<28 or size>128*1024*1024 or size%4: raise CaptureError('Invalid section length')
            rest=_read_exact(f,size-12)
            if struct.unpack(endian+'I',rest[-4:])[0]!=size: raise CaptureError('PCAPNG section length mismatch')
            interfaces=[]
            continue
        if endian is None: raise CaptureError('PCAPNG missing section header')
        size=struct.unpack(endian+'I',lengthb)[0]
        if size<12 or size>128*1024*1024 or size%4: raise CaptureError('Invalid PCAPNG block length')
        block=_read_exact(f,size-8)
        if struct.unpack(endian+'I',block[-4:])[0]!=size: raise CaptureError('PCAPNG block length mismatch')
        body=block[:-4]; kind=struct.unpack(endian+'I',typeb)[0]
        if kind==1:
            if len(body)<8: raise CaptureError('Short interface description')
            linktype=struct.unpack_from(endian+'H',body)[0]
            resolution=1e-6; tsoffset=0
            offset=8
            while offset+4<=len(body):
                code,optlen=struct.unpack_from(endian+'HH',body,offset);offset+=4
                if code==0: break
                if offset+optlen>len(body): break
                val=body[offset:offset+optlen]
                if code==9 and len(val)==1:
                    resolution=(2.0 ** -(val[0]&127)) if (val[0]&128) else (10.0 ** -val[0])
                if code==14 and len(val)==8: tsoffset=struct.unpack(endian+'q',val)[0]
                offset+=(optlen+3)&~3
            interfaces.append((linktype,resolution,tsoffset))
        elif kind==6:  # Enhanced packet block
            if len(body)<20: raise CaptureError('Short enhanced packet block')
            interface,high,low,inc,orig=struct.unpack_from(endian+'IIIII',body)
            if interface>=len(interfaces): raise CaptureError('PCAPNG packet references missing interface')
            if inc>16*1024*1024 or 20+inc>len(body): raise CaptureError('Invalid enhanced frame length')
            link,res,offset=interfaces[interface]
            ts=((high<<32)|low)*res+offset
            n+=1
            yield Frame(n,ts,link,inc,orig,body[20:20+inc])
        elif kind==3:  # Simple packet, no timestamp
            if len(body)<4 or not interfaces: raise CaptureError('Invalid simple packet block')
            orig=struct.unpack_from(endian+'I',body)[0]
            data=body[4:4+min(orig,len(body)-4)]
            n+=1
            yield Frame(n,0.0,interfaces[0][0],len(data),orig,data)
        elif kind==2:  # Obsolete packet block
            if len(body)<20: continue
            interface,_,high,low,inc,orig=struct.unpack_from(endian+'HHIIII',body)
            if interface>=len(interfaces): continue
            if inc>16*1024*1024 or 20+inc>len(body): continue
            link,res,offset=interfaces[interface]
            n+=1
            yield Frame(n,((high<<32)|low)*res+offset,link,inc,orig,body[20:20+inc])


def _u16(b,p): return struct.unpack_from('!H',b,p)[0]

def _dns_name(buf,pos,depth=0):
    if depth>12: return '',pos
    parts=[]; origin=pos; jumped=False
    for _ in range(100):
        if pos>=len(buf): return '',origin
        ln=buf[pos]
        if ln==0:
            pos+=1;break
        if ln&0xc0==0xc0:
            if pos+1>=len(buf): return '',origin
            ptr=((ln&0x3f)<<8)|buf[pos+1]
            if ptr>=len(buf): return '',origin
            sub,_=_dns_name(buf,ptr,depth+1)
            if sub: parts.append(sub)
            pos+=2;jumped=True;break
        if ln&0xc0 or ln>63 or pos+1+ln>len(buf): return '',origin
        label=buf[pos+1:pos+1+ln].decode('ascii','replace')
        parts.append(label);pos+=1+ln
    name='.'.join(parts)
    return name[:253],pos


def _parse_dns(payload, p):
    if len(payload)<12: return
    flags=_u16(payload,2); qd=_u16(payload,4); an=_u16(payload,6)
    if qd>100 or an>100: return
    p['dns_rcode']=flags&0xf if flags&0x8000 else None
    p['dns_response']=bool(flags&0x8000)
    if qd:
        name,at=_dns_name(payload,12)
        if name and at+4<=len(payload):
            p['dns_query']=name
            p['dns_qtype']=_u16(payload,at)
            at+=4
            if p['dns_response']:
                answers=[]
                for _ in range(an):
                    _,at2=_dns_name(payload,at)
                    if at2+10>len(payload): break
                    typ,cl,ttl,rdlen=struct.unpack_from('!HHIH',payload,at2)
                    at=at2+10
                    if at+rdlen>len(payload): break
                    if typ==1 and rdlen==4: answers.append(socket.inet_ntop(socket.AF_INET,payload[at:at+4]))
                    elif typ==28 and rdlen==16: answers.append(socket.inet_ntop(socket.AF_INET6,payload[at:at+16]))
                    at+=rdlen
                p['dns_answers']=','.join(answers[:8])


def _parse_dhcp(payload,packet):
    """Decode DHCPv4 message type only; never store BOOTP vendor/payload data."""
    if len(payload)<240 or payload[236:240]!=b'\x63\x82\x53\x63':return
    kinds={1:'Discover',2:'Offer',3:'Request',4:'Decline',5:'ACK',6:'NAK',7:'Release',8:'Inform'}
    at=240
    while at<len(payload):
        option=payload[at];at+=1
        if option==255:break
        if option==0:continue
        if at>=len(payload):break
        length=payload[at];at+=1
        if at+length>len(payload):break
        if option==53 and length==1:
            packet['note']='DHCP '+kinds.get(payload[at],str(payload[at]))
            return
        at+=length


def _parse_tls(payload,p):
    if len(payload)<9 or payload[0]!=22 or payload[5]!=1: return
    # TLS handshake ClientHello, SNI is metadata only; encrypted traffic remains opaque.
    rec_len=_u16(payload,3)
    end=min(len(payload),5+rec_len)
    at=9
    if at+34>end: return
    at+=34
    if at>=end: return
    session=payload[at];at+=1+session
    if at+2>end: return
    cipher=_u16(payload,at);at+=2+cipher
    if at>=end: return
    comps=payload[at];at+=1+comps
    if at+2>end: return
    exts=_u16(payload,at);at+=2; stop=min(end,at+exts)
    while at+4<=stop:
        kind,elen=struct.unpack_from('!HH',payload,at);at+=4
        if at+elen>stop: break
        if kind==0 and elen>=5:
            d=at+2
            if d+3<=at+elen and payload[d]==0:
                slen=_u16(payload,d+1)
                if d+3+slen<=at+elen:
                    p['tls_sni']=payload[d+3:d+3+slen].decode('ascii','replace')[:253]
            return
        at+=elen


def parse_frame(frame:Frame)->dict:
    """Return sanitized packet metadata. Never returns application payload or credentials."""
    p=dict(no=frame.number,ts=frame.ts,linktype=frame.linktype,length=frame.wire_len,
           captured=frame.recorded_len,src='',dst='',proto='OTHER',src_port=None,dst_port=None,
           tcp_flags='',dns_query='',dns_qtype=None,dns_rcode=None,dns_response=False,dns_answers='',
           tls_sni='',http_host='',http_method='',arp_ip='',arp_mac='',note='')
    b=frame.data; eth=None
    if frame.linktype==1:
        if len(b)<14: p['note']='Truncated Ethernet';return p
        eth=_u16(b,12); pos=14
        for _ in range(2):
            if eth not in (0x8100,0x88a8,0x9100): break
            if pos+4>len(b): p['note']='Truncated VLAN';return p
            eth=_u16(b,pos+2);pos+=4
        if eth==0x0806:
            if len(b)>=pos+28:
                try:
                    p.update(proto='ARP',src=socket.inet_ntop(socket.AF_INET,b[pos+14:pos+18]),
                      dst=socket.inet_ntop(socket.AF_INET,b[pos+24:pos+28]),
                      arp_mac=':'.join(f'{x:02x}' for x in b[pos+8:pos+14]),
                      arp_ip=socket.inet_ntop(socket.AF_INET,b[pos+14:pos+18]),
                      note='ARP reply' if _u16(b,pos+6)==2 else 'ARP request')
                except (ValueError,OSError): pass
            return p
    elif frame.linktype==113:
        if len(b)<16: p['note']='Truncated Linux cooked';return p
        eth=_u16(b,14);pos=16
    elif frame.linktype==276:
        if len(b)<20: p['note']='Truncated Linux cooked v2';return p
        eth=_u16(b,0);pos=20
    elif frame.linktype==101: # raw IP
        pos=0;eth=0x86dd if len(b) and b[0]>>4==6 else 0x0800
    elif frame.linktype==0: # BSD loopback family may be endian-dependent
        if len(b)<4: return p
        fam=int.from_bytes(b[:4],'little');pos=4
        if fam not in (2,24,28,30): fam=int.from_bytes(b[:4],'big')
        eth=0x0800 if fam==2 else 0x86dd if fam in (24,28,30) else None
    else:
        p['note']=f'Unsupported link type {frame.linktype}'
        return p
    if eth==0x0800:
        if len(b)<pos+20: p['note']='Truncated IPv4';return p
        ipstart=pos;verihl=b[pos];ihl=(verihl&0x0f)*4
        if verihl>>4!=4 or ihl<20 or len(b)<pos+ihl: return p
        total=_u16(b,pos+2);proto=b[pos+9];frag=_u16(b,pos+6)
        p['src']=socket.inet_ntop(socket.AF_INET,b[pos+12:pos+16]);p['dst']=socket.inet_ntop(socket.AF_INET,b[pos+16:pos+20]); pos+=ihl
        if frag&0x1fff: p['proto']='IP-FRAGMENT';p['note']='Non-initial IPv4 fragment';return p
        end=min(len(b),ipstart+total) if total else len(b)
    elif eth==0x86dd:
        if len(b)<pos+40 or b[pos]>>4!=6: p['note']='Truncated IPv6';return p
        ipstart=pos;proto=b[pos+6];plen=_u16(b,pos+4)
        p['src']=socket.inet_ntop(socket.AF_INET6,b[pos+8:pos+24]);p['dst']=socket.inet_ntop(socket.AF_INET6,b[pos+24:pos+40]);pos+=40
        end=min(len(b),pos+plen)
        for _ in range(8):
            if proto not in (0,43,44,60,51):break
            if pos+2>end: return p
            nxt=b[pos]
            if proto==44:
                if pos+8>end:return p
                off=_u16(b,pos+2)
                if off&0xfff8: p['proto']='IP-FRAGMENT';p['note']='Non-initial IPv6 fragment';return p
                nbytes=8
            elif proto==51:nbytes=(b[pos+1]+2)*4
            else:nbytes=(b[pos+1]+1)*8
            if pos+nbytes>end:return p
            pos+=nbytes;proto=nxt
    else:
        p['note']='Non-IP Ethernet frame' if eth else 'Unknown frame'
        return p
    if proto==6:
        p['proto']='TCP'
        if pos+20>end:return p
        p['src_port']=_u16(b,pos);p['dst_port']=_u16(b,pos+2)
        hdr=(b[pos+12]>>4)*4
        if hdr<20 or pos+hdr>end:return p
        flags=b[pos+13]
        p['tcp_flags']=''.join(x for mask,x in [(0x02,'S'),(0x10,'A'),(0x01,'F'),(0x04,'R'),(0x08,'P'),(0x20,'U')] if flags&mask)
        app=b[pos+hdr:end]
        if p['src_port'] in (53,) or p['dst_port'] in (53,):
            if len(app)>=2: _parse_dns(app[2:],p)
        if p['src_port'] in (80,8080,8000) or p['dst_port'] in (80,8080,8000):
            first=app[:2048].split(b'\r\n')
            if first:
                words=first[0].split(b' ')
                if len(words)>=3 and words[0] in (b'GET',b'POST',b'PUT',b'HEAD',b'DELETE',b'PATCH'):
                    p['http_method']=words[0].decode('ascii','replace')
                    for line in first[1:]:
                        if line.lower().startswith(b'host:'):
                            p['http_host']=line[5:].strip().decode('ascii','replace')[:253];break
        if p['src_port']==443 or p['dst_port']==443: _parse_tls(app,p)
    elif proto==17:
        p['proto']='UDP'
        if pos+8>end:return p
        p['src_port']=_u16(b,pos);p['dst_port']=_u16(b,pos+2)
        data=b[pos+8:end]
        if p['src_port']==53 or p['dst_port']==53:_parse_dns(data,p)
        if {p['src_port'],p['dst_port']}=={67,68}:_parse_dhcp(data,p)
    elif proto in (1,58):
        p['proto']='ICMP' if proto==1 else 'ICMPv6'
        if pos+2<=end: p['note']=f'Type {b[pos]} code {b[pos+1]}'
    else:
        p['proto']=f'IP-{proto}'
    return p


def is_public_ip(addr):
    try: return ipaddress.ip_address(addr).is_global
    except ValueError: return False
