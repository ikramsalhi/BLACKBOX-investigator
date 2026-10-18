import struct,socket
import pytest
from blackbox.parser import iter_frames,parse_frame,CaptureError
from samples.make_sample import build


def test_pcap_and_heuristic_evidence(tmp_path):
    path=tmp_path/'sample.pcap';n=build(path)
    frames=list(iter_frames(str(path)));assert len(frames)==n
    parsed=[parse_frame(f) for f in frames]
    assert parsed[0]['src']=='10.0.0.12'
    assert parsed[0]['dst_port']==20
    assert parsed[0]['tcp_flags']=='S'
    assert any(p['dns_query']=='app0.example.org' for p in parsed)
    assert any(p['http_host']=='example.org' for p in parsed)
    assert all('password' not in str(p).lower() for p in parsed)


def test_invalid_capture(tmp_path):
    path=tmp_path/'bad.pcap';path.write_bytes(b'BOGUS')
    with pytest.raises(CaptureError):list(iter_frames(str(path)))


def to_pcapng(pcap_path,ng_path):
    # Minimal little-endian section, interface block and enhanced packet blocks
    frames=list(iter_frames(str(pcap_path)))
    def block(typ,payload):
        pad=(-len(payload))%4;length=12+len(payload)+pad
        return struct.pack('<II',typ,length)+payload+b'\0'*pad+struct.pack('<I',length)
    shb=block(0x0a0d0d0a,struct.pack('<IHHq',0x1a2b3c4d,1,0,-1))
    idb=block(1,struct.pack('<HHI',1,0,65535))
    with open(ng_path,'wb') as f:
        f.write(shb);f.write(idb)
        for fr in frames:
            stamp=int(fr.ts*1_000_000);f.write(block(6,struct.pack('<IIIII',0,stamp>>32,stamp&0xffffffff,len(fr.data),fr.wire_len)+fr.data))


def test_pcapng_import(tmp_path):
    p=tmp_path/'data.pcap';q=tmp_path/'data.pcapng';build(p);to_pcapng(p,q)
    a=list(iter_frames(str(p)));b=list(iter_frames(str(q)))
    assert len(a)==len(b)
    assert [x.data for x in a]==[x.data for x in b]
    assert abs(b[0].ts-a[0].ts)<.01


def test_truncated_pcap(tmp_path):
    p=tmp_path/'short.pcap';build(p)
    p.write_bytes(p.read_bytes()[:-6])
    with pytest.raises(CaptureError):list(iter_frames(str(p)))
