from blackbox.parser import iter_frames,parse_frame
from samples.build_scenarios import scenarios

def test_dhcp_parse_is_optional_and_bounded():
    # Other UDP packets must not be mislabelled as DHCP.
    frames=list(iter_frames(str(scenarios()[2])))
    assert any(parse_frame(fr)['proto']=='UDP' for fr in frames)
    assert all(not parse_frame(fr)['note'].startswith('DHCP ') for fr in frames)


def test_dhcp_message_type_tolerates_truncation():
    from blackbox.parser import _parse_dhcp
    packet={'note':''}
    _parse_dhcp(b'abc',packet)
    assert packet['note']==''
    payload=bytearray(243)
    payload[236:240]=b'\x63\x82\x53\x63'
    payload[240:243]=bytes([53,1,5])
    _parse_dhcp(payload,packet)
    assert packet['note']=='DHCP ACK'


def test_dhcp_activity_is_a_read_only_agent_tool(tmp_path,monkeypatch):
    from blackbox import storage
    from blackbox.agent import run_tool
    monkeypatch.setattr(storage,'DATA',tmp_path)
    monkeypatch.setattr(storage,'CAPTURES',tmp_path/'captures')
    storage.init_db()
    case=storage.create_case('DHCP check')
    assert run_tool(case['id'],'dhcp_activity')==[]
