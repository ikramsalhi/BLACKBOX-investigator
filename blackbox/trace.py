"""BLACKBOX TRACE: auditable, read-only alternatives to heuristic findings.

No model-generated facts, attack verdicts or post-hoc ground truth are invented.
The source-of-truth is the case's finding and packet records; evidence is a
bounded *representative subset* selected by the rule engine, not all matches.
"""
from __future__ import annotations
from datetime import datetime, timezone
from . import storage

# Each hypothesis is a possible interpretation, not a classification. Follow-up
# checks require evidence that is typically *outside* the PCAP.
ALTERNATIVES = {
    'port-sweep': (
        ('Reconnaissance', 'A host could be enumerating reachable services.',
         'Check asset ownership, scan approval, firewall logs, and later sessions.'),
        ('Authorized scan or monitoring', 'A vulnerability assessment or administrator can contact many ports.',
         'Check change tickets, scanner inventories, and authorized scan windows.'),
    ),
    'syn-burst': (
        ('Connection pressure', 'Repeated SYN attempts could signal scanning or traffic flooding.',
         'Compare completed handshakes, destinations, and service response health.'),
        ('Legitimate retries or high demand', 'Busy or degraded applications may generate many SYNs.',
         'Correlate application load and network loss or retransmissions.'),
    ),
    'reset-burst': (
        ('Connection disruption', 'RST packets could be associated with interrupted traffic.',
         'Inspect bidirectional sessions, server health, and firewall actions.'),
        ('Normal application teardown', 'Clients or servers may reset connections by design.',
         'Check application logs, expected short-lived sessions, and deployment changes.'),
    ),
    'dns-pattern': (
        ('DNS tunneling candidate', 'Lengthy or diverse names can be consistent with data encoded into DNS.',
         'Inspect full queried names, domain ownership, and resolver logs.'),
        ('Encoded tracking or CDN use', 'Legitimate software may query long structured domain names.',
         'Compare the names with expected business services and DNS infrastructure.'),
    ),
    'dns-nxdomain': (
        ('Generated or suspicious domains', 'Many failed lookups can be consistent with automated domain generation.',
         'Inspect query sequences and investigate host process / resolver logs.'),
        ('Misconfigured application', 'An application or search suffix can repeatedly request invalid names.',
         'Check resolver configuration, search domains, and software updates.'),
    ),
    'arp-conflict': (
        ('ARP identity spoofing', 'More than one MAC claiming an IP can indicate misleading ARP messages.',
         'Inspect switch port and trusted ARP tables, and compare claims over time.'),
        ('Failover or IP reassignment', 'Multiple MACs can be expected during high availability changes.',
         'Review HSRP/VRRP, DHCP leases, failover events, and address ownership.'),
    ),
    'cleartext-service': (
        ('Insecure application session', 'An older service port may permit unencrypted authentication.',
         'Check the actual protocol/session and service configuration; a port alone cannot establish exposure.'),
        ('Port use without sensitive transfer', 'The traffic could be a health check or a service running on a conventional port.',
         'Confirm application identity, session contents if authorized, and whether credentials were transmitted.'),
    ),
    'external-volume': (
        ('Possible data exfiltration', 'Unexpected outbound volume can motivate a data-loss investigation.',
         'Verify destination ownership, transfer direction, contents, and authorized business purpose.'),
        ('Authorized large transfer', 'Backups, downloads, and software distribution can generate large flows.',
         'Review approved jobs, services, and transfer logs.'),
    ),
    'remote-access-public': (
        ('Unapproved remote administration', 'Externally directed admin traffic could reflect risky exposure.',
         'Validate the destination, access policy, users, and source process.'),
        ('Authorized remote access', 'An approved service may legitimately use a common administration port.',
         'Review approved destinations, VPN or jump-host requirements, and change tickets.'),
    ),
}


def build(case_id: str, finding_id: str) -> dict | None:
    finding = storage.get_finding(case_id, finding_id)
    if finding is None:
        return None
    packets = []
    for raw_id in finding['evidence'][:16]:
        try:
            row = storage.get_packet(case_id, int(raw_id))
        except (ValueError, TypeError):
            continue
        if row is None:
            continue
        packets.append({k: row[k] for k in (
            'id', 'frame_no', 'ts', 'src', 'dst', 'proto', 'src_port',
            'dst_port', 'length', 'tcp_flags', 'dns_query', 'arp_ip', 'arp_mac',
            'filename', 'sha256')})
    packets.sort(key=lambda p: (p['ts'] if p['ts'] else 0, p['id']))
    alternatives = ALTERNATIVES.get(finding['rule'], (
        ('Potential security concern', 'The rule pattern may indicate behavior worth investigating.',
         'Correlate with independent security logs and system context.'),
        ('Benign operational activity', 'Authorized software or operational changes can produce similar observations.',
         'Check change approvals, service inventories, and administrator intent.'),
    ))
    alt = [{'title': title, 'interpretation': interpretation, 'verify_with': check,
            'assessment': 'Not confirmed by the available PCAP metadata'}
           for title, interpretation, check in alternatives]
    sources = list({(p['filename'], p['sha256']) for p in packets})
    sources.sort()
    first = finding['first_seen']
    events = []
    for p in packets:
        event = {
            'packet_id': p['id'], 'frame_no': p['frame_no'], 'ts': p['ts'],
            'utc': datetime.fromtimestamp(p['ts'], timezone.utc).isoformat() if p['ts'] else 'Timestamp unavailable',
            'src': p['src'], 'dst': p['dst'], 'protocol': p['proto'],
            'src_port': p['src_port'], 'dst_port': p['dst_port'],
            'tcp_flags': p['tcp_flags'], 'capture': p['filename'], 'sha256': p['sha256'],
            'relative_seconds': round(p['ts'] - first, 3) if first and p['ts'] else None,
        }
        events.append(event)
    return {
        'finding_id': finding['id'], 'case_id': case_id, 'title': finding['title'],
        'rule': finding['rule'], 'severity': finding['severity'],
        'review_status': 'INVESTIGATION REQUIRED — NOT A CONFIRMED ATTACK',
        'observed': finding['summary'], 'indicators': finding['indicators'],
        'first_seen': finding['first_seen'], 'last_seen': finding['last_seen'],
        'alternatives': alt, 'recommended_check': finding['recommendation'],
        'representative_packets': events,
        'sources': [{'filename': filename, 'sha256': sha256} for filename, sha256 in sources],
        'limitations': [
            'A rule match is an investigation lead; this tool cannot establish an attacker\'s intent.',
            'Only up to 16 representative packet references saved by the rule are shown, not every matching packet.',
            'Missing traffic, encrypted payloads, host activity, and out-of-band evidence can alter the interpretation.',
            'Capture provenance and analyst authorization are not independently verified.',
            'Rule severity is a review priority and not a calibrated probability of compromise.',
        ],
        'ml_model_used': False,
        'llm_model_used': False,
        'explanation_engine': 'deterministic-evidence-trace',
    }


def to_markdown(trace: dict) -> str:
    # Guard Markdown control characters inside user-derived metadata.
    def plain(v):
        return str(v).replace('\\', '\\\\').replace('`', "'").replace('\n', ' ').replace('\r', ' ').replace('|', '/')
    lines = [f"# BLACKBOX TRACE — {plain(trace['title'])}", '',
             f"Finding: `{plain(trace['finding_id'])}` · Case: `{plain(trace['case_id'])}`", '',
             f"**Review status:** {trace['review_status']}", '',
             '## Verified observation', '', plain(trace['observed']), '',
             '## Indicators', '']
    for key, value in trace['indicators'].items():
        lines.append(f'- {plain(key)}: {plain(value)}')
    lines += ['', '## Competing interpretations — neither is confirmed', '']
    for h in trace['alternatives']:
        lines += [f"### {plain(h['title'])}", '',plain(h['interpretation']),
                  '', f"**Independent check:** {plain(h['verify_with'])}", '']
    lines += ['## Representative packet evidence', '',
              '| Packet ID | Original frame | UTC | Source → Destination | Protocol | Capture |',
              '|---|---|---|---|---|---|']
    for p in trace['representative_packets']:
        lines.append(f"| {p['packet_id']} | {p['frame_no']} | {plain(p['utc'])} | {plain(p['src'])} → {plain(p['dst'])} | {plain(p['protocol'])} | {plain(p['capture'])} |")
    lines += ['', '## Source-file identity', '']
    for src in trace['sources']:
        lines.append(f"- {plain(src['filename'])}: SHA-256 `{plain(src['sha256'])}`")
    lines += ['', '## Limitations', ''] + [f'- {plain(x)}' for x in trace['limitations']]
    lines += ['', 'This is a read-only analyst aid, not a forensic certification or an automated verdict.', '']
    return '\n'.join(lines)
