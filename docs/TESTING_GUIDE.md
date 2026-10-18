# BLACKBOX — Testing guide

**Start:** `start_windows.bat` → http://127.0.0.1:8765. Create a case per capture; upload one file in **Evidence Vault**, then read **Overview → Findings → Packet Explorer → Investigator → Report**. The original v1.4 purple/navy experience is preserved.

## Test captures to explore (public-safe package)

| Test | File or URL | What it demonstrates |
|---|---|---|
| Synthetic port sweep | `samples/demo_pcaps/SYNTHETIC_01_tcp_sweep.pcap` | Generated TCP connection pattern suitable for investigating a sweep-like lead. |
| Synthetic ARP conflict | `samples/demo_pcaps/SYNTHETIC_02_arp_conflict.pcap` | Generated conflicting ARP claims; compare possible explanations in BLACKBOX TRACE. |
| Synthetic DNS/DHCP | `samples/demo_pcaps/SYNTHETIC_03_dns_and_dhcp_ports.pcap` | Generated DNS and DHCP-port traffic; observe protocol metadata. |
| Synthetic multi-pattern stress | `samples/training/SYNTHETIC_multi_pattern_training.pcap` | 7,861 generated packet records and nine rule-based leads in release testing. |
| Independent public scan (download separately) | [Nmap and Wireshark Lab](https://github.com/Ryan-Sapone/Nmap-and-Wireshark-Lab/blob/main/SS%20Scan.pcapng) | Third-party sample, not redistributed here or verified for this release. |
| Independent public HTTP sample (download separately) | [Wireshark sample captures](https://wiki.wireshark.org/SampleCaptures) | Third-party reference, not redistributed here or verified for this release. |

**All bundled demo captures are synthetic.** The three earlier course/lab captures are intentionally **not distributed** in this GitHub-safe release because acquisition and redistribution permissions were not established. Do not describe synthetic detections as attacks observed on a live network.

## Fast video demonstration (2–4 minutes)

1. Explain: “BLACKBOX helps us investigate network captures and trace suspicious findings back to packet evidence.”
2. Open an empty case; upload the **synthetic multi-pattern** PCAP. Point out that the sample is intentionally generated for demonstration.
3. In **Findings**, select **Challenge this conclusion**. Compare both alternative explanations, follow a real packet reference (original frame and capture SHA-256), and export the TRACE report.
4. In **Network Map**, show observed connections; in **Investigator**, ask “What suspicious behavior is present, and what evidence supports it?”
5. Export a case report, and optionally switch to the synthetic DNS/DHCP sample.

For genuinely captured, independently documented public traffic, show tests 4 or 5 **after personally downloading and checking the PCAP and results**. Avoid claiming any alert proves an intrusion.

## Hands-on TRACE test (works without Cloud AI)

1. Open the **synthetic ARP conflict** demo or create a case and upload `samples/demo_pcaps/SYNTHETIC_02_arp_conflict.pcap`.
2. Open **Findings → Challenge this conclusion** for the ARP identity-conflict finding.
3. Compare **ARP identity spoofing** against **Failover or IP reassignment**; neither explanation is a verdict. The PCAP alone cannot establish ownership or authorization.
4. In the chronological packet list, click a packet and verify its original frame number, timestamp, source, capture filename and SHA-256. Open that same frame in Wireshark for full bytes.
5. Choose **Download TRACE report** or **Export JSON**. The output contains observed facts, both competing explanations, packet references, and limitations.
6. Switch to another case: a TRACE URL from the first case must return HTTP 404 rather than reveal another case's packets.

**TRACE's alternatives are rule-based explanatory templates, not actual AI model judgments.** No model has been trained to decide between them. Confirming an attack requires independent evidence.

## Technical acceptance checks

```bash
python -m pip install -r requirements.txt pytest
python -m pytest tests -q
```

The original v1.7 release had 45 passing Python tests. Re-run the suite and smoke tests locally after the public-safe demo-fixture substitution. The large synthetic stress capture produced nine heuristic findings in release testing. Results are for the current heuristic threshold rules, not ML training accuracy or a real-world false-positive study.

If a capture is unsupported, check its link-layer type and size. Encrypted traffic payloads are not decrypted, and not every Wireshark dissector is replicated. Inspect exact source frames in Wireshark when needed.
