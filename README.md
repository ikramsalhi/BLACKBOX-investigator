<div align="center">

# BLACKBOX
### Network Incident Investigator

**An alert tells you something looks suspicious. BLACKBOX helps you investigate why.**

**From raw packets to a story you can verify.**

[**🚀 Explore the live demo**](https://blackbox-investigator-production.up.railway.app/) · [**📄 Example investigation report**](docs/BLACKBOX_Example_Investigation_Report.pdf) · [**🎤 Thirduni pitch deck**](docs/BLACKBOX_Thirduni_8_Slides_SOLO.pdf)

![BLACKBOX black cube logo](static/blackbox-cube.png)

**PCAP / PCAPNG** · **Evidence-linked findings** · **BLACKBOX TRACE** · **Network visualization** · **Optional AI Copilot** · **PDF reports**

*Built as a solo project for Thirduni 2026 by Ikram Salhi — Master's student in Networks and Embedded Systems.*

</div>

---

## 🕵️ The problem

A security dashboard can raise an alert: **"Possible ARP spoofing."**

But an alert alone does not explain what happened. Which packets triggered it? When did the activity start? Could there be another explanation? What evidence can an analyst actually show?

**BLACKBOX is an evidence-first network investigation workspace.** Upload a packet capture, explore the observed traffic, inspect suspicious patterns, challenge a finding, and turn the investigation into a report.

Its purpose is not to replace a human analyst or declare every anomaly an attack. It is to make packet evidence **easier to investigate, explain, and question**.

## ✨ What makes BLACKBOX different?

**1. The alert is a starting point, not a verdict.** Rules flag possible activity such as a port sweep or inconsistent ARP identities. Findings are leads that need context.

**2. You can challenge the conclusion.** BLACKBOX TRACE presents competing explanations, missing context, and representative source-frame references, so the investigator can test a claim instead of accepting it.

**3. The explanations lead back to the capture.** Case metadata includes source files, SHA-256 hashes, timestamps, frame numbers, endpoints, and available protocol details.

**4. AI assists; evidence stays in control.** Three deterministic, read-only specialists organize traffic, threat and timeline evidence. An offline assistant works without an API key; optional configured Ollama or cloud AI can help explain case findings. A generated answer is not proof.

**5. The entire investigation can be revisited.** Save private cases, inspect packets, compare network relationships, replay recorded time windows, and export human-readable reports.

> **BLACKBOX principle:** Don't just trust the alert. Follow the evidence.

## 🚀 Try it in your browser

**Live application:** https://blackbox-investigator-production.up.railway.app/

On the welcome screen, choose:

| **Explore Demo** | **Private investigator** |
| --- | --- |
| No account needed | Account required |
| Synthetic PCAP investigation gallery | Your own authorized PCAP/PCAPNG files |
| Browse findings, TRACE, maps, replay and reports | Create cases, analyze, save and export private investigations |
| **Read-only** | Available when the hosted login and persistent storage are configured |

**Try this first (about 60 seconds):**

1. Click **Explore Demo** and select **DEMO B — ARP identity conflict (synthetic)**.
2. Open **Findings**. Notice the observed ARP inconsistency.
3. Click **Challenge this conclusion** to open **BLACKBOX TRACE**.
4. Compare the possible explanations and inspect the referenced packets.
5. Visit **Network Map** or **Report** to see the evidence in context.

The question is deliberately more interesting than "Did the tool show an alert?": **does conflicting ARP information mean spoofing, failover, or something else?** BLACKBOX makes that uncertainty visible.

*The demo traffic is generated for education. It does not document an actual intrusion. Hosted features depend on the current deployment configuration.*

## 🔎 Explore the investigation workspace

| Page / tool | What you can do |
| --- | --- |
| **Saved investigations** | Reopen previous cases and their retained evidence |
| **Overview** | View packet totals, observed hosts, protocol distribution, relationships, and event timeline |
| **Evidence Vault** | Import authorized PCAP/PCAPNG files, track SHA-256 provenance, download original captures when permitted, and export ML flow features |
| **Findings** | Review rule-based suspicious patterns and their supporting evidence |
| **BLACKBOX TRACE** | Challenge a finding with competing hypotheses, missing context, and representative packet references |
| **Packet Explorer** | Search and filter parsed packet metadata by protocol and inspect individual frames |
| **Network Map** | Explore **observed** communication relationships (not physical locations) |
| **Incident Replay** | Step through recorded traffic windows (not a reconstructed or proven attack chain) |
| **ML anomaly screening** | Use a local **unsupervised Isolation Forest** to highlight case-relative flow outliers |
| **Investigator** | Ask questions of deterministic evidence specialists, an offline assistant, or an optional configured language model |
| **Report** | Download an evidence-based PDF, Markdown or JSON; optionally request a labeled AI-enhanced PDF |

### A real example of the reasoning

**Observation:** several MAC addresses appear for one IP in a generated ARP capture.

**Possible interpretation A:** a device is attempting to impersonate another machine.

**Possible interpretation B:** failover, reconfiguration, or another legitimate network event produced the observation.

**What BLACKBOX can do:** show the rule that fired, the packet references, chronology, alternative hypotheses and investigative gaps.

**What BLACKBOX cannot know from that capture alone:** the operator's intent or whether the event was malicious. That requires additional context and independent verification.

## 🧠 How it works

~~~mermaid
flowchart TD
    A["PCAP / PCAPNG capture"] --> B["Bounded packet parsing + original file SHA-256"]
    B --> C["Packet records, directional flows, protocol metadata"]
    C --> D["Rule-based findings"]
    C --> E["Network map + timeline + packet explorer"]
    C --> F["Optional local ML: Isolation Forest"]
    D --> G["BLACKBOX TRACE: challenge the finding"]
    D --> H["Traffic / Threat / Timeline evidence specialists"]
    G --> I["Evidence-based investigation report"]
    H --> J["Offline assistant / optional LLM"]
    J --> I
    E --> I
~~~

**Under the hood:** Python, FastAPI, SQLite, JavaScript/CSS, PCAP parsing, scikit-learn's Isolation Forest and ReportLab PDF generation. The interface uses BLACKBOX's custom dark navy and violet design.

**Important ML distinction:** Isolation Forest is an **unsupervised outlier detector**, not a separately validated intrusion classifier. It needs at least **24 directional flows** in the selected case. Its outlier scores do **not** represent verified attacks or calibrated compromise probabilities. The exported CSV leaves ground-truth labels blank rather than inventing them. [Read the ML integration notes](docs/ML_INTEGRATION.md).

### AI without inventing evidence

The basic packet analysis, rules, TRACE and readable PDF report work **without a cloud AI key**. Cloud AI is optional and user-configured. When enabled, selected case metadata and the user's question may be sent to that provider; raw PCAP bytes are **not** sent to the LLM by this application. Treat model-generated explanations as hypotheses to review.

## 💻 Run BLACKBOX on Windows

1. Install [Python 3.10 or newer](https://www.python.org/downloads/) and enable **Add Python to PATH**.
2. Click **Code → Download ZIP** on this repository, then extract it.
3. Double-click **`start_windows.bat`** and keep its terminal window open.
4. Your browser opens **http://127.0.0.1:8765**.
5. Choose **Private investigator** or **Explore Demo**.

The launcher sets up the Python environment, initializes the **synthetic** demo gallery without deleting existing cases, and starts the local server. First-time private users can create their initial account **in the browser** (password: 16+ characters); returning users sign in there. On localhost, the server is restricted to the loopback interface.

**Prefer the command line?**

~~~bash
git clone https://github.com/ikramsalhi/BLACKBOX-investigator.git
cd BLACKBOX-investigator
# Windows: double-click start_windows.bat
~~~

For Linux/macOS, **`bash start_linux_mac.sh`** runs the original local workspace. Manual start: install **`requirements.txt`** and run **`python run.py`**. These legacy commands start the **anonymous `local` mode**, not the new login/demo welcome flow.

**Your data:** local case data and original captures live under **`%USERPROFILE%\.blackbox-investigator`** (Windows) or **`~/.blackbox-investigator`** (Linux/macOS), unless **`BLACKBOX_DATA_DIR`** overrides it. Previous anonymous cases are not automatically assigned to a newly created account. Back up the data directory before changing modes or deleting anything.

## 🧪 Test evidence and reproducibility

Bundled examples are **synthetic and distributable**, not real-world attack captures:

| Capture | Illustrates |
| --- | --- |
| **`SYNTHETIC_01_tcp_sweep.pcap`** | TCP sweep-like traffic |
| **`SYNTHETIC_02_arp_conflict.pcap`** | Conflicting ARP claims and competing interpretations |
| **`SYNTHETIC_03_dns_and_dhcp_ports.pcap`** | DNS/DHCP-port observations |
| **`samples/training/generate_training_pcap.py`** | Optional larger synthetic stress capture generator |

The capture files are in [`samples/demo_pcaps/`](samples/demo_pcaps/). The stress generator creates an additional fixture locally; it is not independently verified intrusion ground truth. No confidential classroom or third-party PCAPs are distributed in this repository.

Run the tests:

~~~bash
python -m pip install -r requirements.txt pytest
python -m pytest tests -q
~~~

See the [testing guide](docs/TESTING_GUIDE.md), the [ML feature contract](docs/ML_INTEGRATION.md), and an [example evidence-based PDF report](docs/BLACKBOX_Example_Investigation_Report.pdf).

## 🔐 Public demo vs private deployment

| Deployment mode | Intended use |
| --- | --- |
| **`local-hybrid`** | One-click Windows welcome screen: private account or read-only local demo |
| **`local`** | Legacy offline-first anonymous workspace |
| **`public-demo`** | Hosted read-only gallery; no private uploads or cloud AI calls |
| **`hybrid`** | Hosted public gallery plus signed-in private investigations |
| **`multi-user`** | Account-required hosted workspace |

For hosted private accounts, use HTTPS, configure **`BLACKBOX_DEPLOY_MODE=hybrid`**, set the allowed public host and bootstrap credentials as **private environment variables**, and attach a persistent volume at **`/var/lib/blackbox`**. Refer to [Railway setup](RAILWAY_AUTH_SETUP.md) for instructions.

**Security and privacy:** BLACKBOX is a research/educational prototype, **not a certified IDS, live traffic sensor, courtroom-ready forensic product, or independently audited production service**. Session controls and case permissions exist, but production use requires further security review, access-control testing, network hardening, backups, and privacy assessment. Upload only captures you are authorized to analyze; consider whether packet metadata contains personal or sensitive information. Never commit passwords, API keys, private captures, or local database files.

## 🎯 Why I built it

I study **Networks and Embedded Systems** and wanted to create something at the intersection of packet analysis, cybersecurity, and practical investigation. BLACKBOX grew from a question:

**What if a cybersecurity tool did more than flag traffic—what if it helped us understand, verify, and explain the evidence behind an alert?**

That is the idea behind BLACKBOX.

Created and integrated as a **solo Thirduni 2026 project by Ikram Salhi**, with AI-assisted development tools used during implementation. The detections, limitations, and reproducibility notes above describe what is actually implemented—not promises of a validated autonomous detection system.

**Have a capture and a question? Start with the evidence.**

<div align="center">

**BLACKBOX — Every packet has a story.**

[**Explore the demo ↗**](https://blackbox-investigator-production.up.railway.app/) · [**Read an example report ↗**](docs/BLACKBOX_Example_Investigation_Report.pdf)

</div>
