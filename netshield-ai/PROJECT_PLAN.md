# NetShield AI — Project Plan & Technical Report Reference

**Project title:** NetShield AI (branded in-app as "NETSEC AI — Commercial Building Security Analysis")
**Domain:** Data Privacy & Network Security — local network reconnaissance, traffic analysis, and privacy tooling
**Type:** Full-stack web application (FastAPI backend + React/Vite frontend)

---

## 1. Project Objective

NetShield AI is a defensive security and privacy auditing tool designed to let a user (student, admin, or security analyst) analyze the network they are on — from the same vantage point an attacker would have — and immediately get **actionable, explained** remediation steps. It targets a single physical LAN/Wi-Fi segment (e.g., a home network, lab, or one floor of a commercial building) rather than the wider internet, and everything it does is **passive analysis or self/local operations** (scanning, sniffing, spoofing your own adapter) — it does not attack, exploit, or modify any third-party system.

The project satisfies four core requirement areas (visible directly in the sidebar's "Security Operations" group and the backend's module boundaries):

1. **Network Discovery** — find every device on the local network.
2. **Packet Capture / Analysis** — Wireshark-style live traffic dissection.
3. **Privacy Lab (MAC Address Tool)** — expose and defeat MAC-based device tracking.
4. **Security Analysis (Port Scanner)** — find open ports, classify risk, generate firewall rules.

Plus two integrating features:

5. **Wi-Fi Security Scanner** — audits nearby access points' encryption posture, independent of the four above.
6. **Threat Analysis & AI Reports** — ties every module's output together into one graded, plain-English report (optionally AI-written), exportable as a PDF.

---

## 2. High-Level Architecture

```
┌─────────────────────────────┐        HTTP/JSON (axios)        ┌───────────────────────────────┐
│   Frontend (React + Vite)   │  <───────────────────────────>  │   Backend (FastAPI + Uvicorn)  │
│   http://localhost:5173     │                                  │   http://127.0.0.1:8000        │
└─────────────────────────────┘                                  └───────────────────────────────┘
                                                                              │
                          ┌───────────────────────────────────────────────────────────────────────┐
                          │  OS-level tools invoked as subprocesses / libraries:                    │
                          │   - nmap (via python-nmap)     -> device & port discovery                │
                          │   - scapy                      -> raw packet capture & dissection        │
                          │   - psutil                      -> adapter/interface enumeration          │
                          │   - nmcli / netsh / airport      -> Wi-Fi scanning (OS-specific)           │
                          │   - ip / PowerShell / ifconfig   -> MAC address spoofing (OS-specific)     │
                          │   - Groq LLM API (optional)      -> AI-written recommendations/summaries   │
                          └───────────────────────────────────────────────────────────────────────┘
```

**Design principle used throughout the backend:** every module that depends on OS-specific tooling (`wifi_scanner.py`, `mac_spoof.py`) detects the platform with `platform.system()` and dispatches to a Windows/Linux/macOS-specific implementation, so the same REST API behaves identically regardless of the host OS. Every AI-dependent module (`ai_summary.py`, `ai_firewall.py`) is optional-by-design: if no API key is configured, or the network call fails for any reason, the app **transparently falls back** to deterministic, offline template logic — the app is fully functional with zero internet access and zero API keys.

---

## 3. Technology Stack

| Layer | Technology | Purpose |
|---|---|---|
| Frontend framework | React 19 + Vite 8 | SPA UI, fast HMR dev server |
| HTTP client | axios | Frontend → backend REST calls |
| Styling | Plain CSS (`App.css`, `index.css`) | Dark "security console" themed UI, no CSS framework |
| Charts | Hand-authored inline SVG (`WifiCharts.jsx`, `NetworkTopology.jsx`) | Risk donut, band bar chart, star network topology map — no charting library dependency |
| Linting | oxlint | Frontend lint |
| Backend framework | FastAPI + Uvicorn | REST API server |
| Data validation | Pydantic `BaseModel` | Request body schemas (`ChangeMacRequest`, `ReportRequest`, etc.) |
| Network scanning | `python-nmap` (wraps the `nmap` binary) | Host discovery, port scanning, OS fingerprinting |
| Packet capture | `scapy` | Raw packet sniffing and protocol dissection |
| System info | `psutil` | Network adapter/interface enumeration |
| Wi-Fi scanning | OS-native CLI tools: `nmcli` (Linux), `netsh` (Windows), `airport` (macOS) | Nearby access point discovery |
| MAC spoofing | OS-native tools: `ip link` (Linux), PowerShell `Set-NetAdapterAdvancedProperty` (Windows), `ifconfig` (macOS) | Hardware address randomization |
| AI/LLM | Groq API (OpenAI-compatible, `llama-3.3-70b-versatile`) via `urllib` (no SDK dependency) | Optional AI-generated recommendations and report summaries |
| CORS | FastAPI `CORSMiddleware` | Allows the Vite dev server (`localhost:5173`) to call the API |

---

## 4. Project Structure

```
netshield-ai/
├── backend/
│   ├── main.py                # FastAPI app: all HTTP routes, network-range detection
│   ├── wifi_scanner.py        # Module 5: Wi-Fi AP scanning + risk classification + rogue AP detection
│   ├── mac_spoof.py           # Module 3: cross-platform MAC address get/set/restore
│   ├── packet_analyzer.py     # Module 2: Scapy packet dissection + traffic summarization
│   ├── security_analyzer.py   # Module 4: port risk/necessity classification, scoring, grading
│   ├── firewall_rules.py      # Module 4 helper: ufw/iptables/netsh command generation
│   ├── ai_firewall.py         # Optional: Groq-generated firewall commands & recommendations
│   ├── ai_summary.py          # Optional: Groq-generated plain-English report summary
│   ├── report_generator.py    # Module 6: aggregates all modules into metrics + summary
│   ├── requirements.txt       # Python dependencies
│   ├── .env.example           # Template for GROQ_API_KEY / GROQ_MODEL
│   └── .env                   # (git-ignored) actual secrets
└── frontend/
    ├── src/
    │   ├── main.jsx            # React entry point
    │   ├── App.jsx              # Page router (simple state-based, no react-router)
    │   ├── Sidebar.jsx          # Navigation + "Current Identity" (MAC) quick-action card
    │   ├── useNetShield.js      # Central hook: ALL shared state + API calls (no Redux/Context)
    │   ├── ErrorBoundary.jsx    # Per-page crash isolation
    │   ├── App.css / index.css  # Theming
    │   └── pages/
    │       ├── NetworkDiscoveryPage.jsx  # Module 1 UI
    │       ├── NetworkTopology.jsx       # Star-topology SVG map (used by Module 1)
    │       ├── PacketSnifferPage.jsx     # Module 2 UI
    │       ├── MacToolPage.jsx           # Module 3 UI
    │       ├── PortScannerPage.jsx       # Module 4 UI
    │       ├── WifiSecurityPage.jsx      # Module 5 UI
    │       ├── WifiCharts.jsx            # Risk donut + band bar SVG charts (used by Module 5)
    │       └── IntelligencePage.jsx      # Module 6 UI (Threat Analysis & AI Reports)
    ├── index.html
    ├── package.json
    └── vite.config.js
```

---

## 5. Module-by-Module Breakdown

### 5.1 Network Discovery
**Files:** `main.py` (`/scan`, `/host-scan`), `NetworkDiscoveryPage.jsx`, `NetworkTopology.jsx`

**Workflow:**
1. Backend auto-detects the machine's local IP by opening a UDP socket toward `8.8.8.8` (no packet actually sent, just used to learn the outbound interface — `_get_local_ip()`).
2. It cross-references `psutil.net_if_addrs()` to find that IP's real subnet mask, building a CIDR range (`_detect_network_range()`). Ranges wider than `/24` are automatically narrowed to a `/24` around the local IP, so the tool never attempts a multi-thousand-host sweep on large institutional Wi-Fi.
3. `GET /scan` runs an `nmap -sn -T4 --host-timeout 2s` ping sweep (`python-nmap`) across that range — a fast "who's alive" discovery scan, no ports touched yet.
4. Each responding host is returned with IP, hostname (reverse DNS if available), and status.
5. The frontend renders results two ways: a sortable table, and a hand-drawn SVG **star topology** (`NetworkTopology.jsx`) with this machine at the hub and each host as a spoke — clicking a node scrolls to/highlights its table row.
6. **Per-host deep scan** (`GET /host-scan?target=<ip>`) is triggered on demand per row (not automatically for all hosts, since OS fingerprinting is slow): runs `nmap -F -O --osscan-guess -sV` to get OS guesses (ranked by accuracy %), open TCP ports, and service/version banners.

**Key engineering decisions:**
- Scan range clamping for performance/safety on large networks.
- Fresh subnet detection on every call (not cached at startup) so switching Wi-Fi networks doesn't stale the scan.
- Deep host scan deliberately decoupled from the sweep to keep discovery fast.

### 5.2 Packet Capture / Analysis (Packet Sniffer)
**Files:** `main.py` (`/capture-live`), `packet_analyzer.py`, `PacketSnifferPage.jsx`

**Workflow:**
1. `GET /capture-live?timeout=&count=&bpf_filter=` uses Scapy's `sniff()` to capture live packets off the wire for N seconds (default 15) or until a packet count cap (default 200), optionally restricted by a Wireshark-style BPF filter (e.g. `"port 53"`, `"tcp port 80"`).
2. Every captured packet is passed through `packet_analyzer.dissect_packet()`, which identifies, layer by layer: ARP, IPv4/IPv6, ICMP (ping request/reply/other), DNS (query vs response, domain, record type, decoded answers), HTTP (method/host/path or status code), HTTPS/TLS (detected via TLS record header magic bytes on raw TCP payload), QUIC (UDP/443 heuristic — HTTP/3 traffic), and generic TCP/UDP with well-known port → service name mapping.
3. Each packet becomes a flat row: source/destination IP+MAC+port, protocol, byte length, a human-readable info string, a `LAN-local` flag (both endpoints inside the detected subnet, or IPv6 link-local), and a coarse activity label (**Browsing / Downloading / DNS Lookup / Ping / Other**) for device drill-down.
4. `packet_analyzer.summarize()` builds an aggregate: protocol counts, top 5 talkers, DNS query log, ICMP stats, **TCP 3-way handshake tracking** (SYN → SYN-ACK → ACK, reporting COMPLETE/IN PROGRESS/NO RESPONSE/INCOMPLETE per connection), a **port-scan detector** (flags any source IP that touched ≥15 distinct destination ports — the classic signature of an nmap-style scan happening *against* you), and a per-device breakdown (IP → MAC, packet count, activity mix).
5. Frontend renders a live-feed table (color-coded by protocol), protocol filter chips, per-device activity drill-down, a DNS query table, and a CSV export button.

**Key engineering decisions:**
- Wireshark-parity dissection rather than raw byte dumps — the point is readability for a report, not a raw pcap.
- A single malformed packet is caught and skipped, never aborting the whole capture.
- Port-scan and handshake detection are deliberately simple, explainable thresholds (not statistically tuned ML) — the report needs to justify *why* something was flagged.

### 5.3 Privacy Lab / MAC Address Tool
**Files:** `main.py` (`/network-adapter-info`, `/privacy-lab/change-mac`, `/privacy-lab/restore-mac`), `mac_spoof.py`, `MacToolPage.jsx`, `Sidebar.jsx` (Current Identity card)

**Workflow:**
1. `GET /network-adapter-info` lists every network interface via `psutil.net_if_addrs()`, extracting each one's hardware (MAC) address.
2. `POST /privacy-lab/change-mac {interface, new_mac?}` — if `new_mac` is omitted, a random, standards-correct **locally-administered, unicast** MAC is generated (`generate_random_mac()`: sets the locally-administered bit, clears the multicast bit, so it can never collide with a real vendor OUI). The change is dispatched per-OS:
   - **Linux:** `ip link set <iface> down` → `ip link set <iface> address <mac>` → `ip link set <iface> up`.
   - **Windows:** PowerShell `Set-NetAdapterAdvancedProperty -RegistryKeyword NetworkAddress` followed by a disable/enable cycle (the modern replacement for manual registry editing).
   - **macOS:** `ifconfig <iface> ether <mac>` (works on older macOS; newer versions increasingly block this for Wi-Fi — surfaced as an explained error, not a silent failure).
3. The original MAC is remembered **in backend process memory** (keyed by interface) so `POST /privacy-lab/restore-mac` can undo the change later — this works even for virtual interfaces with no OS-exposed "permanent" address. On Linux, if nothing was remembered (e.g. backend restarted), it falls back to reading the burned-in address via `ethtool -P` or `/sys/class/net/<iface>/address`.
4. The frontend shows a live adapter table, a change/restore log (session history), and a one-click **"Randomize MAC"** shortcut in the sidebar's persistent "Current Identity" card, visible from every page.

**Why this matters (privacy angle):** a MAC address is a static hardware identifier that persists across Wi-Fi networks and reboots — retailers, advertisers, and trackers use MAC-sniffing to fingerprint devices across visits. Randomizing it defeats that specific tracking vector.

### 5.4 Security Analysis / Port Scanner
**Files:** `main.py` (`/port-scan`, `/security-analysis`), `security_analyzer.py`, `firewall_rules.py`, `ai_firewall.py`, `PortScannerPage.jsx`

**Workflow:**
1. `GET /port-scan?target=<ip>` runs `nmap -F -sV -T4 --host-timeout 30s` (top-100 ports + version detection) and returns each open port with its service name and version banner.
2. `GET /security-analysis?target=<ip>` runs the same scan, then feeds it to `security_analyzer.analyze()`, which for every open port looks up a curated, offline `PORT_TABLE` covering 25+ well-known services (FTP, Telnet, SMTP, POP3, RPC, NetBIOS, IMAP, SNMP, LDAP, SMB, r-services, MSSQL, MySQL, RDP, PostgreSQL, VNC, Redis, MongoDB, HTTP, HTTPS, SSH, DNS, etc.) and classifies each finding along four axes:
   - **Risk:** HIGH / MEDIUM / LOW / INFO
   - **Insecure protocol flag:** plaintext/deprecated transport (e.g. FTP, Telnet, HTTP) vs encrypted (SSH, HTTPS)
   - **Necessity:** EXPECTED (normal, e.g. 22/53/80/443) / REVIEW (unusual, verify) / UNNECESSARY (insecure + high-risk → recommend closing)
   - **CVE hint:** curated, offline notes for notorious services (e.g. port 445 → EternalBlue/WannaCry, 3389 → BlueKeep, 6379 → unauthenticated Redis abuse)
3. For each finding, `firewall_rules.rules_for()` generates ready-to-paste commands in **three formats simultaneously** (ufw, iptables, netsh advfirewall) with either a `deny` (block entirely) or `restrict` (LAN-only) action depending on necessity, plus a plain-English explanation.
4. An overall **0–100 security score and A–F grade** is computed by deducting weighted penalties (HIGH −25, MEDIUM −10, LOW −3, each unnecessary port an extra −5).
5. **Optional AI upgrade:** if `GROQ_API_KEY` is configured, `ai_firewall.py` sends one batched request (not one call per finding) to Groq, grounded in the already-decided facts (port/service/risk/necessity are fixed and given to the model — it's only asked to *write* the recommendation sentence, the specific firewall command, and its explanation). The response is validated for full coverage of every finding before being trusted; any failure (no key, no internet, malformed reply) silently falls back to the deterministic template — the page never breaks or shows inconsistent data.
6. Frontend: target picker (pre-populated from Network Discovery's device list, plus localhost), a findings table with risk/necessity badges, expandable firewall-command panels per finding, and the overall grade.

### 5.5 Wi-Fi Security Scanner
**Files:** `main.py` (`/wifi-scan`), `wifi_scanner.py`, `WifiSecurityPage.jsx`, `WifiCharts.jsx`

**Workflow:**
1. `GET /wifi-scan` dispatches by OS:
   - **Linux:** `nmcli -t -f SSID,SIGNAL,SECURITY,CHAN,FREQ,BSSID dev wifi list` (terse, delimiter-based output; handles nmcli's `\:`-escaped colons inside BSSIDs).
   - **Windows:** `netsh wlan show networks mode=bssid`, parsed block-by-block (SSID → Authentication → per-BSSID Signal/Channel); frequency is approximated from channel number since netsh doesn't report it directly.
   - **macOS:** the bundled `airport -s` utility, column-parsed by header offset (handles SSIDs containing spaces).
   Each path normalizes into the same internal shape so downstream logic is OS-agnostic.
2. Each AP is classified by encryption strength (`_classify_security()`): **Open → HIGH risk, WEP → HIGH, WPA(1) → MEDIUM, WPA2 → LOW, WPA3 → INFO/best-practice.**
3. **Rogue / evil-twin AP detection** (`_detect_rogue_aps()`) — purely from data a normal scan already exposes, no extra privileges: flags any SSID broadcast by multiple BSSIDs where (a) security level is inconsistent (a weak clone next to the real network — classic downgrade attack), (b) BSSIDs come from different hardware vendors (OUI mismatch, skipping locally-administered/virtualized BSSIDs to avoid false positives on legitimate enterprise controllers), or (c) an unusually high BSSID count (3+) for one SSID.
4. Frontend renders a sortable AP table with risk badges, a **risk-distribution donut chart** and a **2.4/5/6GHz band bar chart** (both hand-authored inline SVG, no charting library), and a dedicated Rogue AP alert panel.

**Privacy design note (documented in the code itself):** this module is deliberately AP-level only — it never enumerates or tracks the individual client devices connected to a network, which the project treats as an explicit out-of-scope privacy violation for a *defensive* tool.

### 5.6 Threat Analysis & AI Reports (Intelligence / Reporting)
**Files:** `main.py` (`/generate-report`), `report_generator.py`, `ai_summary.py`, `IntelligencePage.jsx`

**Workflow:**
1. **"Run Full Assessment"** triggers, in sequence: a network scan, an adapter listing, and a security analysis against the selected target — independent of which pages the user has previously visited, always using freshly fetched data — then calls `POST /generate-report` with everything gathered (plus any packets already captured from the Packet Sniffer page, if run).
2. `report_generator.build_metrics()` extracts a countable-metrics table across all four modules (devices found, packet/protocol counts, adapters found, open ports / insecure protocols / unnecessary ports / risk counts / score / grade).
3. `report_generator.build_summary()` writes a deterministic, offline, plain-English paragraph **per section**, explaining not just the numbers but *what they mean and why they matter* to a non-technical reader (e.g., "a MAC address is a fixed hardware ID that networks and trackers can use to recognize your device everywhere it goes").
4. **Optional AI upgrade:** if `GROQ_API_KEY` is set, `ai_summary.py` sends the same metrics + template text to Groq and asks it to *rewrite* (not invent) the summary for clarity — grounded generation, explicitly instructed not to add numbers/findings not already in the data. Falls back to the template on any failure. The report always states its `summary_source` (`"groq"` or `"template"`) transparently.
5. Frontend renders the overall headline, per-section metrics + plain-English summary, the full findings/firewall-rules table, and a **"Download PDF"** button that builds a clean, self-contained, styled HTML document client-side and opens the browser print dialog (Save as PDF) — no server-side PDF library dependency.

---

## 6. Cross-Cutting Design Decisions

- **No database.** The app is stateless/session-based by design — a live auditing tool, not a historical record system. All "memory" (MAC restore state, scan results) lives in backend process RAM or frontend React state and resets on restart. This is a deliberate privacy choice: no persistent log of what was scanned/captured is kept on disk.
- **Cross-platform OS abstraction pattern.** Both `wifi_scanner.py` and `mac_spoof.py` follow the same shape: detect `platform.system()`, dispatch to a `_scan_windows()/_scan_linux()/_scan_macos()` (or `_windows_set_mac()/_linux_set_mac()/_macos_set_mac()`) function, and normalize results into one common return shape before any shared logic (risk classification, scoring) runs. This is what let the Windows `nmcli`-not-found bug get fixed without touching any of the classification/rogue-AP-detection code.
- **Graceful degradation everywhere.** Every module that depends on an external resource (OS tool, AI API, host response) is wrapped so failure returns a clear `{"error": "..."}` JSON payload the frontend already knows how to render, rather than a raw exception/500. AI features specifically are additive-only — the app's core functionality never depends on having an API key or internet access.
- **Deterministic-first, AI-as-upgrade.** All security-relevant judgments (risk level, necessity, insecure-protocol flag, CVE hints, score/grade) are hardcoded, reviewed, offline logic (`PORT_TABLE`, `SECURITY_RISK`) — never left to an LLM to decide. AI is only used for the "writing" layer (rephrasing a recommendation sentence, writing a friendlier report paragraph) on top of facts that are already fixed and given to the model as grounding, with strict response-shape validation before the AI output is trusted.
- **Explainability for a security-course context.** Detection thresholds (15+ distinct ports = port scan, 3+ BSSIDs = check your deployment) are deliberately simple, round numbers instead of statistically tuned/ML thresholds, so they can be explained and justified in a report or viva rather than treated as a black box.
- **Performance safety valves.** Subnet scans are clamped to `/24`; deep OS-fingerprint scans are opt-in per host; packet capture has both a timeout and a count cap — all to keep a live demo responsive on a student laptop.

---

## 7. API Reference (Backend Endpoints)

| Method | Path | Module | Purpose |
|---|---|---|---|
| GET | `/` | — | Health check |
| GET | `/scan` | Network Discovery | Ping-sweep the local subnet |
| GET | `/host-scan?target=` | Network Discovery | Deep per-host OS + port + service scan |
| GET | `/capture-live?timeout=&count=&bpf_filter=` | Packet Analysis | Live traffic capture + dissection |
| GET | `/network-adapter-info` | Privacy Lab | List adapters + MAC addresses |
| POST | `/privacy-lab/change-mac` | Privacy Lab | Randomize/set a MAC address |
| POST | `/privacy-lab/restore-mac` | Privacy Lab | Restore original MAC |
| GET | `/port-scan?target=` | Security Analysis | Fast top-100 port + version scan |
| GET | `/security-analysis?target=` | Security Analysis | Full risk/necessity/firewall-rule analysis |
| GET | `/wifi-scan` | Wi-Fi Security | Nearby AP scan + risk + rogue-AP detection |
| POST | `/generate-report` | Threat Analysis / Reports | Aggregate all module output into a report |

---

## 8. Setup & Run Instructions

**Backend** (Python 3.11+, requires `nmap` installed on the OS and admin/root privileges for OS-fingerprinting and MAC spoofing):
```
cd backend
pip install -r requirements.txt
cp .env.example .env        # optional: add GROQ_API_KEY for AI features
uvicorn main:app --reload --port 8000
```

**Frontend** (Node.js):
```
cd frontend
npm install
npm run dev                  # serves at http://localhost:5173
```

**OS prerequisites for full functionality:**
| OS | Requires |
|---|---|
| Linux | `nmap`, NetworkManager (`nmcli`), `ip` (iproute2), root for MAC spoofing/OS-detection |
| Windows | `nmap` installed, Wi-Fi Location services enabled (Settings > Privacy & security > Location), Administrator privileges for MAC spoofing and OS-detection scans |
| macOS | `nmap`, `airport` utility (or Location Services permission for Terminal), root for MAC spoofing (may be blocked on newer macOS) |

---

## 9. Suggested Report Section Mapping

For writing the formal project report, this plan maps directly onto typical report chapters:

- **Introduction / Problem Statement** → Section 1
- **System Architecture** → Section 2, Section 6
- **Technology Stack / Literature-adjacent tools used** → Section 3
- **Module Design (one subsection per module)** → Section 5.1–5.6
- **API Design** → Section 7
- **Implementation Challenges & Design Decisions** (great source of discussion/viva material) → Section 6
- **Installation / Deployment** → Section 8
- **Future Scope** (ideas not yet built, worth naming honestly): historical scan storage/trend charts, authenticated multi-user access, automated firewall rule application (currently deliberately manual/copy-paste for safety), mobile client, deeper macOS Wi-Fi scanning once Apple's CLI restrictions are worked around.
