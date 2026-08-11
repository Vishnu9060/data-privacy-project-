"""
Report generation for ShopRadar.

Produces a structured report from the results of all four modules
(Network Discovery, Packet Analysis, Privacy Lab, Security Analysis):

  - per-section METRICS (counts the UI renders as a table), and
  - a detailed, plain-English ("layman") SUMMARY that explains, for each
    section, what was done and what the numbers mean — written so a
    non-technical reader can follow it.

The summary is generated from the real data using natural-language templates
(no LLM/API key required), so it is deterministic, offline, and always
available. If an ANTHROPIC_API_KEY is ever added, report_summary_ai() could
replace _template_summary(), but the template output is the default.
"""


def _plural(n: int, singular: str, plural: str | None = None) -> str:
    plural = plural or singular + "s"
    return f"{n} {singular if n == 1 else plural}"


def build_metrics(data: dict) -> dict:
    """Extract the countable metrics from each section for the report table."""
    devices = data.get("devices")
    packets = data.get("packets")
    packet_summary = data.get("packet_summary")
    adapters = data.get("adapters")
    security = data.get("security")

    metrics = {}

    # --- Network Discovery ---
    metrics["network_discovery"] = {
        "ran": devices is not None,
        "devices_found": len(devices) if devices else 0,
    }

    # --- Packet Analysis ---
    if packets is not None:
        proto_counts = {}
        if packet_summary and "protocol_counts" in packet_summary:
            proto_counts = packet_summary["protocol_counts"]
        else:
            for p in packets:
                proto_counts[p["protocol"]] = proto_counts.get(p["protocol"], 0) + 1
        metrics["packet_analysis"] = {
            "ran": True,
            "total_packets": len(packets),
            "protocol_counts": proto_counts,
            "dns_queries": len(packet_summary.get("dns_queries", [])) if packet_summary else 0,
        }
    else:
        metrics["packet_analysis"] = {"ran": False, "total_packets": 0, "protocol_counts": {}, "dns_queries": 0}

    # --- Privacy Lab ---
    metrics["privacy_lab"] = {
        "ran": adapters is not None,
        "adapters_found": len(adapters) if adapters else 0,
    }

    # --- Security Analysis ---
    if security is not None and "metrics" in security:
        m = security["metrics"]
        metrics["security_analysis"] = {
            "ran": True,
            "target": security.get("target", ""),
            "open_ports": m["open_ports"],
            "insecure_protocols": m["insecure_protocols"],
            "unnecessary_ports": m["unnecessary_ports"],
            "high": m["high"], "medium": m["medium"], "low": m["low"], "info": m["info"],
            "score": security.get("score"),
            "grade": security.get("grade"),
        }
    else:
        metrics["security_analysis"] = {"ran": False}

    return metrics


def _summary_network(m: dict) -> str:
    if not m["ran"]:
        return ("Network Discovery was not run. This section scans your local network to list "
                "every device (phones, laptops, IoT gadgets) currently connected, which is the "
                "first step in understanding what is on your network.")
    n = m["devices_found"]
    if n == 0:
        return ("The network scan completed but found no responding devices. This can happen if "
                "devices block ping/scan requests, or if the scan range did not match your network.")
    return (f"The network scan discovered {_plural(n, 'active device')} sharing your local network. "
            f"Each of these is a machine that can potentially see or be seen by the others. Knowing "
            f"exactly what is connected is important because an unexpected device could be an intruder, "
            f"and every device is a possible entry point that needs to be kept secure.")


def _summary_packets(m: dict) -> str:
    if not m["ran"]:
        return ("Packet Analysis was not run. This section captures live network traffic for a few "
                "seconds and sorts it by type (web, DNS lookups, pings, etc.), letting you see what "
                "your machine is actually talking to.")
    total = m["total_packets"]
    counts = m["protocol_counts"]
    if total == 0:
        return ("The capture ran but recorded no packets — the network was quiet during the capture "
                "window, or a filter excluded everything.")
    parts = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)
    top = ", ".join(f"{cnt} {proto}" for proto, cnt in parts[:4])
    https_like = counts.get("HTTPS", 0) + counts.get("HTTPS/TLS", 0)
    enc_note = ""
    if https_like and total:
        pct = round(100 * https_like / total)
        enc_note = (f" About {pct}% of the traffic was encrypted HTTPS/TLS, which is a good sign — "
                    f"it means most of your data was scrambled and unreadable to anyone snooping on the network.")
    dns_note = ""
    if m["dns_queries"]:
        dns_note = (f" The capture also saw {_plural(m['dns_queries'], 'DNS lookup')} — these are the "
                    f"'phone book' requests your device makes to translate website names into addresses.")
    return (f"The analyzer captured {_plural(total, 'packet')} of live traffic and grouped them by type "
            f"(the most common were: {top}).{enc_note}{dns_note} This shows, in real time, exactly who your "
            f"machine is communicating with and whether that communication is protected.")


def _summary_privacy(m: dict) -> str:
    if not m["ran"]:
        return ("The Privacy Lab was not run. This section shows your network adapters' MAC addresses — "
                "the permanent hardware IDs that can be used to track a device across networks — and lets "
                "you randomize (spoof) them to protect your privacy.")
    n = m["adapters_found"]
    return (f"The Privacy Lab listed {_plural(n, 'network adapter')} on this machine along with their MAC "
            f"addresses. A MAC address is a fixed hardware ID that networks and trackers can use to recognize "
            f"your device everywhere it goes, even if you change networks. Being able to see and randomize it "
            f"is a concrete way to reduce this kind of tracking.")


def _summary_security(m: dict) -> str:
    if not m["ran"]:
        return ("Security Analysis was not run. This section scans a target machine for open ports, flags "
                "insecure or unnecessary services, and recommends firewall rules and fixes.")
    op = m["open_ports"]
    target = m["target"] or "the target"
    if op == 0:
        return (f"The security scan of {target} found no open ports — an excellent result. With nothing "
                f"listening, there is very little for an attacker on the network to connect to.")
    grade = m.get("grade")
    score = m.get("score")
    sev = []
    if m["high"]:
        sev.append(f"{_plural(m['high'], 'high-risk issue')}")
    if m["medium"]:
        sev.append(f"{_plural(m['medium'], 'medium-risk issue')}")
    if m["low"]:
        sev.append(f"{_plural(m['low'], 'low-risk issue')}")
    sev_str = ", ".join(sev) if sev else "no significant risks"

    grade_note = ""
    if grade:
        grade_map = {
            "A": "which is a strong result",
            "B": "which is fairly good but has room to improve",
            "C": "which is mediocre and worth hardening",
            "D": "which is weak and should be addressed soon",
            "F": "which is poor and needs urgent attention",
        }
        grade_note = f" This earns an overall security grade of {grade} ({score}/100), {grade_map.get(grade, '')}."

    extra = []
    if m["insecure_protocols"]:
        extra.append(f"{_plural(m['insecure_protocols'], 'service')} using insecure/plaintext protocols "
                     f"(data sent in the clear, readable by anyone in between)")
    if m["unnecessary_ports"]:
        verb = "appears" if m["unnecessary_ports"] == 1 else "appear"
        extra.append(f"{_plural(m['unnecessary_ports'], 'port')} that {verb} unnecessary and should likely be closed")
    extra_str = ""
    if extra:
        extra_str = " In particular, the scan flagged " + " and ".join(extra) + "."

    return (f"The security scan of {target} found {_plural(op, 'open port')} (doors through which the machine "
            f"can be reached over the network), including {sev_str}.{extra_str}{grade_note} For each risky port, "
            f"the report below gives a plain recommendation and ready-to-use firewall commands to close or "
            f"restrict it.")


def build_summary(metrics: dict) -> dict:
    """Build the per-section layman summary and a short overall headline."""
    sections = {
        "network_discovery": _summary_network(metrics["network_discovery"]),
        "packet_analysis": _summary_packets(metrics["packet_analysis"]),
        "privacy_lab": _summary_privacy(metrics["privacy_lab"]),
        "security_analysis": _summary_security(metrics["security_analysis"]),
    }

    ran = [k for k, v in metrics.items() if v.get("ran")]
    if not ran:
        overall = ("No modules have been run yet. Run the sections above (Scan Network, Capture Traffic, "
                   "Privacy Lab, Security Analysis) and then generate the report to see a full assessment.")
    else:
        sec = metrics["security_analysis"]
        if sec.get("ran") and sec.get("grade"):
            overall = (f"This report covers {_plural(len(ran), 'completed check')}. The headline finding is a "
                       f"security grade of {sec['grade']} ({sec['score']}/100) for {sec.get('target', 'the scanned host')}, "
                       f"based on {_plural(sec['open_ports'], 'open port')}. Read each section below for a plain-English "
                       f"explanation and concrete steps to improve.")
        else:
            overall = (f"This report covers {_plural(len(ran), 'completed check')} across network discovery, live "
                       f"traffic, device privacy, and security. Each section below explains in plain terms what was "
                       f"found and what it means for your safety and privacy.")

    return {"overall": overall, "sections": sections}


def generate(data: dict) -> dict:
    """Top-level: turn raw section results into {metrics, summary}.

    Uses a real AI (Groq) summary when GROQ_API_KEY is configured; otherwise
    falls back to the deterministic template summary. `summary_source` tells
    the UI which was used ("groq" or "template").
    """
    metrics = build_metrics(data)
    summary = build_summary(metrics)
    summary_source = "template"

    # Lazy import so the backend still runs if the module is absent.
    try:
        import ai_summary
        ai = ai_summary.generate_ai_summary(metrics, summary)
        if ai is not None:
            summary = {"overall": ai["overall"], "sections": ai["sections"]}
            summary_source = "groq"
    except Exception:
        summary_source = "template"

    return {"metrics": metrics, "summary": summary, "summary_source": summary_source}
