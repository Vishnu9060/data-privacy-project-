"""
Wireshark-grade packet dissection using Scapy.

The project's Packet Capture requirement asks for the same per-protocol
analysis Wireshark shows — not just "TCP vs UDP", but DNS query names,
HTTP hosts/methods, HTTPS (TLS) detection, ICMP types, and the
well-known service behind each port.

This module takes raw Scapy packets and turns each one into a flat dict
describing it the way a Wireshark row would: source/destination IP+MAC with
ports, the highest-level protocol identified, a human-readable "info"
summary, whether it's LAN-local traffic, and a coarse "activity" label
(Browsing / Downloading / DNS Lookup / Ping / Other) for per-device
drill-down. It also builds an aggregate summary (protocol counts, top
talkers, DNS queries seen) so the frontend can render a Wireshark-style
overview.
"""

import ipaddress

from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse

# Well-known ports → service label, so the analyzer can name the application
# protocol the way Wireshark's "Protocol" column does.
WELL_KNOWN_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
}


def _service_for_port(sport: int, dport: int) -> str | None:
    """Return the well-known service name for a TCP/UDP conversation, if any.

    Prefers the destination port (the server side), then the source port.
    """
    if dport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[dport]
    if sport in WELL_KNOWN_PORTS:
        return WELL_KNOWN_PORTS[sport]
    return None


# DNS query type codes -> mnemonic, the way Wireshark's "Type" column shows
# them (A = IPv4 address, AAAA = IPv6 address, 65 = HTTPS/SVCB record, etc.)
DNS_QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY",
}


def _dissect_dns(pkt) -> tuple[str, str, dict]:
    """Return (protocol, info, extra) for a DNS packet.

    `extra` carries the structured fields (domain queried, query type, and
    whether this row is the query or the response) that a flat "info" string
    can't cleanly expose to the frontend's dedicated DNS Queries table.
    """
    dns = pkt[DNS]
    qname = "?"
    qtype_code = None
    if dns.qd is not None and hasattr(dns.qd, "qname"):
        qname = dns.qd.qname.decode(errors="replace").rstrip(".")
        qtype_code = getattr(dns.qd, "qtype", None)
    qtype = DNS_QTYPES.get(qtype_code, str(qtype_code) if qtype_code is not None else "?")

    if dns.qr == 0:  # query
        extra = {"dns_query": True, "dns_domain": qname, "dns_qtype": qtype}
        return "DNS", f"Standard query for {qname}", extra

    # response
    answers = []
    rr = dns.an
    count = 0
    while rr is not None and count < 5:
        if hasattr(rr, "rdata"):
            rdata = rr.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode(errors="replace")
            answers.append(str(rdata))
        rr = rr.payload if rr.payload and rr.payload.name == "DNS Resource Record" else None
        count += 1
    answer_str = ", ".join(answers) if answers else "no records"
    extra = {"dns_query": False, "dns_domain": qname, "dns_qtype": qtype}
    return "DNS", f"Standard query response for {qname}: {answer_str}", extra


def _dissect_http_request(pkt) -> tuple[str, str]:
    http = pkt[HTTPRequest]
    method = http.Method.decode(errors="replace") if http.Method else "?"
    host = http.Host.decode(errors="replace") if http.Host else ""
    path = http.Path.decode(errors="replace") if http.Path else "/"
    return "HTTP", f"{method} {host}{path}"


def _dissect_http_response(pkt) -> tuple[str, str]:
    http = pkt[HTTPResponse]
    status = http.Status_Code.decode(errors="replace") if http.Status_Code else "?"
    reason = http.Reason_Phrase.decode(errors="replace") if http.Reason_Phrase else ""
    return "HTTP", f"Response {status} {reason}".strip()


def _looks_like_tls(payload: bytes) -> bool:
    """Detect a TLS record header (used by HTTPS) in raw TCP payload.

    TLS records start with a content type byte (0x14-0x17) followed by a
    version of 0x03 0x0X. 0x16 = Handshake, which is what a ClientHello is.
    """
    if len(payload) < 3:
        return False
    return payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03


def _classify_activity(protocol: str, info: str, sport, dport) -> str:
    """Coarse, human activity label for per-device drill-down.

    Maps a dissected packet onto one of the activities the lab asks students
    to capture and recognize: Browsing, Downloading, DNS Lookup, Ping, or
    Other (background/unclassified traffic e.g. ACKs, app-specific ports).
    """
    if protocol == "DNS":
        return "DNS Lookup"
    if protocol == "ICMP":
        return "Ping"
    if protocol == "HTTP":
        if info.startswith("GET") or info.startswith("Response"):
            return "Browsing"
        return "Browsing"
    if protocol in ("HTTPS", "HTTPS/TLS", "QUIC"):
        return "Browsing"
    if protocol == "FTP" or protocol == "FTP-DATA":
        return "Downloading"
    return "Other"


def dissect_packet(pkt, local_network: "ipaddress.IPv4Network | None" = None) -> dict | None:
    """Turn one Scapy packet into a Wireshark-style row dict.

    `local_network` (an ipaddress.IPv4Network for the machine's own subnet)
    is used to flag whether a packet is LAN-local (both endpoints inside the
    subnet, e.g. you <-> a teammate's laptop) vs internet-bound.

    Returns None for packets we don't surface (e.g. link-layer noise with
    no IP/ARP layer).
    """
    length = len(pkt)
    timestamp = float(pkt.time) if hasattr(pkt, "time") else None

    # Ethernet MACs, when captured on a wired/Wi-Fi interface that exposes
    # the link layer. For internet-bound traffic, dst_mac is the LAN
    # gateway/router's MAC (Ethernet only ever carries the *next hop*'s
    # address) — expected behavior, not a bug, and is only a "real" peer MAC
    # for LAN-local traffic.
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None

    def is_lan_ip(addr: str) -> bool:
        try:
            parsed = ipaddress.ip_address(addr)
        except ValueError:
            return False
        # IPv6 link-local (fe80::/10) is never routable past the local
        # network by definition — it's LAN-local regardless of the IPv4
        # subnet we detected. This matters because most modern OSes prefer
        # IPv6 link-local for LAN traffic, so without this rule nearly all
        # same-network packets were wrongly excluded by "LAN Only".
        if parsed.is_link_local:
            return True
        # Otherwise fall back to "is this address inside our detected IPv4
        # subnet" — only meaningful for IPv4 addresses since local_network
        # is always an IPv4Network (see main._detect_network_range).
        if local_network is None:
            return False
        if parsed.version != local_network.version:
            return False
        return parsed in local_network

    # ARP — link layer, no IP, but worth showing (Wireshark does). Always
    # LAN-local by nature (ARP never crosses a router).
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        return {
            "source": arp.psrc,
            "destination": arp.pdst,
            "src_ip": arp.psrc,
            "dst_ip": arp.pdst,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": "ARP",
            "length": length,
            "info": f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}",
            "is_lan": True,
            "activity": "Other",
            "timestamp": timestamp,
            "src_port": None,
            "dst_port": None,
        }

    # Must have an IPv4 or IPv6 layer beyond here.
    if pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src, dst = ip_layer.src, ip_layer.dst
    elif pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        src, dst = ip_layer.src, ip_layer.dst
    else:
        return None

    is_lan = is_lan_ip(src) and is_lan_ip(dst)

    def row(protocol, info, sport=None, dport=None, extra=None):
        # src_ip/dst_ip keep the bare address (no port) so aggregation stays
        # correct for IPv6, whose addresses themselves contain colons.
        source = f"{src}:{sport}" if sport is not None else src
        destination = f"{dst}:{dport}" if dport is not None else dst
        result = {
            "source": source,
            "destination": destination,
            "src_ip": src,
            "dst_ip": dst,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "protocol": protocol,
            "length": length,
            "info": info,
            "is_lan": is_lan,
            "activity": _classify_activity(protocol, info, sport, dport),
            "timestamp": timestamp,
            "src_port": sport,
            "dst_port": dport,
        }
        if extra:
            result.update(extra)
        return result

    # ICMP (ping, unreachable, etc.) — split into the subtypes the ICMP
    # Statistics panel needs: echo request (a ping going out), echo reply
    # (the response), and everything else (unreachable, TTL exceeded, etc.).
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_types = {0: "Echo (ping) reply", 8: "Echo (ping) request", 3: "Destination unreachable", 11: "Time exceeded"}
        if icmp.type == 8:
            icmp_kind = "echo_request"
        elif icmp.type == 0:
            icmp_kind = "echo_reply"
        else:
            icmp_kind = "other"
        return row("ICMP", icmp_types.get(icmp.type, f"Type {icmp.type}"), extra={"icmp_kind": icmp_kind})

    # DNS can ride on UDP or TCP; check it before generic UDP/TCP handling.
    if pkt.haslayer(DNS):
        protocol, info, dns_extra = _dissect_dns(pkt)
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0
        # A query goes to the resolver (dst is the DNS server); a response
        # comes from it (src is the DNS server) — surface that server IP
        # either way, for the "DNS Server" column.
        dns_extra["dns_server"] = dst if dns_extra.get("dns_query") else src
        return row(protocol, info, sport, dport, extra=dns_extra)

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        sport, dport = tcp.sport, tcp.dport

        if pkt.haslayer(HTTPRequest):
            protocol, info = _dissect_http_request(pkt)
        elif pkt.haslayer(HTTPResponse):
            protocol, info = _dissect_http_response(pkt)
        elif pkt.haslayer(Raw) and _looks_like_tls(bytes(pkt[Raw].load)):
            protocol = "HTTPS/TLS"
            info = "Encrypted TLS record"
        else:
            service = _service_for_port(sport, dport)
            protocol = service or "TCP"
            flags = tcp.sprintf("%TCP.flags%")
            info = f"{sport} → {dport} [{flags}]"

        result = row(protocol, info, sport, dport)
        # TCP handshake step, for the "TCP handshake" column/filter: a
        # connection's opening SYN, the server's SYN-ACK, or the client's
        # final ACK completing the 3-way handshake.
        flags = tcp.sprintf("%TCP.flags%")
        if flags == "S":
            result["handshake_step"] = "SYN"
        elif flags == "SA":
            result["handshake_step"] = "SYN-ACK"
        elif flags == "A" and tcp.ack and not tcp.payload:
            result["handshake_step"] = "ACK"
        else:
            result["handshake_step"] = None
        return result

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        sport, dport = udp.sport, udp.dport
        udp_len = udp.len if udp.len is not None else len(udp)
        # QUIC (RFC 9000) is UDP/443 by convention — the transport behind
        # HTTP/3, now the default for Chrome/YouTube/most Google traffic.
        # Without this check it silently falls into the generic UDP bucket,
        # hiding what is often the largest single slice of browsing traffic.
        if sport == 443 or dport == 443:
            return row("QUIC", f"{sport} → {dport} Len={udp_len}", sport, dport)
        service = _service_for_port(sport, dport)
        protocol = service or "UDP"
        return row(protocol, f"{sport} → {dport} Len={udp_len}", sport, dport)

    # IP packet we didn't specifically classify.
    return row("IP", "Other IP packet")


def summarize(rows: list[dict]) -> dict:
    """Build a Wireshark-style aggregate overview from dissected rows.

    Includes a per-device breakdown (keyed by IP, with its MAC and an
    activity-type count) so the frontend can offer "select a device, see
    what it was doing" drill-down without a second backend call.
    """
    protocol_counts: dict[str, int] = {}
    talkers: dict[str, int] = {}
    dns_queries: list[str] = []
    dns_query_log: list[dict] = []
    total_bytes = 0
    lan_packets = 0
    icmp_stats = {"echo_request": 0, "echo_reply": 0, "other": 0}

    # (client_ip, server_ip, port) -> {"syn": bool, "syn_ack": bool, "ack": bool}
    # Tracks each TCP connection attempt's 3-way handshake progress so we can
    # report which ones actually completed vs stalled/were reset.
    handshakes: dict[tuple, dict] = {}

    # source_ip -> set of distinct destination ports it contacted this
    # window — the basis for port-scan detection below. A normal browsing
    # session touches a handful of ports (80/443/53); an nmap-style scan
    # touches dozens to thousands in seconds.
    dest_ports_by_source: dict[str, set] = {}

    # device_ip -> {"mac": str|None, "activity": {label: count}, "packets": int}
    devices: dict[str, dict] = {}

    def touch_device(ip, mac, activity):
        dev = devices.setdefault(ip, {"mac": mac, "activity": {}, "packets": 0})
        if mac and not dev["mac"]:
            dev["mac"] = mac
        dev["packets"] += 1
        dev["activity"][activity] = dev["activity"].get(activity, 0) + 1

    for row in rows:
        proto = row["protocol"]
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        total_bytes += row["length"]
        if row.get("is_lan"):
            lan_packets += 1

        # Top talkers keyed by bare IP (src_ip is port-free and IPv6-safe).
        src_ip = row.get("src_ip", row["source"])
        talkers[src_ip] = talkers.get(src_ip, 0) + 1

        if proto == "DNS" and row["info"].startswith("Standard query for "):
            dns_queries.append(row["info"].replace("Standard query for ", ""))

        # Structured DNS query log — only queries (not responses), so each
        # lookup a device made appears once with the domain it asked for.
        if proto == "DNS" and row.get("dns_query"):
            dns_query_log.append({
                "time": row.get("timestamp"),
                "domain": row.get("dns_domain", "?"),
                "type": row.get("dns_qtype", "?"),
                "source": row.get("src_ip"),
                "dns_server": row.get("dns_server"),
            })

        if proto == "ICMP":
            kind = row.get("icmp_kind", "other")
            icmp_stats[kind] = icmp_stats.get(kind, 0) + 1

        # TCP handshake tracking: SYN opens an attempt keyed by
        # (client, server, port); SYN-ACK and the closing ACK update the
        # same entry so we can report which handshakes fully completed.
        step = row.get("handshake_step")
        if step and row.get("dst_port") is not None:
            if step == "SYN":
                key = (row["src_ip"], row["dst_ip"], row["dst_port"])
                handshakes[key] = handshakes.setdefault(key, {"syn": False, "syn_ack": False, "ack": False})
                handshakes[key]["syn"] = True
            elif step == "SYN-ACK":
                # SYN-ACK travels server -> client, so the connection's
                # client/server/port key uses the *destination* as client.
                key = (row["dst_ip"], row["src_ip"], row["src_port"])
                handshakes[key] = handshakes.setdefault(key, {"syn": False, "syn_ack": False, "ack": False})
                handshakes[key]["syn_ack"] = True
            elif step == "ACK":
                key = (row["src_ip"], row["dst_ip"], row["dst_port"])
                if key in handshakes:
                    handshakes[key]["ack"] = True

        activity = row.get("activity", "Other")
        dst_ip = row.get("dst_ip")
        touch_device(src_ip, row.get("src_mac"), activity)
        if dst_ip:
            touch_device(dst_ip, row.get("dst_mac"), activity)

        # Port-scan tracking: record every distinct destination port a
        # source IP contacted this window, TCP or UDP alike (both SYN scans
        # and UDP scans present the same way — one source, many ports).
        dst_port = row.get("dst_port")
        if dst_port is not None:
            dest_ports_by_source.setdefault(src_ip, set()).add(dst_port)

    top_talkers = sorted(talkers.items(), key=lambda kv: kv[1], reverse=True)[:5]

    # Flag any source that touched an unusually large number of distinct
    # destination ports — the classic signature of an nmap-style port scan.
    # Normal browsing/app traffic rarely exceeds a handful of ports; this
    # threshold is deliberately simple and explainable rather than
    # statistically tuned, which matters for a course demo where you need
    # to justify *why* something was flagged.
    PORT_SCAN_THRESHOLD = 15
    port_scan_alerts = [
        {"source": ip, "distinct_ports": len(ports), "sample_ports": sorted(ports)[:20]}
        for ip, ports in dest_ports_by_source.items()
        if len(ports) >= PORT_SCAN_THRESHOLD
    ]
    port_scan_alerts.sort(key=lambda a: a["distinct_ports"], reverse=True)

    tcp_handshake_list = [
        {
            "client": key[0], "server": key[1], "port": key[2],
            "status": "COMPLETE" if state["syn"] and state["syn_ack"] and state["ack"]
                      else "IN PROGRESS" if state["syn"] and state["syn_ack"]
                      else "NO RESPONSE" if state["syn"]
                      else "INCOMPLETE",
        }
        for key, state in handshakes.items()
    ][:20]

    device_list = [
        {"ip": ip, "mac": d["mac"], "packets": d["packets"], "activity": d["activity"]}
        for ip, d in sorted(devices.items(), key=lambda kv: kv[1]["packets"], reverse=True)
    ]

    return {
        "total_packets": len(rows),
        "total_bytes": total_bytes,
        "lan_packets": lan_packets,
        "protocol_counts": protocol_counts,
        "top_talkers": [{"ip": ip, "packets": count} for ip, count in top_talkers],
        "dns_queries": dns_queries[:20],
        "dns_query_log": dns_query_log[:30],
        "icmp_stats": icmp_stats,
        "tcp_handshakes": tcp_handshake_list,
        "port_scan_alerts": port_scan_alerts,
        "devices": device_list[:20],
    }
