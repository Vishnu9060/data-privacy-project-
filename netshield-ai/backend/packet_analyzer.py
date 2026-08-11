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


def _dissect_dns(pkt) -> tuple[str, str]:
    """Return (protocol, info) for a DNS packet."""
    dns = pkt[DNS]
    if dns.qr == 0:  # query
        if dns.qd is not None:
            qname = dns.qd.qname.decode(errors="replace").rstrip(".") if hasattr(dns.qd, "qname") else "?"
            return "DNS", f"Standard query for {qname}"
        return "DNS", "Standard query"
    else:  # response
        qname = "?"
        if dns.qd is not None and hasattr(dns.qd, "qname"):
            qname = dns.qd.qname.decode(errors="replace").rstrip(".")
        answers = []
        # dns.an is a linked list of answer records
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
        return "DNS", f"Standard query response for {qname}: {answer_str}"


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
    if protocol in ("HTTPS", "HTTPS/TLS"):
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

    def row(protocol, info, sport=None, dport=None):
        # src_ip/dst_ip keep the bare address (no port) so aggregation stays
        # correct for IPv6, whose addresses themselves contain colons.
        source = f"{src}:{sport}" if sport is not None else src
        destination = f"{dst}:{dport}" if dport is not None else dst
        return {
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
        }

    # ICMP (ping, unreachable, etc.)
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        icmp_types = {0: "Echo (ping) reply", 8: "Echo (ping) request", 3: "Destination unreachable", 11: "Time exceeded"}
        return row("ICMP", icmp_types.get(icmp.type, f"Type {icmp.type}"))

    # DNS can ride on UDP or TCP; check it before generic UDP/TCP handling.
    if pkt.haslayer(DNS):
        protocol, info = _dissect_dns(pkt)
        sport = pkt.sport if hasattr(pkt, "sport") else 0
        dport = pkt.dport if hasattr(pkt, "dport") else 0
        return row(protocol, info, sport, dport)

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
        service = _service_for_port(sport, dport)
        protocol = service or "UDP"
        udp_len = udp.len if udp.len is not None else len(udp)
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
    total_bytes = 0
    lan_packets = 0

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

        activity = row.get("activity", "Other")
        dst_ip = row.get("dst_ip")
        touch_device(src_ip, row.get("src_mac"), activity)
        if dst_ip:
            touch_device(dst_ip, row.get("dst_mac"), activity)

    top_talkers = sorted(talkers.items(), key=lambda kv: kv[1], reverse=True)[:5]

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
        "devices": device_list[:20],
    }
