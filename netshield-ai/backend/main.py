import ipaddress
import platform
import socket

import psutil
import nmap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scapy.all import sniff

import mac_spoof
import packet_analyzer
import security_analyzer
import report_generator
import wifi_scanner

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


# Cap how large a subnet we'll ever ping-sweep. Large institutional/campus
# Wi-Fi commonly hands out /19 or bigger (thousands of addresses) on one
# segment; fully scanning that from a student laptop is slow (minutes, even
# with aggressive timing) and unnecessary — everything interesting is near
# our own IP. Anything wider than /24 gets narrowed to a /24 around our IP.
MAX_SCAN_PREFIXLEN = 24


def _detect_network_range() -> tuple[str, bool]:
    """Detect the current local subnet to scan.

    Re-run on every /scan call (not cached at import time) so it reflects
    whatever network we're on right now — Wi-Fi can change between when the
    backend was started and when a scan actually runs.

    Returns (cidr, was_narrowed) — was_narrowed is True if the real subnet
    was bigger than /24 and got clamped for scan speed/safety.
    """
    local_ip = _get_local_ip()

    try:
        for addrs in psutil.net_if_addrs().values():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == local_ip and addr.netmask:
                    network = ipaddress.IPv4Network(f"{local_ip}/{addr.netmask}", strict=False)
                    if network.prefixlen < MAX_SCAN_PREFIXLEN:
                        narrowed = ipaddress.IPv4Network(
                            f"{local_ip}/{MAX_SCAN_PREFIXLEN}", strict=False
                        )
                        return str(narrowed), True
                    return str(network), False
    except Exception:
        pass

    octets = local_ip.split(".")
    return f"{'.'.join(octets[:3])}.0/24", False


@app.get("/")
def read_root():
    return {"message": "NetShield AI backend is running"}


@app.get("/scan")
def scan_network():
    network_range, was_narrowed = _detect_network_range()

    try:
        scanner = nmap.PortScanner()
        # -sn: ping scan (no port scan). -T4: aggressive timing.
        # --host-timeout 2s: don't wait long on empty addresses, which is
        # what makes a full-subnet scan feel slow.
        scanner.scan(hosts=network_range, arguments="-sn -T4 --host-timeout 2s")
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    devices = []
    for host in scanner.all_hosts():
        host_info = scanner[host]
        hostname = host_info.hostname() or "unknown"
        devices.append({
            "ip": host,
            "hostname": hostname,
            "status": host_info.state(),
        })

    if not devices:
        return {"error": "No devices found on the network."}

    result = {"devices": devices, "scanned_range": network_range}
    if was_narrowed:
        result["note"] = (
            f"Your network's actual subnet is larger than /24, so the scan was "
            f"narrowed to {network_range} (around your own IP) for speed. "
            f"Devices outside this range won't appear."
        )
    return result


@app.get("/capture-live")
def capture_live(timeout: int = 15, count: int = 200, bpf_filter: str = ""):
    """Capture live traffic and dissect it Wireshark-style.

    Query params:
      timeout    - seconds to sniff (default 15)
      count      - max packets to return (default 200)
      bpf_filter - optional Berkeley Packet Filter (e.g. "port 53" for DNS,
                   "tcp port 80" for HTTP, "icmp" for ping), same syntax
                   Wireshark uses.
    """
    try:
        sniff_kwargs = {"timeout": timeout, "count": count}
        if bpf_filter.strip():
            sniff_kwargs["filter"] = bpf_filter.strip()
        captured = sniff(**sniff_kwargs)
    except Exception as e:
        return {"error": f"Capture failed: {str(e)}"}

    # Used to flag which captured packets are LAN-local (both endpoints on
    # our own subnet, e.g. talking to a teammate's laptop) vs internet-bound.
    range_str, _ = _detect_network_range()
    try:
        local_network = ipaddress.ip_network(range_str, strict=False)
    except ValueError:
        local_network = None

    rows = []
    for pkt in captured:
        try:
            row = packet_analyzer.dissect_packet(pkt, local_network=local_network)
        except Exception:
            # A single malformed/unexpected packet must never abort the whole
            # capture — skip it and keep dissecting the rest.
            continue
        if row is not None:
            rows.append(row)

    return {"packets": rows, "summary": packet_analyzer.summarize(rows)}


@app.get("/network-adapter-info")
def network_adapter_info():
    try:
        interfaces = psutil.net_if_addrs()
    except Exception as e:
        return {"error": f"Failed to read network adapters: {str(e)}"}

    adapters = []
    for name, addr_list in interfaces.items():
        for addr in addr_list:
            if addr.family == psutil.AF_LINK and addr.address:
                mac_address = addr.address.replace("-", ":").upper()
                adapters.append({
                    "name": name,
                    "mac_address": mac_address,
                })
                break

    if not adapters:
        return {"error": "No network adapters with a MAC address were found."}

    return {"adapters": adapters}


class ChangeMacRequest(BaseModel):
    interface: str
    new_mac: str | None = None  # if omitted, a random MAC is generated


class RestoreMacRequest(BaseModel):
    interface: str


@app.post("/privacy-lab/change-mac")
def change_mac(req: ChangeMacRequest):
    before = network_adapter_info()
    if "error" in before:
        return before
    before_mac = next(
        (a["mac_address"] for a in before["adapters"] if a["name"] == req.interface), None
    )
    if before_mac is None:
        return {"error": f"Interface '{req.interface}' was not found."}

    new_mac = req.new_mac.strip().upper() if req.new_mac else mac_spoof.generate_random_mac()

    try:
        mac_spoof.set_mac_address(req.interface, new_mac, current_mac=before_mac)
    except mac_spoof.MacSpoofError as e:
        return {"error": str(e)}

    after = network_adapter_info()
    if "error" in after:
        return after
    after_mac = next(
        (a["mac_address"] for a in after["adapters"] if a["name"] == req.interface), None
    )

    return {
        "interface": req.interface,
        "before_mac": before_mac,
        "after_mac": after_mac,
        "requested_mac": new_mac,
        "success": after_mac == new_mac,
    }


@app.post("/privacy-lab/restore-mac")
def restore_mac(req: RestoreMacRequest):
    before = network_adapter_info()
    if "error" in before:
        return before
    before_mac = next(
        (a["mac_address"] for a in before["adapters"] if a["name"] == req.interface), None
    )
    if before_mac is None:
        return {"error": f"Interface '{req.interface}' was not found."}

    try:
        mac_spoof.restore_mac_address(req.interface)
    except mac_spoof.MacSpoofError as e:
        return {"error": str(e)}

    after = network_adapter_info()
    if "error" in after:
        return after
    after_mac = next(
        (a["mac_address"] for a in after["adapters"] if a["name"] == req.interface), None
    )

    return {
        "interface": req.interface,
        "before_mac": before_mac,
        "after_mac": after_mac,
        "success": after_mac != before_mac,
    }


def _scan_ports(target: str) -> dict:
    if not target:
        return {"error": "Missing required query parameter 'target'."}

    try:
        ipaddress.ip_address(target)
    except ValueError:
        return {"error": f"'{target}' is not a valid IP address."}

    try:
        scanner = nmap.PortScanner()
        # -F: fast scan (top 100 ports). -sV: full service/version detection
        # (more probes than --version-light, catches versions light mode
        # misses, at negligible extra cost once a port is known to be open).
        # -T4: aggressive timing. --host-timeout caps the total so a
        # filtered/slow host can't hang the request.
        scanner.scan(hosts=target, arguments="-F -sV -T4 --host-timeout 30s")
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    if target not in scanner.all_hosts():
        return {"target": target, "open_ports": []}

    open_ports = []
    host_info = scanner[target]
    for proto in host_info.all_protocols():
        if proto != "tcp":
            continue
        for port, port_info in host_info[proto].items():
            if port_info.get("state") == "open":
                open_ports.append({
                    "port": port,
                    "service": port_info.get("name", "unknown"),
                    "version": port_info.get("version", "") or "unknown",
                })

    return {"target": target, "open_ports": open_ports}


@app.get("/port-scan")
def port_scan(target: str = ""):
    return _scan_ports(target)


def _host_scan(target: str) -> dict:
    """Deep per-host scan: OS detection + TCP ports + services + versions.

    This is deliberately a separate, on-demand endpoint (not run for every
    host during /scan) because nmap's OS fingerprinting (-O) is slow
    (several seconds per host) and only a best-effort guess, not a
    certainty — running it automatically for every discovered device would
    make network discovery painfully slow for no benefit on hosts the user
    doesn't care about.
    """
    if not target:
        return {"error": "Missing required query parameter 'target'."}

    try:
        ipaddress.ip_address(target)
    except ValueError:
        return {"error": f"'{target}' is not a valid IP address."}

    try:
        scanner = nmap.PortScanner()
        # -O: OS detection (needs root, which this backend runs as).
        # -sV: full service/version detection (more probes than
        # --version-light, so it actually pulls a version where the light
        # variant would give up and say "unknown").
        # -F: fast scan (top 100 ports) so this stays reasonably quick.
        # --osscan-guess: report a best-effort guess even with imperfect
        # matches, since real-world hosts rarely fingerprint perfectly.
        scanner.scan(
            hosts=target,
            arguments="-F -O --osscan-guess -sV -T4 --host-timeout 45s",
        )
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}

    if target not in scanner.all_hosts():
        return {"target": target, "hostname": "unknown", "os_matches": [], "open_ports": []}

    host_info = scanner[target]

    # OS detection results: nmap ranks candidate OS matches by accuracy %.
    os_matches = []
    if "osmatch" in host_info:
        for match in host_info["osmatch"][:3]:
            os_matches.append({
                "name": match.get("name", "unknown"),
                "accuracy": match.get("accuracy", "0"),
            })

    open_ports = []
    for proto in host_info.all_protocols():
        if proto != "tcp":
            continue
        for port, port_info in host_info[proto].items():
            if port_info.get("state") == "open":
                open_ports.append({
                    "port": port,
                    "service": port_info.get("name", "unknown"),
                    "product": port_info.get("product", "") or "",
                    "version": port_info.get("version", "") or "unknown",
                    "extrainfo": port_info.get("extrainfo", "") or "",
                })

    return {
        "target": target,
        "hostname": host_info.hostname() or "unknown",
        "os_matches": os_matches,
        "open_ports": open_ports,
    }


@app.get("/host-scan")
def host_scan(target: str = ""):
    return _host_scan(target)


@app.get("/wifi-scan")
def wifi_scan():
    """Scan for nearby Wi-Fi access points and their security posture.

    Network-level only (SSID/BSSID/encryption of the access point itself) —
    does not enumerate or track individual client devices connected to it.
    """
    return wifi_scanner.scan_networks()


def _os_key() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows"
    return "linux"  # Linux/macOS both use ufw/iptables-style examples


@app.get("/security-analysis")
def security_analysis(target: str = ""):
    scan_result = _scan_ports(target)
    if "error" in scan_result:
        return scan_result
    return security_analyzer.analyze(scan_result, os_name=_os_key())


class ReportRequest(BaseModel):
    devices: list | None = None
    packets: list | None = None
    packet_summary: dict | None = None
    adapters: list | None = None
    security: dict | None = None


@app.post("/generate-report")
def generate_report(req: ReportRequest):
    return report_generator.generate(req.model_dump())
