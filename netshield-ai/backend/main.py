import nmap
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, IP, TCP, UDP, ICMP

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

NETWORK_RANGE = "192.168.1.0/24"


@app.get("/")
def read_root():
    return {"message": "NetShield AI backend is running"}


@app.get("/scan")
def scan_network():
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=NETWORK_RANGE, arguments="-sn")
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

    return {"devices": devices}


@app.get("/capture-live")
def capture_live():
    try:
        captured = sniff(timeout=15)
    except Exception as e:
        return {"error": f"Capture failed: {str(e)}"}

    packets = []
    for pkt in captured:
        if not pkt.haslayer(IP):
            continue

        ip_layer = pkt[IP]

        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        elif pkt.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = "other"

        packets.append({
            "source_ip": ip_layer.src,
            "destination_ip": ip_layer.dst,
            "protocol": protocol,
            "length": len(pkt),
        })

        if len(packets) >= 200:
            break

    return {"packets": packets}
