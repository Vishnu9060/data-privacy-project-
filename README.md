# NetShield AI — Intelligent Network Security & Privacy Analyzer

NetShield AI is a web-based dashboard that automates network discovery, live packet capture, MAC address privacy testing, and security risk analysis. It was built as a Data Privacy and Security Analytics Lab project, combining a FastAPI backend with a React frontend to give a single, unified interface for common network security and privacy workflows.

## Features

- **Network Discovery** — scans the local network using Nmap to find active devices, returning IP address, hostname, and status for each.
- **Live Packet Analyzer** — captures and classifies live network traffic (TCP/UDP/ICMP) using Scapy, showing source/destination IPs, protocol, and packet length.
- **Privacy Lab** — a guided MAC address spoofing workflow using SMAC, including current MAC address viewing, step-by-step manual instructions, and before/after verification with logging.
- **Security Analysis** — scans open ports on a target host and classifies each one by risk level (HIGH/MEDIUM/LOW/INFO) with a plain-language recommendation.

## Tech Stack

- **Frontend:** React (Vite)
- **Backend:** FastAPI (Python)
- **Networking:** python-nmap, Scapy, psutil
- **Tools integrated:** Nmap, Wireshark/Npcap, SMAC

## Project Structure

```
netshield-ai/
  backend/    FastAPI application (main.py) exposing the scanning, packet
              capture, adapter info, and security analysis routes. Uses a
              Python virtual environment for dependencies.
  frontend/   React (Vite) single-page app that provides the dashboard UI
              and calls the backend API over HTTP.
```

## How to Run

The backend and frontend run as two separate servers and must both be running at the same time, in separate terminals.

### Backend (FastAPI)

```bash
cd netshield-ai/backend
python -m venv venv
venv\Scripts\activate        # on Windows
pip install fastapi uvicorn python-nmap scapy psutil
uvicorn main:app --reload
```

The backend will be available at `http://127.0.0.1:8000`.

### Frontend (React + Vite)

In a second terminal:

```bash
cd netshield-ai/frontend
npm install
npm run dev
```

The frontend will be available at `http://localhost:5173`.

> Both servers need to be running simultaneously for the dashboard to work — the frontend calls the backend API directly from the browser.


