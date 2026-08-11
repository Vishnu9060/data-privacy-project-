"""
AI-generated firewall commands + recommendation text for Port Scanner
findings, via the Groq API, with a deterministic offline fallback.

Risk level, necessity classification, insecure-protocol flag, and CVE hints
stay fully deterministic (security_analyzer.PORT_TABLE) — those are factual
judgments that must be reliable and don't benefit from rephrasing. Only the
two most "writing"-shaped fields per finding — the firewall command
explanation and the recommendation sentence — are handed to Groq to make
richer/more specific, one batched call per scan (not per finding, to avoid
N sequential API calls).

If no GROQ_API_KEY is configured, or the call fails for any reason, callers
get None and should keep using firewall_rules.rules_for() / the static
PORT_TABLE recommendation — the page always works either way.
"""

import json
import os
import urllib.error
import urllib.request

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_MODEL = "llama-3.3-70b-versatile"
REQUEST_TIMEOUT = 30


def _load_env_file() -> None:
    """Load KEY=VALUE lines from a sibling .env file into os.environ.

    Minimal parser (no python-dotenv dependency), mirroring ai_summary.py.
    """
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    if not os.path.isfile(env_path):
        return
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        pass


_load_env_file()


def is_configured() -> bool:
    return bool(os.environ.get("GROQ_API_KEY", "").strip())


def _build_prompt(findings: list[dict], os_name: str) -> str:
    """Ground the model in the real, already-decided facts for each finding
    (port, service, risk, necessity — all deterministic) and ask it only to
    write the firewall command explanation and the recommendation text —
    it must not change any of the facts it's given.
    """
    grounding = [
        {
            "port": f["port"],
            "service": f["service"],
            "risk": f["risk"],
            "necessity": f["necessity"],
            "insecure_protocol": f["insecure_protocol"],
            "action": "deny" if f["necessity"] == "UNNECESSARY" else "restrict",
        }
        for f in findings
    ]
    return (
        f"You are a network security assistant helping harden a {os_name} host. "
        "Below is JSON listing open ports already analyzed, with their risk and necessity "
        "already decided (do not change these facts). For EACH port, write:\n"
        '1. "recommendation": one specific, actionable sentence on what to do about this port.\n'
        '2. "command": the single best firewall command to enforce the given "action" '
        f"(deny = block the port; restrict = allow only from the local network) for a {os_name} host "
        "using ufw if linux, or netsh advfirewall if windows. Include a trailing comment explaining why.\n"
        '3. "explanation": one sentence explaining what that command does and why.\n\n'
        "Return STRICT JSON: an object with a \"findings\" array, one entry per port in the same order, "
        'each with keys "port", "recommendation", "command", "explanation". Do not add ports that were not given.\n\n'
        f"PORTS:\n{json.dumps(grounding, indent=2)}"
    )


def generate_ai_recommendations(findings: list[dict], os_name: str = "linux") -> dict | None:
    """Return {port: {"recommendation", "command", "explanation"}} or None.

    None signals the caller to fall back to the deterministic firewall_rules
    / PORT_TABLE text for every finding.
    """
    if not is_configured() or not findings:
        return None

    api_key = os.environ["GROQ_API_KEY"].strip()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You write precise, correct firewall commands and security advice."},
            {"role": "user", "content": _build_prompt(findings, os_name)},
        ],
        "temperature": 0.3,
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "ShopRadar/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        content = payload["choices"][0]["message"]["content"].strip()
        if content.startswith("```"):
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        parsed = json.loads(content)

        entries = parsed.get("findings")
        if not isinstance(entries, list):
            return None

        by_port = {}
        for entry in entries:
            port = entry.get("port")
            if port is None:
                continue
            if not all(k in entry for k in ("recommendation", "command", "explanation")):
                continue
            by_port[int(port)] = {
                "recommendation": str(entry["recommendation"]),
                "command": str(entry["command"]),
                "explanation": str(entry["explanation"]),
            }

        # Require coverage of every finding we asked about — a partial/
        # malformed reply is safer to discard entirely than to mix AI and
        # template text within the same scan.
        if all(f["port"] in by_port for f in findings):
            return by_port
        return None
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, TimeoutError):
        return None
