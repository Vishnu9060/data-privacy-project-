"""
AI-generated report summary via the Groq API, with an offline fallback.

If a GROQ_API_KEY is configured (in the environment or the backend's .env file),
this module asks a Groq-hosted model to write a plain-English summary of the
scan results. If no key is set, or the API call fails for any reason, it
transparently falls back to the deterministic template summary in
report_generator, so the report always works — with or without internet/credits.

Groq exposes an OpenAI-compatible endpoint. Uses only the Python standard
library (urllib) so no extra pip dependency is needed for the HTTP call.
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

    Minimal parser (no python-dotenv dependency): ignores blank lines and
    comments, strips optional surrounding quotes, and does not overwrite
    variables already present in the real environment.
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


def _build_prompt(metrics: dict, template_sections: dict) -> str:
    """Ask Grok to rewrite the findings as a friendly, layman report.

    We hand it the raw metrics plus our template text as grounding so it stays
    factual and only improves the wording/clarity — it must not invent data.
    """
    return (
        "You are a network-security assistant writing a report for a non-technical reader. "
        "Below is JSON with the metrics from four security/privacy checks, and a draft plain-English "
        "summary for each section. Rewrite the summary so it is clear, friendly, and easy for a layman "
        "to understand, explaining what each result means and what to do about it. Do NOT invent any "
        "numbers or findings — use only what is in the data. Return STRICT JSON with exactly these keys: "
        '"overall" (a 2-3 sentence headline) and "sections" (an object with keys network_discovery, '
        "packet_analysis, privacy_lab, security_analysis, each a paragraph of plain English).\n\n"
        f"METRICS:\n{json.dumps(metrics, indent=2)}\n\n"
        f"DRAFT SECTIONS:\n{json.dumps(template_sections, indent=2)}"
    )


def generate_ai_summary(metrics: dict, template_summary: dict) -> dict | None:
    """Return an AI-written summary dict, or None to signal 'use the fallback'.

    Shape on success matches the template summary: {"overall": str, "sections": {...}}.
    """
    if not is_configured():
        return None

    api_key = os.environ["GROQ_API_KEY"].strip()
    model = os.environ.get("GROQ_MODEL", DEFAULT_MODEL).strip() or DEFAULT_MODEL

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You write clear, accurate, non-technical security summaries."},
            {"role": "user", "content": _build_prompt(metrics, template_summary["sections"])},
        ],
        "temperature": 0.4,
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        GROQ_API_URL,
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            # Groq's Cloudflare edge rejects the default "Python-urllib" agent
            # with a 403 (error 1010); send a normal UA so the request passes.
            "User-Agent": "ShopRadar/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode())
        content = payload["choices"][0]["message"]["content"].strip()
        # Model may wrap JSON in a ```json fence; strip it.
        if content.startswith("```"):
            content = content.split("```", 2)[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        parsed = json.loads(content)
        # Validate the shape before trusting it.
        if "overall" in parsed and "sections" in parsed and isinstance(parsed["sections"], dict):
            required = {"network_discovery", "packet_analysis", "privacy_lab", "security_analysis"}
            if required.issubset(parsed["sections"].keys()):
                parsed["source"] = "groq"
                return parsed
        return None
    except (urllib.error.URLError, urllib.error.HTTPError, KeyError, ValueError, TimeoutError):
        # Any failure (no internet, bad key, rate limit, malformed reply) ->
        # signal the caller to use the reliable template summary instead.
        return None
