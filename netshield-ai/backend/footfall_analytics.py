"""
Footfall Analytics — turns the raw `visits` rows (see footfall_db.py) into
the four things a shop owner actually wants to know:

  1. How many people visited (unique visitor count, trend over time)
  2. How often the same person comes back (repeat-visit frequency)
  3. When the shop is busiest (peak hours / day-of-week)
  4. How long people stay (dwell time distribution)

Everything is computed in Python from the full row set rather than complex
SQL aggregation — the dataset (~30 days of one shop's visits) is small
enough that this is simpler to read and just as fast.
"""

from collections import defaultdict
from datetime import datetime, timedelta
from statistics import mean, median

import footfall_db

DOW_LABELS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

FREQUENCY_BUCKETS = [
    ("1 visit", lambda n: n == 1),
    ("2-3 visits", lambda n: 2 <= n <= 3),
    ("4-9 visits", lambda n: 4 <= n <= 9),
    ("10+ visits", lambda n: n >= 10),
]

DWELL_BUCKETS = [
    ("<5 min", lambda s: s < 5 * 60),
    ("5-15 min", lambda s: 5 * 60 <= s < 15 * 60),
    ("15-30 min", lambda s: 15 * 60 <= s < 30 * 60),
    ("30-60 min", lambda s: 30 * 60 <= s < 60 * 60),
    ("60+ min", lambda s: s >= 60 * 60),
]


def _fetch_all_rows() -> list[dict]:
    with footfall_db._connect() as conn:
        rows = conn.execute(
            "SELECT visitor_id, vendor, session_start, session_end, duration_seconds, visit_date, source FROM visits"
        ).fetchall()
    return [dict(r) for r in rows]


def build_dashboard(days: int = 30) -> dict:
    rows = _fetch_all_rows()
    if not rows:
        return {"empty": True}

    today = datetime.now().date()
    window_start = today - timedelta(days=days - 1)
    windowed = [r for r in rows if datetime.fromisoformat(r["visit_date"]).date() >= window_start]

    # ---- visitor trend (unique + total visits per day) ----
    by_day_visitors = defaultdict(set)
    by_day_visits = defaultdict(int)
    for r in windowed:
        by_day_visitors[r["visit_date"]].add(r["visitor_id"])
        by_day_visits[r["visit_date"]] += 1

    trend = []
    for i in range(days):
        d = (window_start + timedelta(days=i)).isoformat()
        trend.append({
            "date": d,
            "unique_visitors": len(by_day_visitors.get(d, ())),
            "total_visits": by_day_visits.get(d, 0),
        })

    visitors_today = len(by_day_visitors.get(today.isoformat(), ()))
    days_with_data = [t for t in trend if t["total_visits"] > 0]
    avg_visitors_per_day = round(mean(t["unique_visitors"] for t in days_with_data), 1) if days_with_data else 0

    # ---- repeat-visit frequency ----
    visits_per_visitor = defaultdict(int)
    for r in rows:
        visits_per_visitor[r["visitor_id"]] += 1

    total_unique_visitors = len(visits_per_visitor)
    repeat_visitors = sum(1 for n in visits_per_visitor.values() if n > 1)
    repeat_rate_pct = round(100 * repeat_visitors / total_unique_visitors, 1) if total_unique_visitors else 0

    frequency = [
        {"bucket": label, "visitors": sum(1 for n in visits_per_visitor.values() if pred(n))}
        for label, pred in FREQUENCY_BUCKETS
    ]

    vendor_by_visitor = {}
    for r in rows:
        if r["vendor"] and r["visitor_id"] not in vendor_by_visitor:
            vendor_by_visitor[r["visitor_id"]] = r["vendor"]

    top_regulars = sorted(visits_per_visitor.items(), key=lambda kv: kv[1], reverse=True)[:8]
    top_regulars = [
        {
            "visitor_id": vid,
            "visits": count,
            "vendor": vendor_by_visitor.get(vid, "Unknown"),
            "masked_id": _mask_id(vid),
        }
        for vid, count in top_regulars
    ]

    # ---- peak hours (day-of-week x hour matrix + hourly totals) ----
    matrix = defaultdict(lambda: defaultdict(int))  # dow -> hour -> count
    hourly_totals = defaultdict(int)
    for r in rows:
        ts = datetime.fromisoformat(r["session_start"])
        dow = ts.weekday()
        hour = ts.hour
        matrix[dow][hour] += 1
        hourly_totals[hour] += 1

    hours_present = sorted(hourly_totals.keys()) or list(range(9, 22))
    heatmap = [
        {
            "day": DOW_LABELS[dow],
            "hours": {str(h): matrix[dow].get(h, 0) for h in hours_present},
        }
        for dow in range(7)
    ]
    hourly_bar = [{"hour": h, "visits": hourly_totals.get(h, 0)} for h in hours_present]
    peak_hour = max(hourly_totals.items(), key=lambda kv: kv[1])[0] if hourly_totals else None

    # ---- dwell time ----
    durations = [r["duration_seconds"] for r in rows if r["duration_seconds"] and r["duration_seconds"] > 0]
    dwell_buckets = [
        {"bucket": label, "visits": sum(1 for s in durations if pred(s))}
        for label, pred in DWELL_BUCKETS
    ]
    avg_dwell_minutes = round(mean(durations) / 60, 1) if durations else 0
    median_dwell_minutes = round(median(durations) / 60, 1) if durations else 0

    live_count = sum(1 for r in rows if r["source"] == "live")

    return {
        "empty": False,
        "kpis": {
            "total_unique_visitors": total_unique_visitors,
            "visitors_today": visitors_today,
            "avg_visitors_per_day": avg_visitors_per_day,
            "repeat_rate_pct": repeat_rate_pct,
            "avg_dwell_minutes": avg_dwell_minutes,
            "median_dwell_minutes": median_dwell_minutes,
            "peak_hour": peak_hour,
            "total_visits": len(rows),
            "live_sightings": live_count,
        },
        "visitor_trend": trend,
        "frequency": frequency,
        "top_regulars": top_regulars,
        "peak_hours": {"heatmap": heatmap, "hourly": hourly_bar, "hours_present": hours_present},
        "dwell": {"buckets": dwell_buckets, "avg_minutes": avg_dwell_minutes, "median_minutes": median_dwell_minutes},
    }


def _mask_id(visitor_id: str) -> str:
    """Show only the vendor-identifying prefix of a MAC, not the full address."""
    parts = visitor_id.split(":")
    if len(parts) < 6:
        return visitor_id
    return ":".join(parts[:3]) + ":••:••:••"
