"""
Footfall Analytics — SQLite storage.

The shop has no cameras/IoT sensors. Instead we treat every MAC address this
project already observes elsewhere (Network Discovery's ARP sweep, the
Packet Sniffer's captured frames) as an anonymized "visitor ID" — the same
principle real-world WiFi-analytics vendors use in retail: a phone's MAC is
never linked to a real identity, but the same MAC reappearing is a strong
signal of "the same person came back."

Two kinds of rows live in the same `visits` table, distinguished by
`source`:
  - "mock": a synthetic ~30-day visit history generated once on first run,
    so every chart has a believable trend/pattern to render immediately.
  - "live": real sightings recorded whenever a Network Discovery scan or a
    Packet Sniffer capture observes a device, via `record_sighting()`.

A "visit" is a session: a MAC's first sighting opens one, later sightings of
the same MAC within SESSION_GAP_MINUTES extend it (this is how "how long did
they stay" / dwell time is derived), and a sighting after a longer gap starts
a new visit — i.e. the customer left and came back.
"""

import random
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path

DB_PATH = Path(__file__).parent / "footfall.db"

# A sighting of the same visitor_id within this many minutes of the previous
# one is treated as "still in the shop" (extends the current visit) rather
# than a brand new visit.
SESSION_GAP_MINUTES = 30


@contextmanager
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create the schema if missing, then seed mock history on first run."""
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visitor_id TEXT NOT NULL,
                vendor TEXT,
                ip_address TEXT,
                session_start TEXT NOT NULL,
                session_end TEXT NOT NULL,
                duration_seconds INTEGER NOT NULL,
                visit_date TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'live'
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_visits_visitor ON visits(visitor_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_visits_date ON visits(visit_date)")

        count = conn.execute("SELECT COUNT(*) AS n FROM visits").fetchone()["n"]
        if count == 0:
            _seed_mock_data(conn)


# ------------------------------------------------------------------
# Mock history generation
# ------------------------------------------------------------------

# Hour-of-day traffic weights for a mall shop: quiet in the morning, a
# late-morning/lunch bump, a bigger evening peak (after-work/school crowd).
HOUR_WEIGHTS = {
    9: 2, 10: 4, 11: 7, 12: 9, 13: 8, 14: 6, 15: 6, 16: 7,
    17: 9, 18: 10, 19: 9, 20: 6, 21: 3,
}
OPEN_HOURS = list(HOUR_WEIGHTS.keys())

# Weekends draw noticeably more shoppers than weekdays.
DOW_WEIGHTS = {0: 5, 1: 5, 2: 5, 3: 6, 4: 7, 5: 10, 6: 9}  # Mon..Sun

MOCK_DAYS = 30
VENDOR_POOL = ["Apple", "Samsung", "Xiaomi", "OnePlus", "Google", "Huawei", "Realme", "Vivo"]


def _random_mac(rng: random.Random) -> str:
    octets = [rng.randint(0, 255) for _ in range(6)]
    octets[0] |= 0x02  # locally-administered bit, mirrors real random phone MACs
    return ":".join(f"{o:02X}" for o in octets)


def _weighted_choice(rng: random.Random, weights: dict):
    keys = list(weights.keys())
    weights_list = list(weights.values())
    return rng.choices(keys, weights=weights_list, k=1)[0]


def _random_duration_seconds(rng: random.Random) -> int:
    # Most shop visits are short browses (5-20 min); a smaller tail lingers
    # much longer (trying things on, waiting, chatting).
    bucket = rng.choices(
        ["quick", "typical", "long"], weights=[35, 50, 15], k=1
    )[0]
    if bucket == "quick":
        return rng.randint(2, 8) * 60
    if bucket == "typical":
        return rng.randint(9, 30) * 60
    return rng.randint(31, 75) * 60


def _seed_mock_data(conn: sqlite3.Connection) -> None:
    rng = random.Random(1729)  # fixed seed: stable, reproducible demo data
    today = datetime.now().date()
    start_day = today - timedelta(days=MOCK_DAYS - 1)

    # Visitor pool with a realistic long-tail: a handful of regulars who
    # keep coming back, some occasional repeat customers, and a large group
    # of one-time visitors. This is what makes the "repeat frequency" chart
    # meaningful instead of flat.
    regulars = [(_random_mac(rng), rng.randint(8, 20)) for _ in range(25)]
    occasional = [(_random_mac(rng), rng.randint(2, 5)) for _ in range(60)]
    onetime = [(_random_mac(rng), 1) for _ in range(300)]

    mac_vendor = {}
    rows = []

    for mac, visit_count in regulars + occasional + onetime:
        mac_vendor[mac] = rng.choice(VENDOR_POOL)
        # Spread this visitor's visits across the window at random days,
        # weighted so more of them land on busier weekdays.
        candidate_days = list(range(MOCK_DAYS))
        day_weights = [
            DOW_WEIGHTS[(start_day + timedelta(days=d)).weekday()] for d in candidate_days
        ]
        chosen_days = rng.choices(candidate_days, weights=day_weights, k=visit_count)
        for day_offset in chosen_days:
            day = start_day + timedelta(days=day_offset)
            hour = _weighted_choice(rng, HOUR_WEIGHTS)
            minute = rng.randint(0, 59)
            session_start = datetime(day.year, day.month, day.day, hour, minute)
            duration = _random_duration_seconds(rng)
            session_end = session_start + timedelta(seconds=duration)
            rows.append(
                (
                    mac,
                    mac_vendor[mac],
                    None,
                    session_start.isoformat(timespec="seconds"),
                    session_end.isoformat(timespec="seconds"),
                    duration,
                    day.isoformat(),
                    "mock",
                )
            )

    conn.executemany(
        """
        INSERT INTO visits
            (visitor_id, vendor, ip_address, session_start, session_end, duration_seconds, visit_date, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )


# ------------------------------------------------------------------
# Live recording — called from main.py whenever a scan/capture observes a
# device, so real activity blends into the same dashboard as the mock
# history.
# ------------------------------------------------------------------

def record_sighting(visitor_id: str, ip_address: str | None = None, vendor: str | None = None, now: datetime | None = None) -> None:
    if not visitor_id:
        return
    now = now or datetime.now()

    with _connect() as conn:
        row = conn.execute(
            """
            SELECT id, session_start, session_end FROM visits
            WHERE visitor_id = ? AND source = 'live'
            ORDER BY session_end DESC LIMIT 1
            """,
            (visitor_id,),
        ).fetchone()

        if row is not None:
            last_end = datetime.fromisoformat(row["session_end"])
            if now - last_end <= timedelta(minutes=SESSION_GAP_MINUTES):
                # Still the same visit — extend it.
                start = datetime.fromisoformat(row["session_start"])
                duration = int((now - start).total_seconds())
                conn.execute(
                    "UPDATE visits SET session_end = ?, duration_seconds = ?, ip_address = COALESCE(?, ip_address) WHERE id = ?",
                    (now.isoformat(timespec="seconds"), duration, ip_address, row["id"]),
                )
                return

        # New visit for this visitor.
        conn.execute(
            """
            INSERT INTO visits
                (visitor_id, vendor, ip_address, session_start, session_end, duration_seconds, visit_date, source)
            VALUES (?, ?, ?, ?, ?, 0, ?, 'live')
            """,
            (visitor_id, vendor, ip_address, now.isoformat(timespec="seconds"), now.isoformat(timespec="seconds"), now.date().isoformat()),
        )


def record_sightings(visitor_ids: list[str], ip_by_mac: dict | None = None) -> None:
    """Bulk-record sightings from one scan/capture pass, deduped by MAC."""
    ip_by_mac = ip_by_mac or {}
    now = datetime.now()
    seen = set()
    for vid in visitor_ids:
        if not vid or vid in seen:
            continue
        seen.add(vid)
        record_sighting(vid, ip_address=ip_by_mac.get(vid), now=now)
