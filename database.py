import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager

DB_NAME = "threat_intelligence.db"

@contextmanager
def get_db_session(db_name: str = DB_NAME):
    """Context manager that handles both transaction commit/rollback AND connection closing."""
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db(db_name: str = DB_NAME):
    """Initializes normalized tables and foreign keys."""
    with get_db_session(db_name) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS attackers (
            ip_address TEXT PRIMARY KEY,
            country TEXT,
            isp TEXT,
            abuse_score INTEGER,
            total_reports INTEGER,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attack_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            attack_count INTEGER,
            target_port INTEGER DEFAULT 3389,
            recorded_at TIMESTAMP,
            FOREIGN KEY (ip_address) REFERENCES attackers (ip_address) ON DELETE CASCADE
        );
        """)
    print("[+] Database schema initialized (threat_intelligence.db).")

def save_threat_record(conn: sqlite3.Connection, ip: str, enrichment: dict, attack_count: int, last_seen: str, target_port: int = 3389):
    """Upserts attacker metadata and appends attack event inside an existing connection/transaction."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # 1. Upsert attacker record
    conn.execute("""
        INSERT INTO attackers (ip_address, country, isp, abuse_score, total_reports, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            country = excluded.country,
            isp = excluded.isp,
            abuse_score = excluded.abuse_score,
            total_reports = excluded.total_reports,
            last_seen = excluded.last_seen;
    """, (
        ip,
        enrichment.get("country", "UNK"),
        enrichment.get("isp", "UNK"),
        enrichment.get("abuse_score", 0),
        enrichment.get("total_reports", 0),
        now,
        last_seen
    ))

    # 2. Insert event telemetry
    conn.execute("""
        INSERT INTO attack_events (ip_address, attack_count, target_port, recorded_at)
        VALUES (?, ?, ?, ?);
    """, (ip, attack_count, target_port, now))