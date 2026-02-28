"""
PhishShield AI - Database Models & Data Access Layer
SQLite-based storage for users and analysis metadata only.
No message content is ever stored (privacy-first design).
"""

import sqlite3
import os
import hashlib
import secrets
import time
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishshield.db")


def get_db():
    """Get a database connection with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            verified INTEGER NOT NULL DEFAULT 0,
            otp TEXT,
            otp_expiry REAL,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            last_login TEXT,
            analysis_count INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS analysis_meta (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            preview_snippet TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS detection_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            pattern TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'medium',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_analysis_user ON analysis_meta(user_id);
        CREATE INDEX IF NOT EXISTS idx_analysis_timestamp ON analysis_meta(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_rules_category ON detection_rules(category);
    """)

    # Seed default admin account (password: Admin@1234)
    admin_exists = cursor.execute(
        "SELECT id FROM users WHERE role='admin' LIMIT 1"
    ).fetchone()
    if not admin_exists:
        cursor.execute(
            "INSERT INTO users (email, username, password_hash, role, verified) VALUES (?, ?, ?, 'admin', 1)",
            ("admin@phishshield.ai", "Admin", generate_password_hash("Admin@1234")),
        )

    # Seed default detection rules if empty
    rule_count = cursor.execute("SELECT COUNT(*) FROM detection_rules").fetchone()[0]
    if rule_count == 0:
        default_rules = [
            # Keyword rules
            ("keyword", "act now", "high"),
            ("keyword", "verify immediately", "high"),
            ("keyword", "account blocked", "high"),
            ("keyword", "confirm identity", "high"),
            ("keyword", "urgent action required", "high"),
            ("keyword", "account suspended", "high"),
            ("keyword", "unauthorized login", "high"),
            ("keyword", "click here immediately", "high"),
            ("keyword", "verify your account", "medium"),
            ("keyword", "update your payment", "high"),
            ("keyword", "your account will be closed", "high"),
            ("keyword", "dear user", "medium"),
            ("keyword", "dear customer", "medium"),
            ("keyword", "dear valued member", "medium"),
            ("keyword", "congratulations you won", "high"),
            ("keyword", "you have been selected", "medium"),
            ("keyword", "limited time offer", "medium"),
            ("keyword", "risk of suspension", "high"),
            ("keyword", "confirm your otp", "high"),
            ("keyword", "share your password", "high"),
            ("keyword", "send your bank details", "high"),
            ("keyword", "credit card number", "high"),
            ("keyword", "social security number", "high"),
            ("keyword", "wire transfer", "high"),
            ("keyword", "bitcoin payment", "high"),
            ("keyword", "gift card", "medium"),
            ("keyword", "scholarship approved", "medium"),
            ("keyword", "job offer", "medium"),
            ("keyword", "work from home", "medium"),
            ("keyword", "earn money fast", "high"),
            ("keyword", "free iphone", "high"),
            ("keyword", "login credentials", "high"),
            ("keyword", "password expired", "high"),
            ("keyword", "security alert", "medium"),
            ("keyword", "unusual activity", "medium"),
            # Regex link rules
            ("regex", r"bit\.ly/\S+", "high"),
            ("regex", r"tinyurl\.com/\S+", "high"),
            ("regex", r"t\.co/\S+", "medium"),
            ("regex", r"goo\.gl/\S+", "high"),
            ("regex", r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "high"),
            ("regex", r"[a-zA-Z0-9-]+\.(xyz|tk|ml|ga|cf|gq|top|buzz|click)/", "high"),
            # Tone rules
            ("tone", "urgency", "high"),
            ("tone", "fear", "high"),
            ("tone", "greed", "medium"),
            ("tone", "curiosity_exploit", "medium"),
        ]
        cursor.executemany(
            "INSERT INTO detection_rules (category, pattern, severity) VALUES (?, ?, ?)",
            default_rules,
        )

    conn.commit()
    conn.close()


# ─── User Operations ───────────────────────────────────────────

def create_user(email, username, password):
    """Create a new user and return (user_id, otp) or raise ValueError."""
    conn = get_db()
    try:
        otp = f"{secrets.randbelow(900000) + 100000}"
        otp_expiry = time.time() + 300  # 5 minutes

        conn.execute(
            """INSERT INTO users (email, username, password_hash, otp, otp_expiry)
               VALUES (?, ?, ?, ?, ?)""",
            (email.lower().strip(), username.strip(), generate_password_hash(password), otp, otp_expiry),
        )
        conn.commit()
        user_id = conn.execute(
            "SELECT id FROM users WHERE email=?", (email.lower().strip(),)
        ).fetchone()["id"]
        return user_id, otp
    except sqlite3.IntegrityError:
        raise ValueError("Email already registered")
    finally:
        conn.close()


def verify_user_otp(email, otp):
    """Verify OTP for a user. Returns True on success."""
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT id, otp, otp_expiry FROM users WHERE email=?",
            (email.lower().strip(),),
        ).fetchone()
        if not user:
            return False
        if user["otp"] != otp:
            return False
        if time.time() > user["otp_expiry"]:
            return False
        conn.execute(
            "UPDATE users SET verified=1, otp=NULL, otp_expiry=NULL WHERE id=?",
            (user["id"],),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def resend_otp(email):
    """Generate and return a new OTP for the user."""
    conn = get_db()
    try:
        otp = f"{secrets.randbelow(900000) + 100000}"
        otp_expiry = time.time() + 300
        conn.execute(
            "UPDATE users SET otp=?, otp_expiry=? WHERE email=?",
            (otp, otp_expiry, email.lower().strip()),
        )
        conn.commit()
        return otp
    finally:
        conn.close()


def authenticate_user(email, password):
    """Authenticate user. Returns user dict or None."""
    conn = get_db()
    try:
        user = conn.execute(
            "SELECT * FROM users WHERE email=?", (email.lower().strip(),)
        ).fetchone()
        if not user:
            return None
        if not check_password_hash(user["password_hash"], password):
            return None
        if not user["verified"]:
            return {"error": "not_verified", "email": user["email"]}
        conn.execute(
            "UPDATE users SET last_login=datetime('now') WHERE id=?", (user["id"],)
        )
        conn.commit()
        return dict(user)
    finally:
        conn.close()


def get_user_by_id(user_id):
    """Get user by ID."""
    conn = get_db()
    try:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(user) if user else None
    finally:
        conn.close()


# ─── Analysis Metadata Operations ──────────────────────────────

def save_analysis_meta(user_id, risk_score, risk_level, message_text):
    """Save analysis metadata (preview snippet only, max 60 chars)."""
    preview = message_text[:57].replace("\n", " ").strip()
    if len(message_text) > 57:
        preview += "..."

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO analysis_meta (user_id, risk_score, risk_level, preview_snippet)
               VALUES (?, ?, ?, ?)""",
            (user_id, risk_score, risk_level, preview),
        )
        conn.execute(
            "UPDATE users SET analysis_count = analysis_count + 1 WHERE id=?",
            (user_id,),
        )
        conn.commit()
    finally:
        conn.close()


def get_user_analyses(user_id, limit=20):
    """Get recent analysis metadata for a user."""
    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT id, timestamp, risk_score, risk_level, preview_snippet
               FROM analysis_meta WHERE user_id=?
               ORDER BY timestamp DESC LIMIT ?""",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_user_dashboard_stats(user_id):
    """Get aggregate dashboard statistics for a user."""
    conn = get_db()
    try:
        total = conn.execute(
            "SELECT COUNT(*) as c FROM analysis_meta WHERE user_id=?", (user_id,)
        ).fetchone()["c"]

        dist = conn.execute(
            """SELECT risk_level, COUNT(*) as c FROM analysis_meta
               WHERE user_id=? GROUP BY risk_level""",
            (user_id,),
        ).fetchall()

        distribution = {"safe": 0, "suspicious": 0, "high_risk": 0}
        for row in dist:
            distribution[row["risk_level"]] = row["c"]

        avg_score = conn.execute(
            "SELECT AVG(risk_score) as a FROM analysis_meta WHERE user_id=?",
            (user_id,),
        ).fetchone()["a"]

        return {
            "total_analyses": total,
            "risk_distribution": distribution,
            "average_risk_score": round(avg_score, 1) if avg_score else 0,
        }
    finally:
        conn.close()


# ─── Admin Operations ──────────────────────────────────────────

def get_admin_stats():
    """Get system-wide statistics for admin dashboard."""
    conn = get_db()
    try:
        total_users = conn.execute("SELECT COUNT(*) as c FROM users WHERE role='student'").fetchone()["c"]
        total_analyses = conn.execute("SELECT COUNT(*) as c FROM analysis_meta").fetchone()["c"]

        dist = conn.execute(
            "SELECT risk_level, COUNT(*) as c FROM analysis_meta GROUP BY risk_level"
        ).fetchall()
        distribution = {"safe": 0, "suspicious": 0, "high_risk": 0}
        for row in dist:
            distribution[row["risk_level"]] = row["c"]

        recent_users = conn.execute(
            """SELECT id, email, username, role, created_at, analysis_count, last_login
               FROM users ORDER BY created_at DESC LIMIT 20"""
        ).fetchall()

        avg_score = conn.execute(
            "SELECT AVG(risk_score) as a FROM analysis_meta"
        ).fetchone()["a"]

        return {
            "total_users": total_users,
            "total_analyses": total_analyses,
            "risk_distribution": distribution,
            "average_risk_score": round(avg_score, 1) if avg_score else 0,
            "recent_users": [dict(u) for u in recent_users],
        }
    finally:
        conn.close()


def get_detection_rules():
    """Get all detection rules."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM detection_rules ORDER BY category, severity DESC"
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_detection_rule(category, pattern, severity="medium"):
    """Add a new detection rule."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO detection_rules (category, pattern, severity) VALUES (?, ?, ?)",
            (category, pattern, severity),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def update_detection_rule(rule_id, enabled=None, pattern=None, severity=None):
    """Update an existing detection rule."""
    conn = get_db()
    try:
        updates = []
        params = []
        if enabled is not None:
            updates.append("enabled=?")
            params.append(int(enabled))
        if pattern is not None:
            updates.append("pattern=?")
            params.append(pattern)
        if severity is not None:
            updates.append("severity=?")
            params.append(severity)
        if updates:
            updates.append("updated_at=datetime('now')")
            params.append(rule_id)
            conn.execute(
                f"UPDATE detection_rules SET {', '.join(updates)} WHERE id=?", params
            )
            conn.commit()
        return True
    finally:
        conn.close()


def delete_detection_rule(rule_id):
    """Delete a detection rule."""
    conn = get_db()
    try:
        conn.execute("DELETE FROM detection_rules WHERE id=?", (rule_id,))
        conn.commit()
        return True
    finally:
        conn.close()
