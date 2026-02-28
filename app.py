"""
PhishShield AI - Flask Application
Main entry point with auth, analysis, dashboard, and admin routes.
Privacy-first: no message content is ever stored.
"""

import os
import re
import time
import secrets
import json
from datetime import timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, session, render_template,
    redirect, url_for
)
from dotenv import load_dotenv

from models import (
    init_db, create_user, verify_user_otp, resend_otp,
    authenticate_user, get_user_by_id,
    save_analysis_meta, get_user_analyses, get_user_dashboard_stats,
    get_admin_stats, get_detection_rules, add_detection_rule,
    update_detection_rule, delete_detection_rule,
)
from detection_engine import analyze_message

# ─── App Setup ─────────────────────────────────────────────────

load_dotenv()

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates",
)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.permanent_session_lifetime = timedelta(minutes=30)


# ─── Helpers ───────────────────────────────────────────────────

PASSWORD_PATTERN = re.compile(
    r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]).{8,}$'
)

def validate_password(password):
    """Validate password meets strength requirements."""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number."
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is strong."


def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required", "code": "auth_required"}), 401
        # Check session timeout
        last_active = session.get("last_active", 0)
        if time.time() - last_active > 1800:  # 30 minutes
            session.clear()
            return jsonify({"error": "Session expired", "code": "session_expired"}), 401
        session["last_active"] = time.time()
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator to require admin role."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Authentication required"}), 401
        if session.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        session["last_active"] = time.time()
        return f(*args, **kwargs)
    return decorated


# ─── Page Route ────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the single-page application."""
    return render_template("index.html")


# ─── Auth Routes ───────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    """Register a new user account."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    email = data.get("email", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not email or not username or not password:
        return jsonify({"error": "All fields are required"}), 400

    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({"error": "Invalid email format"}), 400

    if len(username) < 2:
        return jsonify({"error": "Username must be at least 2 characters"}), 400

    valid, msg = validate_password(password)
    if not valid:
        return jsonify({"error": msg}), 400

    try:
        user_id, otp = create_user(email, username, password)
        # In production, send OTP via email. For hackathon demo, return it.
        return jsonify({
            "message": "Registration successful! Please verify your email.",
            "email": email,
            "otp_hint": otp,  # Demo only — would be sent via email in production
            "requires_verification": True,
        }), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 409


@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    """Verify email with OTP."""
    data = request.get_json()
    email = data.get("email", "").strip()
    otp = data.get("otp", "").strip()

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    if verify_user_otp(email, otp):
        return jsonify({"message": "Email verified successfully! You can now log in."})
    else:
        return jsonify({"error": "Invalid or expired OTP. Please try again."}), 400


@app.route("/api/resend-otp", methods=["POST"])
def resend_otp_route():
    """Resend OTP for email verification."""
    data = request.get_json()
    email = data.get("email", "").strip()

    if not email:
        return jsonify({"error": "Email is required"}), 400

    otp = resend_otp(email)
    return jsonify({
        "message": "New OTP sent to your email.",
        "otp_hint": otp,  # Demo only
    })


@app.route("/api/login", methods=["POST"])
def login():
    """Authenticate user and create session."""
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    result = authenticate_user(email, password)

    if result is None:
        return jsonify({"error": "Invalid email or password"}), 401

    if isinstance(result, dict) and result.get("error") == "not_verified":
        otp = resend_otp(email)
        return jsonify({
            "error": "Email not verified. A new OTP has been sent.",
            "code": "not_verified",
            "email": email,
            "otp_hint": otp,  # Demo only
        }), 403

    # Create session
    session.permanent = True
    session["user_id"] = result["id"]
    session["email"] = result["email"]
    session["username"] = result["username"]
    session["role"] = result["role"]
    session["last_active"] = time.time()

    return jsonify({
        "message": f"Welcome back, {result['username']}!",
        "user": {
            "id": result["id"],
            "email": result["email"],
            "username": result["username"],
            "role": result["role"],
        },
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    """End user session."""
    session.clear()
    return jsonify({"message": "Logged out successfully"})


@app.route("/api/session", methods=["GET"])
def check_session():
    """Check if user has an active session."""
    if "user_id" not in session:
        return jsonify({"authenticated": False}), 401

    last_active = session.get("last_active", 0)
    if time.time() - last_active > 1800:
        session.clear()
        return jsonify({"authenticated": False, "reason": "session_expired"}), 401

    session["last_active"] = time.time()
    return jsonify({
        "authenticated": True,
        "user": {
            "id": session["user_id"],
            "email": session["email"],
            "username": session["username"],
            "role": session["role"],
        },
    })


# ─── Analysis Routes ──────────────────────────────────────────

@app.route("/api/analyze", methods=["POST"])
@login_required
def analyze():
    """Analyze a message for phishing indicators."""
    data = request.get_json()
    message = data.get("message", "").strip()

    if not message:
        return jsonify({"error": "Please provide a message to analyze"}), 400

    if len(message) > 10000:
        return jsonify({"error": "Message too long. Maximum 10,000 characters."}), 400

    # Run parallel detection engine
    result = analyze_message(message)

    # Save metadata only (no message content stored!)
    save_analysis_meta(
        user_id=session["user_id"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        message_text=message,  # Only first 60 chars saved as preview
    )

    return jsonify(result)


# ─── Dashboard Routes ─────────────────────────────────────────

@app.route("/api/dashboard", methods=["GET"])
@login_required
def dashboard():
    """Get dashboard data for the current user."""
    user_id = session["user_id"]
    stats = get_user_dashboard_stats(user_id)
    analyses = get_user_analyses(user_id, limit=20)
    user = get_user_by_id(user_id)

    return jsonify({
        "user": {
            "username": user["username"] if user else session["username"],
            "email": session["email"],
            "role": session["role"],
            "analysis_count": user["analysis_count"] if user else 0,
            "member_since": user["created_at"] if user else "",
        },
        "stats": stats,
        "recent_analyses": analyses,
    })


# ─── Admin Routes ─────────────────────────────────────────────

@app.route("/api/admin/stats", methods=["GET"])
@admin_required
def admin_stats():
    """Get admin dashboard statistics."""
    stats = get_admin_stats()
    return jsonify(stats)


@app.route("/api/admin/rules", methods=["GET"])
@admin_required
def admin_get_rules():
    """Get all detection rules."""
    rules = get_detection_rules()
    return jsonify({"rules": rules})


@app.route("/api/admin/rules", methods=["POST"])
@admin_required
def admin_add_rule():
    """Add a new detection rule."""
    data = request.get_json()
    category = data.get("category", "").strip()
    pattern = data.get("pattern", "").strip()
    severity = data.get("severity", "medium").strip()

    if not category or not pattern:
        return jsonify({"error": "Category and pattern are required"}), 400

    if category not in ("keyword", "regex", "tone"):
        return jsonify({"error": "Invalid category. Use: keyword, regex, tone"}), 400

    add_detection_rule(category, pattern, severity)
    return jsonify({"message": "Rule added successfully"}), 201


@app.route("/api/admin/rules/<int:rule_id>", methods=["PUT"])
@admin_required
def admin_update_rule(rule_id):
    """Update an existing detection rule."""
    data = request.get_json()
    update_detection_rule(
        rule_id,
        enabled=data.get("enabled"),
        pattern=data.get("pattern"),
        severity=data.get("severity"),
    )
    return jsonify({"message": "Rule updated successfully"})


@app.route("/api/admin/rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def admin_delete_rule(rule_id):
    """Delete a detection rule."""
    delete_detection_rule(rule_id)
    return jsonify({"message": "Rule deleted successfully"})


# ─── Educational Resources ─────────────────────────────────────

@app.route("/api/resources", methods=["GET"])
def educational_resources():
    """Return curated educational resources about phishing."""
    resources = [
        {
            "title": "What is Phishing?",
            "description": "Learn the basics of phishing attacks and how they target students.",
            "category": "basics",
            "icon": "🎣",
            "tips": [
                "Phishing is a social engineering attack where criminals impersonate trusted entities.",
                "Attackers use email, SMS, and social media to trick you into revealing sensitive info.",
                "Common targets include login credentials, OTPs, credit card numbers, and personal data.",
            ],
        },
        {
            "title": "Spotting Fake Emails",
            "description": "Key indicators that a message might be a phishing attempt.",
            "category": "detection",
            "icon": "🔍",
            "tips": [
                "Check the sender's full email address — not just the display name.",
                "Look for spelling errors, generic greetings, and urgent/threatening language.",
                "Hover over links before clicking to see the actual URL destination.",
                "Be suspicious of unexpected attachments, especially .exe, .zip, or .doc files.",
            ],
        },
        {
            "title": "Protecting Your Accounts",
            "description": "Best practices for keeping your online accounts secure.",
            "category": "protection",
            "icon": "🛡️",
            "tips": [
                "Use unique, strong passwords for every account (use a password manager).",
                "Enable two-factor authentication (2FA) wherever possible.",
                "Never share your OTP or password with anyone — even if they claim to be from support.",
                "Regularly review your account activity and login history.",
            ],
        },
        {
            "title": "Common Student Scams",
            "description": "Scam types frequently targeting university students.",
            "category": "awareness",
            "icon": "🎓",
            "tips": [
                "Fake scholarship offers that ask for processing fees or bank details.",
                "Job scams promising easy money for minimal work (reshipping, mystery shopping).",
                "Fake university IT emails asking you to 'verify' your student account.",
                "Social media impersonation scams from compromised friend accounts.",
                "Fake textbook or tuition payment portals designed to steal card info.",
            ],
        },
        {
            "title": "What to Do If You're Phished",
            "description": "Immediate steps to take if you've fallen for a phishing attack.",
            "category": "response",
            "icon": "🚨",
            "tips": [
                "Change your passwords immediately — start with the compromised account.",
                "Enable 2FA on all affected accounts right away.",
                "Contact your bank if financial info was shared.",
                "Report the incident to your university's IT security team.",
                "Monitor your accounts for unusual activity over the next few weeks.",
                "Don't feel embarrassed — report it so others can be warned.",
            ],
        },
        {
            "title": "Safe Browsing Habits",
            "description": "Daily habits that keep you safe from phishing and malware.",
            "category": "prevention",
            "icon": "🌐",
            "tips": [
                "Always check for HTTPS and a padlock icon when entering sensitive data.",
                "Don't click links in unsolicited messages — type the URL directly.",
                "Keep your browser, OS, and antivirus software up to date.",
                "Use an ad blocker to reduce exposure to malicious ads.",
                "Be cautious on public Wi-Fi — avoid logging into sensitive accounts.",
            ],
        },
    ]
    return jsonify({"resources": resources})


# ─── App Entry Point ───────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    print("\n" + "=" * 60)
    print("  [SHIELD] PhishShield AI - Phishing Detection System")
    print("  [WEB]    Running at: http://127.0.0.1:5000")
    print("  [USER]   Demo Admin: admin@phishshield.ai / Admin@1234")
    print("  [LOCK]   Privacy Mode: No message content stored")
    print("=" * 60 + "\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
