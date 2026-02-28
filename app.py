"""PhishShield AI - Main Flask Application"""
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import html
import re
import os

from config import Config
from models import db, User, AnalysisMetadata, DetectionRule
from auth import auth_bp
from detection.engine import analyze_text

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = 'auth.login'
login_manager.login_message_category = 'warning'

app.register_blueprint(auth_bp)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.before_request
def check_session_timeout():
    """30-minute session timeout on inactivity."""
    if current_user.is_authenticated:
        last_activity = session.get('last_activity')
        if last_activity:
            elapsed = datetime.utcnow() - datetime.fromisoformat(last_activity)
            if elapsed > timedelta(minutes=30):
                from flask_login import logout_user
                logout_user()
                flash('Session expired due to inactivity.', 'warning')
                return redirect(url_for('auth.login'))
        session['last_activity'] = datetime.utcnow().isoformat()


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('auth.login'))


@app.route('/dashboard')
@login_required
def dashboard():
    analyses = AnalysisMetadata.query.filter_by(
        user_id=current_user.id
    ).order_by(AnalysisMetadata.timestamp.desc()).limit(10).all()

    total = AnalysisMetadata.query.filter_by(user_id=current_user.id).count()
    safe_count = AnalysisMetadata.query.filter_by(
        user_id=current_user.id, risk_level='safe'
    ).count()
    suspicious_count = AnalysisMetadata.query.filter_by(
        user_id=current_user.id, risk_level='suspicious'
    ).count()
    high_risk_count = AnalysisMetadata.query.filter_by(
        user_id=current_user.id, risk_level='high_risk'
    ).count()

    return render_template('dashboard.html',
                           analyses=analyses,
                           total=total,
                           safe_count=safe_count,
                           suspicious_count=suspicious_count,
                           high_risk_count=high_risk_count)


@app.route('/analysis', methods=['GET', 'POST'])
@login_required
def analysis():
    result = None
    if request.method == 'POST':
        text = request.form.get('message_text', '')

        if 'message_file' in request.files:
            file = request.files['message_file']
            if file and file.filename and file.filename.endswith(('.txt', '.eml')):
                content = file.read().decode('utf-8', errors='ignore')
                if content.strip():
                    text = content

        if not text.strip():
            flash('Please provide a message to analyze.', 'warning')
            return render_template('analysis.html', result=None)

        result = analyze_text(text)

        meta = AnalysisMetadata(
            user_id=current_user.id,
            risk_level=result['risk_level'],
            risk_score=result['final_score'],
            rule_score=result['rule_score'],
            nlp_score=result['nlp_score'],
            regex_score=result['regex_score'],
        )
        db.session.add(meta)
        db.session.commit()

        result['highlighted_text'] = _highlight_suspicious(text, result)

    return render_template('analysis.html', result=result)


@app.route('/api/analyze', methods=['POST'])
@login_required
def api_analyze():
    """JSON API endpoint for analysis."""
    data = request.get_json()
    if not data or not data.get('text'):
        return jsonify({'error': 'No text provided'}), 400

    text = data['text']
    if len(text) > 10000:
        return jsonify({'error': 'Text too long (max 10000 characters)'}), 400

    result = analyze_text(text)

    meta = AnalysisMetadata(
        user_id=current_user.id,
        risk_level=result['risk_level'],
        risk_score=result['final_score'],
        rule_score=result['rule_score'],
        nlp_score=result['nlp_score'],
        regex_score=result['regex_score'],
    )
    db.session.add(meta)
    db.session.commit()

    return jsonify({
        'score': result['final_score'],
        'risk_level': result['risk_level'],
        'label': result['label'],
        'emoji': result['emoji'],
        'findings': result['findings'],
        'tips': result['tips'],
        'confidence': result['confidence'],
        'engine_scores': {
            'rule_based': result['rule_score'],
            'nlp': result['nlp_score'],
            'regex': result['regex_score'],
        }
    })


@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))

    total_users = User.query.count()
    total_analyses = AnalysisMetadata.query.count()
    safe_count = AnalysisMetadata.query.filter_by(risk_level='safe').count()
    suspicious_count = AnalysisMetadata.query.filter_by(risk_level='suspicious').count()
    high_risk_count = AnalysisMetadata.query.filter_by(risk_level='high_risk').count()
    recent_analyses = AnalysisMetadata.query.order_by(
        AnalysisMetadata.timestamp.desc()
    ).limit(20).all()
    rules = DetectionRule.query.all()

    return render_template('admin/panel.html',
                           total_users=total_users,
                           total_analyses=total_analyses,
                           safe_count=safe_count,
                           suspicious_count=suspicious_count,
                           high_risk_count=high_risk_count,
                           recent_analyses=recent_analyses,
                           rules=rules)


@app.route('/admin/rules/add', methods=['POST'])
@login_required
def admin_add_rule():
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    data = request.get_json()
    rule = DetectionRule(
        category=data.get('category', ''),
        pattern=data.get('pattern', ''),
        weight=float(data.get('weight', 1.0)),
        created_by=current_user.id
    )
    db.session.add(rule)
    db.session.commit()
    return jsonify({'success': True, 'id': rule.id})


@app.route('/admin/rules/<int:rule_id>/toggle', methods=['POST'])
@login_required
def admin_toggle_rule(rule_id):
    if current_user.role != 'admin':
        return jsonify({'error': 'Unauthorized'}), 403
    rule = DetectionRule.query.get_or_404(rule_id)
    rule.is_active = not rule.is_active
    db.session.commit()
    return jsonify({'success': True, 'is_active': rule.is_active})


def _highlight_suspicious(text: str, result: dict) -> str:
    """Highlight suspicious phrases in text for display."""
    safe_text = html.escape(text)

    from detection.rule_based import URGENT_PHRASES, THREAT_KEYWORDS, SENSITIVE_REQUESTS
    all_phrases = URGENT_PHRASES + THREAT_KEYWORDS + SENSITIVE_REQUESTS

    for phrase in sorted(all_phrases, key=len, reverse=True):
        pattern = re.compile(re.escape(html.escape(phrase)), re.IGNORECASE)
        safe_text = pattern.sub(
            f'<mark class="highlight-suspicious" title="Suspicious phrase">{html.escape(phrase)}</mark>',
            safe_text
        )

    return safe_text


def create_admin_user():
    """Create default admin user with a random password if not exists."""
    admin = User.query.filter_by(email='admin@phishshield.ai').first()
    if not admin:
        import secrets as _secrets
        random_password = _secrets.token_urlsafe(16) + 'A1!'  # meets complexity rules
        admin = User(
            email='admin@phishshield.ai',
            username='admin',
            role='admin',
            is_verified=True
        )
        admin.set_password(random_password)
        db.session.add(admin)
        db.session.commit()
        print("=" * 60)
        print("DEFAULT ADMIN CREATED — SAVE THESE CREDENTIALS NOW:")
        print(f"  Email:    admin@phishshield.ai")
        print(f"  Password: {random_password}")
        print("=" * 60)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_admin_user()
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=5000)
