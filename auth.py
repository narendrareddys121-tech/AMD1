"""Authentication Blueprint"""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
import secrets
import re
from datetime import datetime, timedelta
from models import db, User

auth_bp = Blueprint('auth', __name__)


def validate_password_strength(password):
    """Returns list of failures; empty list means password is strong."""
    errors = []
    if len(password) < 8:
        errors.append("At least 8 characters required")
    if not re.search(r'[A-Z]', password):
        errors.append("At least one uppercase letter required")
    if not re.search(r'[a-z]', password):
        errors.append("At least one lowercase letter required")
    if not re.search(r'\d', password):
        errors.append("At least one number required")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append("At least one special character required")
    return errors


def generate_otp():
    return str(secrets.randbelow(900000) + 100000)  # 6-digit OTP


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email first.', 'warning')
                return redirect(url_for('auth.login'))
            login_user(user, remember=remember)
            user.last_login = datetime.utcnow()
            db.session.commit()
            session.permanent = True
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        errors = []
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters")
        if not email or '@' not in email:
            errors.append("Valid email required")
        pw_errors = validate_password_strength(password)
        errors.extend(pw_errors)
        if password != confirm:
            errors.append("Passwords do not match")
        if User.query.filter_by(email=email).first():
            errors.append("Email already registered")
        if User.query.filter_by(username=username).first():
            errors.append("Username already taken")

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('auth/register.html')

        user = User(email=email, username=username)
        user.set_password(password)
        user.otp_code = generate_otp()
        user.otp_expiry = datetime.utcnow() + timedelta(minutes=15)
        db.session.add(user)
        db.session.commit()

        flash(f'Account created! Your verification OTP is: {user.otp_code} (valid 15 min)', 'info')
        return redirect(url_for('auth.verify_otp', user_id=user.id))

    return render_template('auth/register.html')


@auth_bp.route('/verify-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        otp = request.form.get('otp', '').strip()
        if (user.otp_code == otp and
                user.otp_expiry and
                datetime.utcnow() < user.otp_expiry):
            user.is_verified = True
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            flash('Email verified! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid or expired OTP.', 'danger')

    return render_template('auth/verify_otp.html', user_id=user_id)


@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            flash(f'Password reset link: /reset-password/{token} (valid 1 hour)', 'info')
        else:
            flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('auth.login'))
    return render_template('auth/forgot_password.html')


@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user or not user.reset_token_expiry or datetime.utcnow() > user.reset_token_expiry:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        errors = validate_password_strength(password)
        if password != confirm:
            errors.append("Passwords do not match")
        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('auth/reset_password.html', token=token)
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/reset_password.html', token=token)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
