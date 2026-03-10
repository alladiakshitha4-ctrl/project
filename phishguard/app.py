from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import json, os, re, io
from utils.phishing_detector import PhishingDetector
from utils.email_analyzer import EmailAnalyzer
from utils.report_generator import generate_pdf_report
from utils.threat_intel import ThreatIntelligence
# Fix for psycopg2 on Vercel
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
app = Flask(__name__)
app.config['SECRET_KEY'] = 'phishguard-secret-key-2024-ultra-secure'
import os
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///phishguard.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
detector = PhishingDetector()
email_analyzer = EmailAnalyzer()
threat_intel = ThreatIntelligence()

# ─── Models ───────────────────────────────────────────────────────────────────

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    scans_count = db.Column(db.Integer, default=0)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    features = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))

class EmailScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(300))
    risk_score = db.Column(db.Float)
    verdict = db.Column(db.String(20))
    flags = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class PhishingReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    status = db.Column(db.String(20), default='pending')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ─── Auth Helpers ──────────────────────────────────────────────────────────────

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user or user.role != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def current_user():
    if 'user_id' in session:
        return User.query.get(session['user_id'])
    return None

# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required'}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'message': 'Username already taken'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'message': 'Email already registered'}), 400
        hashed = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed)
        # First user is admin
        if User.query.count() == 0:
            user.role = 'admin'
        db.session.add(user)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Account created successfully'})
    return render_template('auth.html', mode='signup')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.get_json() or request.form
        username = data.get('username', '').strip()
        password = data.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            user.last_login = datetime.utcnow()
            db.session.commit()
            return jsonify({'success': True, 'role': user.role})
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401
    return render_template('auth.html', mode='login')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = current_user()
    recent_scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).limit(5).all()
    total_scans = ScanHistory.query.filter_by(user_id=user.id).count()
    phishing_found = ScanHistory.query.filter_by(user_id=user.id, verdict='PHISHING').count()
    safe_count = ScanHistory.query.filter_by(user_id=user.id, verdict='SAFE').count()
    return render_template('dashboard.html', user=user, recent_scans=recent_scans,
                           total_scans=total_scans, phishing_found=phishing_found, safe_count=safe_count)

@app.route('/scan', methods=['GET'])
@login_required
def scan_page():
    return render_template('scan.html', user=current_user())

@app.route('/api/scan/url', methods=['POST'])
@login_required
def api_scan_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        result = detector.analyze(url)
        # Check threat intel
        ti_result = threat_intel.check_url(url)
        result['threat_intel'] = ti_result
        user = current_user()
        scan = ScanHistory(
            user_id=user.id, url=url,
            risk_score=result['risk_score'],
            verdict=result['verdict'],
            features=json.dumps(result.get('features', {})),
            ip_address=request.remote_addr
        )
        user.scans_count = (user.scans_count or 0) + 1
        db.session.add(scan)
        db.session.commit()
        result['scan_id'] = scan.id
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/email', methods=['POST'])
@login_required
def api_scan_email():
    data = request.get_json()
    subject = data.get('subject', '')
    body = data.get('body', '')
    sender = data.get('sender', '')
    result = email_analyzer.analyze(subject, body, sender)
    user = current_user()
    escan = EmailScan(user_id=user.id, subject=subject,
                      risk_score=result['risk_score'],
                      verdict=result['verdict'],
                      flags=json.dumps(result.get('flags', [])))
    db.session.add(escan)
    db.session.commit()
    return jsonify(result)

@app.route('/history')
@login_required
def history():
    user = current_user()
    scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.timestamp.desc()).all()
    return render_template('history.html', user=user, scans=scans)

@app.route('/statistics')
@login_required
def statistics():
    user = current_user()
    return render_template('statistics.html', user=user)

@app.route('/api/statistics')
@login_required
def api_statistics():
    user = current_user()
    scans = ScanHistory.query.filter_by(user_id=user.id).all()
    verdicts = {'SAFE': 0, 'SUSPICIOUS': 0, 'PHISHING': 0}
    daily = {}
    risk_dist = [0, 0, 0, 0, 0]  # 0-20, 20-40, 40-60, 60-80, 80-100
    for s in scans:
        verdicts[s.verdict] = verdicts.get(s.verdict, 0) + 1
        day = s.timestamp.strftime('%Y-%m-%d')
        daily[day] = daily.get(day, 0) + 1
        idx = min(int(s.risk_score // 20), 4)
        risk_dist[idx] += 1
    # Last 7 days
    last7 = []
    for i in range(6, -1, -1):
        d = (datetime.utcnow() - timedelta(days=i)).strftime('%Y-%m-%d')
        last7.append({'date': d, 'count': daily.get(d, 0)})
    return jsonify({'verdicts': verdicts, 'daily': last7, 'risk_distribution': risk_dist,
                    'total': len(scans), 'accuracy': detector.get_model_accuracy()})

@app.route('/report', methods=['GET'])
@login_required
def report_page():
    return render_template('report.html', user=current_user())

@app.route('/api/report', methods=['POST'])
@login_required
def api_submit_report():
    data = request.get_json()
    report = PhishingReport(
        user_id=session['user_id'],
        url=data.get('url', ''),
        description=data.get('description', ''),
        category=data.get('category', 'phishing')
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'success': True, 'message': 'Report submitted successfully', 'id': report.id})

@app.route('/api/export/pdf/<int:scan_id>')
@login_required
def export_pdf(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    if scan.user_id != session['user_id']:
        return jsonify({'error': 'Unauthorized'}), 403
    user = current_user()
    features = json.loads(scan.features) if scan.features else {}
    pdf_buffer = generate_pdf_report(scan, user, features)
    return send_file(pdf_buffer, mimetype='application/pdf',
                     as_attachment=True, download_name=f'phishguard_report_{scan_id}.pdf')

@app.route('/admin')
@admin_required
def admin():
    users = User.query.all()
    reports = PhishingReport.query.order_by(PhishingReport.timestamp.desc()).all()
    total_scans = ScanHistory.query.count()
    total_phishing = ScanHistory.query.filter_by(verdict='PHISHING').count()
    return render_template('admin.html', user=current_user(), users=users,
                           reports=reports, total_scans=total_scans, total_phishing=total_phishing)

@app.route('/api/admin/report/<int:report_id>/status', methods=['POST'])
@admin_required
def update_report_status(report_id):
    report = PhishingReport.query.get_or_404(report_id)
    data = request.get_json()
    report.status = data.get('status', 'pending')
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/admin/stats')
@admin_required
def admin_stats():
    total_users = User.query.count()
    total_scans = ScanHistory.query.count()
    total_phishing = ScanHistory.query.filter_by(verdict='PHISHING').count()
    total_reports = PhishingReport.query.count()
    pending_reports = PhishingReport.query.filter_by(status='pending').count()
    return jsonify({'total_users': total_users, 'total_scans': total_scans,
                    'total_phishing': total_phishing, 'total_reports': total_reports,
                    'pending_reports': pending_reports})

# Auto-create tables on startup (needed for Vercel)
with app.app_context():
    db.create_all()
    try:
        if User.query.count() == 0:
            hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(
                username='admin',
                email='admin@phishguard.ai',
                password=hashed,
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
    except:
        pass

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)