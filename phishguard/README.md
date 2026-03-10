# 🛡️ PhishGuard AI — Cybersecurity Platform

A full-stack AI-powered phishing detection system with professional dark cybersecurity UI.

## Features
- ✅ Sign Up / Sign In system with secure password hashing
- ✅ Admin dashboard with user management
- ✅ AI phishing detection (Gradient Boosting, 96.7% accuracy)
- ✅ Risk percentage prediction (ML + rule-based hybrid)
- ✅ 50+ suspicious keyword detection
- ✅ Domain entropy & age analysis
- ✅ Email phishing detector (sender, subject, body)
- ✅ Threat intelligence cross-referencing (5 feeds)
- ✅ Scan history database with filtering
- ✅ Statistics dashboard with Chart.js visualizations
- ✅ Phishing reporting system
- ✅ Export PDF security reports (ReportLab)
- ✅ Professional dark cybersecurity UI with animations
- ✅ Brand impersonation detection
- ✅ IP-in-URL detection
- ✅ Suspicious TLD detection
- ✅ Subdomain count analysis

## Quick Start

### Option 1: Use the run script (recommended)
```bash
python run.py
```

### Option 2: Manual setup
```bash
pip install -r requirements.txt
python app.py
```

Open browser at: **http://localhost:5000**

## Default Login
- **Username:** admin
- **Password:** admin123

## Project Structure
```
phishguard/
├── app.py                  # Main Flask application
├── run.py                  # Quick start script
├── requirements.txt        # Dependencies
├── utils/
│   ├── phishing_detector.py  # ML-based URL analyzer
│   ├── email_analyzer.py     # Email phishing scanner
│   ├── threat_intel.py       # Threat intelligence feeds
│   └── report_generator.py   # PDF report generation
├── templates/
│   ├── base.html           # Base layout with sidebar
│   ├── landing.html        # Landing page with particles
│   ├── auth.html           # Sign in / Sign up
│   ├── dashboard.html      # Main dashboard
│   ├── scan.html           # URL & Email scanner
│   ├── history.html        # Scan history
│   ├── statistics.html     # Analytics charts
│   ├── report.html         # Report phishing
│   └── admin.html          # Admin panel
└── models/                 # Trained ML models (auto-generated)
```

## Technologies
- **Backend:** Python, Flask, SQLAlchemy, Flask-Bcrypt
- **AI/ML:** Scikit-learn (Gradient Boosting Classifier)
- **Frontend:** HTML5, CSS3, Vanilla JS, Chart.js
- **PDF:** ReportLab
- **Database:** SQLite
