#!/usr/bin/env python3
"""
PhishGuard AI — Startup Script
Installs dependencies and launches the application.
"""
import subprocess, sys, os

def install():
    print("📦 Installing dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"])
    print("✅ Dependencies installed.")

def run():
    print("\n🛡️  Starting PhishGuard AI...")
    print("🌐  Open your browser at: http://localhost:5000")
    print("👤  Default admin: admin / admin123\n")
    os.system(f"{sys.executable} app.py")

if __name__ == "__main__":
    install()
    run()
