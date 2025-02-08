#!/usr/bin/env python3
"""
TorGuard WireGuard VPN Manager
A secure web interface for managing WireGuard VPN configurations
"""

import os
import sys
import subprocess
import json
import time
import secrets
from datetime import datetime
from pathlib import Path
from functools import wraps

from flask import Flask, request, render_template, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
import bcrypt
from cryptography.fernet import Fernet
import netifaces
import psutil

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
csrf = CSRFProtect(app)

CONF_DIR = Path('/etc/wireguard-manager')
WG_CONF_PATH = Path('/etc/wireguard/wg0.conf')
KEY_FILE = CONF_DIR / 'key.enc'
CREDS_FILE = CONF_DIR / 'credentials.enc'

def initialize_crypto():
    """Initialize encryption key for storing sensitive data"""
    if not CONF_DIR.exists():
        CONF_DIR.mkdir(mode=0o700)
    
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        KEY_FILE.chmod(0o600)
    
    return Fernet(KEY_FILE.read_bytes())

crypto = initialize_crypto()

def requires_auth(f):
    """Decorator to require authentication for routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not CREDS_FILE.exists():
            return redirect(url_for('register'))
        if 'authenticated' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def check_system_config():
    """Verify system configuration for WireGuard"""
    issues = []
    
    # Check IP forwarding
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            if f.read().strip() != '1':
                issues.append("IP forwarding is not enabled")
    except Exception as e:
        issues.append(f"Failed to check IP forwarding: {str(e)}")

    # Check NAT rules
    try:
        output = subprocess.check_output(['iptables', '-t', 'nat', '-L', 'POSTROUTING', '-n'], text=True)
        if "MASQUERADE" not in output:
            issues.append("NAT masquerade rule is missing")
    except Exception as e:
        issues.append(f"Failed to check NAT rules: {str(e)}")

    # Check WireGuard module
    try:
        subprocess.check_output(['lsmod'], text=True)
        if 'wireguard' not in subprocess.check_output(['lsmod'], text=True):
            issues.append("WireGuard kernel module is not loaded")
    except Exception as e:
        issues.append(f"Failed to check WireGuard module: {str(e)}")

    return issues

def get_wg_status():
    """Get WireGuard interface status and statistics"""
    try:
        # Check system configuration
        system_issues = check_system_config()
        if system_issues:
            return {
                'status': 'error',
                'issues': system_issues
            }

        # Check WireGuard interface
        if not WG_CONF_PATH.exists():
            return {'status': 'disconnected', 'message': 'No configuration file found'}

        try:
            output = subprocess.check_output(['wg', 'show', 'wg0'], text=True)
            if 'peer' not in output:
                return {'status': 'disconnected'}
            
            # Parse WireGuard stats
            stats = {'status': 'connected'}
            for line in output.split('\n'):
                if 'transfer:' in line:
                    tx, rx = line.split('transfer:')[1].split(',')
                    stats['tx'] = tx.strip()
                    stats['rx'] = rx.strip()
                elif 'latest handshake:' in line:
                    time_str = line.split('latest handshake:')[1].strip()
                    stats['connected_since'] = time_str
            
            # Add interface information
            try:
                interface_stats = psutil.net_io_counters(pernic=True).get('wg0', None)
                if interface_stats:
                    stats['total_tx'] = f"{interface_stats.bytes_sent / (1024*1024):.2f} MB"
                    stats['total_rx'] = f"{interface_stats.bytes_recv / (1024*1024):.2f} MB"
            except:
                pass

            return stats
        except subprocess.CalledProcessError:
            return {'status': 'disconnected'}
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }

def validate_wireguard_config(config):
    """Validate WireGuard configuration format"""
    required_fields = {
        'Interface': ['PrivateKey', 'Address'],
        'Peer': ['PublicKey', 'AllowedIPs', 'Endpoint']
    }
    
    current_section = None
    found_fields = {'Interface': set(), 'Peer': set()}
    
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            continue
            
        if current_section and '=' in line:
            key = line.split('=')[0].strip()
            if current_section in found_fields and key in required_fields[current_section]:
                found_fields[current_section].add(key)
    
    # Check if all required fields are present
    missing_fields = []
    for section, fields in required_fields.items():
        for field in fields:
            if field not in found_fields[section]:
                missing_fields.append(f"{section}/{field}")
    
    return len(missing_fields) == 0, missing_fields

@app.route('/')
def index():
    if not CREDS_FILE.exists():
        return redirect(url_for('register'))
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    status = get_wg_status()
    return render_template('index.html', status=status, WG_CONF_PATH=WG_CONF_PATH)

@app.route('/status')
@requires_auth
def get_status_route():
    """API endpoint for getting VPN status"""
    return jsonify(get_wg_status())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not CREDS_FILE.exists():
        return redirect(url_for('register'))
        
    if 'authenticated' in session:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            stored_creds = json.loads(crypto.decrypt(CREDS_FILE.read_bytes()))
            if username == stored_creds['username'] and \
               check_password_hash(stored_creds['password'], password):
                session['authenticated'] = True
                session['username'] = username
                return redirect(url_for('index'))
        except Exception as e:
            app.logger.error(f"Login error: {str(e)}")
            flash('Error accessing credentials')
            return render_template('login.html')
        
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if CREDS_FILE.exists():
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Validate input
        if not username or not password:
            flash('Username and password are required')
            return render_template('register.html')
        
        if len(password) < 8:
            flash('Password must be at least 8 characters long')
            return render_template('register.html')
        
        try:
            # Store encrypted credentials
            creds = {
                'username': username,
                'password': generate_password_hash(password)
            }
            CREDS_FILE.write_bytes(crypto.encrypt(json.dumps(creds).encode()))
            CREDS_FILE.chmod(0o600)
            flash('Account created successfully. Please login.')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Registration error: {str(e)}")
            flash('Error creating account')
            
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/config', methods=['POST'])
@requires_auth
def save_config():
    try:
        if 'config_file' in request.files:
            config = request.files['config_file'].read().decode()
        else:
            config = request.form['config_text']
        
        # Validate WireGuard config format
        is_valid, missing_fields = validate_wireguard_config(config)
        if not is_valid:
            flash(f'Invalid WireGuard configuration. Missing fields: {", ".join(missing_fields)}')
            return redirect(url_for('index'))
        
        # Save config securely
        WG_CONF_PATH.write_text(config)
        WG_CONF_PATH.chmod(0o600)
        
        flash('Configuration saved successfully')
    except Exception as e:
        app.logger.error(f"Config save error: {str(e)}")
        flash('Error saving configuration')
        
    return redirect(url_for('index'))

@app.route('/toggle', methods=['POST'])
@requires_auth
def toggle_vpn():
    status = get_wg_status()
    
    try:
        if status['status'] == 'connected':
            subprocess.run(['wg-quick', 'down', 'wg0'], check=True)
            flash('VPN disconnected successfully')
        else:
            # Check system configuration before connecting
            issues = check_system_config()
            if issues:
                flash(f'System configuration issues found: {", ".join(issues)}')
                return redirect(url_for('index'))
                
            subprocess.run(['wg-quick', 'up', 'wg0'], check=True)
            flash('VPN connected successfully')
    except subprocess.CalledProcessError as e:
        app.logger.error(f"VPN toggle error: {e.stderr.decode() if e.stderr else str(e)}")
        flash(f'Error toggling VPN: {e.stderr.decode() if e.stderr else str(e)}')
    except Exception as e:
        app.logger.error(f"VPN toggle error: {str(e)}")
        flash(f'Error toggling VPN: {str(e)}')
        
    return redirect(url_for('index'))

def main():
    """Main entry point"""
    # Check if running as root
    if os.geteuid() != 0:
        print("This program must be run as root")
        sys.exit(1)
    
    # Initialize directories
    CONF_DIR.mkdir(mode=0o700, exist_ok=True)
    
    # Check system configuration
    issues = check_system_config()
    if issues:
        print("Warning: System configuration issues found:")
        for issue in issues:
            print(f"  - {issue}")
    
    # Start Flask server
    app.run(host='0.0.0.0', port=1337)

if __name__ == '__main__':
    main()