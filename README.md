# TorGuard WireGuard Manager for Ubuntu/Debian Servers

This is the TorGuard WireGuard web interface for managing WireGuard VPN connections on Ubuntu/Debian servers. This tool provides a simple, user-friendly dashboard for managing your TorGuard WireGuard VPN configuration from a web browser. You can upload or paste new WireGuard configs and connect or disconnect the VPN tunnel through the web interface. This tool has been tested on Ubuntu/Debian servers and is compatible with both x86 and ARM architectures. It is compatible with TorGuard's shared IP or Dedicated IP WireGuard services, as well as its Dedicated WireGuard services for remote access or self-hosting.

If you install this on a public web server, make sure to register with a unique password, and it is recommended to restrict IP access in the TG member's area.

![Screenshot 1](https://gittylab.com/ben/TorGuard_WireGuard/raw/branch/main/static/screenshot1.png)

![Screenshot 2](https://gittylab.com/ben/TorGuard_WireGuard/raw/branch/main/static/screenshot2.png)

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![TorGuard](https://img.shields.io/badge/TorGuard-Official-green.svg)

## Features

- 🌐 Modern, responsive web interface for WireGuard management
- 🔒 Enterprise-grade authentication system with password strength enforcement
- 📊 Real-time connection status and detailed transfer statistics
- 🔄 Easy configuration import with validation
- 🚀 One-click connect/disconnect with status feedback
- 🔧 Automatic system configuration and dependency management
- 🎯 Systemd integration for reliable boot-time autostart
- 🛡️ Security features and input validation
- 📈 Live status updates and connection monitoring

## Prerequisites

- Ubuntu/Debian-based system (20.04 LTS or newer recommended)
- Python 3.8 or higher
- Root/sudo privileges
- Internet connection for TorGuard services

## Quick Start

1. Download the latest release:
```bash
git clone https://github.com/torguardvpn/wireguard-server-manager.git
```

2. Run the installer script:
```bash
sudo python3 install.py
```

3. Access the web interface:
```
http://your-server-ip:1337
```

## Security Features

- 🔐 Secure credential storage using bcrypt and Fernet encryption
- 🛡️ CSRF protection on all forms
- 🔒 Strict file permissions and ownership
- 🚫 Input validation and sanitization
- 🔑 Secure session management
- 🔍 Real-time password strength meter
- 🚦 Rate limiting for authentication attempts
- 🛑 Protection against brute force attacks

## System Integration

The installer configures:

1. System Services:
   - `wg-quick@wg0.service` for WireGuard with enhanced dependencies
   - `wireguard-manager.service` with systemd hardening

2. Network Configuration:
   - IP forwarding with sysctl persistence
   - NAT rules with iptables-persistent
   - DNS configuration (Cloudflare 1.1.1.1)
   - Network service dependencies

3. Security Settings:
   - Restricted file permissions
   - Secure directory ownership
   - Protected configuration storage
   - System service hardening

## Web Interface Features

- Dashboard:
  - Real-time connection status
  - Live transfer statistics
  - Total bandwidth usage
  - Connection duration tracking
  - System status monitoring

- Configuration:
  - Secure config import
  - File upload with validation
  - Format verification
  - Syntax highlighting
  - Auto-save functionality

- Security:
  - Password strength requirements
  - Session management
  - Activity logging
  - Secure logout

## Troubleshooting

1. **Verification**
   Check service status:
   ```bash
   sudo systemctl status wireguard-manager
   sudo systemctl status wg-quick@wg0
   ```

2. **Diagnostics**
   View detailed logs:
   ```bash
   sudo journalctl -u wireguard-manager -f
   sudo journalctl -u wg-quick@wg0 -f
   ```

3. **Common Solutions**
   - Port access: `sudo ufw allow 1337/tcp`
   - Service issues: `sudo systemctl restart wireguard-manager`
   - Permission fixes: `sudo chmod -R 700 /etc/wireguard-manager`

## Support

For official TorGuard support:
- Visit: https://torguard.net/support
- Email: support@torguard.net
- Live Chat: Available 24/7 on TorGuard website

## Uninstall

To uninstall and reverse all changes run:
```bash
sudo python3 uninstall.py
```

---

Powered by TorGuard® - Secure Private VPN Service
https://torguard.net
