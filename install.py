#!/usr/bin/env python3
"""
TorGuard WireGuard Manager Installer
Installs and configures the WireGuard Manager web interface with complete system setup
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path
import time

def print_step(emoji, message):
    """Print a step with emoji and message"""
    print(f"\n{emoji}  {message}")

def run_command(command, error_message, shell=False):
    """Run a shell command and handle errors"""
    try:
        if shell:
            subprocess.run(command, check=True, shell=True)
        else:
            subprocess.run(command, check=True)
        print("✅ Done!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {error_message}")
        if hasattr(e, 'stderr') and e.stderr:
            print(f"Details: {e.stderr.decode()}")
        return False

def get_local_ip():
    """Get the local IP address"""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"

def setup_wireguard():
    """Set up WireGuard with complete system configuration"""
    print_step("🔒", "Setting up WireGuard system configuration...")

    # Ensure WireGuard kernel module is loaded
    print("Loading WireGuard kernel module...")
    run_command("sudo modprobe wireguard", "Failed to load WireGuard kernel module", shell=True)

    # Enable IP forwarding
    print("Enabling IP forwarding...")
    run_command(
        "sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf",
        "Failed to update sysctl.conf",
        shell=True
    )
    run_command(
        "sudo sysctl -p",
        "Failed to apply sysctl changes",
        shell=True
    )

    # Apply iptables rules
    print("Applying iptables rules to allow SSH and route traffic correctly...")

    # Ensure SSH access is allowed
    ssh_rules = [
        "sudo iptables -I INPUT -p tcp --dport 22 -j ACCEPT",
        "sudo iptables -I OUTPUT -p tcp --sport 22 -j ACCEPT",
        "sudo iptables -I FORWARD -p tcp --dport 22 -j ACCEPT",
        "sudo iptables -t nat -I POSTROUTING -p tcp --dport 22 -j RETURN"
    ]

    for rule in ssh_rules:
        run_command(rule, f"Failed to apply iptables rule: {rule}", shell=True)

    # Apply NAT rules for VPN traffic
    nat_rules = [
        "sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        "sudo iptables -A FORWARD -i wg0 -j ACCEPT",
        "sudo iptables -A FORWARD -o wg0 -j ACCEPT"
    ]

    for rule in nat_rules:
        run_command(rule, f"Failed to apply iptables rule: {rule}", shell=True)

    # Install and save iptables rules persistently
    print("Installing and saving iptables-persistent...")
    run_command(["apt-get", "install", "-y", "iptables-persistent"], "Failed to install iptables-persistent")
    run_command("sudo netfilter-persistent save", "Failed to save iptables rules", shell=True)
    run_command("sudo netfilter-persistent reload", "Failed to reload iptables rules", shell=True)

    # Update nameserver
    print("Updating nameserver...")
    run_command(
        "sudo sed -i 's/nameserver .*/nameserver 1.1.1.1/' /etc/resolv.conf",
        "Failed to update nameserver",
        shell=True
    )

    # Install iptables-persistent and save rules
    print("Making iptables rules persistent...")
    run_command(
        ["apt-get", "install", "-y", "iptables-persistent"],
        "Failed to install iptables-persistent"
    )
    run_command(
        "sudo iptables-save | sudo tee /etc/iptables/rules.v4",
        "Failed to save iptables rules",
        shell=True
    )

def main():
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        sys.exit(1)

    print("""
🚀 TorGuard WireGuard Manager Installer
=======================================
This installer will set up WireGuard and the Manager web interface.
    """)

    # System update and upgrade
    print_step("📦", "Updating system packages...")
    run_command(["apt-get", "update"], "Failed to update package list")
    run_command(["apt-get", "upgrade", "-y"], "Failed to upgrade packages")

     # Install WireGuard
    print_step("🔧", "Installing WireGuard...")
    run_command(
        ["apt-get", "install", "-y", "wireguard", "wireguard-tools"],
        "Failed to install WireGuard"
    )

    # Ensure WireGuard module is loaded at boot
    run_command("echo 'wireguard' | sudo tee -a /etc/modules-load.d/wireguard.conf", "Failed to set WireGuard module to load at boot", shell=True)

    install_dir = Path("/opt/wireguard-manager")
    config_dir = Path("/etc/wireguard-manager")
    service_file = Path("/etc/systemd/system/wireguard-manager.service")

    # Create directories
    print_step("📁", "Creating installation directories...")
    install_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)

    # Install Python dependencies
    print_step("🐍", "Setting up Python environment...")
    run_command(
        ["apt-get", "install", "-y", "python3-pip", "python3-venv"],
        "Failed to install Python tools"
    )

    # Create virtual environment
    run_command(
        ["python3", "-m", "venv", str(install_dir / "venv")],
        "Failed to create virtual environment"
    )

    # Install Python packages
    pip = install_dir / "venv/bin/pip"
    run_command(
        [str(pip), "install", "flask", "flask-wtf", "cryptography", "bcrypt", "werkzeug", "netifaces", "psutil"],
        "Failed to install Python packages"
    )

    # Upgrade pip and setuptools
    run_command(
        [str(pip), "install", "--upgrade", "pip", "setuptools"],
        "Failed to upgrade pip and setuptools"
    )

    # Copy application files
    print_step("📝", "Installing application files...")
    script_dir = Path(__file__).parent.resolve()

    files_to_copy = {
        "app.py": install_dir / "app.py",
        "templates/base.html": install_dir / "templates/base.html",
        "templates/index.html": install_dir / "templates/index.html",
        "templates/login.html": install_dir / "templates/login.html",
        "templates/register.html": install_dir / "templates/register.html",
    }

    for src, dest in files_to_copy.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(script_dir / src, dest)

    # Create static directories and copy files
    static_dir = install_dir / "static"
    css_dir = static_dir / "css"
    js_dir = static_dir / "js"

    # Ensure directories exist
    css_dir.mkdir(parents=True, exist_ok=True)
    js_dir.mkdir(parents=True, exist_ok=True)

    # Copy CSS files
    css_files = ["bootstrap.min.css", "bootstrap-icons.css"]
    for css_file in css_files:
        src = script_dir / "static/css" / css_file
        dest = css_dir / css_file
        if src.exists():
            shutil.copy2(src, dest)

    # Copy JS files
    js_files = ["bootstrap.bundle.min.js"]
    for js_file in js_files:
        src = script_dir / "static/js" / js_file
        dest = js_dir / js_file
        if src.exists():
            shutil.copy2(src, dest)

    # Copy Bootstrap Icons fonts
    fonts_dir = static_dir / "fonts"
    fonts_dir.mkdir(parents=True, exist_ok=True)

    font_files = ["bootstrap-icons.woff", "bootstrap-icons.woff2"]
    for font_file in font_files:
        src = script_dir / f"static/fonts/{font_file}"
        dest = fonts_dir / font_file
        if src.exists():
            shutil.copy2(src, dest)  # Fixed indentation here

    # Copy logo.png
    if (script_dir / "static/logo.png").exists():
        shutil.copy2(script_dir / "static/logo.png", static_dir / "logo.png")


    # Set permissions
    print_step("🔒", "Setting secure permissions...")
    run_command(["chown", "-R", "root:root", str(install_dir)], "Failed to set ownership")
    run_command(["chmod", "-R", "755", str(install_dir)], "Failed to set permissions")
    run_command(["chmod", "700", str(config_dir)], "Failed to set config directory permissions")

    # Configure WireGuard system settings
    setup_wireguard()

    # Create systemd service for web interface
    print_step("⚙️", "Creating web interface service...")
    service_content = f"""[Unit]
Description=TorGuard WireGuard Manager
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory={install_dir}
Environment=PATH={install_dir}/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart={install_dir}/venv/bin/python3 {install_dir}/app.py
Restart=always
RestartSec=3
TimeoutStartSec=0

# Hardening
ProtectSystem=full
ReadWritePaths={install_dir} /etc/wireguard /etc/wireguard-manager
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""
    service_file.write_text(service_content)

    # Enable and start web interface service
    print_step("🎯", "Starting web interface...")
    run_command(["systemctl", "enable", "wireguard-manager"], "Failed to enable web interface service")
    run_command(["systemctl", "restart", "wireguard-manager"], "Failed to start web interface service")

    # Final instructions
    local_ip = get_local_ip()
    print(f"""
✨ Installation Complete! ✨
==========================

WireGuard Manager has been installed successfully!

📱 Access the web interface at:
   http://{local_ip}:1337

💡 On first access, you'll be prompted to create an admin account.

✅ System Configuration:
   - WireGuard is installed and ready
   - IP forwarding is enabled
   - NAT rules are configured
   - DNS is set to 1.1.1.1
   - Web interface will start automatically on boot

📝 Important locations:
   - WireGuard config: /etc/wireguard/wg0.conf
   - Manager config: {config_dir}
   - Web interface: {install_dir}

⚠️  Security Notes:
   - Make sure port 1337 is only accessible from trusted networks
   - Use a strong password for your admin account
   - Keep your system and packages updated

Need help? Visit https://torguard.net/support
""")

if __name__ == "__main__":
    main()