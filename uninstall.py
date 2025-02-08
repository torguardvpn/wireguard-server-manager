#!/usr/bin/env python3
"""
TorGuard WireGuard Manager Uninstaller
Completely removes the WireGuard Manager, its configurations, services, and dependencies.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

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

def remove_firewall_rules():
    """Remove firewall rules related to WireGuard Manager"""
    print_step("🛑", "Removing firewall rules...")
    rules = [
        "ufw delete allow 1337/tcp",
        "ufw --force disable"
    ]
    for rule in rules:
        run_command(rule, "Failed to remove firewall rule", shell=True)

def stop_and_disable_services():
    """Stops and removes the WireGuard Manager system service"""
    print_step("🛑", "Stopping and disabling WireGuard Manager service...")
    service_name = "wireguard-manager"
    run_command(f"systemctl stop {service_name}", "Failed to stop WireGuard Manager service", shell=True)
    run_command(f"systemctl disable {service_name}", "Failed to disable WireGuard Manager service", shell=True)
    run_command(f"rm -f /etc/systemd/system/{service_name}.service", "Failed to remove service file", shell=True)
    run_command("systemctl daemon-reload", "Failed to reload systemd", shell=True)

def remove_wireguard():
    """Removes WireGuard and its configurations"""
    print_step("🗑️", "Removing WireGuard and its configurations...")
    
    # Remove WireGuard kernel module
    run_command("modprobe -r wireguard", "Failed to remove WireGuard kernel module", shell=True)
    
    # Uninstall WireGuard packages
    run_command("apt-get remove --purge -y wireguard wireguard-tools", "Failed to uninstall WireGuard", shell=True)
    
    # Remove WireGuard configurations
    run_command("rm -rf /etc/wireguard", "Failed to remove WireGuard configurations", shell=True)

def reset_network_config():
    """Resets networking configurations made by the installer"""
    print_step("🔄", "Resetting network configurations...")

    # Reset IP forwarding
    run_command("sed -i 's/net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' /etc/sysctl.conf", "Failed to reset sysctl.conf", shell=True)
    run_command("sysctl -p", "Failed to apply sysctl changes", shell=True)

    # Reset NAT rules
    run_command("iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE", "Failed to remove NAT rule", shell=True)
    run_command("iptables -D FORWARD -i wg0 -j ACCEPT", "Failed to remove iptables FORWARD rule", shell=True)
    run_command("iptables -D FORWARD -o wg0 -j ACCEPT", "Failed to remove iptables FORWARD rule", shell=True)

    # Reset iptables rules to default
    run_command("iptables -F", "Failed to flush iptables rules", shell=True)
    run_command("iptables -X", "Failed to delete custom chains", shell=True)
    run_command("iptables -t nat -F", "Failed to flush NAT rules", shell=True)
    run_command("iptables -t nat -X", "Failed to delete custom NAT chains", shell=True)

    # Remove iptables-persistent package
    run_command("apt-get remove --purge -y iptables-persistent", "Failed to remove iptables-persistent", shell=True)

def remove_wireguard_manager():
    """Deletes all files and directories related to the WireGuard Manager"""
    print_step("🗑️", "Removing WireGuard Manager files...")

    install_dir = Path("/opt/wireguard-manager")
    config_dir = Path("/etc/wireguard-manager")

    # Delete directories
    if install_dir.exists():
        shutil.rmtree(install_dir, ignore_errors=True)
    if config_dir.exists():
        shutil.rmtree(config_dir, ignore_errors=True)

    # Remove WireGuard kernel module auto-load setting
    run_command("rm -f /etc/modules-load.d/wireguard.conf", "Failed to remove WireGuard module auto-load config", shell=True)

def remove_python_env():
    """Removes the Python virtual environment"""
    print_step("🐍", "Removing Python virtual environment...")
    venv_path = Path("/opt/wireguard-manager/venv")
    if venv_path.exists():
        shutil.rmtree(venv_path, ignore_errors=True)

    # Remove Python dependencies
    run_command("apt-get remove --purge -y python3-pip python3-venv", "Failed to remove Python dependencies", shell=True)

def final_cleanup():
    """Performs final cleanup and system reset"""
    print_step("🧹", "Performing final cleanup...")
    
    # Clear APT cache
    run_command("apt-get autoremove -y", "Failed to remove unnecessary packages", shell=True)
    run_command("apt-get clean", "Failed to clean package cache", shell=True)

def main():
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        sys.exit(1)

    print("""
🛑 TorGuard WireGuard Manager Uninstaller
========================================
This will completely remove WireGuard Manager, its configurations, services, and dependencies.
    """)

    confirmation = input("⚠️ Are you sure you want to proceed? This action is irreversible! (yes/no): ").strip().lower()
    if confirmation != "yes":
        print("❌ Uninstallation aborted.")
        sys.exit(1)

    stop_and_disable_services()
    remove_firewall_rules()
    remove_wireguard()
    reset_network_config()
    remove_wireguard_manager()
    remove_python_env()
    final_cleanup()

    print("""
✅ Uninstallation Complete! 
==========================
TorGuard WireGuard Manager and all associated configurations have been successfully removed.

If you need to reinstall, run the installer script again.
""")

if __name__ == "__main__":
    main()
