#!/usr/bin/env python3
"""
Mobile Data Detector
Uses public IP analysis to detect mobile data usage and apply bandwidth throttling
Supports multiple carriers with Three UK as default
"""

import subprocess
import time
import json
import logging
import os
import signal
import sys
import socket
import requests
import ipaddress
import re
from typing import Dict, Optional

# Configure logging
def setup_logging():
    """Setup logging with fallback for non-root users"""
    handlers = [logging.StreamHandler()]

    # Try to add file handler if we have permission
    try:
        handlers.append(logging.FileHandler('/var/log/mobile_detector.log'))
    except PermissionError:
        # Fallback to user's home directory
        log_dir = os.path.expanduser('~/.local/share/mobile-detector')
        os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(os.path.join(log_dir, 'mobile_detector.log')))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger(__name__)

class MobileDetector:
    def __init__(self, config_file: str = "/etc/mobile_data_monitor.conf"):
        self.config_file = config_file
        self.config = self.load_config()

        # Set usage file path based on permissions
        if os.access("/var/lib", os.W_OK):
            self.usage_file = "/var/lib/mobile_data_monitor/usage.json"
        else:
            # Fallback to user's home directory
            usage_dir = os.path.expanduser('~/.local/share/mobile-detector')
            self.usage_file = os.path.join(usage_dir, 'usage.json')

        self.running = False

        # No hardcoded carrier domains; read from config when needed

        # Initialize usage tracking
        self.init_usage_tracking()

    def load_config(self) -> Dict:
        """Load configuration from file. Single source of truth is the config file."""
        loaded: Dict = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_content = f.read()
                    for line in config_content.split('\n'):
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            # Normalize keys to lowercase for internal usage
                            k_norm = key.lower()
                            # List-like values (comma-separated)
                            if k_norm in {
                                'android_ssid_whitelist',
                                'unthrottled_ssid_whitelist',
                                'android_subnets',
                                'mobile_carrier_domains'
                            }:
                                loaded[k_norm] = [v.strip() for v in value.split(',') if v.strip()]
                            elif k_norm in {
                                'enable_throttling'
                            }:
                                loaded[k_norm] = value.lower() == 'true'
                            elif k_norm in {
                                'detection_interval',
                                'bandwidth_check_interval',
                                'monthly_allowance_gb',
                                'min_bandwidth_mbps',
                                'max_bandwidth_mbps'
                            }:
                                try:
                                    # ints for intervals/allowance; floats for bandwidth
                                    if k_norm.endswith('_mbps'):
                                        loaded[k_norm] = float(value)
                                    else:
                                        loaded[k_norm] = int(value)
                                except ValueError:
                                    pass
                            elif k_norm in {
                                'three_allowance_url',
                                'ssid_cookie_profiles'
                            }:
                                if k_norm == 'ssid_cookie_profiles':
                                    loaded[k_norm] = [v.strip() for v in value.split(',') if v.strip()]
                                else:
                                    loaded[k_norm] = value
                            else:
                                loaded[k_norm] = value
            except Exception as e:
                logger.error(f"Error loading config: {e}")

        return loaded

    def get_active_ssid(self) -> Optional[str]:
        """Return the active WiFi SSID (connection name) if connected."""
        # Check if we're in test mode with a specific SSID
        if hasattr(self, '_test_ssid') and self._test_ssid:
            return self._test_ssid
            
        rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        if rc == 0:
            for line in devs_out.strip().split('\n'):
                if not line:
                    continue
                device, dtype, state, connection_name = (line.split(':') + [None, None, None, None])[:4]
                if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                    return connection_name
        return None

    def fetch_three_allowance(self) -> Optional[dict]:
        """Fetch Three Mobile allowance data using external three_client.py script"""
        try:
            import subprocess, os
            three_client_path = os.path.join(os.path.dirname(__file__), 'three_client.py')
            # Create a pipe for FD 3
            r_fd, w_fd = os.pipe()
            # Build environment (pass-through)
            env = os.environ.copy()
            # Get current SSID to pass to external script (use test SSID if set)
            current_ssid = getattr(self, '_test_ssid', None) or self.get_active_ssid()
            # Spawn child with FD 3 duplicated to writer end
            cmd = [sys.executable, three_client_path]
            if current_ssid:
                cmd.append(current_ssid)
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(w_fd,),
                env=env
            )
            # Parent doesn't write
            os.close(w_fd)
            # Read remaining MB from r_fd
            with os.fdopen(r_fd, 'rb', closefd=True) as rf:
                fd3_data = rf.read().decode(errors='ignore').strip()
            out, err = proc.communicate(timeout=120)
            if out:
                print(out.decode(errors='ignore'))
            if err:
                print(err.decode(errors='ignore'))
            try:
                remaining_mb = int(fd3_data)
            except (TypeError, ValueError):
                print("Could not parse remaining MB from three_client")
                return None
            # Return a minimal structure for upstream callers
            return {
                'remaining_mb': remaining_mb
            }
        except Exception as e:
            print(f"External three_client failed: {e}")
            return None

    def init_usage_tracking(self):
        """Initialize usage tracking file"""
        os.makedirs(os.path.dirname(self.usage_file), exist_ok=True)

        if not os.path.exists(self.usage_file):
            usage_data = {
                'current_month': time.strftime('%Y-%m'),
                'total_bytes': 0,
                'last_reset': time.strftime('%Y-%m-%d'),
                'daily_usage': {},
                'hourly_usage': {},
                'last_check': int(time.time())
            }

            with open(self.usage_file, 'w') as f:
                json.dump(usage_data, f, indent=2)

    def reset_usage_tracking(self) -> None:
        """Reset usage tracking data and last bandwidth snapshot"""
        try:
            # Remove usage file and last bandwidth snapshot
            if os.path.exists(self.usage_file):
                os.remove(self.usage_file)
            last_bandwidth_file = "/tmp/last_bandwidth"
            if os.path.exists(last_bandwidth_file):
                os.remove(last_bandwidth_file)

            # Re-initialize
            self.init_usage_tracking()
            logger.info("Usage tracking has been reset")
        except Exception as e:
            logger.error(f"Error resetting usage tracking: {e}")

    def run_command(self, cmd: list, timeout: int = 10, env: Optional[Dict] = None) -> tuple[int, str, str]:
        """Run a command and return (return_code, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    def get_public_ip(self) -> Optional[str]:
        """Get public IP address"""
        try:
            # Try multiple services for redundancy
            services = [
                'https://ifconfig.me',
                'https://icanhazip.com',
                'https://ipinfo.io/ip',
                'https://api.ipify.org'
            ]

            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        ip = response.text.strip()
                        if self.is_valid_ip(ip):
                            return ip
                except:
                    continue

            return None
        except Exception as e:
            logger.error(f"Error getting public IP: {e}")
            return None

    def is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False

    def get_public_ip_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for public IP address"""
        try:
            cmd = ["nslookup", ip]
            returncode, stdout, stderr = self.run_command(cmd, timeout=10)

            if returncode == 0:
                # Extract hostname from nslookup output
                lines = stdout.split('\n')
                for line in lines:
                    if 'name =' in line:
                        hostname = line.split('name =')[1].strip().rstrip('.')
                        return hostname

            return None
        except Exception as e:
            logger.error(f"Error getting hostname for {ip}: {e}")
            return None

    def is_mobile_data(self) -> bool:
        """Check if public IP belongs to mobile data network"""
        public_ip = self.get_public_ip()
        if not public_ip:
            return False

        hostname = self.get_public_ip_hostname(public_ip)
        if not hostname:
            return False

        logger.info(f"Public IP: {public_ip}, Hostname: {hostname}")

        # Check if hostname contains mobile carrier domains
        for domain in self.config.get('mobile_carrier_domains', []):
            if domain in hostname.lower():
                logger.info(f"Mobile data detected: {hostname}")
                return True

        return False

    def is_android_connection(self) -> bool:
        """Check if current connection is Android tether.

        Detection heuristics (any True => Android connection):
        - Active WiFi SSID matches whitelist
        - Active connection name matches configured android connection patterns
        - Default interface IPv4 address is within configured android_subnets
        - Fallback: mobile carrier hostname detection on public IP
        """
        try:
            # 1) Fast path: map default interface to active connection name (no Wi-Fi scan)
            rc, route_out, _ = self.run_command(["ip", "route", "show", "default"])
            default_iface = None
            if rc == 0 and route_out.strip():
                rparts = route_out.strip().split()
                if len(rparts) >= 5:
                    default_iface = rparts[4]

            rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
            if rc == 0:
                for line in devs_out.strip().split('\n'):
                    if not line:
                        continue
                    dparts = (line.split(':') + [None, None, None, None])[:4]
                    device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                    if dtype == 'wifi' and state and state.startswith('connected'):
                        if default_iface is None or device == default_iface:
                            if connection_name:
                                # If SSID is known mobile (case-insensitive), confirm Android/mobile tether
                                for allowed in self.config.get('android_ssid_whitelist', []):
                                    if connection_name.lower() == allowed.lower():
                                        logger.info(f"Android connection detected by SSID: {connection_name}")
                                        return True
                                # If SSID is explicitly unthrottled, still consider Android connection True
                                for unthrottled in self.config.get('unthrottled_ssid_whitelist', []):
                                    if connection_name.lower() == unthrottled.lower():
                                        logger.info(f"Unthrottled mobile SSID detected: {connection_name}")
                                        return True

            # 2) Check active connection names/types (non-whitelist path and capture iface types)
            rc, stdout, stderr = self.run_command(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"])
            if rc != 0:
                logger.error(f"Failed to get active connections: {stderr}")
                return False

            active_iface_types = {}
            for line in stdout.strip().split('\n'):
                if not line:
                    continue
                    parts = line.split(':')
                if len(parts) >= 3:
                    _name, conn_type, device = parts[0], parts[1], parts[2]
                elif len(parts) >= 2:
                    _name, conn_type = parts[0], parts[1]
                    device = None
                else:
                    continue

                if conn_type in ['wifi', 'ethernet'] and device:
                    active_iface_types[device] = conn_type

            # 3) Check default interface subnet against whitelist
            rc, route_out, _ = self.run_command(["ip", "route", "show", "default"])
            if rc == 0 and route_out.strip():
                parts = route_out.strip().split()
                if len(parts) >= 5:
                    default_iface = parts[4]
                    # Get the IPv4 address on that interface
                    rc, addr_out, _ = self.run_command(["ip", "-4", "addr", "show", default_iface])
                    if rc == 0:
                        for line in addr_out.split('\n'):
                            line = line.strip()
                            if line.startswith('inet '):
                                ip_cidr = line.split()[1]  # e.g. 10.231.218.176/24
                                try:
                                    iface_network = ipaddress.ip_interface(ip_cidr).network
                                    for subnet in self.config.get('android_subnets', []):
                                        try:
                                            net = ipaddress.ip_network(subnet, strict=False)
                                            if ipaddress.ip_interface(ip_cidr).ip in net:
                                                logger.info(f"Android connection detected by subnet {subnet} on {default_iface}")
                                                return True
                                        except ValueError:
                                            continue
                                except ValueError:
                                    pass
                                break

            # 4) Do not fall back to public IP here; let detect_mobile_data handle IP checks

            return False
        except Exception as e:
            logger.error(f"Error checking Android connection: {e}")
            return False

    def get_bandwidth_usage(self) -> tuple[int, int]:
        """Get current bandwidth usage from network interface"""
        try:
            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]

                        rx_path = f"/sys/class/net/{interface}/statistics/rx_bytes"
                        tx_path = f"/sys/class/net/{interface}/statistics/tx_bytes"

                        rx_bytes = 0
                        tx_bytes = 0

                        if os.path.exists(rx_path):
                            with open(rx_path, 'r') as f:
                                rx_bytes = int(f.read().strip())

                        if os.path.exists(tx_path):
                            with open(tx_path, 'r') as f:
                                tx_bytes = int(f.read().strip())

                        return rx_bytes, tx_bytes

            return 0, 0
        except Exception as e:
            logger.error(f"Error getting bandwidth usage: {e}")
            return 0, 0

    def update_usage_tracking(self) -> int:
        """Update usage tracking and return total bytes used"""
        current_rx, current_tx = self.get_bandwidth_usage()
        current_time = int(time.time())
        current_date = time.strftime('%Y-%m-%d')
        current_hour = time.strftime('%Y-%m-%d-%H')

        # Load current usage data
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            usage_data = {
                'total_bytes': 0,
                'daily_usage': {},
                'hourly_usage': {},
                'last_check': 0
            }

        last_check = usage_data.get('last_check', 0)
        total_bytes = usage_data.get('total_bytes', 0)

        if last_check == 0:
            last_check = current_time

        # Get last bandwidth values
        last_bandwidth_file = "/tmp/last_bandwidth"
        last_rx = last_tx = 0

        if os.path.exists(last_bandwidth_file):
            try:
                with open(last_bandwidth_file, 'r') as f:
                    values = f.read().strip().split()
                    if len(values) >= 2:
                        last_rx, last_tx = int(values[0]), int(values[1])
            except (ValueError, IndexError):
                pass

        # Save current values
        with open(last_bandwidth_file, 'w') as f:
            f.write(f"{current_rx} {current_tx}")

        # Calculate delta (handle counter wraparound)
        rx_delta = current_rx - last_rx
        tx_delta = current_tx - last_tx

        # Handle counter wraparound (32-bit unsigned int max)
        if rx_delta < 0:
            rx_delta += 4294967295
        if tx_delta < 0:
            tx_delta += 4294967295

        total_delta = rx_delta + tx_delta
        new_total = total_bytes + total_delta

        # Update usage data
        usage_data.update({
            'current_month': time.strftime('%Y-%m'),
            'total_bytes': new_total,
            'last_reset': current_date,
            'daily_usage': {current_date: new_total // (1024 * 1024)},
            'hourly_usage': {current_hour: total_delta // (1024 * 1024)},
            'last_check': current_time
        })

        # Save updated data
        with open(self.usage_file, 'w') as f:
            json.dump(usage_data, f, indent=2)

        # Log bandwidth usage
        usage_mb = total_delta // (1024 * 1024)
        total_gb = new_total // (1024 * 1024 * 1024)
        allowance_gb = self.config.get('monthly_allowance_gb', 60)
        logger.info(f"Bandwidth usage: {usage_mb}MB (Total: {total_gb}GB / {allowance_gb}GB)")

        return new_total

    def get_remaining_allowance_percent(self) -> int:
        """Get remaining allowance percentage"""
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

            total_bytes = usage_data.get('total_bytes', 0)
            total_gb = total_bytes // (1024 * 1024 * 1024)
            allowance_gb = self.config.get('monthly_allowance_gb', 60)
            remaining_gb = allowance_gb - total_gb

            if remaining_gb <= 0:
                return 0

            percent = (remaining_gb * 100) // allowance_gb
            return percent
        except Exception as e:
            logger.error(f"Error calculating remaining allowance: {e}")
            return 100

    def apply_bandwidth_throttling(self, remaining_percent: int):
        """Apply bandwidth throttling based on remaining allowance"""
        if not self.config.get('enable_throttling', True):
            return

        try:
            # Skip throttling entirely if connected to an explicitly unthrottled SSID
            rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
            if rc == 0:
                for line in devs_out.strip().split('\n'):
                    if not line:
                        continue
                    dparts = (line.split(':') + [None, None, None, None])[:4]
                    _device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                    if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                        if connection_name in self.config.get('unthrottled_ssid_whitelist', []):
                            logger.info(f"Skipping throttling for unthrottled SSID: {connection_name}")
                            return

            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]

                        if remaining_percent == 100:
                            # Remove throttling
                            subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                         capture_output=True)
                            return

                        # Calculate bandwidth limit
                        max_bandwidth = self.config.get('max_bandwidth_mbps', 50)
                        min_bandwidth = self.config.get('min_bandwidth_mbps', 0.5)

                        limited_bandwidth = (max_bandwidth * remaining_percent) // 100

                        if limited_bandwidth < min_bandwidth:
                            limited_bandwidth = min_bandwidth

                        logger.info(f"Applying bandwidth limit: {limited_bandwidth}Mbps ({remaining_percent}% of allowance remaining)")

                        # Apply tc rules
                        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                     capture_output=True)
                        subprocess.run(["tc", "qdisc", "add", "dev", interface, "root", "handle", "1:", "htb", "default", "30"],
                                     capture_output=True)
                        subprocess.run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:1", "htb",
                                       "rate", f"{limited_bandwidth}mbit"], capture_output=True)
                        subprocess.run(["tc", "class", "add", "dev", interface, "parent", "1:", "classid", "1:30", "htb",
                                       "rate", f"{limited_bandwidth}mbit"], capture_output=True)
        except Exception as e:
            logger.error(f"Error applying bandwidth throttling: {e}")

    def remove_bandwidth_throttling(self):
        """Remove bandwidth throttling"""
        try:
            cmd = ["ip", "route", "show", "default"]
            returncode, stdout, stderr = self.run_command(cmd)

            if returncode == 0 and stdout.strip():
                lines = stdout.strip().split('\n')
                if lines:
                    parts = lines[0].split()
                    if len(parts) >= 5:
                        interface = parts[4]
                        subprocess.run(["tc", "qdisc", "del", "dev", interface, "root"],
                                     capture_output=True)
        except Exception as e:
            logger.error(f"Error removing bandwidth throttling: {e}")

    def detect_mobile_data(self, force_android: Optional[bool] = None) -> bool:
        """Detect if using mobile data, prioritizing SSID.

        - If SSID is in android_ssid_whitelist: treat as mobile without IP check
        - If SSID is in unthrottled_ssid_whitelist: treat as mobile but later avoid throttling
        - Else, fall back to public IP hostname check
        """
        # Determine Android connection quickly
        is_android = force_android if force_android is not None else self.is_android_connection()
        if not is_android:
            return False

        # If we matched on SSID already, skip IP checks
        rc, devs_out, _ = self.run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device"])
        if rc == 0:
            for line in devs_out.strip().split('\n'):
                if not line:
                    continue
                dparts = (line.split(':') + [None, None, None, None])[:4]
                device, dtype, state, connection_name = dparts[0], dparts[1], dparts[2], dparts[3]
                if dtype == 'wifi' and state and state.startswith('connected') and connection_name:
                    if any(connection_name.lower() == s.lower() for s in self.config.get('android_ssid_whitelist', [])) or \
                       any(connection_name.lower() == s.lower() for s in self.config.get('unthrottled_ssid_whitelist', [])):
                        return True

        # Otherwise, check the carrier via public IP hostname
        return self.is_mobile_data()

    def monitor_network(self):
        """Main monitoring loop"""
        last_state = "unknown"
        last_bandwidth_check = 0

        logger.info("Starting mobile data monitoring...")

        while self.running:
            try:
                current_time = int(time.time())

                # Update bandwidth usage tracking
                if current_time - last_bandwidth_check >= self.config.get('bandwidth_check_interval', 60):
                    self.update_usage_tracking()
                    last_bandwidth_check = current_time

                is_mobile = self.detect_mobile_data()

                if is_mobile:
                    remaining_percent = self.get_remaining_allowance_percent()

                    if last_state != "mobile":
                        logger.info(f"Mobile data detected - applying bandwidth throttling")
                        self.apply_bandwidth_throttling(remaining_percent)
                        last_state = "mobile"

                        # Notify user
                        try:
                            subprocess.run(["notify-send", "Mobile Data Active",
                                          f"Bandwidth throttling applied. {remaining_percent}% allowance remaining.",
                                          "-u", "normal"], capture_output=True)
                        except:
                            pass
                    elif self.config.get('enable_throttling', True):
                        # Update throttling based on current usage
                        self.apply_bandwidth_throttling(remaining_percent)
                else:
                    if last_state != "wifi":
                        logger.info(f"WiFi connection detected - removing bandwidth throttling")
                        self.remove_bandwidth_throttling()
                        last_state = "wifi"

                        # Notify user
                        try:
                            subprocess.run(["notify-send", "WiFi Connection Detected",
                                          "Bandwidth throttling removed. Full speed enabled.",
                                          "-u", "normal"], capture_output=True)
                        except:
                            pass

                time.sleep(self.config.get('detection_interval', 30))

            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(5)

    def start(self):
        """Start the monitoring service"""
        self.running = True
        self.monitor_network()

    def stop(self):
        """Stop the monitoring service"""
        self.running = False
        self.remove_bandwidth_throttling()

    def get_usage_stats(self) -> Dict:
        """Get usage statistics"""
        try:
            with open(self.usage_file, 'r') as f:
                usage_data = json.load(f)

            total_bytes = usage_data.get('total_bytes', 0)
            total_gb = total_bytes // (1024 * 1024 * 1024)
            allowance_gb = self.config.get('monthly_allowance_gb', 60)
            remaining_gb = allowance_gb - total_gb
            remaining_percent = (remaining_gb * 100) // allowance_gb if allowance_gb > 0 else 0

            return {
                'total_gb': total_gb,
                'allowance_gb': allowance_gb,
                'remaining_gb': remaining_gb,
                'remaining_percent': remaining_percent,
                'daily_usage': usage_data.get('daily_usage', {}),
                'hourly_usage': usage_data.get('hourly_usage', {})
            }
        except Exception as e:
            logger.error(f"Error getting usage stats: {e}")
            return {}

def main():
    detector = MobileDetector()

    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        detector.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "test":
            # Run a comprehensive detection test
            print("=== Mobile Data Detection Test ===")

            # Android/SSID first (fast path)
            print("\nAndroid/SSID:")
            android_connected = detector.is_android_connection()
            if android_connected:
                print("   ✓ Android connection detected")
            else:
                print("   ✗ No Android connection detected")

            # Public IP Analysis only if SSID not recognized as mobile
            is_mobile_by_ip = False
            if not android_connected:
                print("\nPublic IP Analysis:")
            public_ip = detector.get_public_ip()
            if public_ip:
                print(f"   Public IP: {public_ip}")
                hostname = detector.get_public_ip_hostname(public_ip)
                if hostname:
                    print(f"   Hostname: {hostname}")
                    # Determine mobile data once (and allow logging here only)
                    is_mobile_by_ip = detector.is_mobile_data()
                    if is_mobile_by_ip:
                        print("   ✓ Mobile data detected")
                    else:
                        print("   ✗ Not mobile data")
                else:
                    print("   ✗ Could not resolve hostname")
            else:
                print("   ✗ Could not get public IP")

            # Overall detection
            print("\nOverall Detection:")
            is_mobile = android_connected or is_mobile_by_ip
            print(f"   Mobile data detected: {is_mobile}")

            if is_mobile:
                remaining_percent = detector.get_remaining_allowance_percent()
                print(f"   Remaining allowance: {remaining_percent}%")

        elif command in ["status", "usage"]:
            # Unified, concise status output
            is_android = detector.is_android_connection()
            # Avoid duplicate logs by reusing the computed Android status
            is_mobile = detector.detect_mobile_data(force_android=is_android)

            # One-line connectivity summary
            print(f"Android: {is_android} | Mobile data: {is_mobile}")

            # One-line usage summary
            usage_stats = detector.get_usage_stats()
            if usage_stats:
                line = f"Usage: {usage_stats['total_gb']}/{usage_stats['allowance_gb']}GB ({usage_stats['remaining_percent']}% remaining)"
                # If mobile, try to fetch network allowance from Three
                if is_mobile:
                    three_remaining = detector.fetch_three_allowance()
                    if three_remaining:
                        line += f" | Three: {three_remaining}"
                print(line)

                if usage_stats['daily_usage']:
                    print("\nRecent daily usage:")
                    for date, usage in list(usage_stats['daily_usage'].items())[-5:]:
                        print(f"  {date}: {usage}MB")
            else:
                print("No usage data available")

        elif command == "start":
            # Start monitoring
            detector.start()

        elif command == "reset":
            # Reset usage tracking and confirm
            detector.reset_usage_tracking()
            print("Usage tracking reset.")
        elif command == "dump-three":
            # Dump full Three allowances HTML for inspection using Selenium
            save_to = None
            if len(sys.argv) > 2:
                save_to = sys.argv[2]
            
            # Debug: show what we detect
            ssid = detector.get_active_ssid()
            print(f"Active SSID: {ssid}")
            if ssid:
                cookie_db = detector._resolve_cookie_db_for_ssid(ssid)
                print(f"Cookie DB path: {cookie_db}")
                if cookie_db and os.path.exists(cookie_db):
                    print(f"Cookie DB exists: {os.path.getsize(cookie_db)} bytes")
            else:
                    print("Cookie DB not found or invalid path")
            
            # Fetch with Selenium
            print("Fetching Three allowances page with Selenium...")
            path = detector.fetch_three_html(save_to)
            if path:
                print(f"Saved Three allowances HTML to: {path}")
            else:
                print("Failed to fetch Three allowances page (check cookies mapping and SSID)")
        
        elif command == "test-three":
            # Test Three allowance fetching with API
            test_ssid = sys.argv[2] if len(sys.argv) > 2 else None
            if test_ssid:
                print(f"Testing Three allowance fetching with API (using test SSID: {test_ssid})...")
                detector._test_ssid = test_ssid
            else:
                print("Testing Three allowance fetching with API...")
            
            allowance_data = detector.fetch_three_allowance()
            if allowance_data:
                print("✓ Found allowance data (raw response):")
                try:
                    import json as _json
                    print(_json.dumps(allowance_data, indent=2, ensure_ascii=False))
                except Exception:
                    print(allowance_data)
            else:
                print("✗ No allowance data found")
            
            # Clean up test SSID
            if test_ssid:
                detector._test_ssid = None
        
        elif command == "refresh-three":
            print("Refreshing Three Mobile session...")
            ssid = detector.get_active_ssid()
            if not ssid:
                print("Could not determine active SSID")
                return
            
            cookie_db_path = detector._resolve_cookie_db_for_ssid(ssid)
            if not cookie_db_path:
                print(f"No cookie database configured for SSID: {ssid}")
                return
            
            cookie_header = detector._load_cookie_header_via_helper(cookie_db_path)
            if not cookie_header:
                print(f"No cookies found in database: {cookie_db_path}")
                return
            
            if detector._refresh_session(cookie_header):
                print("✅ Session refreshed successfully!")
                print("You can now run 'test-three' to fetch your allowance data.")
            else:
                print("❌ Session refresh failed. Please log in to Three Mobile in your browser.")
                print("1. Go to https://www.three.co.uk/account")
                print("2. Log in to your account")
                print("3. Run 'refresh-three' again")
        else:
            print("Usage: python3 mobile_detector.py {test|status|start|reset|dump-three [path]|test-three [ssid]|refresh-three}")

if __name__ == "__main__":
    main()
