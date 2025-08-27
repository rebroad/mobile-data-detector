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
from typing import Dict, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/mobile_detector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class MobileDetector:
    def __init__(self, config_file: str = "/etc/mobile_data_monitor.conf"):
        self.config_file = config_file
        self.config = self.load_config()
        self.usage_file = "/var/lib/mobile_data_monitor/usage.json"
        self.running = False
        
        # Mobile carrier domains (Three UK as default)
        self.mobile_carrier_domains = self.config.get('mobile_carrier_domains', [
            'threembb.co.uk',
            'three.co.uk', 
            'three.com'
        ])
        
        # Initialize usage tracking
        self.init_usage_tracking()
    
    def load_config(self) -> Dict:
        """Load configuration from file"""
        default_config = {
            'detection_interval': 30,
            'bandwidth_check_interval': 60,
            'monthly_allowance_gb': 60,
            'android_connections': ["Ed's iPhone", "Android", "Personal Hotspot", "USB Tethering"],
            'enable_throttling': True,
            'min_bandwidth_mbps': 0.5,
            'max_bandwidth_mbps': 50,
            'mobile_carrier_domains': [
                'threembb.co.uk',
                'three.co.uk',
                'three.com'
            ]
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_content = f.read()
                    for line in config_content.split('\n'):
                        if '=' in line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"')
                            if key in default_config:
                                if isinstance(default_config[key], list):
                                    default_config[key] = [v.strip() for v in value.split(',')]
                                elif isinstance(default_config[key], bool):
                                    default_config[key] = value.lower() == 'true'
                                else:
                                    default_config[key] = value
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        return default_config
    
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
    
    def run_command(self, cmd: list, timeout: int = 10) -> tuple[int, str, str]:
        """Run a command and return (return_code, stdout, stderr)"""
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout
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
        for domain in self.mobile_carrier_domains:
            if domain in hostname.lower():
                logger.info(f"Mobile data detected: {hostname}")
                return True
        
        return False
    
    def is_android_connection(self) -> bool:
        """Check if current connection is Android tether"""
        try:
            cmd = ["nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active"]
            returncode, stdout, stderr = self.run_command(cmd)
            
            if returncode != 0:
                logger.error(f"Failed to get active connections: {stderr}")
                return False
            
            for line in stdout.strip().split('\n'):
                if line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        name = parts[0]
                        conn_type = parts[1]
                        
                        if conn_type in ['wifi', 'ethernet']:
                            for pattern in self.config['android_connections']:
                                if pattern.lower() in name.lower():
                                    logger.info(f"Android connection detected: {name}")
                                    return True
            
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
    
    def detect_mobile_data(self) -> bool:
        """Detect if using mobile data"""
        if not self.is_android_connection():
            return False
        
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
            
            # Test public IP
            print("\n1. Public IP Analysis:")
            public_ip = detector.get_public_ip()
            if public_ip:
                print(f"   Public IP: {public_ip}")
                hostname = detector.get_public_ip_hostname(public_ip)
                if hostname:
                    print(f"   Hostname: {hostname}")
                    if detector.is_mobile_data():
                        print("   ✓ Mobile data detected")
                    else:
                        print("   ✗ Not mobile data")
                else:
                    print("   ✗ Could not resolve hostname")
            else:
                print("   ✗ Could not get public IP")
            
            # Test Android connection
            print("\n2. Android Connection:")
            if detector.is_android_connection():
                print("   ✓ Android connection detected")
            else:
                print("   ✗ No Android connection detected")
            
            # Overall detection
            print("\n3. Overall Detection:")
            is_mobile = detector.detect_mobile_data()
            print(f"   Mobile data detected: {is_mobile}")
            
            if is_mobile:
                remaining_percent = detector.get_remaining_allowance_percent()
                print(f"   Remaining allowance: {remaining_percent}%")
            
        elif command == "status":
            # Show current status
            is_android = detector.is_android_connection()
            print(f"Android connection: {is_android}")
            
            if is_android:
                is_mobile = detector.detect_mobile_data()
                print(f"Mobile data: {is_mobile}")
                
                if is_mobile:
                    remaining_percent = detector.get_remaining_allowance_percent()
                    print(f"Remaining allowance: {remaining_percent}%")
            
            # Show usage statistics
            usage_stats = detector.get_usage_stats()
            if usage_stats:
                print(f"Data usage: {usage_stats['total_gb']}GB / {usage_stats['allowance_gb']}GB")
                print(f"Remaining: {usage_stats['remaining_percent']}%")
            
        elif command == "usage":
            # Show detailed usage statistics
            usage_stats = detector.get_usage_stats()
            if usage_stats:
                print("=== Mobile Data Usage Statistics ===")
                print(f"Total usage: {usage_stats['total_gb']}GB / {usage_stats['allowance_gb']}GB")
                print(f"Remaining: {usage_stats['remaining_percent']}%")
                print(f"Allowance remaining: {usage_stats['remaining_gb']}GB")
                
                if usage_stats['daily_usage']:
                    print("\nRecent daily usage:")
                    for date, usage in list(usage_stats['daily_usage'].items())[-5:]:
                        print(f"  {date}: {usage}MB")
            else:
                print("No usage data available")
            
        elif command == "start":
            # Start monitoring
            detector.start()
            
        else:
            print("Usage: python3 mobile_detector.py {test|status|usage|start}")
    else:
        print("Usage: python3 mobile_detector.py {test|status|usage|start}")

if __name__ == "__main__":
    main()
