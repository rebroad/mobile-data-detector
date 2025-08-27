# Three UK Mobile Data Detector

A simple, reliable system to detect when your Android device is using Three UK mobile data vs WiFi and apply intelligent bandwidth throttling based on your remaining data allowance.

## How It Works

The detector uses **public IP analysis** - the most reliable method to determine if you're using mobile data:

1. **Gets your public IP address** from multiple services (ifconfig.me, icanhazip.com, etc.)
2. **Resolves the hostname** for that IP address using reverse DNS
3. **Checks if the hostname contains Three UK domains** (threembb.co.uk, three.co.uk, three.com)
4. **Applies bandwidth throttling** based on your remaining data allowance

This method is much more reliable than gateway detection or speed tests because:
- It directly identifies the carrier network you're connected to
- It works regardless of your phone's internal gateway configuration
- It doesn't waste bandwidth with speed tests
- It's the same method used by websites to detect your location/carrier

## Features

- ✅ **Reliable detection** using public IP analysis
- ✅ **Bandwidth tracking** - monitors your actual data usage
- ✅ **Intelligent throttling** - reduces speed based on remaining allowance
- ✅ **No process killing** - just throttles bandwidth
- ✅ **Desktop notifications** - informs you of connection changes
- ✅ **Usage statistics** - track daily and monthly usage
- ✅ **Automatic operation** - runs as a system service

## Installation

1. **Clone or download the files** to your system
2. **Run the installation script:**
   ```bash
   sudo ./install.sh
   ```

The script will:
- Install required packages (python3, requests, tc, iproute2)
- Copy the detector to `/usr/local/bin/`
- Create a systemd service
- Set up log rotation
- Create user-friendly commands
- Start the service automatically

## Usage

### Commands

- `mobile-status` - Show service status and current detection results
- `mobile-test` - Run a manual detection test
- `mobile-usage` - Show detailed usage statistics

### Service Management

```bash
# Start/stop/restart the service
sudo systemctl start mobile-detector.service
sudo systemctl stop mobile-detector.service
sudo systemctl restart mobile-detector.service

# Enable/disable auto-start
sudo systemctl enable mobile-detector.service
sudo systemctl disable mobile-detector.service

# View logs
sudo journalctl -u mobile-detector.service -f
```

### Configuration

Edit `/etc/mobile_data_monitor.conf` to customize:

```bash
# Detection settings
DETECTION_INTERVAL=30          # Check every 30 seconds
BANDWIDTH_CHECK_INTERVAL=60    # Update usage every 60 seconds
MONTHLY_ALLOWANCE_GB=60        # Your monthly data allowance

# Android connection patterns
ANDROID_CONNECTIONS="Ed's iPhone,Android,Personal Hotspot,USB Tethering"

# Bandwidth throttling
ENABLE_THROTTLING=true
MIN_BANDWIDTH_MBPS=0.5         # Minimum speed (0.5 Mbps)
MAX_BANDWIDTH_MBPS=50          # Maximum speed (50 Mbps)
```

## How Throttling Works

When mobile data is detected, the system:

1. **Calculates remaining allowance percentage**
2. **Applies proportional throttling**:
   - 100% allowance remaining = no throttling
   - 50% allowance remaining = 50% of max speed
   - 25% allowance remaining = 25% of max speed
   - etc.

3. **Uses Linux Traffic Control (tc)** to limit bandwidth at the network interface level

## Example Output

```
=== Three UK Mobile Data Detection Test ===

1. Public IP Analysis:
   Public IP: 92.40.217.174
   Hostname: 92.40.217.174.threembb.co.uk
   ✓ Three UK mobile data detected

2. Android Connection:
   ✓ Android connection detected

3. Overall Detection:
   Mobile data detected: True
   Remaining allowance: 85%
```

## Files

- `mobile_detector.py` - Main detection script
- `mobile-detector.service` - systemd service file
- `install.sh` - Installation script
- `README.md` - This file

## Troubleshooting

1. **Service not starting:**
   ```bash
   sudo systemctl status mobile-detector.service
   sudo journalctl -u mobile-detector.service -n 50
   ```

2. **Detection not working:**
   ```bash
   mobile-test
   ```

3. **Check logs:**
   ```bash
   sudo tail -f /var/log/mobile_detector.log
   ```

4. **Verify public IP manually:**
   ```bash
   curl ifconfig.me
   nslookup $(curl -s ifconfig.me)
   ```

## Why This Method Works

Mobile carriers assign specific IP ranges and hostnames to their networks. When you connect to Three UK's mobile data, your public IP will resolve to a hostname containing their domain (like `threembb.co.uk`). This is the same method used by:

- Streaming services to detect your location
- Websites to show region-specific content
- CDNs to route traffic efficiently

It's much more reliable than trying to detect gateway IPs or measure network characteristics, which can vary significantly.

## License

This project is provided as-is for educational and personal use. Modify and distribute as needed.
