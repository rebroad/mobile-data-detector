#!/bin/bash

# Three UK Mobile Data Detector Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Three UK Mobile Data Detector Installation${NC}"
echo "=============================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root${NC}"
   echo "Please run: sudo $0"
   exit 1
fi

# Install required packages
echo -e "${YELLOW}Installing required packages...${NC}"
apt update
apt install -y python3 python3-pip iproute2 tc requests

# Install Python requests if not available
pip3 install --break-system-packages requests

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p /var/lib/mobile_data_monitor
mkdir -p /var/log

# Copy script
echo -e "${YELLOW}Installing script...${NC}"
cp mobile_detector.py /usr/local/bin/mobile_detector
chmod +x /usr/local/bin/mobile_detector

# Install systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
cp mobile-detector.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

# Create default configuration
echo -e "${YELLOW}Creating default configuration...${NC}"
cat > /etc/mobile_data_monitor.conf << EOF
# Mobile Data Monitor Configuration
DETECTION_INTERVAL=30
BANDWIDTH_CHECK_INTERVAL=60
MONTHLY_ALLOWANCE_GB=60

# Android connection identifiers (partial matches)
ANDROID_CONNECTIONS="Ed's iPhone,Android,Personal Hotspot,USB Tethering"

# Mobile carrier domains (comma-separated, Three UK by default)
MOBILE_CARRIER_DOMAINS="threembb.co.uk,three.co.uk,three.com"

# Bandwidth throttling settings
ENABLE_THROTTLING=true
MIN_BANDWIDTH_MBPS=0.5
MAX_BANDWIDTH_MBPS=50
EOF

# Set up log rotation
echo -e "${YELLOW}Setting up log rotation...${NC}"
cat > /etc/logrotate.d/mobile_detector << EOF
/var/log/mobile_detector.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

# Create user-friendly commands
echo -e "${YELLOW}Creating user commands...${NC}"
cat > /usr/local/bin/mobile-status << 'EOF'
#!/bin/bash
echo "=== Mobile Data Detector Status ==="
systemctl status mobile-detector.service --no-pager -l
echo ""
echo "=== Detection Test ==="
python3 /usr/local/bin/mobile_detector status
EOF

cat > /usr/local/bin/mobile-test << 'EOF'
#!/bin/bash
echo "=== Mobile Data Detection Test ==="
python3 /usr/local/bin/mobile_detector test
EOF

cat > /usr/local/bin/mobile-usage << 'EOF'
#!/bin/bash
echo "=== Mobile Data Usage ==="
python3 /usr/local/bin/mobile_detector usage
EOF

chmod +x /usr/local/bin/mobile-status
chmod +x /usr/local/bin/mobile-test
chmod +x /usr/local/bin/mobile-usage

# Enable and start service
echo -e "${YELLOW}Enabling and starting service...${NC}"
systemctl enable mobile-detector.service
systemctl start mobile-detector.service

# Test the installation
echo -e "${YELLOW}Testing installation...${NC}"
sleep 2

if systemctl is-active --quiet mobile-detector.service; then
    echo -e "${GREEN}✓ Service is running${NC}"
else
    echo -e "${RED}✗ Service failed to start${NC}"
    systemctl status mobile-detector.service
fi

# Test the detector
echo -e "${YELLOW}Testing detector...${NC}"
python3 /usr/local/bin/mobile_detector test

echo ""
echo -e "${GREEN}Installation completed successfully!${NC}"
echo ""
echo -e "${BLUE}Available commands:${NC}"
echo "  mobile-status  - Show service status and detection results"
echo "  mobile-test    - Run detection test"
echo "  mobile-usage   - Show usage statistics"
echo ""
echo -e "${BLUE}Service management:${NC}"
echo "  sudo systemctl start/stop/restart mobile-detector.service"
echo "  sudo systemctl enable/disable mobile-detector.service"
echo ""
echo -e "${BLUE}Configuration:${NC}"
echo "  Edit /etc/mobile_data_monitor.conf to customize settings"
echo ""
echo -e "${YELLOW}The service is now running and will automatically detect mobile data usage.${NC}"
