#!/bin/bash

set -e

echo "=== i6.shark Disk Cleanup ==="

# 1. Clean up journal logs (major disk space consumer)
echo "[1/6] Cleaning up systemd journal logs..."
journalctl --vacuum-size=50M
journalctl --vacuum-time=2d

# 2. Clear old logs
echo "[2/6] Clearing old log files..."
find /var/log -type f -name "*.log" -mtime +7 -delete 2>/dev/null || true
find /var/log -type f -name "*.gz" -delete 2>/dev/null || true
find /var/log -type f -name "*.1" -delete 2>/dev/null || true
find /var/log -type f -name "*.old" -delete 2>/dev/null || true

# Truncate large log files instead of deleting
for logfile in /var/log/syslog /var/log/messages /var/log/auth.log; do
    if [ -f "$logfile" ]; then
        truncate -s 0 "$logfile" 2>/dev/null || true
    fi
done

# 3. Clean apt cache
echo "[3/6] Cleaning apt cache..."
apt-get clean 2>/dev/null || true
apt-get autoremove -y 2>/dev/null || true

# 4. Configure journald to limit disk usage
echo "[4/6] Configuring journald limits..."
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/size-limit.conf << 'EOF'
[Journal]
SystemMaxUse=100M
RuntimeMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxFileSize=10M
MaxRetentionSec=7day
Compress=yes
EOF

# Restart journald to apply
systemctl restart systemd-journald

