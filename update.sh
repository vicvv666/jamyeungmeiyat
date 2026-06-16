#!/bin/bash
# One-shot update script for drunk.vic999.com
# Run on server: bash /opt/jamyeungmeiyat/update.sh
set -e
cd /opt/jamyeungmeiyat

echo "=== Updating 今晚飲咗未 ==="

# Install git if missing
if ! command -v git &>/dev/null; then
    echo "Installing git..."
    yum install -y git
fi

# If not a git repo, clone it
if [ ! -d .git ]; then
    echo "Cloning from GitHub..."
    cd /opt
    rm -rf jamyeungmeiyat_bak 2>/dev/null || true
    mv jamyeungmeiyat jamyeungmeiyat_bak 2>/dev/null || true
    git clone https://github.com/vicvv666/jamyeungmeiyat.git
    cd jamyeungmeiyat
    # Restore local config
    cp ../jamyeungmeiyat_bak/data/jymy.db data/jymy.db 2>/dev/null || true
    cp ../jamyeungmeiyat_bak/.env .env 2>/dev/null || true
else
    # Pull latest
    echo "Pulling latest from GitHub..."
    git fetch origin
    git reset --hard origin/master
fi

# Install dependencies
pip3 install -r requirements.txt 2>/dev/null || pip install -r requirements.txt 2>/dev/null || true

# Restart service
echo "Restarting service..."
systemctl restart jamyeungmeiyat
sleep 2
systemctl is-active jamyeungmeiyat

echo "=== Update complete! ==="
