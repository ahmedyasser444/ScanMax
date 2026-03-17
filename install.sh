#!/bin/bash

# ======================================
# 🚀 ScanMax Pro Installer (Updated)
# ======================================

echo "======================================"
echo "🚀 ScanMax Pro Installer Starting..."
echo "======================================"

# ----------------------------
# 1️⃣ Detect OS
# ----------------------------
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "[+] Detected OS: $OS"

# ----------------------------
# 2️⃣ Update system
# ----------------------------
echo "[+] Updating system..."
sudo apt update -y && sudo apt upgrade -y

# ----------------------------
# 3️⃣ Install base packages
# ----------------------------
echo "[+] Installing base packages..."
sudo apt install -y python3 python3-venv python3-pip git curl nmap

# ----------------------------
# 4️⃣ Setup Python Virtual Environment
# ----------------------------
echo "[+] Setting up Python virtual environment..."
cd "$(dirname "$0")"
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "[✔] Virtual environment created at $(pwd)/venv"
fi

# Activate venv and install requirements
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# ----------------------------
# 5️⃣ Add alias for scanmax
# ----------------------------
echo "[+] Adding alias..."
ALIAS_CMD="alias scanmax='source $(pwd)/venv/bin/activate && python $(pwd)/scanmax.py'"
SHELL_RC=""

# Detect shell
if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

# Add alias if not already added
if ! grep -Fxq "$ALIAS_CMD" "$SHELL_RC"; then
    echo "$ALIAS_CMD" >> "$SHELL_RC"
    echo "[✔] Alias added to $SHELL_RC"
fi

# ----------------------------
# 6️⃣ Done
# ----------------------------
echo "[✔] Installation completed successfully!"
echo "🔥 You can now run:"
echo "   scanmax example.com"
echo "⚠ If command not found, restart terminal or run:"
echo "   source $SHELL_RC"