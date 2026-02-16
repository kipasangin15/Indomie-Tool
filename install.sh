#!/data/data/com.termux/files/usr/bin/bash
# ============================================
clear
echo "╔════════════════════════════════════╗"
echo "║   INDOMIE TOOL INSTALLER    ║"
echo "╚════════════════════════════════════╝"
echo ""

# ========== STEP 1: UPDATE ==========
echo "[1/4] Updating packages..."
pkg update -y && pkg upgrade -y

# ========== STEP 2: INSTALL TERMUX PACKAGES ==========
echo "[2/4] Installing main packages..."
pkg install -y nmap python git curl wget ruby figlet toilet

# ========== STEP 3: INSTALL RUBY GEMS ==========
echo "[3/4] Installing Ruby gems..."
gem install lolcat

# ========== STEP 4: INSTALL PYTHON MODULES ==========
echo "[4/4] Installing Python modules..."
pip install --upgrade pip
pip install -r requirements.txt

# ========== SELESAI ==========
echo ""
echo "✅ INSTALLATION COMPLETE!"
echo ""
echo "To run the tool:"
echo "  chmod +x indomie.py"
echo "  ./indomie.py"
echo ""
