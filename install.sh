#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
#  MNet — Mapping Network Tool
#  Kali Linux / Debian / Ubuntu Installer
#  Author: brainrotshiva | github.com/brainrotshiva
# ─────────────────────────────────────────────────────────────────

set -e

GREEN='\033[38;5;46m'
CYAN='\033[38;5;87m'
RED='\033[38;5;196m'
GRAY='\033[38;5;245m'
RESET='\033[0m'

echo -e "${GREEN}"
echo "███╗   ███╗███╗   ██╗███████╗████████╗"
echo "████╗ ████║████╗  ██║██╔════╝╚══██╔══╝"
echo "██╔████╔██║██╔██╗ ██║█████╗     ██║   "
echo "██║╚██╔╝██║██║╚██╗██║██╔══╝     ██║   "
echo "██║ ╚═╝ ██║██║ ╚████║███████╗   ██║   "
echo "╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   "
echo -e "${RESET}${GRAY}  Mapping Network Tool  v2.0.26  |  @brainrotshiva${RESET}"
echo ""

echo -e "${CYAN}[*]${RESET} Installing MNet..."

# ── 1. Check Python 3 ─────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[-]${RESET} Python 3 not found. Installing..."
    sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+]${RESET} Python $PYTHON_VER detected"

# ── 2. Clone repo ─────────────────────────────────────────────
INSTALL_DIR="$HOME/.local/share/mnet"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${CYAN}[*]${RESET} Updating existing installation..."
    cd "$INSTALL_DIR" && git pull -q
else
    echo -e "${CYAN}[*]${RESET} Cloning MNet repository..."
    git clone https://github.com/brainrotshiva/mnet "$INSTALL_DIR" -q
fi

cd "$INSTALL_DIR"

# ── 3. Install Python dependencies ────────────────────────────
echo -e "${CYAN}[*]${RESET} Installing dependencies..."
pip3 install -r requirements.txt -q 2>/dev/null || true

# ── 4. Create global command ──────────────────────────────────
LAUNCHER="/usr/local/bin/mnet"

sudo tee "$LAUNCHER" > /dev/null << EOF
#!/usr/bin/env bash
python3 $INSTALL_DIR/mnet.py "\$@"
EOF

sudo chmod +x "$LAUNCHER"
echo -e "${GREEN}[+]${RESET} Installed as global command: ${CYAN}mnet${RESET}"

# ── 5. Optional: set ANTHROPIC_API_KEY ────────────────────────
echo ""
echo -e "${GRAY}─────────────────────────────────────────────────────${RESET}"
echo -e "${CYAN}[*]${RESET} Optional: Set your Anthropic API key for AI-powered analysis"
echo -e "    ${GRAY}export ANTHROPIC_API_KEY='your-key-here'${RESET}"
echo -e "    ${GRAY}echo 'export ANTHROPIC_API_KEY=...' >> ~/.bashrc${RESET}"
echo -e "${GRAY}─────────────────────────────────────────────────────${RESET}"
echo ""

# ── 6. Done ───────────────────────────────────────────────────
echo -e "${GREEN}[+]${RESET} MNet installed successfully!"
echo ""
echo -e "  Usage:"
echo -e "  ${GREEN}mnet 192.168.1.1${RESET}                       # Basic scan"
echo -e "  ${GREEN}mnet scanme.nmap.org --vuln --os${RESET}       # Full recon"
echo -e "  ${GREEN}mnet 192.168.1.0/24 --sweep${RESET}            # Host discovery"
echo -e "  ${GREEN}mnet 10.0.0.1 --html report.html${RESET}       # HTML report"
echo -e "  ${GREEN}mnet --help${RESET}                             # All options"
echo ""
echo -e "${GRAY}  GitHub : https://github.com/brainrotshiva/mnet${RESET}"
echo -e "${GRAY}  Author : @brainrotshiva${RESET}"
echo ""
