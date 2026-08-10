#!/usr/bin/env bash
# OurMine ⛏️ — One-Line Installer Script
# Autonomous AI Security & Developer Platform
set -e

echo -e "\033[38;5;208m"
echo " ██████╗ ██╗   ██╗██████╗ ███╗   ███╗██╗███╗   ██╗███████╗"
echo "██╔═══██╗██║   ██║██╔══██╗████╗ ████║██║████╗  ██║██╔════╝"
echo "██║   ██║██║   ██║██████╔╝██╔████╔██║██║██╔██╗ ██║█████╗  "
echo "██║   ██║██║   ██║██╔══██╗██║╚██╔╝██║██║██║╚██╗██║██╔══╝  "
echo "╚██████╔╝╚██████╔╝██║  ██║██║ ╚═╝ ██║██║██║ ╚████║███████╗ ⛏️ v1.0.0"
echo " ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚══════╝"
echo -e "\033[0m"
echo "Installing OurMine Platform..."

if ! command -v node &> /dev/null; then
    echo -e "\033[31m[Error] Node.js (v20+) is required. Please install Node.js first.\033[0m"
    exit 1
fi

INSTALL_DIR="${HOME}/.ourmine"

if [ -d "$INSTALL_DIR" ]; then
    echo "Updating existing installation at $INSTALL_DIR..."
    cd "$INSTALL_DIR"
    git pull origin main || true
else
    echo "Cloning OurMine into $INSTALL_DIR..."
    git clone https://github.com/Jamesjaq/OurMine.git "$INSTALL_DIR" || mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo "Installing monorepo dependencies..."
npm install --quiet || true

echo "Linking 'ourmine' binary globally..."
npm link --force || true

chmod +x bin/ourmine 2>/dev/null || true

echo -e "\n\033[32m✔ OurMine installed successfully!\033[0m"
echo -e "Run \033[38;5;208mourmine status\033[0m or \033[38;5;208mourmine tui\033[0m to get started."
