#!/usr/bin/env bash
# envy one-line install script
# Usage: curl -fsSL https://raw.githubusercontent.com/DylanGates/envy/master/install.sh | bash

set -e

REPO="DylanGates/envy"
INSTALL_DIR="${ENVY_INSTALL_DIR:-$HOME/.local/bin}"

# Colors
GREEN='\033[1;32m'
CYAN='\033[1;36m'
RED='\033[1;31m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${GREEN}"
cat << "EOF"
 ▄████▄   ███▄    █  ██▒   █▓▓██   ██▓
▒██▀ ▀█   ██ ▀█   █ ▓██░   █▒ ▒██  ██▒
▒▓█    ▄ ▓██  ▀█ ██▒ ▓██  █▒░  ▒██ ██░
▒▓▓▄ ▄██▒▓██▒  ▐▌██▒  ▒██ █░░  ░ ▐██▓░
▒ ▓███▀ ░▒██░   ▓██░   ▒▀█░    ░ ██▒▓░
░ ░▒ ▒  ░░ ▒░   ▒ ▒    ░ ▐░     ██▒▒▒ 
  ░  ▒   ░ ░░   ░ ▒░   ░ ░░   ▓██ ░▒░ 
░           ░   ░ ░      ░░   ▒ ▒ ░░  
EOF
echo -e "${NC}"
echo -e "${BOLD}Installing envy — Local-First Secrets & Infrastructure Gateway${NC}\n"

# 1. Detect OS and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
    darwin)
        if [ "$ARCH" = "arm64" ]; then
            TARGET="aarch64-apple-darwin"
        else
            TARGET="x86_64-apple-darwin"
        fi
        ;;
    linux)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    msys*|cygwin*|mingw*)
        TARGET="x86_64-pc-windows-msvc.exe"
        ;;
    *)
        echo -e "${RED}Unsupported operating system: $OS${NC}"
        exit 1
        ;;
esac

ASSET_NAME="envy-$TARGET"

# 2. Fetch Latest Release Version
echo -e "${CYAN}▶ Fetching latest release from GitHub...${NC}"
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    LATEST_TAG="v0.1.1"
fi

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$ASSET_NAME"

# 3. Download Binary
mkdir -p "$INSTALL_DIR"
DEST="$INSTALL_DIR/envy"
if [[ "$TARGET" == *".exe"* ]]; then
    DEST="$INSTALL_DIR/envy.exe"
fi

echo -e "${CYAN}▶ Downloading $ASSET_NAME ($LATEST_TAG)...${NC}"
curl -fsSL "$DOWNLOAD_URL" -o "$DEST"
chmod +x "$DEST"

echo -e "\n${GREEN}✔ Successfully installed envy to $DEST${NC}"

# 4. PATH Verification
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "\n⚠️  ${BOLD}$INSTALL_DIR is not currently in your PATH.${NC}"
    echo "Add it to your shell profile:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
fi

echo -e "\nRun '${BOLD}envy --help${NC}' to get started!"
