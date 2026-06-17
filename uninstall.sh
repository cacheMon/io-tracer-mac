#!/bin/bash
#
# IO-Tracer (macOS) uninstaller.

set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

if [ -n "$SUDO_USER" ]; then
    REAL_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    [ -z "$REAL_HOME" ] && REAL_HOME="/Users/$SUDO_USER"
else
    REAL_HOME="$HOME"
fi

BIN_NAME="iotrc"
BIN_DIR="/usr/local/bin"
INSTALL_DIR="$REAL_HOME/io-tracer-mac"

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

remove_bin() {
    if [ -f "$BIN_DIR/$BIN_NAME" ]; then
        rm -f "$BIN_DIR/$BIN_NAME"
        log_success "Removed $BIN_DIR/$BIN_NAME"
    else
        log_warning "$BIN_NAME not found in $BIN_DIR — nothing to remove"
    fi
}

remove_repo() {
    if [ -d "$INSTALL_DIR" ]; then
        read -r -p "Delete the cloned repo at $INSTALL_DIR? [y/N]: " ans
        if [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
            rm -rf "$INSTALL_DIR"
            log_success "Removed $INSTALL_DIR"
        else
            log_info "Keeping $INSTALL_DIR"
        fi
    fi
}

check_root
remove_bin
remove_repo
log_success "Uninstall complete."
