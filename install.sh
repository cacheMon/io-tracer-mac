#!/bin/bash
#
# IO-Tracer (macOS) installer.
#
# Installs the macOS IO-Tracer: verifies DTrace + Python, installs the Python
# dependencies, clones/updates the repo, and drops an `iotrc` wrapper in
# /usr/local/bin that runs the tracer from the repo root (required because
# iotrc.py uses package-relative imports).

set -e

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; BLUE='\033[0;34m'; NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

if [ -n "$SUDO_USER" ]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME=$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    [ -z "$REAL_HOME" ] && REAL_HOME="/Users/$SUDO_USER"
else
    REAL_USER="$USER"
    REAL_HOME="$HOME"
fi

INSTALL_DIR="$REAL_HOME/io-tracer-mac"
REPO_URL="https://github.com/cacheMon/io-tracer-mac.git"
BIN_NAME="iotrc"
BIN_DIR="/usr/local/bin"

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                IO-Tracer (macOS) Installer               ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_macos() {
    if [ "$(uname -s)" != "Darwin" ]; then
        log_error "This is the macOS installer. For Linux use io-tracer-linux."
        exit 1
    fi
    log_success "macOS detected ($(sw_vers -productVersion 2>/dev/null || uname -r))"
}

check_dtrace() {
    if ! command -v dtrace &> /dev/null && [ ! -x /usr/sbin/dtrace ]; then
        log_error "dtrace not found. It ships with macOS; ensure it is available."
        exit 1
    fi
    log_success "DTrace available"
    log_warning "DTrace requires sudo and may require System Integrity Protection"
    log_warning "to permit tracing. The syscall/io providers used here work under"
    log_warning "the default SIP policy for unrestricted processes."
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "python3 is not installed. Install Python 3.9+ (e.g. 'brew install python')."
        exit 1
    fi
    log_success "Python $(python3 --version 2>&1 | awk '{print $2}') detected"
}

install_python_deps() {
    log_info "Installing Python dependencies..."
    # Run pip as the invoking user so packages land in their environment, not root's.
    sudo -u "$REAL_USER" python3 -m pip install --user -r "$INSTALL_DIR/requirements.txt" \
        || python3 -m pip install -r "$INSTALL_DIR/requirements.txt" \
        || log_warning "pip install reported errors; zstandard is optional (traces stay uncompressed if missing)"
}

clone_repo() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        log_info "Updating existing installation at $INSTALL_DIR..."
        sudo -u "$REAL_USER" git -C "$INSTALL_DIR" pull origin main || true
    else
        log_info "Cloning IO-Tracer to $INSTALL_DIR..."
        sudo -u "$REAL_USER" git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

install_bin() {
    log_info "Installing $BIN_NAME wrapper to $BIN_DIR..."
    mkdir -p "$BIN_DIR"
    cat > "$BIN_DIR/$BIN_NAME" << EOF
#!/bin/bash
exec python3 "$INSTALL_DIR/iotrc.py" "\$@"
EOF
    chmod +x "$BIN_DIR/$BIN_NAME"
    log_success "Installed wrapper: $BIN_DIR/$BIN_NAME -> $INSTALL_DIR/iotrc.py"
}

print_success() {
    echo ""
    echo -e "${GREEN}IO-Tracer (macOS) installed successfully!${NC}"
    echo ""
    echo "Installation directory: $INSTALL_DIR"
    echo "Binary:                 $BIN_DIR/$BIN_NAME"
    echo ""
    echo "To run:          sudo $BIN_NAME            # fs + block + network"
    echo "Without network: sudo $BIN_NAME --no-network"
    echo "Help:            sudo $BIN_NAME --help"
    echo "Uninstall:     sudo bash $INSTALL_DIR/uninstall.sh"
    echo ""
}

main() {
    print_banner
    check_root
    check_macos
    check_dtrace
    check_python
    clone_repo
    install_python_deps
    install_bin
    print_success
}

main "$@"
