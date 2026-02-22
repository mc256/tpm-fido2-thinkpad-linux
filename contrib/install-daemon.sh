#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY_NAME="tpm-fido"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[x]${NC} $*"; }

echo "============================================="
echo "  TPM-FIDO2 Virtual Security Key Installer"
echo "============================================="
echo ""

# ------------------------------------------------------------------
# 1. Check prerequisites
# ------------------------------------------------------------------
info "Checking prerequisites..."

MISSING=()

if ! command -v go &>/dev/null; then
    MISSING+=("go (golang compiler)")
fi

if ! command -v fprintd-verify &>/dev/null; then
    MISSING+=("fprintd (fingerprint daemon)")
fi

if [ ! -e /dev/tpmrm0 ]; then
    MISSING+=("/dev/tpmrm0 (TPM 2.0 device)")
fi

if [ ${#MISSING[@]} -ne 0 ]; then
    error "Missing prerequisites:"
    for m in "${MISSING[@]}"; do
        echo "       - $m"
    done
    exit 1
fi

# Check group membership
if ! id -nG "$USER" | grep -qw tss; then
    warn "User '$USER' is not in the 'tss' group (needed for TPM access)"
    echo "       Run: sudo usermod -aG tss \$USER"
    echo "       Then log out and back in."
fi

if ! id -nG "$USER" | grep -qw plugdev; then
    warn "User '$USER' is not in the 'plugdev' group (needed for /dev/uhid)"
    echo "       Run: sudo usermod -aG plugdev \$USER"
    echo "       Then log out and back in."
fi

# Check enrolled fingerprints
if fprintd-list "$USER" 2>/dev/null | grep -q "no enrolled"; then
    warn "No fingerprints enrolled. Enroll with: fprintd-enroll"
fi

echo ""

# ------------------------------------------------------------------
# 2. Build
# ------------------------------------------------------------------
info "Building $BINARY_NAME (pure Go static binary)..."
cd "$PROJECT_DIR"
CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BINARY_NAME" tpmfido.go
info "Build complete"
echo ""

# ------------------------------------------------------------------
# 3. Install binary
# ------------------------------------------------------------------
info "Installing binary to ~/bin/$BINARY_NAME..."
mkdir -p ~/bin
install -m 755 "$BINARY_NAME" ~/bin/"$BINARY_NAME"
echo ""

# ------------------------------------------------------------------
# 4. Install systemd user service
# ------------------------------------------------------------------
info "Installing systemd user service..."
mkdir -p ~/.config/systemd/user
install -m 644 contrib/tpm-fido.service ~/.config/systemd/user/tpm-fido.service
systemctl --user daemon-reload
echo ""

# ------------------------------------------------------------------
# 5. Install udev rules + uhid module (requires sudo)
# ------------------------------------------------------------------
info "Installing udev rules and kernel module config (requires sudo)..."
echo ""

sudo install -m 644 contrib/90-tpm-fido-uhid.rules /etc/udev/rules.d/90-tpm-fido-uhid.rules
sudo install -m 644 contrib/uhid.conf /etc/modules-load.d/uhid.conf
sudo udevadm control --reload-rules
sudo modprobe uhid

info "Udev rules and uhid module installed"
echo ""

# ------------------------------------------------------------------
# 6. Detect and configure browsers
# ------------------------------------------------------------------
info "Detecting browsers..."
echo ""

BROWSERS_FOUND=()

# Chromium (snap)
if snap list chromium &>/dev/null 2>&1; then
    BROWSERS_FOUND+=("chromium-snap")
    info "Found: Chromium (snap)"
    if snap connections chromium 2>/dev/null | grep -q "u2f-devices.*-"; then
        info "  Connecting u2f-devices interface..."
        sudo snap connect chromium:u2f-devices || warn "  Could not connect u2f-devices (may need manual connection)"
    else
        info "  u2f-devices interface already connected"
    fi
fi

# Chromium (native)
if command -v chromium-browser &>/dev/null && ! snap list chromium &>/dev/null 2>&1; then
    BROWSERS_FOUND+=("chromium-native")
    info "Found: Chromium (native package)"
fi

# Google Chrome (native -- Chrome is not distributed as a snap)
if command -v google-chrome &>/dev/null || command -v google-chrome-stable &>/dev/null; then
    BROWSERS_FOUND+=("chrome")
    info "Found: Google Chrome"
fi

# Firefox (snap)
if snap list firefox &>/dev/null 2>&1; then
    BROWSERS_FOUND+=("firefox-snap")
    info "Found: Firefox (snap)"
    if snap connections firefox 2>/dev/null | grep -q "u2f-devices.*-"; then
        info "  Connecting u2f-devices interface..."
        sudo snap connect firefox:u2f-devices || warn "  Could not connect u2f-devices (may need manual connection)"
    else
        info "  u2f-devices interface already connected"
    fi
fi

# Firefox (native)
if command -v firefox &>/dev/null && ! snap list firefox &>/dev/null 2>&1; then
    BROWSERS_FOUND+=("firefox-native")
    info "Found: Firefox (native package)"
fi

if [ ${#BROWSERS_FOUND[@]} -eq 0 ]; then
    warn "No supported browsers detected"
fi

echo ""

# ------------------------------------------------------------------
# 7. Trigger udev for the virtual device (if daemon already running)
# ------------------------------------------------------------------
sudo udevadm trigger

# ------------------------------------------------------------------
# 8. Enable and start the service
# ------------------------------------------------------------------
info "Enabling and starting tpm-fido service..."
systemctl --user enable tpm-fido
systemctl --user restart tpm-fido
sleep 1

if systemctl --user is-active --quiet tpm-fido; then
    info "Service is running"
else
    error "Service failed to start. Check: journalctl --user -u tpm-fido"
    exit 1
fi

# Verify hidraw device appeared
HIDRAW=$(ls /dev/hidraw* 2>/dev/null | tail -1)
if [ -n "$HIDRAW" ]; then
    if udevadm info "$HIDRAW" 2>/dev/null | grep -q "ID_FIDO_TOKEN=1"; then
        info "Virtual FIDO2 device created: $HIDRAW"
    fi
fi

echo ""

# ------------------------------------------------------------------
# Done
# ------------------------------------------------------------------
echo "============================================="
echo -e "  ${GREEN}Installation complete!${NC}"
echo "============================================="
echo ""
echo "Detected browsers:"
for b in "${BROWSERS_FOUND[@]}"; do
    echo "  - $b"
done
echo ""
echo "The virtual security key is now active. To test:"
echo "  1. Open a browser"
echo "  2. Go to https://webauthn.io"
echo "  3. Click Register -> Use your security key"
echo "  4. Touch your fingerprint sensor"
echo ""
echo "Useful commands:"
echo "  journalctl --user -u tpm-fido -f    # follow daemon logs"
echo "  systemctl --user status tpm-fido     # check service status"
echo "  systemctl --user restart tpm-fido    # restart daemon"
