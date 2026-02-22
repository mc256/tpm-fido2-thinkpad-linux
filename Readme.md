# tpm-fido

tpm-fido is a FIDO2/WebAuthn authenticator for Linux that uses your system's TPM 2.0 and fingerprint reader to act as a virtual security key. It works with Chromium, Google Chrome, and Firefox — no browser extension required.

The daemon creates a virtual FIDO2 HID device via `/dev/uhid` that browsers discover automatically, just like a plugged-in YubiKey. Private keys are protected by the TPM and user verification is done through the fingerprint sensor.

## Tested Hardware

- **Lenovo ThinkPad P14s Gen 5** (AMD)
  - Fingerprint reader: Synaptics 06cb:00f9 (via fprintd)
  - TPM: AMD TPM 2.0 (`/dev/tpmrm0`)
  - OS: Ubuntu 24.04+, Linux 6.14

Other laptops with a TPM 2.0 and an fprintd-compatible fingerprint reader should work as well.

## Features

- **Virtual security key**: Appears as a USB FIDO2 device to all browsers — no extension needed
- **TPM-backed keys**: Private keys never leave the TPM hardware
- **Fingerprint verification**: User presence and verification via fprintd
- **PRF extension**: hmac-secret support for deriving cryptographic material from credentials
- **Resident keys**: Discoverable credentials stored locally
- **Multi-browser**: Works with Chromium (snap), Firefox (snap), Google Chrome, and native builds
- **Systemd service**: Runs as a user service, starts on login

## Quick Start

```bash
git clone https://github.com/mc256/tpm-fido2-thinkpad-linux.git
cd tpm-fido2-thinkpad-linux
./contrib/install-daemon.sh
```

The installer will:
1. Check prerequisites (Go, TPM, fprintd)
2. Build a static binary and install it to `~/bin/tpm-fido`
3. Install a systemd user service
4. Set up udev rules and load the `uhid` kernel module (requires sudo)
5. Detect installed browsers and connect snap interfaces as needed
6. Start the virtual security key daemon

After installation, open your browser and test at [webauthn.io](https://webauthn.io).

## Prerequisites

- **TPM 2.0**: Your system must have `/dev/tpmrm0`
- **Fingerprint reader**: Compatible with fprintd, with at least one finger enrolled
- **Go 1.21+**: Required to build from source
- **Linux kernel**: `uhid` module (loaded automatically by the installer)

### User Setup

```bash
# Grant TPM access
sudo usermod -aG tss $USER

# Grant uhid access
sudo usermod -aG plugdev $USER

# Log out and back in for group changes to take effect

# Enroll a fingerprint (if not already done)
fprintd-enroll
```

## Architecture

```
Browser (Chromium/Firefox/Chrome)
    |
    |  /dev/hidrawN  (FIDO2 HID, usage page 0xF1D0)
    |
  kernel HID subsystem
    |
    |  /dev/uhid
    |
  tpm-fido daemon  (systemd user service)
    |         |
    v         v
  TPM 2.0   fprintd
```

The daemon runs outside any browser sandbox, so it has full access to the TPM and fingerprint reader. Browsers discover the virtual HID device through standard OS mechanisms — the same way they find a physical YubiKey.

## Manual Installation

If you prefer to install step by step instead of using the installer script:

```bash
# Build
CGO_ENABLED=0 go build -ldflags="-s -w" -o tpm-fido tpmfido.go

# Install binary
install -m 755 tpm-fido ~/bin/tpm-fido

# Install systemd service
install -m 644 contrib/tpm-fido.service ~/.config/systemd/user/tpm-fido.service

# Install udev rules and uhid module config (requires sudo)
sudo cp contrib/90-tpm-fido-uhid.rules /etc/udev/rules.d/
sudo cp contrib/uhid.conf /etc/modules-load.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo modprobe uhid

# Connect snap interfaces (if using snap browsers)
sudo snap connect chromium:u2f-devices   # for Chromium snap
sudo snap connect firefox:u2f-devices    # for Firefox snap

# Start the service
systemctl --user enable --now tpm-fido
```

## Usage

Once the service is running, any FIDO2/WebAuthn request from a browser will trigger a fingerprint prompt via a desktop notification. Touch your fingerprint sensor to approve.

```bash
# Check service status
systemctl --user status tpm-fido

# Follow logs
journalctl --user -u tpm-fido -f

# Restart after updates
systemctl --user restart tpm-fido
```

## How It Works

**Registration (MakeCredential):**
1. Browser sends a WebAuthn create request to the virtual HID device
2. Daemon generates a P-256 key pair in the TPM, bound to the site's RP ID
3. Fingerprint verification confirms user presence
4. The public key and attestation are returned to the browser

**Authentication (GetAssertion):**
1. Browser sends a WebAuthn get request with credential IDs
2. Daemon loads the matching key from the TPM
3. Fingerprint verification confirms user presence
4. The TPM signs the assertion, which is returned to the browser

Key handles are a concatenation of the TPM child key's public/private blobs and a random seed. They can only be used on the same TPM that created them.

## Credential Storage

Resident credential metadata is stored at:
```
~/.local/share/tpm-fido/credentials.json
```

This file contains credential metadata only (user info, RP info, credential ID). Private keys remain in the TPM and are never written to disk.

## Snap Browser Notes

Ubuntu ships Chromium and Firefox as snap packages, which run in a confined sandbox. The virtual FIDO2 device works with snaps because:

- **AppArmor** already allows `/dev/hidraw*` access in the snap profiles
- **Device cgroup** access is granted via custom udev rules that tag the virtual hidraw device with `snap_chromium_chromium` and `snap_firefox_firefox`
- The `u2f-devices` snap interface may need to be connected for sysfs descriptor access

The installer handles all of this automatically.

## Troubleshooting

### Browser doesn't detect the security key
- Check the daemon is running: `systemctl --user status tpm-fido`
- Check a hidraw device exists: `ls -la /dev/hidraw*`
- Verify snap tags: `udevadm info /dev/hidrawN | grep TAGS`
- For snap browsers, ensure u2f-devices is connected: `snap connections chromium | grep u2f`

### "Permission denied" on /dev/tpmrm0
```bash
sudo usermod -aG tss $USER
# Log out and back in
```

### "Permission denied" on /dev/uhid
```bash
sudo usermod -aG plugdev $USER
# Log out and back in
```

### Fingerprint prompt doesn't appear
- Check fingerprints are enrolled: `fprintd-list $USER`
- Enroll a fingerprint: `fprintd-enroll`
- Check that fprintd is running: `systemctl status fprintd`

### Service won't start after reboot
- Ensure uhid module loads: `lsmod | grep uhid`
- If not: `sudo modprobe uhid` and check `/etc/modules-load.d/uhid.conf` exists

## License

See [LICENSE](LICENSE) file.
