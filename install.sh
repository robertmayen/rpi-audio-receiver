#!/bin/bash

#==============================================================================
# Audio Receiver Installation Script
# Supports: Bluetooth Audio (BlueALSA), AirPlay 2 (Shairport Sync), Spotify Connect
# Target: Debian 12/13 (including Raspberry Pi OS)
#==============================================================================

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration
#------------------------------------------------------------------------------
readonly SCRIPT_VERSION="2.0.0"
readonly NQPTP_VERSION="1.2.4"
readonly SHAIRPORT_SYNC_VERSION="4.3.7"
readonly LOG_FILE="/var/log/audio-receiver-install.log"
readonly BACKUP_DIR="/var/backups/audio-receiver"

# SHA256 checksums for downloaded files (update these with actual checksums)
readonly NQPTP_SHA256="SKIP"  # Set to actual checksum or "SKIP" to disable
readonly SHAIRPORT_SHA256="SKIP"

# Global variables
TMP_DIR=""
DRY_RUN=false
VERBOSE=false
INSTALLED_COMPONENTS=()

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

log() {
    local level="$1"
    shift
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $*"
    
    # Write to stderr
    echo "$msg" >&2
    
    # Write to log file if it exists and is writable
    if [[ -f "$LOG_FILE" && -w "$LOG_FILE" ]]; then
        echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; }
error() { log "ERROR" "$@"; }
success() { log "SUCCESS" "$@"; }

die() {
    error "$@"
    cleanup
    exit 1
}

debug() {
    if [[ "$VERBOSE" == true ]]; then
        log "DEBUG" "$@"
    fi
}

show_progress() {
    local msg="$1"
    echo -ne "\r\033[K$msg"
}

finish_progress() {
    echo
}

prompt_yn() {
    local prompt="$1"
    local default="${2:-N}"
    local reply
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would prompt: $prompt"
        return 1
    fi
    
    while true; do
        read -p "$prompt " reply
        reply="${reply:-$default}"
        case "$reply" in
            [Yy]|[Yy][Ee][Ss]) return 0 ;;
            [Nn]|[Nn][Oo]) return 1 ;;
            *) echo "Please answer yes or no." ;;
        esac
    done
}

validate_hostname() {
    local hostname="$1"
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        return 1
    fi
    return 0
}

validate_pretty_hostname() {
    local hostname="$1"
    # Allow more characters for pretty hostname, but limit length
    if [[ ${#hostname} -gt 64 ]]; then
        return 1
    fi
    return 0
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup="${BACKUP_DIR}/$(basename "$file").$(date +%s).bak"
        sudo mkdir -p "$BACKUP_DIR"
        sudo cp "$file" "$backup"
        info "Backed up $file to $backup"
    fi
}

cleanup() {
    if [[ -n "${TMP_DIR}" && -d "${TMP_DIR}" ]]; then
        debug "Cleaning up temporary directory: $TMP_DIR"
        rm -rf "${TMP_DIR}"
    fi
}

verify_checksum() {
    local file="$1"
    local expected="$2"
    
    if [[ "$expected" == "SKIP" ]]; then
        warn "Checksum verification skipped for $file"
        return 0
    fi
    
    info "Verifying checksum for $file..."
    local actual
    actual=$(sha256sum "$file" | awk '{print $1}')
    
    if [[ "$actual" != "$expected" ]]; then
        die "Checksum mismatch for $file! Expected: $expected, Got: $actual"
    fi
    
    success "Checksum verified for $file"
}

#------------------------------------------------------------------------------
# System Verification
#------------------------------------------------------------------------------

verify_root() {
    if [[ $EUID -eq 0 ]]; then
        die "This script should not be run as root. It will use sudo when needed."
    fi
    
    if ! sudo -v; then
        die "This script requires sudo privileges"
    fi
}

init_log() {
    sudo mkdir -p "$(dirname "$LOG_FILE")"
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    info "Log file initialized: $LOG_FILE"
}

verify_os() {
    info "Verifying operating system..."
    
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot determine OS: /etc/os-release not found"
    fi
    
    # shellcheck source=/dev/null
    . /etc/os-release
    
    if [[ "$ID" != "debian" && "$ID" != "raspbian" ]]; then
        die "Unsupported OS: $ID (Debian/Raspbian required)"
    fi
    
    if [[ "$VERSION_ID" != "12" && "$VERSION_ID" != "13" ]]; then
        die "Unsupported Debian version: $VERSION_ID (12 or 13 required)"
    fi
    
    success "OS verified: $PRETTY_NAME"
}

check_network() {
    info "Checking network connectivity..."
    
    if ! ping -c 1 -W 3 8.8.8.8 >/dev/null 2>&1; then
        die "No network connectivity. Please check your connection."
    fi
    
    success "Network connectivity verified"
}

#------------------------------------------------------------------------------
# Hostname Configuration
#------------------------------------------------------------------------------

set_hostname() {
    info "Configuring hostname..."
    
    local current_hostname
    current_hostname=$(hostname)
    local current_pretty
    current_pretty=$(hostnamectl status --pretty 2>/dev/null || echo "Audio Receiver")
    
    echo
    echo "Current hostname: $current_hostname"
    echo "Current pretty hostname: $current_pretty"
    echo
    
    if ! prompt_yn "Do you want to change the hostname? [y/N]" "N"; then
        PRETTY_HOSTNAME="$current_pretty"
        return 0
    fi
    
    local new_hostname
    while true; do
        read -p "Enter new hostname [$current_hostname]: " new_hostname
        new_hostname="${new_hostname:-$current_hostname}"
        
        if validate_hostname "$new_hostname"; then
            break
        else
            error "Invalid hostname. Use only letters, numbers, and hyphens (1-63 chars)."
        fi
    done
    
    local new_pretty
    while true; do
        read -p "Enter pretty hostname [$current_pretty]: " new_pretty
        new_pretty="${new_pretty:-$current_pretty}"
        
        if validate_pretty_hostname "$new_pretty"; then
            break
        else
            error "Pretty hostname too long (max 64 characters)."
        fi
    done
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would set hostname to: $new_hostname"
        info "[DRY RUN] Would set pretty hostname to: $new_pretty"
    else
        sudo hostnamectl set-hostname "$new_hostname"
        sudo hostnamectl set-hostname --pretty "$new_pretty"
        success "Hostname configured: $new_hostname ($new_pretty)"
    fi
    
    PRETTY_HOSTNAME="$new_pretty"
}

#------------------------------------------------------------------------------
# Bluetooth Installation
#------------------------------------------------------------------------------

install_bluetooth() {
    info "Bluetooth Audio installation starting..."
    
    if ! prompt_yn "Install Bluetooth Audio (ALSA)? [y/N]" "N"; then
        info "Skipping Bluetooth installation"
        return 0
    fi
    
    if systemctl is-active --quiet bluealsa 2>/dev/null; then
        if ! prompt_yn "Bluetooth already installed. Reinstall? [y/N]" "N"; then
            return 0
        fi
    fi
    
    info "Installing Bluetooth packages..."
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would install Bluetooth packages"
    else
        sudo apt-get update || die "Failed to update package list"
        
        local pkgs=(bluez bluez-tools)
        
        # Detect available BlueALSA packages
        if apt-cache show bluez-alsa-utils >/dev/null 2>&1; then
            pkgs+=(bluez-alsa-utils)
        else
            if apt-cache show bluealsa >/dev/null 2>&1; then
                pkgs+=(bluealsa)
            fi
            if apt-cache show bluealsa-utils >/dev/null 2>&1; then
                pkgs+=(bluealsa-utils)
            fi
        fi
        
        sudo apt-get install -y --no-install-recommends "${pkgs[@]}" || \
            die "Failed to install Bluetooth packages"
    fi
    
    # Configure Bluetooth
    info "Configuring Bluetooth..."
    backup_file /etc/bluetooth/main.conf
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would configure Bluetooth"
    else
        sudo tee /etc/bluetooth/main.conf >/dev/null <<'EOF'
[General]
Class = 0x200414
DiscoverableTimeout = 0

[Policy]
AutoEnable=true
EOF
    fi
    
    # Install Bluetooth agent service
    info "Installing Bluetooth agent service..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /etc/systemd/system/bt-agent@.service >/dev/null <<'EOF'
[Unit]
Description=Bluetooth Agent
Requires=bluetooth.service
After=bluetooth.service

[Service]
ExecStartPre=/bin/sleep 2
ExecStartPre=/usr/bin/bluetoothctl --timeout 30 power on
ExecStartPre=/usr/bin/bluetoothctl --timeout 30 pairable on
ExecStartPre=/usr/bin/bluetoothctl --timeout 30 discoverable on
ExecStart=/usr/bin/bt-agent --capability=NoInputNoOutput
RestartSec=5
Restart=always
KillSignal=SIGUSR1

[Install]
WantedBy=multi-user.target
EOF
        
        # Install udev script
        sudo tee /usr/local/bin/bluetooth-udev >/dev/null <<'EOF'
#!/bin/bash
if [[ ! $NAME =~ ^\"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\"$ ]]; then exit 0; fi

action=$(expr "$ACTION" : "\([a-zA-Z]\+\).*")

if [[ "$action" == "add" ]]; then
    bluetoothctl discoverable off
fi

if [[ "$action" == "remove" ]]; then
    bluetoothctl discoverable on
fi
EOF
        sudo chmod 755 /usr/local/bin/bluetooth-udev
        
        sudo tee /etc/udev/rules.d/99-bluetooth-udev.rules >/dev/null <<'EOF'
SUBSYSTEM=="input", GROUP="input", MODE="0660"
KERNEL=="input[0-9]*", RUN+="/usr/local/bin/bluetooth-udev"
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable bt-agent@hci0.service
        
        # Try to start the service
        if sudo systemctl start bt-agent@hci0.service 2>/dev/null; then
            success "Bluetooth agent service started"
        else
            warn "Could not start Bluetooth agent (may start on next boot)"
        fi
    fi
    
    INSTALLED_COMPONENTS+=("bluetooth")
    success "Bluetooth installation completed"
}

#------------------------------------------------------------------------------
# Shairport Sync Installation
#------------------------------------------------------------------------------

install_shairport() {
    info "Shairport Sync (AirPlay 2) installation starting..."
    
    if ! prompt_yn "Install Shairport Sync (AirPlay 2)? [y/N]" "N"; then
        info "Skipping Shairport Sync installation"
        return 0
    fi
    
    if systemctl is-active --quiet shairport-sync 2>/dev/null; then
        if ! prompt_yn "Shairport Sync already installed. Reinstall? [y/N]" "N"; then
            return 0
        fi
        sudo systemctl stop shairport-sync 2>/dev/null || true
    fi
    
    # Install dependencies
    info "Installing build dependencies..."
    local build_deps=(
        autoconf automake build-essential libtool git pkg-config
        libsystemd-dev libpopt-dev libconfig-dev libasound2-dev
        libavahi-client-dev libssl-dev libsoxr-dev libplist-dev
        libsodium-dev libavutil-dev libavcodec-dev libavformat-dev
        uuid-dev libgcrypt20-dev xxd
    )
    
    local runtime_deps=(
        avahi-daemon alsa-utils wget unzip
    )
    
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would install dependencies"
    else
        sudo apt-get update || die "Failed to update package list"
        sudo apt-get install -y --no-install-recommends "${runtime_deps[@]}" "${build_deps[@]}" || \
            die "Failed to install dependencies"
    fi
    
    # Create temporary directory
    TMP_DIR=$(mktemp -d)
    debug "Using temporary directory: $TMP_DIR"
    
    # Build NQPTP
    info "Downloading and building NQPTP ${NQPTP_VERSION}..."
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would build NQPTP"
    else
        (
            cd "$TMP_DIR" || die "Failed to enter temp directory"
            
            wget --quiet --show-progress \
                -O "nqptp-${NQPTP_VERSION}.zip" \
                "https://github.com/mikebrady/nqptp/archive/refs/tags/${NQPTP_VERSION}.zip" || \
                die "Failed to download NQPTP"
            
            verify_checksum "nqptp-${NQPTP_VERSION}.zip" "$NQPTP_SHA256"
            
            unzip -q "nqptp-${NQPTP_VERSION}.zip" || die "Failed to extract NQPTP"
            cd "nqptp-${NQPTP_VERSION}" || die "Failed to enter NQPTP directory"
            
            info "Configuring NQPTP..."
            autoreconf -fi || die "NQPTP autoreconf failed"
            ./configure --with-systemd-startup || die "NQPTP configure failed"
            
            info "Compiling NQPTP (this may take a few minutes)..."
            make -j "$(nproc)" || die "NQPTP compilation failed"
            
            info "Installing NQPTP..."
            sudo make install \
                systemdsystemunitdir=/lib/systemd/system \
                systemduserunitdir=/usr/lib/systemd/user || \
                die "NQPTP installation failed"
        ) || die "NQPTP build process failed"
        
        success "NQPTP installed successfully"
    fi
    
    # Disable any existing shairport-sync service
    sudo systemctl disable --now shairport-sync 2>/dev/null || true
    
    # Build Shairport Sync
    info "Downloading and building Shairport Sync ${SHAIRPORT_SYNC_VERSION}..."
    if [[ "$DRY_RUN" == false ]]; then
        (
            cd "$TMP_DIR" || die "Failed to enter temp directory"
            
            wget --quiet --show-progress \
                -O "shairport-sync-${SHAIRPORT_SYNC_VERSION}.zip" \
                "https://github.com/mikebrady/shairport-sync/archive/refs/tags/${SHAIRPORT_SYNC_VERSION}.zip" || \
                die "Failed to download Shairport Sync"
            
            verify_checksum "shairport-sync-${SHAIRPORT_SYNC_VERSION}.zip" "$SHAIRPORT_SHA256"
            
            unzip -q "shairport-sync-${SHAIRPORT_SYNC_VERSION}.zip" || \
                die "Failed to extract Shairport Sync"
            cd "shairport-sync-${SHAIRPORT_SYNC_VERSION}" || \
                die "Failed to enter Shairport Sync directory"
            
            info "Configuring Shairport Sync..."
            autoreconf -fi || die "Shairport Sync autoreconf failed"
            ./configure \
                --sysconfdir=/etc \
                --with-alsa \
                --with-soxr \
                --with-avahi \
                --with-ssl=openssl \
                --with-systemd \
                --with-airplay-2 || die "Shairport Sync configure failed"
            
            info "Compiling Shairport Sync (this may take several minutes)..."
            make -j "$(nproc)" || die "Shairport Sync compilation failed"
            
            info "Installing Shairport Sync..."
            sudo make install \
                systemdsystemunitdir=/lib/systemd/system \
                systemduserunitdir=/usr/lib/systemd/user || \
                die "Shairport Sync installation failed"
        ) || die "Shairport Sync build process failed"
        
        success "Shairport Sync installed successfully"
    fi
    
    # Clean up build dependencies
    info "Removing build dependencies..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo apt-get remove -y "${build_deps[@]}" 2>/dev/null || warn "Some build deps could not be removed"
        sudo apt-get autoremove -y || warn "Autoremove failed"
    fi
    
    # Install output detection script
    info "Installing ALSA output detection script..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /usr/local/bin/shairport-output-detect >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

readonly CONF="/etc/shairport-sync.conf"
readonly MAX_WAIT=10

log() {
    logger -t shairport-output-detect "$@"
    echo "$@" >&2
}

pick_default_device() {
    local hdmi_connected=0
    
    # Check for connected HDMI displays
    if ls /proc/asound/card*/eld#* >/dev/null 2>&1; then
        while IFS= read -r path; do
            if grep -qs "monitor_present *1" "$path"; then
                hdmi_connected=1
                break
            fi
        done < <(ls /proc/asound/card*/eld#* 2>/dev/null || true)
    fi
    
    if [[ $hdmi_connected -eq 1 ]]; then
        log "HDMI display detected, searching for HDMI audio device..."
        # Find first HDMI device
        while IFS= read -r line; do
            local cardname devnum
            cardname=$(awk '{print $3}' <<<"$line" | sed 's/://')
            devnum=$(awk '{print $6}' <<<"$line" | sed 's/://')
            if [[ -n "${cardname}" && -n "${devnum}" ]]; then
                echo "plughw:CARD=${cardname},DEV=${devnum}"
                return 0
            fi
        done < <(aplay -l 2>/dev/null | grep -i hdmi || true)
    fi
    
    # Try ALSA default
    local default_dev
    default_dev=$(aplay -L 2>/dev/null | awk -F: '/^default:/{print $1":"$2; exit}' || echo "")
    if [[ -n "$default_dev" ]]; then
        echo "$default_dev"
        return 0
    fi
    
    # Try first plughw device
    local plughw_dev
    plughw_dev=$(aplay -L 2>/dev/null | awk '/^plughw:/{print $1; exit}' || echo "")
    if [[ -n "$plughw_dev" ]]; then
        echo "$plughw_dev"
        return 0
    fi
    
    # Last resort
    echo "default"
}

# Wait for ALSA to be ready
for i in $(seq 1 $MAX_WAIT); do
    if aplay -l >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done

DEVICE=$(pick_default_device)
DEVICE=$(printf '%s' "$DEVICE" | tr -d '\r' | awk '{print $1}')

# Validate device name
case "$DEVICE" in
    default|default:*|plughw:*|hw:*|hdmi:*) ;;
    *) DEVICE="default" ;;
esac

log "Selected ALSA device: $DEVICE"

# Ensure config file exists
if [[ ! -f "$CONF" ]]; then
    echo 'general = { name = "'"$(hostname)"'"; output_backend = "alsa"; };' | sudo tee "$CONF" >/dev/null
fi

# Update ALSA configuration
if grep -qE '^alsa[[:space:]]*=' "$CONF"; then
    # Update existing ALSA block
    sudo awk -v dev="$DEVICE" '
        BEGIN {in_alsa=0; has_device=0; has_rate=0}
        /^alsa[[:space:]]*=.*\{/ {print; in_alsa=1; next}
        in_alsa && /^[[:space:]]*output_device[[:space:]]*=/ {
            print "  output_device = \"" dev "\";"; has_device=1; next
        }
        in_alsa && /^[[:space:]]*output_rate[[:space:]]*=/ {
            print "  output_rate = 48000;"; has_rate=1; next
        }
        in_alsa && /^\}/ {
            if (!has_device) print "  output_device = \"" dev "\";";
            if (!has_rate) print "  output_rate = 48000;";
            print; in_alsa=0; has_device=0; has_rate=0; next
        }
        {print}
    ' "$CONF" > "$CONF.tmp" && sudo mv "$CONF.tmp" "$CONF"
else
    # Add new ALSA block
    printf '\nalsa = {\n  output_device = "%s";\n  output_rate = 48000;\n};\n' "$DEVICE" | sudo tee -a "$CONF" >/dev/null
fi

log "Configuration updated successfully"
EOF
        sudo chmod 755 /usr/local/bin/shairport-output-detect
    fi
    
    # Create configuration file
    info "Creating Shairport Sync configuration..."
    backup_file /etc/shairport-sync.conf
    
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /etc/shairport-sync.conf >/dev/null <<EOF
general = {
    name = "${PRETTY_HOSTNAME:-$(hostname)}";
    output_backend = "alsa";
};

sessioncontrol = {
    session_timeout = 20;
};
EOF
    fi
    
    # Create systemd service
    info "Creating Shairport Sync systemd service..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /etc/systemd/system/shairport-sync.service >/dev/null <<'EOF'
[Unit]
Description=Shairport Sync - AirPlay Audio Receiver
After=network-online.target avahi-daemon.service sound.target alsa-restore.service
Wants=network-online.target avahi-daemon.service

[Service]
User=shairport-sync
Group=shairport-sync
SupplementaryGroups=audio
ExecStartPre=/usr/local/bin/shairport-output-detect
ExecStart=/usr/local/bin/shairport-sync -c /etc/shairport-sync.conf
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
        
        # Add gpio group if available (Raspberry Pi)
        if getent group gpio >/dev/null 2>&1; then
            sudo usermod -a -G gpio shairport-sync 2>/dev/null || true
        fi
    fi
    
    # Install udev hotplug rules
    info "Installing udev hotplug rules..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /usr/local/bin/shairport-udev-restart >/dev/null <<'EOF'
#!/bin/sh
/usr/bin/systemctl try-restart shairport-sync.service
EOF
        sudo chmod 755 /usr/local/bin/shairport-udev-restart
        
        sudo tee /etc/udev/rules.d/99-shairport-hotplug.rules >/dev/null <<'EOF'
ACTION=="change", SUBSYSTEM=="drm", ENV{HOTPLUG}=="1", RUN+="/usr/local/bin/shairport-udev-restart"
ACTION=="change", SUBSYSTEM=="sound", KERNEL=="card*", RUN+="/usr/local/bin/shairport-udev-restart"
EOF
        
        sudo udevadm control --reload
    fi
    
    # Enable and start services
    info "Enabling Shairport Sync services..."
    if [[ "$DRY_RUN" == false ]]; then
        sudo systemctl daemon-reload
        sudo systemctl enable --now nqptp || warn "Could not start NQPTP"
        sudo systemctl enable shairport-sync
        
        # Trigger initial device detection
        sudo /usr/local/bin/shairport-output-detect || warn "Initial device detection failed"
        
        sudo systemctl start shairport-sync || warn "Could not start Shairport Sync immediately"
        sleep 2
        
        if systemctl is-active --quiet shairport-sync; then
            success "Shairport Sync is running"
        else
            warn "Shairport Sync not running yet (may start after reboot)"
        fi
    fi
    
    INSTALLED_COMPONENTS+=("shairport")
    success "Shairport Sync installation completed"
}

#------------------------------------------------------------------------------
# Raspotify Installation
#------------------------------------------------------------------------------

install_raspotify() {
    info "Raspotify (Spotify Connect) installation starting..."
    
    if ! prompt_yn "Install Raspotify (Spotify Connect)? [y/N]" "N"; then
        info "Skipping Raspotify installation"
        return 0
    fi
    
    if systemctl is-active --quiet raspotify 2>/dev/null; then
        if ! prompt_yn "Raspotify already installed. Reinstall? [y/N]" "N"; then
            return 0
        fi
    fi
    
    info "Installing Raspotify..."
    if [[ "$DRY_RUN" == true ]]; then
        info "[DRY RUN] Would install Raspotify"
    else
        sudo apt-get update || die "Failed to update package list"
        sudo apt-get install -y --no-install-recommends curl apt-transport-https || \
            die "Failed to install curl"
        
        # Download and verify installer
        local installer="/tmp/raspotify-install.sh"
        wget --quiet --show-progress \
            -O "$installer" \
            https://dtcooper.github.io/raspotify/install.sh || \
            die "Failed to download Raspotify installer"
        
        info "Running Raspotify installer..."
        bash "$installer" || die "Raspotify installation failed"
        rm -f "$installer"
    fi
    
    # Configure Raspotify
    info "Configuring Raspotify..."
    backup_file /etc/raspotify/conf
    
    local librespot_name="${PRETTY_HOSTNAME// /-}"
    librespot_name="${librespot_name:-$(hostname)}"
    
    if [[ "$DRY_RUN" == false ]]; then
        sudo tee /etc/raspotify/conf >/dev/null <<EOF
LIBRESPOT_QUIET=on
LIBRESPOT_AUTOPLAY=on
LIBRESPOT_DISABLE_AUDIO_CACHE=on
LIBRESPOT_DISABLE_CREDENTIAL_CACHE=on
LIBRESPOT_ENABLE_VOLUME_NORMALISATION=on
LIBRESPOT_NAME="${librespot_name}"
LIBRESPOT_DEVICE_TYPE="avr"
LIBRESPOT_BITRATE="320"
LIBRESPOT_INITIAL_VOLUME="100"
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable raspotify
        
        if sudo systemctl start raspotify 2>/dev/null; then
            success "Raspotify service started"
        else
            warn "Could not start Raspotify (may start on next boot)"
        fi
    fi
    
    INSTALLED_COMPONENTS+=("raspotify")
    success "Raspotify installation completed"
}

#------------------------------------------------------------------------------
# Uninstall Functions
#------------------------------------------------------------------------------

uninstall_bluetooth() {
    info "Uninstalling Bluetooth Audio..."
    
    sudo systemctl disable --now bt-agent@hci0.service 2>/dev/null || true
    sudo rm -f /etc/systemd/system/bt-agent@.service
    sudo rm -f /usr/local/bin/bluetooth-udev
    sudo rm -f /etc/udev/rules.d/99-bluetooth-udev.rules
    sudo systemctl daemon-reload
    
    if prompt_yn "Remove Bluetooth packages? [y/N]" "N"; then
        sudo apt-get remove -y bluez bluez-tools bluez-alsa-utils bluealsa bluealsa-utils 2>/dev/null || true
        sudo apt-get autoremove -y
    fi
    
    success "Bluetooth uninstalled"
}

uninstall_shairport() {
    info "Uninstalling Shairport Sync..."
    
    sudo systemctl disable --now shairport-sync nqptp 2>/dev/null || true
    sudo rm -f /etc/systemd/system/shairport-sync.service
    sudo rm -f /usr/local/bin/shairport-sync
    sudo rm -f /usr/local/bin/nqptp
    sudo rm -f /usr/local/bin/shairport-output-detect
    sudo rm -f /usr/local/bin/shairport-udev-restart
    sudo rm -f /etc/udev/rules.d/99-shairport-hotplug.rules
    sudo rm -f /etc/shairport-sync.conf
    sudo systemctl daemon-reload
    
    if getent passwd shairport-sync >/dev/null 2>&1; then
        sudo userdel shairport-sync 2>/dev/null || true
    fi
    
    success "Shairport Sync uninstalled"
}

uninstall_raspotify() {
    info "Uninstalling Raspotify..."
    
    sudo systemctl disable --now raspotify 2>/dev/null || true
    sudo apt-get remove -y raspotify 2>/dev/null || true
    sudo apt-get autoremove -y
    sudo rm -rf /etc/raspotify
    
    success "Raspotify uninstalled"
}

uninstall_all() {
    warn "This will remove all audio receiver components"
    
    if ! prompt_yn "Are you sure you want to uninstall everything? [y/N]" "N"; then
        info "Uninstall cancelled"
        return 0
    fi
    
    uninstall_raspotify
    uninstall_shairport
    uninstall_bluetooth
    
    success "All components uninstalled"
}

#------------------------------------------------------------------------------
# Main Menu
#------------------------------------------------------------------------------

show_usage() {
    cat <<EOF
Audio Receiver Installation Script v${SCRIPT_VERSION}

Usage: $0 [OPTIONS]

OPTIONS:
    -h, --help          Show this help message
    -v, --verbose       Enable verbose output
    -d, --dry-run       Show what would be done without making changes
    -u, --uninstall     Uninstall all components
    --uninstall-bt      Uninstall Bluetooth only
    --uninstall-airplay Uninstall Shairport Sync only
    --uninstall-spotify Uninstall Raspotify only

EXAMPLES:
    $0                  Run interactive installation
    $0 --dry-run        Preview changes without installing
    $0 --uninstall      Remove all installed components
    $0 -v               Run with verbose output

SUPPORTED SYSTEMS:
    - Debian 12 (Bookworm)
    - Debian 13 (Trixie)
    - Raspberry Pi OS (based on Debian 12/13)

COMPONENTS:
    - Bluetooth Audio (BlueALSA)
    - AirPlay 2 (Shairport Sync with NQPTP)
    - Spotify Connect (Raspotify)

For more information, see: https://github.com/your-repo/audio-receiver
EOF
}

show_banner() {
    cat <<'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║           Audio Receiver Installation Script                ║
║                                                              ║
║  Supports: Bluetooth • AirPlay 2 • Spotify Connect          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo
}

show_summary() {
    echo
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Installation Summary"
    echo "═══════════════════════════════════════════════════════════════"
    
    if [[ ${#INSTALLED_COMPONENTS[@]} -eq 0 ]]; then
        echo "  No components were installed"
    else
        echo "  Installed components:"
        for component in "${INSTALLED_COMPONENTS[@]}"; do
            echo "    ✓ $component"
        done
    fi
    
    echo
    echo "  Log file: $LOG_FILE"
    echo "  Backups:  $BACKUP_DIR"
    echo
    
    if [[ ${#INSTALLED_COMPONENTS[@]} -gt 0 ]]; then
        echo "  IMPORTANT: A reboot is recommended to ensure all services"
        echo "             start correctly with the new configuration."
        echo
        if prompt_yn "Reboot now? [y/N]" "N"; then
            info "Rebooting..."
            sudo reboot
        fi
    fi
    
    echo "═══════════════════════════════════════════════════════════════"
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -u|--uninstall)
                show_banner
                verify_root
                init_log
                uninstall_all
                exit 0
                ;;
            --uninstall-bt)
                show_banner
                verify_root
                init_log
                uninstall_bluetooth
                exit 0
                ;;
            --uninstall-airplay)
                show_banner
                verify_root
                init_log
                uninstall_shairport
                exit 0
                ;;
            --uninstall-spotify)
                show_banner
                verify_root
                init_log
                uninstall_raspotify
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    show_banner
    
    if [[ "$DRY_RUN" == true ]]; then
        warn "DRY RUN MODE - No changes will be made"
        echo
    fi
    
    # Pre-flight checks (verify root first, then create log)
    verify_root
    init_log
    
    if [[ "$DRY_RUN" == true ]]; then
        warn "DRY RUN MODE - No changes will be made"
        echo
    fi
    
    # Pre-flight checks
    verify_root
    verify_os
    check_network
    
    # Configuration
    set_hostname
    
    # Component installation
    install_bluetooth
    install_shairport
    install_raspotify
    
    # Summary
    show_summary
    
    success "Installation complete!"
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"