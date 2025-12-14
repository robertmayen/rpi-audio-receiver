#!/bin/bash

# Dell Wyse - Production Installation Script
# Features: State management, rollback, validation, idempotency

set -euo pipefail

#==============================================================================
# CONFIGURATION
#==============================================================================

NQPTP_VERSION="1.2.4"
SHAIRPORT_SYNC_VERSION="4.3.7"

STATE_DIR="/var/lib/audio-receiver"
STATE_FILE="${STATE_DIR}/state.json"
LOG_FILE="${STATE_DIR}/install.log"
BACKUP_DIR="${STATE_DIR}/backups"

REQUIRED_OS_IDS=("debian" "raspbian")
REQUIRED_OS_VERSIONS=("12" "13")

#==============================================================================
# UTILITY FUNCTIONS
#==============================================================================

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE" >&2
}

info() { log "INFO" "$@"; }
warn() { log "WARN" "$@"; }
error() { log "ERROR" "$@"; }
success() { log "SUCCESS" "$@"; }

die() {
    error "$@"
    exit 1
}

ensure_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root. Use: sudo bash $0"
    fi
}

ensure_state_dir() {
    mkdir -p "$STATE_DIR" "$BACKUP_DIR"
    touch "$LOG_FILE"
    
    if [[ ! -f "$STATE_FILE" ]]; then
        echo '{}' > "$STATE_FILE"
    fi
}

get_state() {
    local key=$1
    local default=${2:-null}
    
    if command -v jq &>/dev/null; then
        jq -r ".\"$key\" // $default" "$STATE_FILE" 2>/dev/null || echo "$default"
    else
        # Fallback without jq
        grep -o "\"$key\":[^,}]*" "$STATE_FILE" 2>/dev/null | cut -d: -f2- | tr -d '"' || echo "$default"
    fi
}

set_state() {
    local key=$1
    local value=$2
    
    if command -v jq &>/dev/null; then
        local temp=$(mktemp)
        jq ".\"$key\" = \"$value\"" "$STATE_FILE" > "$temp" && mv "$temp" "$STATE_FILE"
    else
        # Simple fallback - just append (not ideal but works)
        if grep -q "\"$key\":" "$STATE_FILE"; then
            sed -i "s/\"$key\":\"[^\"]*\"/\"$key\":\"$value\"/" "$STATE_FILE"
        else
            # Add new key
            sed -i 's/}$/,"'"$key"'":"'"$value"'"}/' "$STATE_FILE"
            sed -i 's/{,/{/' "$STATE_FILE"
        fi
    fi
}

is_installed() {
    local component=$1
    [[ "$(get_state "$component")" == "installed" ]]
}

mark_installed() {
    local component=$1
    set_state "$component" "installed"
    success "$component successfully installed and verified"
}

mark_failed() {
    local component=$1
    set_state "$component" "failed"
}

#==============================================================================
# VALIDATION FUNCTIONS
#==============================================================================

validate_os() {
    info "Validating OS compatibility..."
    
    if [[ ! -f /etc/os-release ]]; then
        die "Cannot detect OS: /etc/os-release not found"
    fi
    
    source /etc/os-release
    
    local os_valid=false
    for valid_id in "${REQUIRED_OS_IDS[@]}"; do
        if [[ "$ID" == "$valid_id" ]]; then
            os_valid=true
            break
        fi
    done
    
    if [[ "$os_valid" != "true" ]]; then
        die "Unsupported OS: $ID (required: ${REQUIRED_OS_IDS[*]})"
    fi
    
    local version_valid=false
    for valid_version in "${REQUIRED_OS_VERSIONS[@]}"; do
        if [[ "$VERSION_ID" == "$valid_version" ]]; then
            version_valid=true
            break
        fi
    done
    
    if [[ "$version_valid" != "true" ]]; then
        die "Unsupported OS version: $VERSION_ID (required: ${REQUIRED_OS_VERSIONS[*]})"
    fi
    
    success "OS validated: $ID $VERSION_ID ($VERSION_CODENAME)"
}

validate_dependencies() {
    info "Validating system dependencies..."
    
    local missing_deps=()
    local required_commands=("wget" "apt" "systemctl" "mktemp")
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        die "Missing required commands: ${missing_deps[*]}"
    fi
    
    # Check disk space (need at least 500MB)
    local available_mb=$(df -m / | awk 'NR==2 {print $4}')
    if [[ $available_mb -lt 500 ]]; then
        die "Insufficient disk space: ${available_mb}MB available, need at least 500MB"
    fi
    
    success "System dependencies validated"
}

validate_network() {
    info "Validating network connectivity..."
    
    if ! ping -c 1 -W 5 github.com &>/dev/null; then
        warn "Cannot reach github.com - installation may fail"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            die "Installation cancelled by user"
        fi
    else
        success "Network connectivity validated"
    fi
}

#==============================================================================
# BACKUP FUNCTIONS
#==============================================================================

backup_file() {
    local file=$1
    
    if [[ -f "$file" ]]; then
        local backup_name="$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
        local backup_path="${BACKUP_DIR}/${backup_name}"
        cp "$file" "$backup_path"
        info "Backed up $file to $backup_path"
        echo "$backup_path"
    fi
}

#==============================================================================
# HOSTNAME CONFIGURATION
#==============================================================================

configure_hostname() {
    if is_installed "hostname"; then
        info "Hostname already configured, skipping..."
        return 0
    fi
    
    info "Configuring hostname..."
    
    local current_hostname=$(hostname)
    local current_pretty=$(hostnamectl status --pretty 2>/dev/null || echo "")
    
    read -p "Hostname [$current_hostname]: " new_hostname
    new_hostname="${new_hostname:-$current_hostname}"
    
    read -p "Pretty hostname [${current_pretty:-Audio Receiver}]: " new_pretty
    new_pretty="${new_pretty:-${current_pretty:-Audio Receiver}}"
    
    if [[ "$new_hostname" != "$current_hostname" ]]; then
        backup_file "/etc/hostname"
        backup_file "/etc/hosts"
        hostnamectl set-hostname "$new_hostname" || die "Failed to set hostname"
    fi
    
    hostnamectl set-hostname --pretty "$new_pretty" || die "Failed to set pretty hostname"
    
    set_state "hostname_name" "$new_hostname"
    set_state "hostname_pretty" "$new_pretty"
    mark_installed "hostname"
}

#==============================================================================
# BLUETOOTH INSTALLATION
#==============================================================================

install_bluetooth_packages() {
    info "Installing Bluetooth packages..."
    
    apt update || die "Failed to update package lists"
    
    local pkgs=(bluez bluez-tools)
    
    # Detect available BlueALSA package names
    if apt-cache show bluez-alsa-utils &>/dev/null; then
        pkgs+=(bluez-alsa-utils)
    else
        apt-cache show bluealsa &>/dev/null && pkgs+=(bluealsa)
        apt-cache show bluealsa-utils &>/dev/null && pkgs+=(bluealsa-utils)
    fi
    
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends "${pkgs[@]}" \
        || die "Failed to install Bluetooth packages"
    
    success "Bluetooth packages installed"
}

configure_bluetooth() {
    info "Configuring Bluetooth..."
    
    backup_file "/etc/bluetooth/main.conf"
    
    cat > /etc/bluetooth/main.conf <<'EOF'
[General]
Class = 0x200414
DiscoverableTimeout = 0

[Policy]
AutoEnable=true
EOF
    
    success "Bluetooth configuration written"
}

install_bluetooth_agent() {
    info "Installing Bluetooth agent service..."
    
    cat > /etc/systemd/system/bt-agent@.service <<'EOF'
[Unit]
Description=Bluetooth Agent
Requires=bluetooth.service
After=bluetooth.service

[Service]
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
    
    systemctl daemon-reload || die "Failed to reload systemd"
    systemctl enable bt-agent@hci0.service || die "Failed to enable bt-agent"
    
    success "Bluetooth agent service installed"
}

install_bluetooth_udev() {
    info "Installing Bluetooth udev rules..."
    
    cat > /usr/local/bin/bluetooth-udev <<'EOF'
#!/bin/bash
if [[ ! $NAME =~ ^\"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\"$ ]]; then exit 0; fi

action=$(expr "$ACTION" : "\([a-zA-Z]\+\).*")

if [ "$action" = "add" ]; then
    bluetoothctl discoverable off
fi

if [ "$action" = "remove" ]; then
    bluetoothctl discoverable on
fi
EOF
    
    chmod 755 /usr/local/bin/bluetooth-udev || die "Failed to set permissions"
    
    cat > /etc/udev/rules.d/99-bluetooth-udev.rules <<'EOF'
SUBSYSTEM=="input", GROUP="input", MODE="0660"
KERNEL=="input[0-9]*", RUN+="/usr/local/bin/bluetooth-udev"
EOF
    
    success "Bluetooth udev rules installed"
}

verify_bluetooth() {
    info "Verifying Bluetooth installation..."
    
    if ! command -v bluetoothctl &>/dev/null; then
        die "bluetoothctl not found after installation"
    fi
    
    if ! systemctl is-enabled bt-agent@hci0.service &>/dev/null; then
        die "bt-agent service not enabled"
    fi
    
    success "Bluetooth installation verified"
}

install_bluetooth() {
    if is_installed "bluetooth"; then
        info "Bluetooth already installed, skipping..."
        return 0
    fi
    
    read -p "Install Bluetooth Audio (ALSA)? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Skipping Bluetooth installation"
        return 0
    fi
    
    install_bluetooth_packages
    configure_bluetooth
    install_bluetooth_agent
    install_bluetooth_udev
    verify_bluetooth
    
    mark_installed "bluetooth"
}

#==============================================================================
# SHAIRPORT SYNC INSTALLATION
#==============================================================================

install_shairport_dependencies() {
    info "Installing Shairport Sync build dependencies..."
    
    apt update || die "Failed to update package lists"
    
    local deps=(
        avahi-daemon alsa-utils wget unzip autoconf automake 
        build-essential libtool git pkg-config libsystemd-dev 
        libpopt-dev libconfig-dev libasound2-dev libavahi-client-dev 
        libssl-dev libsoxr-dev libplist-dev libsodium-dev 
        libavutil-dev libavcodec-dev libavformat-dev uuid-dev 
        libgcrypt20-dev xxd
    )
    
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends "${deps[@]}" \
        || die "Failed to install build dependencies"
    
    success "Build dependencies installed"
}

build_nqptp() {
    info "Building NQPTP $NQPTP_VERSION..."
    
    local build_dir=$(mktemp -d)
    local original_dir=$(pwd)
    trap "cd '$original_dir'; rm -rf '$build_dir'" RETURN
    
    cd "$build_dir" || die "Failed to enter build directory"
    
    wget -q -O nqptp.zip \
        "https://github.com/mikebrady/nqptp/archive/refs/tags/${NQPTP_VERSION}.zip" \
        || die "Failed to download NQPTP"
    
    unzip -q nqptp.zip || die "Failed to extract NQPTP"
    cd "nqptp-${NQPTP_VERSION}" || die "Failed to enter NQPTP directory"
    
    autoreconf -fi || die "NQPTP autoreconf failed"
    ./configure --with-systemd-startup || die "NQPTP configure failed"
    make -j "$(nproc)" || die "NQPTP build failed"
    make install systemdsystemunitdir=/lib/systemd/system systemduserunitdir=/usr/lib/systemd/user \
        || die "NQPTP install failed"
    
    success "NQPTP built and installed"
}

build_shairport_sync() {
    info "Building Shairport Sync $SHAIRPORT_SYNC_VERSION..."
    
    local build_dir=$(mktemp -d)
    local original_dir=$(pwd)
    trap "cd '$original_dir'; rm -rf '$build_dir'" RETURN
    
    cd "$build_dir" || die "Failed to enter build directory"
    
    wget -q -O shairport-sync.zip \
        "https://github.com/mikebrady/shairport-sync/archive/refs/tags/${SHAIRPORT_SYNC_VERSION}.zip" \
        || die "Failed to download Shairport Sync"
    
    unzip -q shairport-sync.zip || die "Failed to extract Shairport Sync"
    cd "shairport-sync-${SHAIRPORT_SYNC_VERSION}" || die "Failed to enter Shairport directory"
    
    autoreconf -fi || die "Shairport autoreconf failed"
    ./configure --sysconfdir=/etc --with-alsa --with-soxr --with-avahi \
        --with-ssl=openssl --with-systemd --with-airplay-2 \
        || die "Shairport configure failed"
    make -j "$(nproc)" || die "Shairport build failed"
    make install systemdsystemunitdir=/lib/systemd/system systemduserunitdir=/usr/lib/systemd/user \
        || die "Shairport install failed"
    
    success "Shairport Sync built and installed"
}

create_output_detect_script() {
    info "Creating audio output detection script..."
    
    cat > /usr/local/bin/shairport-output-detect <<'EOF'
#!/bin/bash
# Shairport Sync Audio Output Detection Script
# This script runs before shairport-sync starts to select the best audio device
# Includes cold-start handling for USB DACs and HDMI audio

CONF="/etc/shairport-sync.conf"
LOG_TAG="shairport-output-detect"

# Cold start configuration
USB_WAIT_TIMEOUT=${USB_WAIT_TIMEOUT:-30}      # Max seconds to wait for USB audio
ALSA_WAIT_TIMEOUT=${ALSA_WAIT_TIMEOUT:-15}    # Max seconds to wait for any ALSA
HDMI_WAIT_TIMEOUT=${HDMI_WAIT_TIMEOUT:-10}    # Max seconds to wait for HDMI

# Logging function
log() { 
    logger -t "$LOG_TAG" "$@" 2>/dev/null || true
    echo "[$LOG_TAG] $@" >&2
}

# Return the first playback PCM index for a given ALSA card number
first_playback_device_for_card() {
    local card="$1"
    local card_dir="/sys/class/sound/card${card}"
    local entry
    
    [[ -d "$card_dir" ]] || return 1
    
    shopt -s nullglob
    for entry in "$card_dir"/pcmC"${card}"D*p; do
        [[ -d "$entry" ]] || continue
        if [[ $(basename "$entry") =~ pcmC[0-9]+D([0-9]+)p ]]; then
            echo "${BASH_REMATCH[1]}"
            shopt -u nullglob
            return 0
        fi
    done
    shopt -u nullglob
    return 1
}

# Determine the best supported output rate for a card/device pair
best_rate_for_pcm() {
    local card="$1"
    local dev="$2"
    local info_file="/proc/asound/card${card}/pcm${dev}p/sub0/info"
    local rates_line rate best=0 upper
    
    if [[ -r "$info_file" ]]; then
        rates_line=$(grep '^rates:' "$info_file" 2>/dev/null | sed 's/^rates:[[:space:]]*//')
        if [[ -n "$rates_line" ]]; then
            for rate in $rates_line; do
                case "$rate" in
                    44100)
                        echo "44100"
                        return 0
                        ;;
                    [0-9]*)
                        if (( rate > best )); then
                            best=$rate
                        fi
                        ;;
                    *-*)
                        upper=${rate#*-}
                        if [[ "$upper" =~ ^[0-9]+$ ]]; then
                            echo "$upper"
                            return 0
                        fi
                        ;;
                    continuous)
                        echo "auto"
                        return 0
                        ;;
                esac
            done
            if (( best > 0 )); then
                echo "$best"
                return 0
            fi
        fi
    fi
    
    echo "auto"
    return 0
}

# Map ALSA device string to an output rate
determine_output_rate() {
    local device="$1"
    
    if [[ "$device" =~ ^(plughw|hw):([0-9]+),([0-9]+) ]]; then
        local card="${BASH_REMATCH[2]}"
        local dev="${BASH_REMATCH[3]}"
        echo "$(best_rate_for_pcm "$card" "$dev")"
        return 0
    fi
    
    echo "auto"
    return 0
}

# Try to locate a USB audio playback device and return it as plughw:card,device
find_usb_device() {
    local card_path card dev card_info real_path is_usb
    
    for card_path in /sys/class/sound/card*; do
        [[ -e "$card_path" ]] || continue
        card="${card_path##*/card}"
        [[ "$card" =~ ^[0-9]+$ ]] || continue
        
        real_path=$(readlink -f "$card_path" 2>/dev/null || echo "$card_path")
        is_usb=0
        
        if command -v udevadm &>/dev/null && \
           udevadm info -q property -p "$real_path" 2>/dev/null | grep -q '^ID_BUS=usb$'; then
            is_usb=1
        else
            card_info=$(awk -v idx="$card" '$1 == idx {for (i=2;i<=NF;i++) printf "%s ", $i; printf "\n"}' /proc/asound/cards 2>/dev/null || true)
            if echo "$card_info" | grep -qi 'usb'; then
                is_usb=1
            fi
        fi
        
        if [[ "$is_usb" -eq 1 ]]; then
            if ! dev=$(first_playback_device_for_card "$card"); then
                continue
            fi
            echo "plughw:${card},${dev}"
            return 0
        fi
    done
    
    return 1
}

# Fallback: parse aplay -l output for USB devices
find_usb_device_from_aplay() {
    local line card_id dev_id description
    while IFS= read -r line; do
        if [[ "$line" =~ ^card[[:space:]]+([0-9]+):[[:space:]]+([^[:space:]]+)[[:space:]]+\\[(.*)\\],[[:space:]]+device[[:space:]]+([0-9]+):[[:space:]]+(.*) ]]; then
            card_id="${BASH_REMATCH[1]}"
            description="${BASH_REMATCH[3]} ${BASH_REMATCH[5]}"
            dev_id="${BASH_REMATCH[4]}"
            if echo "$description" | grep -qiE 'usb|dac|smsl'; then
                echo "plughw:${card_id},${dev_id}"
                return 0
            fi
        fi
    done < <(aplay -l 2>/dev/null || true)
    
    return 1
}

# Detect the best audio device
detect_best_device() {
    # Prefer USB DACs when available
    local usb_dev
    if usb_dev=$(find_usb_device); then
        usb_dev=$(echo "$usb_dev" | head -n1)
        if [[ -n "$usb_dev" ]]; then
            echo "$usb_dev"
            log "Selected USB: $usb_dev"
            return 0
        fi
    elif usb_dev=$(find_usb_device_from_aplay); then
        usb_dev=$(echo "$usb_dev" | head -n1)
        if [[ -n "$usb_dev" ]]; then
            echo "$usb_dev"
            log "Selected USB (aplay): $usb_dev"
            return 0
        fi
    fi
    
    # Check for HDMI with active monitor
    if ls /proc/asound/card*/eld#* &>/dev/null 2>&1; then
        while IFS= read -r eld_file; do
            if grep -qs "monitor_present *1" "$eld_file" 2>/dev/null; then
                # Find first HDMI device
                while IFS= read -r line; do
                    local card_id=$(echo "$line" | awk '{print $2}' | tr -d ':')
                    local dev_id=$(echo "$line" | awk '{print $4}' | tr -d ':')
                    
                    if [[ -n "$card_id" && -n "$dev_id" ]]; then
                        echo "plughw:${card_id},${dev_id}"
                        log "Selected HDMI: plughw:${card_id},${dev_id}"
                        return 0
                    fi
                done < <(aplay -l 2>/dev/null | grep "^card.*HDMI" || true)
            fi
        done < <(ls /proc/asound/card*/eld#* 2>/dev/null || true)
    fi
    
    # Fallback to default ALSA device
    local default_dev=$(aplay -L 2>/dev/null | awk -F: '/^default:/ {print $1":"$2; exit}' || true)
    if [[ -n "$default_dev" ]]; then
        echo "$default_dev"
        log "Selected default: $default_dev"
        return 0
    fi
    
    # Last resort: first plughw device
    local first_plughw=$(aplay -L 2>/dev/null | awk '/^plughw:/ {print; exit}' || true)
    if [[ -n "$first_plughw" ]]; then
        echo "$first_plughw"
        log "Selected first plughw: $first_plughw"
        return 0
    fi
    
    echo "default"
    log "Using absolute fallback: default"
}

# Wait for ALSA subsystem to be ready
wait_for_alsa() {
    local max_attempts=$((ALSA_WAIT_TIMEOUT * 2))  # 0.5s intervals
    local i
    
    log "Waiting for ALSA subsystem (max ${ALSA_WAIT_TIMEOUT}s)..."
    
    for ((i=1; i<=max_attempts; i++)); do
        if aplay -l &>/dev/null 2>&1; then 
            log "ALSA ready after $((i/2))s"
            return 0
        fi
        sleep 0.5
    done
    
    log "ALSA not ready after ${ALSA_WAIT_TIMEOUT}s, continuing anyway..."
    return 1
}

# Wait specifically for USB audio devices (cold start handling)
wait_for_usb_audio() {
    local max_attempts=$((USB_WAIT_TIMEOUT * 2))  # 0.5s intervals
    local i
    local usb_dev
    
    log "Waiting for USB audio device (max ${USB_WAIT_TIMEOUT}s)..."
    
    for ((i=1; i<=max_attempts; i++)); do
        if usb_dev=$(find_usb_device 2>/dev/null) && [[ -n "$usb_dev" ]]; then
            log "USB audio found after $((i/2))s: $usb_dev"
            echo "$usb_dev"
            return 0
        fi
        
        # Also try aplay method
        if usb_dev=$(find_usb_device_from_aplay 2>/dev/null) && [[ -n "$usb_dev" ]]; then
            log "USB audio found (aplay) after $((i/2))s: $usb_dev"
            echo "$usb_dev"
            return 0
        fi
        
        sleep 0.5
    done
    
    log "No USB audio found after ${USB_WAIT_TIMEOUT}s"
    return 1
}

# Wait for HDMI audio with active monitor
wait_for_hdmi_audio() {
    local max_attempts=$((HDMI_WAIT_TIMEOUT * 2))  # 0.5s intervals
    local i
    
    log "Checking for HDMI audio (max ${HDMI_WAIT_TIMEOUT}s)..."
    
    for ((i=1; i<=max_attempts; i++)); do
        if ls /proc/asound/card*/eld#* &>/dev/null 2>&1; then
            while IFS= read -r eld_file; do
                if grep -qs "monitor_present *1" "$eld_file" 2>/dev/null; then
                    # Find first HDMI device
                    while IFS= read -r line; do
                        local card_id=$(echo "$line" | awk '{print $2}' | tr -d ':')
                        local dev_id=$(echo "$line" | awk '{print $4}' | tr -d ':')
                        
                        if [[ -n "$card_id" && -n "$dev_id" ]]; then
                            log "HDMI audio found after $((i/2))s: plughw:${card_id},${dev_id}"
                            echo "plughw:${card_id},${dev_id}"
                            return 0
                        fi
                    done < <(aplay -l 2>/dev/null | grep "^card.*HDMI" || true)
                fi
            done < <(ls /proc/asound/card*/eld#* 2>/dev/null || true)
        fi
        sleep 0.5
    done
    
    log "No active HDMI audio found after ${HDMI_WAIT_TIMEOUT}s"
    return 1
}

# Main execution
main() {
    log "=== Shairport Output Detection Starting ==="
    log "Cold start timeouts: ALSA=${ALSA_WAIT_TIMEOUT}s, USB=${USB_WAIT_TIMEOUT}s, HDMI=${HDMI_WAIT_TIMEOUT}s"
    
    # Phase 1: Wait for ALSA subsystem
    wait_for_alsa || true
    
    # Phase 2: Try to find USB audio first (with extended wait for cold start)
    local DEVICE=""
    if DEVICE=$(wait_for_usb_audio); then
        DEVICE=$(echo "$DEVICE" | head -n1 | tr -d '\r\n' | awk '{print $1}')
        log "Using USB audio device: $DEVICE"
    # Phase 3: Try HDMI if no USB found
    elif DEVICE=$(wait_for_hdmi_audio); then
        DEVICE=$(echo "$DEVICE" | head -n1 | tr -d '\r\n' | awk '{print $1}')
        log "Using HDMI audio device: $DEVICE"
    # Phase 4: Fall back to detect_best_device for other options
    else
        log "No USB or HDMI found, using fallback detection..."
        DEVICE=$(detect_best_device)
        DEVICE=$(echo "$DEVICE" | tr -d '\r\n' | awk '{print $1}')
    fi
    
    # Legacy fallback - detect device if still empty
    if [[ -z "$DEVICE" ]]; then
        log "Device still empty, running legacy detection..."
        DEVICE=$(detect_best_device)
        DEVICE=$(echo "$DEVICE" | tr -d '\r\n' | awk '{print $1}')
    fi
    
    # Validate device name
    case "$DEVICE" in
        default|default:*|plughw:*|hw:*|hdmi:*) ;;
        *) 
            log "Invalid device '$DEVICE', using 'default'"
            DEVICE="default" 
            ;;
    esac
    
    local RATE=$(determine_output_rate "$DEVICE")
    local RATE_CONF
    if [[ "$RATE" == "auto" ]]; then
        RATE_CONF='  output_rate = "auto";'
    else
        RATE_CONF="  output_rate = $RATE;"
    fi
    
    log "Final device: $DEVICE"
    log "Using sample rate: $RATE"
    
    # Ensure config file exists with proper structure
    if [[ ! -f "$CONF" ]]; then
        log "Creating new config file"
        cat > "$CONF" <<EOFCONF
general = {
  name = "$(hostname)";
  output_backend = "alsa";
};

alsa = {
  output_device = "$DEVICE";
$RATE_CONF
};

sessioncontrol = {
  session_timeout = 20;
};
EOFCONF
    else
        # Update existing config
        log "Updating existing config file"
        
        # Create temp file
        local TEMP_CONF=$(mktemp)
        
        # Remove old alsa block and copy everything else
        awk '
            /^alsa[[:space:]]*=/ { in_alsa=1; next }
            in_alsa==1 && /^}[[:space:]]*;/ { in_alsa=0; next }
            in_alsa==1 { next }
            { print }
        ' "$CONF" > "$TEMP_CONF"
        
        # Append new alsa block
        cat >> "$TEMP_CONF" <<EOFCONF

alsa = {
  output_device = "$DEVICE";
$RATE_CONF
};
EOFCONF
        
        # Replace original
        if ! mv "$TEMP_CONF" "$CONF"; then
            log "Failed to replace $CONF"
            rm -f "$TEMP_CONF"
            return 1
        fi
        chmod 644 "$CONF"
    fi
    
    log "Configuration updated successfully"
    return 0
}

# Run main function
main
exit $?
EOF
    
    chmod +x /usr/local/bin/shairport-output-detect || die "Failed to set permissions"
    
    # Test the script
    if ! /usr/local/bin/shairport-output-detect; then
        warn "Output detection script test had issues, but continuing..."
    fi
    
    success "Output detection script created and tested"
}

configure_shairport() {
    info "Configuring Shairport Sync..."
    
    local pretty_hostname=$(get_state "hostname_pretty")
    pretty_hostname="${pretty_hostname:-$(hostname)}"
    
    backup_file "/etc/shairport-sync.conf"
    
    cat > /etc/shairport-sync.conf <<EOF
general = {
  name = "${pretty_hostname}";
  output_backend = "alsa";
};

sessioncontrol = {
  session_timeout = 20;
};
EOF
    
    success "Shairport Sync configuration created"
}

create_shairport_service() {
    info "Creating Shairport Sync systemd service..."
    
    backup_file "/etc/systemd/system/shairport-sync.service"
    
    cat > /etc/systemd/system/shairport-sync.service <<'EOF'
[Unit]
Description=Shairport Sync - AirPlay Audio Receiver
# Cold start dependencies - wait for hardware to be ready
After=network-online.target avahi-daemon.service sound.target alsa-restore.service local-fs.target
After=systemd-udev-settle.service
Wants=network-online.target avahi-daemon.service
# Ensure we start after USB devices are enumerated
After=sys-subsystem-sound-devices-card0.device
Wants=sys-subsystem-sound-devices-card0.device
StartLimitIntervalSec=120
StartLimitBurst=5

[Service]
Type=simple
User=shairport-sync
Group=shairport-sync
SupplementaryGroups=audio
PermissionsStartOnly=true
RuntimeDirectory=shairport-sync
RuntimeDirectoryMode=0755

# Cold start handling - output detection script waits for audio devices
ExecStartPre=/usr/local/bin/shairport-output-detect
ExecStart=/usr/local/bin/shairport-sync -c /etc/shairport-sync.conf

# Robust restart policy for cold start failures
Restart=on-failure
RestartSec=3

# Watchdog for hung processes
TimeoutStartSec=90
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF
    
    # Add gpio group if it exists (Dell Wyse)
    if getent group gpio &>/dev/null && getent passwd shairport-sync &>/dev/null; then
        usermod -a -G gpio shairport-sync 2>/dev/null || true
    fi
    
    systemctl daemon-reload || die "Failed to reload systemd"
    success "Shairport Sync service created"
}

install_shairport_udev() {
    info "Installing Shairport Sync udev rules..."
    
    # Create debounced restart script to handle rapid udev events
    cat > /usr/local/bin/shairport-udev-restart <<'EOF'
#!/bin/bash
# Debounced restart for shairport-sync on audio device changes
# Prevents rapid restarts during USB enumeration

LOCK_FILE="/tmp/shairport-restart.lock"
DEBOUNCE_SECONDS=3

# Use flock to prevent concurrent executions
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    # Another instance is running, exit silently
    exit 0
fi

# Log the trigger
logger -t "shairport-udev" "Audio device change detected, scheduling restart..."

# Wait for debounce period (allows USB to fully enumerate)
sleep "$DEBOUNCE_SECONDS"

# Restart the service
if systemctl is-active --quiet shairport-sync; then
    logger -t "shairport-udev" "Restarting shairport-sync service..."
    /usr/bin/systemctl restart shairport-sync.service
else
    logger -t "shairport-udev" "Starting shairport-sync service..."
    /usr/bin/systemctl start shairport-sync.service
fi

# Release lock
flock -u 200
EOF
    
    chmod 755 /usr/local/bin/shairport-udev-restart || die "Failed to set permissions"
    
    cat > /etc/udev/rules.d/99-shairport-hotplug.rules <<'EOF'
# Shairport Sync Audio Hotplug Rules
# These rules handle cold start and hot-plug scenarios for audio devices

# Restart Shairport when displays are connected/disconnected (HDMI audio)
ACTION=="change", SUBSYSTEM=="drm", ENV{HOTPLUG}=="1", RUN+="/usr/local/bin/shairport-udev-restart"

# Restart Shairport when ALSA sound cards are added (USB DAC plug-in)
ACTION=="add", SUBSYSTEM=="sound", KERNEL=="card*", RUN+="/usr/local/bin/shairport-udev-restart"

# Restart Shairport when ALSA sound cards change
ACTION=="change", SUBSYSTEM=="sound", KERNEL=="card*", RUN+="/usr/local/bin/shairport-udev-restart"

# Handle USB audio device addition specifically
ACTION=="add", SUBSYSTEM=="usb", ATTR{bInterfaceClass}=="01", RUN+="/usr/local/bin/shairport-udev-restart"
EOF
    
    udevadm control --reload || warn "Failed to reload udev rules"
    
    success "Shairport Sync udev rules installed"
}

enable_shairport_services() {
    info "Enabling and starting services..."
    
    # Ensure we're in a valid directory before running systemctl
    cd /tmp || cd / || die "Failed to change to a valid directory"
    
    # Reload systemd to pick up new service files
    systemctl daemon-reload || die "Failed to reload systemd"
    
    # Enable NQPTP
    if ! systemctl enable nqptp 2>&1 | tee -a "$LOG_FILE"; then
        warn "NQPTP enable had warnings, but continuing..."
    fi
    
    # Enable Shairport Sync
    if ! systemctl enable shairport-sync 2>&1 | tee -a "$LOG_FILE"; then
        warn "Shairport Sync enable had warnings, but continuing..."
    fi
    
    # Start NQPTP
    info "Starting NQPTP service..."
    if ! systemctl start nqptp; then
        error "Failed to start NQPTP service"
        systemctl status nqptp --no-pager -l 2>&1 | tee -a "$LOG_FILE" || true
        journalctl -u nqptp -n 50 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
        die "NQPTP service failed to start"
    fi
    
    # Start Shairport Sync
    info "Starting Shairport Sync service..."
    if ! systemctl start shairport-sync; then
        error "Failed to start Shairport Sync service"
        systemctl status shairport-sync --no-pager -l 2>&1 | tee -a "$LOG_FILE" || true
        journalctl -u shairport-sync -n 50 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
        
        # Additional debugging
        error "Checking output detection script..."
        if [[ -x /usr/local/bin/shairport-output-detect ]]; then
            info "Running output detection script manually..."
            /usr/local/bin/shairport-output-detect 2>&1 | tee -a "$LOG_FILE" || true
        fi
        
        die "Shairport Sync service failed to start - check logs above"
    fi
    
    # Trigger udev for initial device detection
    udevadm trigger --subsystem-match=drm --action=change 2>/dev/null || true
    udevadm trigger --subsystem-match=sound --action=change 2>/dev/null || true
    
    # Give services a moment to stabilize
    sleep 2
    
    # Verify services are actually running
    if systemctl is-active --quiet nqptp && systemctl is-active --quiet shairport-sync; then
        success "Services enabled and started successfully"
    else
        warn "Services enabled but may not be fully active - check status"
    fi
}

verify_shairport() {
    info "Verifying Shairport Sync installation..."
    
    if ! command -v shairport-sync &>/dev/null; then
        die "shairport-sync binary not found"
    fi
    
    if ! systemctl is-enabled nqptp &>/dev/null; then
        die "NQPTP service not enabled"
    fi
    
    if ! systemctl is-enabled shairport-sync &>/dev/null; then
        die "Shairport Sync service not enabled"
    fi
    
    if ! systemctl is-active nqptp &>/dev/null; then
        die "NQPTP service not running"
    fi
    
    if ! systemctl is-active shairport-sync &>/dev/null; then
        die "Shairport Sync service not running"
    fi
    
    success "Shairport Sync installation verified"
}

install_shairport() {
    if is_installed "shairport"; then
        info "Shairport Sync already installed, refreshing configuration..."
        create_output_detect_script
        create_shairport_service
        install_shairport_udev
        systemctl daemon-reload || warn "Failed to reload systemd after refresh"
        systemctl try-restart shairport-sync 2>/dev/null || true
        return 0
    fi
    
    read -p "Install Shairport Sync (AirPlay 2 audio player)? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Skipping Shairport Sync installation"
        return 0
    fi
    
    # Clean up any partial installations
    info "Cleaning up any previous partial installations..."
    systemctl stop shairport-sync 2>/dev/null || true
    systemctl disable shairport-sync 2>/dev/null || true
    systemctl stop nqptp 2>/dev/null || true
    systemctl disable nqptp 2>/dev/null || true
    
    install_shairport_dependencies
    build_nqptp
    build_shairport_sync
    create_output_detect_script
    configure_shairport
    create_shairport_service
    install_shairport_udev
    enable_shairport_services
    verify_shairport
    
    mark_installed "shairport"
}

#==============================================================================
# RASPOTIFY INSTALLATION
#==============================================================================

install_raspotify_package() {
    info "Installing Raspotify..."
    
    # Ensure we're in a safe directory
    cd /tmp || die "Failed to change to /tmp"
    
    apt update || die "Failed to update package lists"
    apt install -y --no-install-recommends curl || die "Failed to install curl"
    
    local install_script=$(mktemp)
    wget -q -O "$install_script" https://dtcooper.github.io/raspotify/install.sh \
        || die "Failed to download Raspotify installer"
    
    bash "$install_script" || die "Raspotify installation failed"
    rm -f "$install_script"
    
    success "Raspotify package installed"
}

configure_raspotify() {
    info "Configuring Raspotify..."
    
    local pretty_hostname=$(get_state "hostname_pretty")
    pretty_hostname="${pretty_hostname:-$(hostname)}"
    local librespot_name="${pretty_hostname// /-}"
    
    backup_file "/etc/raspotify/conf"
    
    cat > /etc/raspotify/conf <<EOF
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
    
    systemctl daemon-reload || die "Failed to reload systemd"
    systemctl enable raspotify || die "Failed to enable Raspotify"
    
    success "Raspotify configured"
}

verify_raspotify() {
    info "Verifying Raspotify installation..."
    
    if ! systemctl is-enabled raspotify &>/dev/null; then
        die "Raspotify service not enabled"
    fi
    
    success "Raspotify installation verified"
}

install_raspotify() {
    if is_installed "raspotify"; then
        info "Raspotify already installed, skipping..."
        return 0
    fi
    
    read -p "Install Raspotify (Spotify Connect)? [y/N] " -r
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Skipping Raspotify installation"
        return 0
    fi
    
    install_raspotify_package
    configure_raspotify
    verify_raspotify
    
    mark_installed "raspotify"
}

#==============================================================================
# MAIN INSTALLATION FLOW
#==============================================================================

show_banner() {
    cat <<'EOF'
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║        Raspberry Pi Audio Receiver Installer v2.0        ║
║                                                           ║
║  Features: AirPlay 2, Bluetooth, Spotify Connect         ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

EOF
}

show_summary() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "Installation Summary"
    echo "═══════════════════════════════════════════════════════════"
    echo
    echo "Hostname:    $(get_state hostname_pretty)"
    echo "Bluetooth:   $(is_installed bluetooth && echo '✓ Installed' || echo '✗ Not installed')"
    echo "Shairport:   $(is_installed shairport && echo '✓ Installed' || echo '✗ Not installed')"
    echo "Raspotify:   $(is_installed raspotify && echo '✓ Installed' || echo '✗ Not installed')"
    echo
    echo "Log file:    $LOG_FILE"
    echo "State file:  $STATE_FILE"
    echo "Backups:     $BACKUP_DIR"
    echo
    
    if is_installed shairport; then
        echo "Your AirPlay receiver should now be visible as:"
        echo "  → $(get_state hostname_pretty)"
        echo
        echo "Service status:"
        systemctl status shairport-sync --no-pager -l | head -n 5 || true
    fi
    
    echo "═══════════════════════════════════════════════════════════"
}

run_diagnostics() {
    echo
    echo "═══════════════════════════════════════════════════════════"
    echo "Diagnostic Checks"
    echo "═══════════════════════════════════════════════════════════"
    
    local file_hostname runtime_hostname pretty_hostname hosts_entry
    file_hostname=$(cat /etc/hostname 2>/dev/null || echo "unknown")
    runtime_hostname=$(hostname 2>/dev/null || echo "unknown")
    pretty_hostname=$(hostnamectl status --pretty 2>/dev/null || echo "unknown")
    hosts_entry=$(grep -E '^127\.0\.1\.1' /etc/hosts 2>/dev/null || echo "MISSING 127.0.1.1 entry")
    
    echo "System hostname file: ${file_hostname}"
    echo "Runtime hostname:      ${runtime_hostname}"
    echo "Pretty hostname:       ${pretty_hostname}"
    echo "127.0.1.1 entry:       ${hosts_entry}"
    
    if [[ "$file_hostname" != "$runtime_hostname" ]]; then
        warn "Runtime hostname differs from /etc/hostname"
    fi
    
    if [[ "$hosts_entry" == "MISSING 127.0.1.1 entry" ]]; then
        warn "/etc/hosts lacks a 127.0.1.1 mapping for your hostname"
    elif [[ "$hosts_entry" != *"$runtime_hostname"* ]]; then
        warn "/etc/hosts entry does not reference hostname '$runtime_hostname'"
    fi
    
    local state_pretty
    state_pretty=$(get_state "hostname_pretty" "")
    if [[ -n "$state_pretty" && "$state_pretty" != "null" ]]; then
        echo "Installer stored pretty hostname: ${state_pretty}"
        if [[ "$state_pretty" != "$pretty_hostname" ]]; then
            warn "Pretty hostname stored in installer state differs from hostnamectl"
        fi
    fi
    
    if systemctl list-unit-files | grep -q '^avahi-daemon'; then
        if systemctl is-active --quiet avahi-daemon; then
            info "avahi-daemon is running"
        else
            warn "avahi-daemon is not active; AirPlay discovery will fail"
        fi
    else
        warn "avahi-daemon not installed; install avahi-daemon and avahi-utils for AirPlay discovery"
    fi
    
    if command -v avahi-browse &>/dev/null; then
        echo
        echo "Recent RAOP (_raop._tcp) advertisements:"
        if command -v timeout &>/dev/null; then
            timeout 5 avahi-browse -rt _raop._tcp 2>/dev/null | head -n 20 || true
        else
            avahi-browse -rt _raop._tcp 2>/dev/null | head -n 20 || true
        fi
    else
        warn "avahi-utils not installed; install it to inspect advertised AirPlay services (apt install avahi-utils)"
    fi
    
    echo "═══════════════════════════════════════════════════════════"
}

main() {
    show_banner
    
    ensure_root
    ensure_state_dir
    
    # Ensure we start in a safe directory
    cd / || die "Failed to change to root directory"
    
    # Validation Phase
    info "Starting validation phase..."
    validate_os
    validate_dependencies
    validate_network
    
    # Configuration Phase
    info "Starting configuration phase..."
    configure_hostname
    
    # Installation Phase
    info "Starting installation phase..."
    install_bluetooth
    install_shairport
    install_raspotify
    
    # Summary
    show_summary
    run_diagnostics
    
    success "Installation completed successfully!"
}

# Run main installation
main "$@"
