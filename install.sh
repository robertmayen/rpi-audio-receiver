#!/bin/bash

set -e

NQPTP_VERSION="1.2.4"
SHAIRPORT_SYNC_VERSION="4.3.2"
TMP_DIR=""

cleanup() {
    if [ -d "${TMP_DIR}" ]; then
        rm -rf "${TMP_DIR}"
    fi
}

verify_os() {
    MSG="Unsupported OS: Debian 12/13 is required."

    if [ ! -f /etc/os-release ]; then
        echo $MSG
        exit 1
    fi

    . /etc/os-release

    # Accept Debian / Raspbian 12 (bookworm) and 13 (trixie)
    if [[ ("$ID" != "debian" && "$ID" != "raspbian") || ("$VERSION_ID" != "12" && "$VERSION_ID" != "13") ]]; then
        echo $MSG
        exit 1
    fi
}

set_hostname() {
    CURRENT_PRETTY_HOSTNAME=$(hostnamectl status --pretty)

    read -p "Hostname [$(hostname)]: " HOSTNAME
    # Use hostnamectl on generic Debian instead of raspi-config
    if [[ -n "${HOSTNAME}" ]]; then
        sudo hostnamectl set-hostname "${HOSTNAME}"
    fi

    read -p "Pretty hostname [${CURRENT_PRETTY_HOSTNAME:-Audio Receiver}]: " PRETTY_HOSTNAME
    PRETTY_HOSTNAME="${PRETTY_HOSTNAME:-${CURRENT_PRETTY_HOSTNAME:-Audio Receiver}}"
    sudo hostnamectl set-hostname --pretty "$PRETTY_HOSTNAME"
}

install_bluetooth() {
    read -p "Do you want to install Bluetooth Audio (ALSA)? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^(yes|y|Y)$ ]]; then return; fi

    # Bluetooth stack and BlueALSA backend (avoid recommends for lean install)
    sudo apt update
    sudo apt install -y --no-install-recommends bluez bluez-tools bluez-alsa-utils

    # Bluetooth settings
    sudo tee /etc/bluetooth/main.conf >/dev/null <<'EOF'
[General]
Class = 0x200414
DiscoverableTimeout = 0

[Policy]
AutoEnable=true
EOF

    # Bluetooth Agent
    sudo tee /etc/systemd/system/bt-agent@.service >/dev/null <<'EOF'
[Unit]
Description=Bluetooth Agent
Requires=bluetooth.service
After=bluetooth.service

[Service]
# Ensure adapter is ready for pairing and discoverable without relying on deprecated hciconfig
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
    sudo systemctl daemon-reload
    sudo systemctl enable bt-agent@hci0.service

    # Bluetooth udev script
    sudo tee /usr/local/bin/bluetooth-udev >/dev/null <<'EOF'
#!/bin/bash
if [[ ! $NAME =~ ^\"([0-9A-F]{2}[:-]){5}([0-9A-F]{2})\"$ ]]; then exit 0; fi

action=$(expr "$ACTION" : "\([a-zA-Z]\+\).*")

if [ "$action" = "add" ]; then
    bluetoothctl discoverable off
    # disconnect wifi to prevent dropouts
    #ifconfig wlan0 down &
fi

if [ "$action" = "remove" ]; then
    # reenable wifi
    #ifconfig wlan0 up &
    bluetoothctl discoverable on
fi
EOF
    sudo chmod 755 /usr/local/bin/bluetooth-udev

    sudo tee /etc/udev/rules.d/99-bluetooth-udev.rules >/dev/null <<'EOF'
SUBSYSTEM=="input", GROUP="input", MODE="0660"
KERNEL=="input[0-9]*", RUN+="/usr/local/bin/bluetooth-udev"
EOF
}

install_shairport() {
    read -p "Do you want to install Shairport Sync (AirPlay 2 audio player)? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^(yes|y|Y)$ ]]; then return; fi

    # Base tools and services
    sudo apt update
    sudo apt install -y --no-install-recommends avahi-daemon alsa-utils

    # Build and install NQPTP for AirPlay 2 timing (packaged shairport-sync can use it)
    if [[ -z "$TMP_DIR" ]]; then
        TMP_DIR=$(mktemp -d)
    fi
    ( cd "$TMP_DIR" && \
      wget -O nqptp-${NQPTP_VERSION}.zip https://github.com/mikebrady/nqptp/archive/refs/tags/${NQPTP_VERSION}.zip && \
      unzip -q nqptp-${NQPTP_VERSION}.zip && \
      cd nqptp-${NQPTP_VERSION} && \
      autoreconf -fi && \
      ./configure --with-systemd-startup && \
      make -j $(nproc) && \
      sudo make install systemdsystemunitdir=/lib/systemd/system systemduserunitdir=/usr/lib/systemd/user )

    # Prefer packaged Shairport on Debian 12/13 to avoid FFmpeg-7 segfaults on source builds
    sudo apt install -y --no-install-recommends shairport-sync

    # Create a native systemd unit that runs before playback to pick the best ALSA device
    sudo tee /usr/local/bin/shairport-output-detect >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

CONF="/etc/shairport-sync.conf"

pick_default() {
  # Prefer HDMI if a monitor is connected; else analog/default
  local chosen="default"
  if ls /proc/asound/card*/eld#* &>/dev/null; then
    # Map common HDA HDMI indices to ALSA hdmi DEV numbers 0..3
    # For card N, ELD index K typically corresponds to hdmi DEV=K
    local card_index=0
    while read -r path; do
      if grep -qs "monitor_present *1" "$path"; then
        # Extract ELD index (e.g., eld#0.1 -> 1)
        idx=$(basename "$path" | awk -F'.' '{print $2}')
        # Determine CARD name for this card index from aplay -L
        card_name=$(aplay -L 2>/dev/null | awk -v ci="$card_index" '/^hdmi:CARD=/{print $1}' | sed -n "$(($idx+1))p" | sed -E 's/^hdmi:CARD=([^,]+).*/\1/')
        if [[ -n "${card_name:-}" ]]; then
          echo "hdmi:CARD=${card_name},DEV=${idx}"
          return 0
        fi
      fi
      card_index=$((card_index+1))
    done < <(ls /proc/asound/card*/eld#* 2>/dev/null | sort)
  fi
  # Fall back to system default or first plughw device
  if aplay -L 2>/dev/null | grep -qx "default"; then
    echo "default"
  else
    dev=$(aplay -L 2>/dev/null | awk '/^plughw:|^hw:/{print $1; exit}')
    echo "${dev:-default}"
  fi
}

DEVICE=$(pick_default)

# Ensure config exists and set ALSA device
if [[ ! -f "$CONF" ]]; then
  echo "general = { name = \"$(hostname)\"; output_backend = \"alsa\"; };" > "$CONF"
fi

# If an alsa block exists, update or insert output_device; otherwise add a new block
if grep -qE '^alsa *= *\{' "$CONF"; then
  if grep -qE '^[[:space:]]*output_device[[:space:]]*=' "$CONF"; then
    sed -i -E "s#(^[[:space:]]*output_device[[:space:]]*=).*#\1 \"${DEVICE}\";#" "$CONF"
  else
    # Insert before closing brace of the alsa block
    awk -v dev="$DEVICE" '
      BEGIN{ins=0}
      /^alsa[[:space:]]*=.*\{/ {print; ins=1; next}
      ins==1 && /^\}/ {print "  output_device = \"" dev "\";"; ins=0}
      {print}
    ' "$CONF" > "$CONF.tmp" && mv "$CONF.tmp" "$CONF"
  fi
else
  cat <<EOC >> "$CONF"
alsa = {
  output_device = "${DEVICE}";
};
EOC
fi
EOF
    sudo chmod +x /usr/local/bin/shairport-output-detect

    # Minimal config with pretty name and ALSA backend; device will be set by pre-start script
    sudo tee /etc/shairport-sync.conf >/dev/null <<EOF
general = {
  name = "${PRETTY_HOSTNAME:-$(hostname)}";
  output_backend = "alsa";
};

sessioncontrol = {
  session_timeout = 20;
};
EOF

    # Native systemd unit (override SysV shim) with device auto-detect
    sudo tee /etc/systemd/system/shairport-sync.service >/dev/null <<'EOF'
[Unit]
Description=Shairport Sync - AirPlay Audio Receiver
After=network-online.target sound.target
Wants=network-online.target

[Service]
User=shairport-sync
Group=shairport-sync
SupplementaryGroups=audio
PermissionsStartOnly=true
ExecStartPre=/usr/local/bin/shairport-output-detect
ExecStart=/usr/bin/shairport-sync -c /etc/shairport-sync.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

    # Add gpio group only if it exists (Raspberry Pi specific)
    if getent group gpio >/dev/null; then
        sudo usermod -a -G gpio shairport-sync
    fi

    sudo systemctl daemon-reload
    sudo systemctl enable --now nqptp
    sudo systemctl enable --now shairport-sync

    # Udev hotplug hook to re-detect output on HDMI / sound card changes
    sudo tee /usr/local/bin/shairport-udev-restart >/dev/null <<'EOF'
#!/bin/sh
/usr/bin/systemctl try-restart shairport-sync.service
EOF
    sudo chmod 755 /usr/local/bin/shairport-udev-restart

    sudo tee /etc/udev/rules.d/99-shairport-hotplug.rules >/dev/null <<'EOF'
# Restart Shairport when displays are connected/disconnected (HDMI hotplug)
ACTION=="change", SUBSYSTEM=="drm", ENV{HOTPLUG}=="1", RUN+="/usr/local/bin/shairport-udev-restart"
# Restart Shairport when ALSA cards change (USB DACs, etc.)
ACTION=="change", SUBSYSTEM=="sound", KERNEL=="card*", RUN+="/usr/local/bin/shairport-udev-restart"
EOF

    sudo udevadm control --reload
    # Optional: prime current state so we pick initial device when headless
    sudo udevadm trigger --subsystem-match=drm --action=change || true
    sudo udevadm trigger --subsystem-match=sound --action=change || true
}

install_raspotify() {
    read -p "Do you want to install Raspotify (Spotify Connect)? [y/N] " REPLY
    if [[ ! "$REPLY" =~ ^(yes|y|Y)$ ]]; then return; fi

    # Install Raspotify
    sudo apt update && sudo apt install -y --no-install-recommends curl
    curl -sL https://dtcooper.github.io/raspotify/install.sh | sh

    # Configure Raspotify
    LIBRESPOT_NAME="${PRETTY_HOSTNAME// /-}"
    LIBRESPOT_NAME=${LIBRESPOT_NAME:-$(hostname)}

    sudo tee /etc/raspotify/conf >/dev/null <<EOF
LIBRESPOT_QUIET=on
LIBRESPOT_AUTOPLAY=on
LIBRESPOT_DISABLE_AUDIO_CACHE=on
LIBRESPOT_DISABLE_CREDENTIAL_CACHE=on
LIBRESPOT_ENABLE_VOLUME_NORMALISATION=on
LIBRESPOT_NAME="${LIBRESPOT_NAME}"
LIBRESPOT_DEVICE_TYPE="avr"
LIBRESPOT_BITRATE="320"
LIBRESPOT_INITIAL_VOLUME="100"
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable raspotify
}

trap cleanup EXIT

echo "Raspberry Pi Audio Receiver"

verify_os
set_hostname
install_bluetooth
install_shairport
install_raspotify
