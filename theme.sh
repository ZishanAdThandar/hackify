#!/usr/bin/env bash

# =============================================================================
# HACKIFY - Ultimate Penetration Testing Tools Installer
# Author: Zishan Ahamed Thandar
# Description: Automated installation of 200+ hacking tools for penetration testing
# =============================================================================

set -o pipefail

# Color Codes for Beautiful Output
readonly BLACK='\033[0;30m'
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[0;37m'
readonly NC='\033[0m'

# -----------------------------------------------------------------------------
# Theme palette (Gruvbox Dark - warm, low-blue, eye-friendly)
# -----------------------------------------------------------------------------
readonly BG='#282828'
readonly FG='#EBDBB2'
readonly CURSOR='#EBDBB2'
readonly SEL_BG='#504945'
readonly SEL_FG='#EBDBB2'
readonly FONT="JetBrains Mono"
readonly FONT_SIZE=14

PALETTE=(
  '#282828' '#CC241D' '#98971A' '#D79921'
  '#458588' '#B16286' '#689D6A' '#A89984'
  '#928374' '#FB4934' '#B8BB26' '#FABD2F'
  '#83A598' '#D3869B' '#8EC07C' '#EBDBB2'
)

# -----------------------------------------------------------------------------
# History + Scrollback tuning
# -----------------------------------------------------------------------------
readonly HIST_SIZE=100000
readonly HIST_FILE_SIZE=200000
readonly HIST_CONTROL='ignorespace:erasedups'

readonly SCROLLBACK_GSETTINGS=2147483647
readonly SCROLLBACK_GNOME=2147483647
readonly SCROLLBACK_MATE=2147483647
readonly SCROLLBACK_XFCE=2147483647
readonly SCROLLBACK_QTERM=1000000
readonly SCROLLBACK_KITTY=200000
readonly SCROLLBACK_ALACRITTY=500000

# -----------------------------------------------------------------------------
# Wallpaper + Conky paths
# -----------------------------------------------------------------------------
readonly WALLPAPER_COLOR='#282828'
readonly WALLPAPER_DIR="$HOME/.local/share/hackify/wallpapers"
readonly WALLPAPER_FILE="$WALLPAPER_DIR/solid-gruvbox.png"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly CONKY_SRC="$SCRIPT_DIR/theme/conky.conf"
readonly CONKY_DST="$HOME/.config/conky/hackify.conf"
readonly CONKY_AUTOSTART="$HOME/.config/autostart/hackify-conky.desktop"

# -----------------------------------------------------------------------------
# Banner
# -----------------------------------------------------------------------------
show_banner() {
    clear
    printf "${YELLOW}"
    cat << "EOF"

    ▄▖▘  ▌       ▄▖ ▌  ▄▖▌      ▌    
    ▗▘▌▛▘▛▌▀▌▛▌  ▌▌▛▌  ▐ ▛▌▀▌▛▌▛▌▀▌▛▘
    ▙▖▌▄▌▌▌█▌▌▌  ▛▌▙▌  ▐ ▌▌█▌▌▌▙▌█▌▌ 
                                 
EOF
    printf "\n"
    printf "    Hackify Powered by ZishanHack\n"
    printf "    About Me: https://ZishanHack.com/about/ \n"
    printf "    Links: https://ZishanHack.com/links/ ${NC}\n\n"
}

log()  { printf "${GREEN}[+]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[!]${NC} %s\n" "$*"; }
err()  { printf "${RED}[x]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[✓]${NC} %s\n" "$*"; }

# =============================================================================
# 1) DNS (from config.sh)
# =============================================================================
configure_dns() {
    log "Configuring DNS (Cloudflare) + DNS-over-TLS ..."

    if [ ! -f /etc/systemd/resolved.conf ]; then
        warn "/etc/systemd/resolved.conf not found — skipping DNS config."
        return 1
    fi

    sudo bash -c '
        set_config() {
            local key="$1" value="$2" file="/etc/systemd/resolved.conf"
            sed -i "/^#*${key}=/d" "$file"
            echo "${key}=${value}" >> "$file"
        }
        set_config "DNS" "1.1.1.1"
        set_config "FallbackDNS" "1.0.0.1"
        set_config "DNSOverTLS" "yes"
        systemctl restart systemd-resolved
    ' && ok "DNS updated (1.1.1.1, DoT enabled)." \
      || warn "DNS config failed — check systemd-resolved."
}

# =============================================================================
# 2) Solid eye-care wallpaper
# =============================================================================
detect_desktop() {
    local d="${XDG_CURRENT_DESKTOP:-} ${XDG_SESSION_DESKTOP:-} ${DESKTOP_SESSION:-} ${GDMSESSION:-}"
    d=$(printf '%s' "$d" | tr '[:upper:]' '[:lower:]')

    case "$d" in
        *gnome*|*ubuntu*)   printf 'gnome'; return 0 ;;
        *mate*)             printf 'mate';  return 0 ;;
        *xfce*)             printf 'xfce';  return 0 ;;
    esac

    if pgrep -x gnome-shell >/dev/null 2>&1; then printf 'gnome'; return 0; fi
    if pgrep -x mate-session >/dev/null 2>&1; then printf 'mate'; return 0; fi
    if pgrep -x xfce4-session >/dev/null 2>&1; then printf 'xfce'; return 0; fi
    if pgrep -x plasmashell >/dev/null 2>&1; then printf 'kde'; return 0; fi

    case "${XDG_SESSION_TYPE:-}" in
        x11|wayland) printf 'x11'; return 0 ;;
    esac

    printf 'unknown'
}

ensure_wallpaper_tool() {
    if command -v convert >/dev/null 2>&1 || command -v magick >/dev/null 2>&1; then
        return 0
    fi
    if command -v ffmpeg >/dev/null 2>&1; then return 0; fi
    if python3 -c 'import PIL' 2>/dev/null; then return 0; fi

    log "No image tool found — installing imagemagick ..."
    if   command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y imagemagick
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y ImageMagick
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm imagemagick
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y ImageMagick
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add imagemagick
    else
        warn "Cannot install imagemagick automatically."
        return 1
    fi
}

generate_solid_wallpaper() {
    mkdir -p "$WALLPAPER_DIR"

    if [ -f "$WALLPAPER_FILE" ]; then
        ok "Solid wallpaper already exists: $WALLPAPER_FILE"
        return 0
    fi

    ensure_wallpaper_tool || return 1
    log "Generating solid $WALLPAPER_COLOR wallpaper ..."

    if command -v convert >/dev/null 2>&1; then
        convert -size 3840x2160 "xc:$WALLPAPER_COLOR" "$WALLPAPER_FILE" || return 1
    elif command -v magick >/dev/null 2>&1; then
        magick -size 3840x2160 "xc:$WALLPAPER_COLOR" "$WALLPAPER_FILE" || return 1
    elif command -v ffmpeg >/dev/null 2>&1; then
        ffmpeg -f lavfi -i "color=c=${WALLPAPER_COLOR}:s=3840x2160" \
               -frames:v 1 -y "$WALLPAPER_FILE" >/dev/null 2>&1 || return 1
    elif python3 -c 'import PIL' 2>/dev/null; then
        python3 - "$WALLPAPER_FILE" "$WALLPAPER_COLOR" <<'PY' || return 1
import sys
from PIL import Image
path, color = sys.argv[1], sys.argv[2]
color = color.lstrip('#')
rgb = tuple(int(color[i:i+2], 16) for i in (0, 2, 4))
Image.new('RGB', (3840, 2160), rgb).save(path)
PY
    else
        warn "All wallpaper generators failed."
        return 1
    fi

    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "$USER" ]; then
        chown "$SUDO_USER":"$SUDO_USER" "$WALLPAPER_FILE" 2>/dev/null || true
    fi

    [ -s "$WALLPAPER_FILE" ] && ok "Wallpaper created: $WALLPAPER_FILE" || {
        warn "Wallpaper file was not created."; return 1; }
}

apply_wallpaper_gnome() {
    local uri="file://$WALLPAPER_FILE"
    gsettings set org.gnome.desktop.background picture-uri "$uri" 2>/dev/null || true
    gsettings set org.gnome.desktop.background picture-uri-dark "$uri" 2>/dev/null || true
    gsettings set org.gnome.desktop.background picture-options 'zoom' 2>/dev/null || true
    gsettings set org.gnome.desktop.background primary-color   "$WALLPAPER_COLOR" 2>/dev/null || true
    gsettings set org.gnome.desktop.background secondary-color "$WALLPAPER_COLOR" 2>/dev/null || true
    gsettings set org.gnome.desktop.background color-shading-type 'solid' 2>/dev/null || true

    local got
    got=$(gsettings get org.gnome.desktop.background picture-uri 2>/dev/null | tr -d "'")
    if [ "$got" = "$uri" ]; then
        ok "GNOME wallpaper applied."
    else
        warn "GNOME wallpaper did not stick (got: $got)."
        return 1
    fi
}

apply_wallpaper_mate() {
    gsettings set org.mate.background picture-filename "$WALLPAPER_FILE" 2>/dev/null || true
    gsettings set org.mate.background picture-options  'zoom' 2>/dev/null || true
    gsettings set org.mate.background primary-color    "$WALLPAPER_COLOR" 2>/dev/null || true
    gsettings set org.mate.background color-shading-type 'solid' 2>/dev/null || true

    local got
    got=$(gsettings get org.mate.background picture-filename 2>/dev/null | tr -d "'")
    if [ "$got" = "$WALLPAPER_FILE" ]; then
        ok "MATE wallpaper applied."
    else
        warn "MATE wallpaper did not stick (got: $got)."
        return 1
    fi
}

apply_wallpaper_xfce() {
    local props
    props=$(xfconf-query -c xfce4-desktop -l 2>/dev/null | grep 'last-image' || true)

    if [ -z "$props" ]; then
        warn "No XFCE last-image properties found."
        return 1
    fi

    local p
    while IFS= read -r p; do
        xfconf-query -c xfce4-desktop -p "$p" -s "$WALLPAPER_FILE" 2>/dev/null || true
    done <<< "$props"

    local style_props
    style_props=$(xfconf-query -c xfce4-desktop -l 2>/dev/null | grep 'image-style' || true)
    while IFS= read -r p; do
        [ -n "$p" ] && xfconf-query -c xfce4-desktop -p "$p" -s 5 2>/dev/null || true
    done <<< "$style_props"

    ok "XFCE wallpaper applied to all monitors/workspaces."
}

apply_wallpaper_feh() {
    if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
        warn "Wayland session — feh cannot set wallpaper."
        return 1
    fi
    if ! command -v feh >/dev/null 2>&1; then
        log "Installing feh ..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get install -y feh
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y feh
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm feh
        else
            warn "Cannot install feh."
            return 1
        fi
    fi
    feh --bg-fill "$WALLPAPER_FILE" && ok "Wallpaper applied via feh."
}

apply_wallpaper() {
    local de="$1"
    generate_solid_wallpaper || return 1

    log "Applying wallpaper (desktop=$de) ..."
    case "$de" in
        gnome) apply_wallpaper_gnome || apply_wallpaper_feh ;;
        mate)  apply_wallpaper_mate  || apply_wallpaper_feh ;;
        xfce)  apply_wallpaper_xfce  || apply_wallpaper_feh ;;
        kde)
            if command -v plasma-apply-wallpaperimage >/dev/null 2>&1; then
                plasma-apply-wallpaperimage "$WALLPAPER_FILE" \
                    && ok "KDE wallpaper applied." \
                    || warn "KDE wallpaper failed."
            else
                warn "KDE detected but plasma-apply-wallpaperimage not found."
                warn "Set wallpaper manually: $WALLPAPER_FILE"
            fi
            ;;
        *) apply_wallpaper_feh ;;
    esac
}

# =============================================================================
# 3) Conky (idempotent — never re-prompts if already set up)
# =============================================================================
conky_is_installed() {
    command -v conky >/dev/null 2>&1
}

conky_is_running() {
    pgrep -u "$USER" -x conky >/dev/null 2>&1
}

conky_is_running_with_hackify() {
    pgrep -u "$USER" -x conky >/dev/null 2>&1 || return 1
    pgrep -u "$USER" -af conky 2>/dev/null | grep -q -- "$CONKY_DST"
}

conky_config_installed() {
    [ -f "$CONKY_DST" ]
}

conky_autostart_configured() {
    [ -f "$CONKY_AUTOSTART" ] && grep -q "$CONKY_DST" "$CONKY_AUTOSTART" 2>/dev/null
}

install_conky() {
    log "Installing conky ..."
    if   command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y conky-all
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y conky
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm conky
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y conky
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add conky
    else
        warn "Unknown package manager. Install conky manually."
        return 1
    fi
    conky_is_installed && ok "conky installed." || warn "conky install failed."
}

start_conky() {
    mkdir -p "$(dirname "$CONKY_DST")"
    cp "$CONKY_SRC" "$CONKY_DST"
    ok "Conky config copied to $CONKY_DST"

    if conky_is_running; then
        warn "conky is already running — restarting to load new config."
        pkill -u "$USER" -x conky
        sleep 1
    fi

    nohup conky -c "$CONKY_DST" >/dev/null 2>&1 &
    sleep 1
    if conky_is_running; then
        ok "conky started."
    else
        warn "conky did not start — check $CONKY_DST for syntax errors."
    fi
}

setup_conky_autostart() {
    mkdir -p "$(dirname "$CONKY_AUTOSTART")"
    cat > "$CONKY_AUTOSTART" <<EOF
[Desktop Entry]
Type=Application
Name=Hackify Conky
Exec=conky -c $CONKY_DST
X-GNOME-Autostart-enabled=true
Hidden=false
NoDisplay=false
Terminal=false
EOF
    ok "Autostart entry created: $CONKY_AUTOSTART"
}

maybe_configure_conky() {
    # Nothing to do if the bundled config isn't present
    if [ ! -f "$CONKY_SRC" ]; then
        warn "No theme/conky.conf found next to this script — skipping conky."
        return 0
    fi

    # ---------------------------------------------------------------------
    # Fully applied already? (installed + config copied + running our config
    # + autostart in place) → silently succeed, no prompts.
    # ---------------------------------------------------------------------
    if conky_is_installed \
       && conky_config_installed \
       && conky_is_running_with_hackify \
       && conky_autostart_configured; then
        ok "Conky already installed, running, and set to autostart — skipping."
        return 0
    fi

    # ---------------------------------------------------------------------
    # Conky is installed + running our config, but autostart is missing.
    # Ask ONLY about autostart — not about applying conky again.
    # ---------------------------------------------------------------------
    if conky_is_installed \
       && conky_config_installed \
       && conky_is_running_with_hackify \
       && ! conky_autostart_configured; then
        ok "Conky already applied and running."
        printf "\n"
        read -rp "Add conky to autostart on login? [y/N] " ans
        case "$ans" in
            [yY]|[yY][eE][sS]) setup_conky_autostart ;;
            *) warn "Autostart skipped." ;;
        esac
        return 0
    fi

    # ---------------------------------------------------------------------
    # Not fully set up — report state and ask once.
    # ---------------------------------------------------------------------
    if ! conky_is_installed; then
        warn "Conky is not installed."
    elif conky_is_running; then
        warn "Conky is running, but not with $CONKY_DST."
    else
        warn "Conky is installed but not currently running with our config."
    fi

    printf "\n"
    read -rp "Apply the bundled conky theme now? [y/N] " ans
    case "$ans" in
        [yY]|[yY][eE][sS]) ;;
        *) warn "Conky skipped."; return 0 ;;
    esac

    conky_is_installed || install_conky || return 1
    start_conky

    # After applying, offer autostart ONLY if not already configured
    if [ -f "$CONKY_AUTOSTART" ]; then
        ok "Conky autostart already configured — skipping prompt."
    else
        printf "\n"
        read -rp "Enable conky autostart on login? [y/N] " ans
        case "$ans" in
            [yY]|[yY][eE][sS]) setup_conky_autostart ;;
            *) warn "Autostart skipped." ;;
        esac
    fi
}

# =============================================================================
# 4) Shell history
# =============================================================================
configure_shell_history() {
    local rc="$HOME/.bashrc"
    [ -f "$rc" ] || touch "$rc"

    if grep -q '# >>> hackify-history >>>' "$rc"; then
        ok "Shell history already configured in $rc"
        return 0
    fi

    cp "$rc" "$rc.bak.$(date +%s)"

    cat >> "$rc" <<EOF

# >>> hackify-history >>>
export HISTSIZE=$HIST_SIZE
export HISTFILESIZE=$HIST_FILE_SIZE
export HISTCONTROL=$HIST_CONTROL
export HISTIGNORE='ls:ll:cd:pwd:exit:clear:history'
shopt -s histappend
export PROMPT_COMMAND="history -a; history -n; \${PROMPT_COMMAND:-}"
# <<< hackify-history <<<
EOF

    ok "Shell history appended to $rc (backup created)."
}

# =============================================================================
# 5) Terminal detection / theme
# =============================================================================
detect_terminal() {
    local p=$$ t depth=0
    while [ "$p" -gt 1 ] && [ "$depth" -lt 30 ]; do
        t=$(ps -o comm= -p "$p" 2>/dev/null)
        case "$t" in
            gnome-terminal*|mate-terminal*|xfce4-terminal*|qterminal*|kitty*|alacritty*)
                printf '%s' "$t"; return 0 ;;
        esac
        p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
        [ -z "$p" ] && break
        depth=$((depth + 1))
    done
    case "${TERM_PROGRAM:-}" in
        kitty|alacritty) printf '%s' "${TERM_PROGRAM}"; return 0 ;;
    esac
    case "${TERM:-}" in
        xterm-kitty) printf 'kitty'; return 0 ;;
        alacritty)   printf 'alacritty'; return 0 ;;
    esac
    return 1
}

install_font() {
    if fc-list 2>/dev/null | grep -qiE 'JetBrains[ _-]?Mono'; then
        ok "$FONT already installed."; return 0
    fi
    if command -v fc-match >/dev/null 2>&1 && \
       fc-match "$FONT" 2>/dev/null | grep -qi 'JetBrains'; then
        ok "$FONT already installed (via fc-match)."; return 0
    fi
    log "Installing $FONT ..."
    if   command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update -qq && sudo apt-get install -y fonts-jetbrains-mono
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y jetbrains-mono-fonts
    elif command -v pacman >/dev/null 2>&1; then
        sudo pacman -S --noconfirm ttf-jetbrains-mono
    elif command -v zypper >/dev/null 2>&1; then
        sudo zypper install -y jetbrains-mono-fonts
    elif command -v apk >/dev/null 2>&1; then
        sudo apk add font-jetbrains-mono
    else
        warn "Unknown package manager. Install '$FONT' manually."; return 1
    fi
    fc-cache -f >/dev/null 2>&1
    ok "$FONT installed."
}

build_gsettings_palette() {
    local out="[" c
    for c in "$@"; do out+="'$c', "; done
    out="${out%, }]"; printf '%s' "$out"
}

configure_gnome_terminal() {
    local d base
    d=$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d "'")
    base="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$d/"
    gsettings set "$base" use-theme-colors false
    gsettings set "$base" use-transparent-background false
    gsettings set "$base" background-color "'$BG'"
    gsettings set "$base" foreground-color "'$FG'"
    gsettings set "$base" bold-color-same-as-fg true
    gsettings set "$base" cursor-colors-set true
    gsettings set "$base" cursor-background-color "'$CURSOR'"
    gsettings set "$base" cursor-foreground-color "'$BG'"
    gsettings set "$base" highlight-colors-set true
    gsettings set "$base" highlight-background-color "'$SEL_BG'"
    gsettings set "$base" highlight-foreground-color "'$SEL_FG'"
    gsettings set "$base" palette "$(build_gsettings_palette "${PALETTE[@]}")"
    gsettings set "$base" use-system-font false
    gsettings set "$base" font "'$FONT $FONT_SIZE'"
    gsettings set "$base" scrollback-unlimited false
    gsettings set "$base" scrollback-lines "$SCROLLBACK_GNOME"
    ok "gnome-terminal configured (scrollback $SCROLLBACK_GNOME)."
}

configure_mate_terminal() {
    local d base
    d=$(gsettings get org.mate.terminal.global default-profile | tr -d "'")
    base="org.mate.terminal.profile:/org/mate/terminal/profiles/$d/"
    gsettings set "$base" use-theme-colors false
    gsettings set "$base" background-color "'$BG'"
    gsettings set "$base" foreground-color "'$FG'"
    gsettings set "$base" bold-color-same-as-fg true
    gsettings set "$base" cursor-colors-set true
    gsettings set "$base" cursor-background-color "'$CURSOR'"
    gsettings set "$base" cursor-foreground-color "'$BG'"
    gsettings set "$base" highlight-colors-set true
    gsettings set "$base" highlight-background-color "'$SEL_BG'"
    gsettings set "$base" highlight-foreground-color "'$SEL_FG'"
    gsettings set "$base" palette "$(build_gsettings_palette "${PALETTE[@]}")"
    gsettings set "$base" use-system-font false
    gsettings set "$base" font "'$FONT $FONT_SIZE'"
    gsettings set "$base" scrollback-unlimited false
    gsettings set "$base" scrollback-lines "$SCROLLBACK_MATE"
    ok "mate-terminal configured (scrollback $SCROLLBACK_MATE)."
}

configure_xfce4_terminal() {
    xfconf-query -c xfce4-terminal -p /color-use-theme           -s false   --create -t bool
    xfconf-query -c xfce4-terminal -p /color-background          -s "$BG"   --create -t string
    xfconf-query -c xfce4-terminal -p /color-foreground          -s "$FG"   --create -t string
    xfconf-query -c xfce4-terminal -p /color-cursor              -s "$CURSOR" --create -t string
    xfconf-query -c xfce4-terminal -p /color-selection           -s "$SEL_BG" --create -t string
    xfconf-query -c xfce4-terminal -p /color-selection-use-theme -s false  --create -t bool
    xfconf-query -c xfce4-terminal -p /font-use-system           -s false   --create -t bool
    xfconf-query -c xfce4-terminal -p /font-name                 -s "$FONT $FONT_SIZE" --create -t string
    xfconf-query -c xfce4-terminal -p /scrollback-unlimited      -s true --create -t bool
    xfconf-query -c xfce4-terminal -p /scrollback-lines          -s "$SCROLLBACK_XFCE" --create -t int
    xfconf-query -c xfce4-terminal -p /scrolling-unlimited       -s false --create -t bool 2>/dev/null || true
    ok "xfce4-terminal configured (scrollback $SCROLLBACK_XFCE)."
}

configure_qterminal() {
    local dir="$HOME/.local/share/qterminal.org/color-schemes"
    local ini="$HOME/.config/qterminal.org/qterminal.ini"
    mkdir -p "$dir" "$(dirname "$ini")"
    cat > "$dir/gruvbox-dark.colorscheme" <<EOF
[ColorScheme]
name=Gruvbox Dark
description=Warm eye-care dark theme
foreground=235,219,178
background=40,40,40
highlight=80,73,69
black=40,40,40
red=204,36,29
green=152,151,26
yellow=215,153,33
blue=69,133,136
magenta=177,98,134
cyan=104,157,106
white=168,153,132
brightBlack=146,131,116
brightRed=251,73,52
brightGreen=184,187,38
brightYellow=250,189,47
brightBlue=131,165,152
brightMagenta=211,134,155
brightCyan=142,192,124
brightWhite=235,219,178
EOF
    if [ -f "$ini" ]; then
        sed -i '/^fontFamily=/d; /^fontSize=/d; /^colorScheme=/d; /^HistorySize=/d; /^HistoryLimited=/d' "$ini"
    else
        printf '[General]\n' > "$ini"
    fi
    printf 'colorScheme=Gruvbox Dark\nfontFamily=%s\nfontSize=%s\nHistoryLimited=false\nHistorySize=%s\n' \
        "$FONT" "$FONT_SIZE" "$SCROLLBACK_QTERM" >> "$ini"
    ok "qterminal configured (scrollback $SCROLLBACK_QTERM, HistoryLimited=false)."
    warn "Fully quit qterminal and reopen for changes."
}

configure_kitty() {
    local dir="$HOME/.config/kitty"
    local main="$dir/kitty.conf"
    local theme="$dir/theme-hackify.conf"
    mkdir -p "$dir"
    cat > "$theme" <<EOF
# Hackify eye-care theme (Gruvbox Dark)
font_family      $FONT
bold_font        auto
italic_font      auto
bold_italic_font auto
font_size        $FONT_SIZE

background            $BG
foreground            $FG
cursor                $CURSOR
cursor_text_color     $BG
selection_background  $SEL_BG
selection_foreground  $SEL_FG
url_color             #83A598

scrollback_lines $SCROLLBACK_KITTY
scrollback_pager_history_size 100

color0  ${PALETTE[0]}
color8  ${PALETTE[8]}
color1  ${PALETTE[1]}
color9  ${PALETTE[9]}
color2  ${PALETTE[2]}
color10 ${PALETTE[10]}
color3  ${PALETTE[3]}
color11 ${PALETTE[11]}
color4  ${PALETTE[4]}
color12 ${PALETTE[12]}
color5  ${PALETTE[5]}
color13 ${PALETTE[13]}
color6  ${PALETTE[6]}
color14 ${PALETTE[14]}
color7  ${PALETTE[7]}
color15 ${PALETTE[15]}
EOF
    if [ ! -f "$main" ]; then
        printf 'include theme-hackify.conf\n' > "$main"
    elif ! grep -q 'theme-hackify.conf' "$main"; then
        cp "$main" "$main.bak.$(date +%s)"
        printf '\ninclude theme-hackify.conf\n' >> "$main"
        warn "Appended include to existing kitty.conf (backup created)."
    fi
    ok "kitty configured (scrollback $SCROLLBACK_KITTY + 100 MB pager)."
    warn "Open a NEW kitty window."
}

configure_alacritty() {
    local dir="$HOME/.config/alacritty"
    local main="$dir/alacritty.toml"
    local theme="$dir/theme-hackify.toml"
    mkdir -p "$dir"
    cat > "$theme" <<EOF
# Hackify eye-care theme (Gruvbox Dark)

[font]
size = $FONT_SIZE

[font.normal]
family = "$FONT"
style  = "Regular"

[font.bold]
family = "$FONT"
style  = "Bold"

[font.italic]
family = "$FONT"
style  = "Italic"

[scrolling]
history = $SCROLLBACK_ALACRITTY
multiplier = 3

[colors.primary]
background = "$BG"
foreground = "$FG"

[colors.cursor]
text   = "$BG"
cursor = "$CURSOR"

[colors.selection]
text       = "$SEL_FG"
background = "$SEL_BG"

[colors.normal]
black   = "${PALETTE[0]}"
red     = "${PALETTE[1]}"
green   = "${PALETTE[2]}"
yellow  = "${PALETTE[3]}"
blue    = "${PALETTE[4]}"
magenta = "${PALETTE[5]}"
cyan    = "${PALETTE[6]}"
white   = "${PALETTE[7]}"

[colors.bright]
black   = "${PALETTE[8]}"
red     = "${PALETTE[9]}"
green   = "${PALETTE[10]}"
yellow  = "${PALETTE[11]}"
blue    = "${PALETTE[12]}"
magenta = "${PALETTE[13]}"
cyan    = "${PALETTE[14]}"
white   = "${PALETTE[15]}"
EOF
    if [ ! -f "$main" ]; then
        cat > "$main" <<EOF
[general]
import = ["~/.config/alacritty/theme-hackify.toml"]
EOF
    elif ! grep -q 'theme-hackify.toml' "$main"; then        cp "$main" "$main.bak.$(date +%s)"
        warn "Existing alacritty.toml found. Add this manually:"
        printf '\n    [general]\n    import = ["~/.config/alacritty/theme-hackify.toml"]\n\n'
    fi
    ok "alacritty theme written (scrollback $SCROLLBACK_ALACRITTY)."
    warn "Restart alacritty fully."
}

verify_settings() {
    local term="$1"
    printf "\n${CYAN}── Verification ──${NC}\n"
    case "$term" in
        *gnome-terminal*)
            local d base
            d=$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d "'")
            base="org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles:/:$d/"
            printf "  scrollback-unlimited: %s\n" "$(gsettings get "$base" scrollback-unlimited)"
            printf "  scrollback-lines    : %s\n" "$(gsettings get "$base" scrollback-lines)"
            ;;
        *mate-terminal*)
            local d base
            d=$(gsettings get org.mate.terminal.global default-profile | tr -d "'")
            base="org.mate.terminal.profile:/org/mate/terminal/profiles/$d/"
            printf "  scrollback-unlimited: %s\n" "$(gsettings get "$base" scrollback-unlimited)"
            printf "  scrollback-lines    : %s\n" "$(gsettings get "$base" scrollback-lines)"
            ;;
        *xfce4-terminal*)
            printf "  scrollback-unlimited: %s\n" "$(xfconf-query -c xfce4-terminal -p /scrollback-unlimited 2>/dev/null)"
            printf "  scrollback-lines    : %s\n" "$(xfconf-query -c xfce4-terminal -p /scrollback-lines 2>/dev/null)"
            ;;
        *qterminal*)
            printf "  HistoryLimited      : %s\n" "$(grep '^HistoryLimited=' "$HOME/.config/qterminal.org/qterminal.ini" 2>/dev/null | cut -d= -f2)"
            printf "  HistorySize         : %s\n" "$(grep '^HistorySize=' "$HOME/.config/qterminal.org/qterminal.ini" 2>/dev/null | cut -d= -f2)"
            ;;
        *kitty*)     printf "  scrollback_lines    : %s\n" "$SCROLLBACK_KITTY" ;;
        *alacritty*) printf "  scrolling.history   : %s\n" "$SCROLLBACK_ALACRITTY" ;;
    esac
}

# =============================================================================
# Main
# =============================================================================
main() {
    show_banner

    if [ ! -d "$SCRIPT_DIR/theme" ]; then
        warn "No ./theme directory found next to this script — conky will be skipped."
    fi

    # 1) DNS
    configure_dns || true

    # 2) Shell history
    configure_shell_history

    # 3) Wallpaper
    local de
    de=$(detect_desktop)
    log "Detected desktop: $de"
    apply_wallpaper "$de" || true

    # 4) Terminal
    local term
    if ! term=$(detect_terminal); then
        err "Could not detect a supported terminal emulator."
        err "Supported: gnome-terminal, mate-terminal, xfce4-terminal, qterminal, kitty, alacritty."
    else
        log "Detected terminal: $term"
        install_font || true
        case "$term" in
            *gnome-terminal*) configure_gnome_terminal ;;
            *mate-terminal*)  configure_mate_terminal  ;;
            *xfce4-terminal*) configure_xfce4_terminal ;;
            *qterminal*)      configure_qterminal      ;;
            *kitty*)          configure_kitty          ;;
            *alacritty*)      configure_alacritty      ;;
        esac
        verify_settings "$term"
    fi

    # 5) Conky (idempotent)
    maybe_configure_conky

    printf "\n"
    ok "All done."
    warn "FULLY restart the terminal (quit the app, not just a tab) to apply terminal changes."
    warn "For shell history: run 'source ~/.bashrc' or open a new shell."
}

main "$@"
