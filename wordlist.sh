#!/usr/bin/env bash

# ====================== COLOR CODES ======================
Black='\033[0;30m'    Red='\033[0;31m'    Green='\033[0;32m'
Yellow='\033[0;33m'   Blue='\033[0;34m'   Purple='\033[0;35m'
Cyan='\033[0;36m'     White='\033[0;37m'  Nc='\033[0m' # No Color

# ====================== BANNER ======================
clear
# Banner and ASCII Art
show_banner() {
    clear
    printf "${Yellow}"
    cat << "EOF"

    ▄▖▘  ▌       ▄▖ ▌  ▄▖▌      ▌    
    ▗▘▌▛▘▛▌▀▌▛▌  ▌▌▛▌  ▐ ▛▌▀▌▛▌▛▌▀▌▛▘
    ▙▖▌▄▌▌▌█▌▌▌  ▛▌▙▌  ▐ ▌▌█▌▌▌▙▌█▌▌ 
                                 
EOF
    printf "\n"
    printf "    Hackify Powered by ZishanHack\n"
    printf "    About Me: https://ZishanHack.com/about/ \n"
    printf "    Links: https://ZishanHack.com/links/ ${Nc}\n\n"
}
show_banner

# ====================== CHECK ROOT ======================
if [[ "$EUID" -ne 0 ]]; then
    printf "\n\033[30;5;41mPlease run as root.${Nc}\n"
    exec sudo bash "$0" "$@"  # Re-run script as root
fi

# ====================== SETUP DIRECTORY ======================
WORDLIST_DIR="/opt/wordlists"
mkdir -p "$WORDLIST_DIR"
cd "$WORDLIST_DIR" || exit 1
printf "We are in $(pwd).\n\n$WORDLIST_DIR/ contains:\n"
ls

# ====================== FUNCTIONS ======================
# Fix git HTTP/1.1 error — only write the global config once, not on every run
if [[ "$(git config --global --get http.version 2>/dev/null)" != "HTTP/1.1" ]]; then
    git config --global http.version HTTP/1.1
fi

download_git() {
    local name=$1
    local repo=$2
    if [[ -d "$WORDLIST_DIR/$name" ]]; then
        printf "${Green}$name already installed${Nc}\n"
    elif git clone --depth=1 "$repo" "$WORDLIST_DIR/$name"; then
        printf "${Purple}$name downloaded successfully\n${Nc}"
    else
        printf "${Red}Failed to download $name from $repo${Nc}\n" >&2
        exit 1
    fi
}

download_wget() {
    local filename=$1
    local url=$2
    if [[ -f "$WORDLIST_DIR/$filename" ]]; then
        printf "${Green}$filename already downloaded${Nc}\n"
    elif wget --progress=bar:force -O "$WORDLIST_DIR/$filename" "$url"; then
        printf "${Purple}$filename downloaded\n${Nc}"
    else
        printf "${Red}Failed to download $filename from $url${Nc}\n" >&2
        exit 1
    fi
}


download_zip() {
    local name=$1
    local url=$2
    local zipfile="$WORDLIST_DIR/${name}.zip"
    if [[ -d "$WORDLIST_DIR/$name" ]]; then
        printf "${Green}$name already installed${Nc}\n"
    else
        if ! command -v unzip >/dev/null 2>&1; then
            printf "${Red}unzip is required but not installed — run: sudo apt install unzip${Nc}\n" >&2
            exit 1
        fi
        if wget --progress=bar:force -O "$zipfile" "$url"; then
            if unzip -q "$zipfile" -d "$WORDLIST_DIR/"; then
                rm -f "$zipfile"
                # GitHub archive zips extract into <name>-master/ — rename to target name
                if [[ -d "$WORDLIST_DIR/${name}-master" && ! -d "$WORDLIST_DIR/$name" ]]; then
                    mv "$WORDLIST_DIR/${name}-master" "$WORDLIST_DIR/$name"
                    printf "${Purple}$name downloaded and extracted\n${Nc}"
                else
                    printf "${Red}Unexpected extraction layout for $name${Nc}\n" >&2
                    exit 1
                fi
            else
                printf "${Red}Failed to unzip $name${Nc}\n" >&2
                exit 1
            fi
        else
            printf "${Red}Failed to download $name from $url${Nc}\n" >&2
            exit 1
        fi
    fi
}

# ====================== WORDLIST SOURCES ======================
declare -A GIT_WORDLISTS=(
    [PayloadsAllTheThings]="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    [fuzzdb]="https://github.com/fuzzdb-project/fuzzdb.git"
    [api_wordlist]="https://github.com/chrislockard/api_wordlist.git"
)

declare -A WGET_WORDLISTS=(
    [all.txt]="https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt"
    [markdownxss.txt]="https://raw.githubusercontent.com/cujanovic/Markdown-XSS-Payloads/refs/heads/master/Markdown-XSS-Payloads.txt"
)

declare -A ZIP_WORDLISTS=(
    [SecLists]="https://github.com/danielmiessler/SecLists/archive/master.zip"
)

# ====================== DOWNLOAD WORDLISTS ======================
for name in "${!GIT_WORDLISTS[@]}"; do
    download_git "$name" "${GIT_WORDLISTS[$name]}"
done

for file in "${!WGET_WORDLISTS[@]}"; do
    download_wget "$file" "${WGET_WORDLISTS[$file]}"
done

for name in "${!ZIP_WORDLISTS[@]}"; do
    download_zip "$name" "${ZIP_WORDLISTS[$name]}"
done

# ====================== UNZIP ROCKYOU ======================
if [[ -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    printf "${Green}rockyou.txt already extracted${Nc}\n"
else
    tar -xf "$WORDLIST_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -C "$WORDLIST_DIR/" && printf "${Purple}Unzipped rockyou.txt${Nc}\n"
fi


# ====== Directory fix for Kali and other security distros ===============

# Create target directory if it doesn't exist
mkdir -p "/usr/share/wordlists"

# Check if SecLists directory exists and no symbolic link exists at target, then create link
# Only create links when nothing exists at the target yet — [ ! -L ] alone isn't
# enough: a pre-existing regular file or directory also makes ln -s fail.
[ -d "/opt/wordlists/SecLists" ] && [ ! -e "/usr/share/seclists" ] && [ ! -L "/usr/share/seclists" ] && ln -s "/opt/wordlists/SecLists" "/usr/share/seclists"
[ -d "/opt/wordlists/SecLists" ] && [ ! -e "/usr/share/wordlists/SecLists" ] && [ ! -L "/usr/share/wordlists/SecLists" ] && ln -s "/opt/wordlists/SecLists" "/usr/share/wordlists/SecLists"

# Check if rockyou.txt file exists and no symbolic link exists at target, then create link
[ -f "/opt/wordlists/rockyou.txt" ] && [ ! -e "/usr/share/wordlists/rockyou.txt" ] && [ ! -L "/usr/share/wordlists/rockyou.txt" ] && ln -s "/opt/wordlists/rockyou.txt" "/usr/share/wordlists/rockyou.txt"


# ====================== ASSETNOTE API WORDLIST (Optional) ======================
# Uncomment to download (Warning: Large files, needs SSD & 12GB+ RAM)
# if [[ ! -d "$WORDLIST_DIR/assetnote" ]]; then
#     mkdir -p "$WORDLIST_DIR/assetnote"
#     wget -r --no-parent -R "index.html*" -P "$WORDLIST_DIR/assetnote/" https://wordlists-cdn.assetnote.io/data/
#     mv "$WORDLIST_DIR/assetnote/data/"* "$WORDLIST_DIR/assetnote/"
#     rm -rf "$WORDLIST_DIR/assetnote/data"
#     printf "${Purple}Assetnote API wordlist downloaded successfully\n${Nc}"
# else
#     printf "\n${Yellow}Assetnote API wordlist already installed${Nc}\n"
# fi

printf "\n${Cyan}Stage 1 Finished!\nAll Wordlists Downloaded.${Nc}\n\n"
sleep 1
