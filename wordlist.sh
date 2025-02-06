#!/usr/bin/env bash

# ====================== COLOR CODES ======================
Black='\033[0;30m'    Red='\033[0;31m'    Green='\033[0;32m'
Yellow='\033[0;33m'   Blue='\033[0;34m'   Purple='\033[0;35m'
Cyan='\033[0;36m'     White='\033[0;37m'  Nc='\033[0m' # No Color

# ====================== BANNER ======================
clear
printf "\n\n${Green}Hacking Tools and Wordlist Installer by,\n\n\n"
printf "${Red}" # banner bg and fg color
cat << "EOF"
  _____    _                _      _ _____ _                 _          
 |_  (_)__| |_  __ _ _ _   /_\  __| |_   _| |_  __ _ _ _  __| |__ _ _ _ 
  / /| (_-| ' \/ _` | ' \ / _ \/ _` | | | | ' \/ _` | ' \/ _` / _` | '_|
 /___|_/__|_||_\__,_|_||_/_/ \_\__,_| |_| |_||_\__,_|_||_\__,_\__,_|_|  
EOF
printf "\n\n${Cyan}Profile: https://zishanadthandar.github.io\nLinkTree: https://zishanadthandar.github.io/linktree\nLinkedIn: https://linkedin.com/in/zishanadthandar${Nc}\n\n"
sleep 2

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
download_git() {
    local name=$1
    local repo=$2
    if [[ -d "$WORDLIST_DIR/$name" ]]; then
        printf "${Green}$name already installed${Nc}\n"
    else
        git clone --depth=1 "$repo" "$WORDLIST_DIR/$name" && printf "${Purple}$name downloaded successfully\n${Nc}"
    fi
}

download_wget() {
    local filename=$1
    local url=$2
    if [[ -f "$WORDLIST_DIR/$filename" ]]; then
        printf "${Green}$filename already downloaded${Nc}\n"
    else
        wget --progress=bar:force -O "$WORDLIST_DIR/$filename" "$url" && printf "${Purple}$filename downloaded\n${Nc}"
    fi
}

# ====================== WORDLIST SOURCES ======================
declare -A GIT_WORDLISTS=(
    [PayloadsAllTheThings]="https://github.com/swisskyrepo/PayloadsAllTheThings.git"
    [SecLists]="https://github.com/danielmiessler/SecLists.git"
    [fuzzdb]="https://github.com/fuzzdb-project/fuzzdb.git"
    [api_wordlist]="https://github.com/chrislockard/api_wordlist.git"
)

declare -A WGET_WORDLISTS=(
    [all.txt]="https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt"
    [markdownxss.txt]="https://raw.githubusercontent.com/cujanovic/Markdown-XSS-Payloads/master/Markdown-XSS-Payloads.txt"
)

# ====================== DOWNLOAD WORDLISTS ======================
for name in "${!GIT_WORDLISTS[@]}"; do
    download_git "$name" "${GIT_WORDLISTS[$name]}"
done

for file in "${!WGET_WORDLISTS[@]}"; do
    download_wget "$file" "${WGET_WORDLISTS[$file]}"
done

# ====================== UNZIP ROCKYOU ======================
if [[ -f "$WORDLIST_DIR/rockyou.txt" ]]; then
    printf "${Green}rockyou.txt already extracted${Nc}\n"
else
    tar -xf "$WORDLIST_DIR/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz" -C "$WORDLIST_DIR/" && printf "${Purple}Unzipped rockyou.txt${Nc}\n"
fi

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
