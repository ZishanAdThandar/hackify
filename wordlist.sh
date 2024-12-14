#! /usr/bin/env bash

# Color Codes of Regular Colors
Black='\033[0;30m'        # Black
Red='\033[0;31m'          # Red
Green='\033[0;32m'        # Green
Yellow='\033[0;33m'       # Yellow
Blue='\033[0;34m'         # Blue
Purple='\033[0;35m'       # Purple
Cyan='\033[0;36m'         # Cyan
White='\033[0;37m'        # White
Nc='\033[0m'              # No Color

# banner
clear
printf "\n\n${Green}Hacking Tools and Wordlist Installer written by,\n\n\n"
printf "${Red}" # banner bg and fg color

cat << "EOF"
  _____    _                _      _ _____ _                 _          
 |_  (_)__| |_  __ _ _ _   /_\  __| |_   _| |_  __ _ _ _  __| |__ _ _ _ 
  / /| (_-| ' \/ _` | ' \ / _ \/ _` | | | | ' \/ _` | ' \/ _` / _` | '_|
 /___|_/__|_||_\__,_|_||_/_/ \_\__,_| |_| |_||_\__,_|_||_\__,_\__,_|_|  
 
EOF
printf "\n\n${Cyan}Profile: https://zishanadthandar.github.io\nLinkTree: https://zishanadthandar.github.io/linktree\nLinkedIn: https://linkedin.com/in/zishanadthandar${Nc}\n\n"
sleep 2 #banner break  
                              
# one liner bash if loop to check root user
[ "$EUID" -ne 0 ] && printf "\n\033[30;5;41mPlease run as root.${Nc}\n" && sudo su

# ===================================WORDLIST======================== 

# function for wordlists from github
function wsgit { 
[ -d "/opt/wordlist/$1" ] && printf "${Green}$1 already installed${Nc}\n"
[ ! -d "/opt/wordlist/$1" ] && git clone $2 /opt/wordlist/$1 && printf "${Purple}$1 downloaded successfully\n${Nc}"
}
# function for wordlists with wget
function wswget { 
[ -f "/opt/wordlist/$1" ] && printf "${Green}$1 already downloaded${Nc}\n"
[ ! -f "/opt/wordlist/$1" ] && wget $2 -O /opt/wordlist/$1 && printf "${Purple}$1 downloaded\n${Nc}"
}
# Making wordlist folder if not exist
[ ! -d "/opt/wordlist" ] && mkdir /opt/wordlist
cd /opt/wordlist
printf "we are in $(pwd) folder.\n\n/opt/wordlist/ Folder Contains:\n"
ls
# Array for wordlists
declare -A wsgitarray=( [PayloadsAllTheThings]="https://github.com/swisskyrepo/PayloadsAllTheThings" [SecLists]="https://github.com/danielmiessler/SecLists" [fuzzdb]="https://github.com/fuzzdb-project/fuzzdb" [api_wordlist]="https://github.com/chrislockard/api_wordlist")
declare -A wsgetarray=( [all.txt]="https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt" [markdownxss.txt]="https://raw.githubusercontent.com/cujanovic/Markdown-XSS-Payloads/master/Markdown-XSS-Payloads.txt")

# for loop to git clone wordlists
for i in "${!wsgitarray[@]}"
do
  wsgit $i ${wsgitarray[$i]}
done
# for loop to wget wordlists
for i in "${!wsgetarray[@]}"
do
  wswget $i ${wsgetarray[$i]}
done

# Rockyou unzipping
[ -f "/opt/wordlist/rockyou.txt" ] && printf "${Green}rockyou.txt already downloaded${Nc}\n"
[ ! -f "/opt/wordlist/rockyou.txt" ] && tar -xf /opt/wordlist/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz -C /opt/wordlist/ && printf "${Purple}unzipped rockyou.txt${Nc}\n"


# Assetnote API wordlist (creates logical block error, because of large files)
# [ -d "/opt/wordlist/assetnote" ] && printf "\n${Yellow}Assetnote API wordlist already installed${Nc}\n"
#[ ! -d "/opt/wordlist/assetnote" ] && mkdir /opt/wordlist/assetnote && wget -r --no-parent -R "index.html*" https://wordlists-cdn.assetnote.io/data/ -nH -np /opt/wordlist/assetnote/ && printf "${Purple}Assetnote API wordlist downloaded successfully\n${Nc}" && mv /opt/wordlist/data/* /opt/wordlist/assetnote && rm -rf /opt/wordlist/data

printf "\n${Cyan}Stage 1 Finished!\nWordlists Downloaded.${Nc}\n\n"
sleep 1 #stage 1 break

