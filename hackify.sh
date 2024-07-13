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
printf "\n\n${Cyan}Profile: https://zishanadthandar.github.io\nLinkedIn: https://linkedin.com/in/zishanadthandar${Nc}\n\n"
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




# ===================================APT========================  


declare -a aptarray=("aircrack-ng" "audacity" "axiom" "beef" "binwalk" "bully" "cargo" "cewl" "cowpatty" "crunch" "dirb" "dnsenum" "dnsrecon" "ffmpeg" "git" "hashcat" "hcxdumptool" "httrack" "hydra" "john" "jq" "masscan" "macchanger" "ndiff" "nikto" "openvpn" "parcellite" "pipx" "pixiewps" "pngcheck" "proxychains" "python2" "python3" "reaver" "rlwrap" "stegcracker" "steghide" "tmux" "tor" "whatweb" "whois" "wifite" "wireshark")

#Function to check if installed and install it
function aptinstall {
dpkg -l "$1" | grep -q ^ii && return 1
apt-get -y install "$1"
return 0
}
#Installing from array
for i in "${aptarray[@]}"
do
  aptinstall $i
done
#functions to check missing tools
function missapt {
if ! command -v $1 &> /dev/null
then
	printf "${Red}Install $1 manually.\n${Nc}"
fi
}
#Recommending missing tools from array
for i in "${aptarray[@]}"
do
  missapt $i
done

printf "\n${Cyan}Stage 2 Finished!\nApt Installation Finished.\nCheck for missing tools and manually install.${Nc}\n"


# APT 1
function aptinstall1 {
[ ! -f "$1" ] && apt-get -y install "$2"
return 0
}
declare -A aptarray1=( [/usr/bin/exiftool]="libimage-exiftool-perl" [/usr/bin/pip3]="python3-pip" [/usr/bin/uget-gtk]="uget" [/usr/share/doc/libpcap0.8-dev/copyright]="libpcap-dev" )
for i in "${!aptarray1[@]}"
do
  aptinstall1 $i ${aptarray1[$i]}
done


sleep 1 #stage 2 break


# ==============NODEJS NPM REACT =======================
[ -x "$(command -v npm)" ] && printf "${Green}nodejs already installed${Nc}\n" || { sudo apt purge -y nodejs && sudo rm -f /usr/bin/npm /usr/bin/nodejs /usr/local/bin/npm /usr/local/bin/nodejs && sudo apt autoremove -y && sudo apt autoclean && curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash - && sudo apt install -y nodejs && sudo rm -f /etc/apt/sources.list.d/nodesource.list && sudo apt update -y && sudo npm install -g electron-packager && printf "${Purple}nodejs Installed Successfully.${Nc}\n"; }



# ===================================GO LANG======================== 


# installing and setting up Golang
[ -d "/usr/local/go" ] && printf "\n${Green}GoLang already downloaded${Nc}\n"
[ ! -d "/usr/local/go" ] && cd /tmp && wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz && tar -C /usr/local/ -xzf go1.22.0.linux-amd64.tar.gz && cd /usr/local/ && printf "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin \nexport GOROOT=/usr/local/go" >> ~/.bashrc && printf "export PATH=\$PATH:/usr/local/go/bin:\$HOME/go/bin \nexport GOROOT=/usr/local/go" >> /home/*/.bashrc && source ~/.bashrc && source /home/*/.bashrc

export GO111MODULE="on" #Go Module on
# Installing GoLang tools
printf "\n${Cyan}Installing Go Tools for user ${Red}ROOT${Nc}${Cyan} (Current User).${Nc}\n\n"
sleep 1
function goinstall {
[ -f "$HOME/go/bin/$1" ] && printf "${Green}$1 already installed.\n${Nc}"
[ ! -f "$HOME/go/bin/$1" ] &&  go install -v $2 && printf "$1 Installed Successfully.\n"
}
declare -A goinstallarray=( [amass]="github.com/owasp-amass/amass/v3/...@master" [assetfinder]="github.com/tomnomnom/assetfinder@latest" [chaos]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest" [dalfox]="github.com/hahwul/dalfox@latest" [ffuf]="github.com/ffuf/ffuf@latest" [gf]="github.com/tomnomnom/gf@latest" [git-hound]="github.com/tillson/git-hound@latest" [gobuster]="github.com/OJ/gobuster/v3@latest" [hakrawler]="github.com/hakluke/hakrawler@latest" [httprobe]="github.com/tomnomnom/httprobe@master" [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest" [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" [nuclei]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest" [qsreplace]="github.com/tomnomnom/qsreplace@latest" [waybackurls]="github.com/tomnomnom/waybackurls@latest" [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" [subzy]="github.com/LukaSikic/subzy@latest" [tlsx]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest")

for i in "${!goinstallarray[@]}"
do
  goinstall $i ${goinstallarray[$i]}
done

# Moving All tools for all users
# cp /root/go/bin/* /usr/local/bin/
# rm /usr/local/bin/amass



#Manual GoTOOLS starts here

[ -f "/usr/bin/kerbrute" ] && printf "${Nc}${Green}Ropnop Kerbrute already installed.\n${Nc}"
[ ! -f "/usr/bin/kerbrute" ] && wget -q https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 -O /usr/bin/kerbrute && chmod +x /usr/bin/kerbrute && printf "Ropnop Kerbrute Just Installed Successfully.\n"


#Manual GoTOOLS ends here


# setting gf patterns by 1ndianl33t
[ -d "$HOME/.gf" ] && printf "${Green}gf patterns by 1ndianl33t already installed.\n${Nc}"
[ ! -d "$HOME/.gf" ] && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf && printf "gf patterns by 1ndianl33t Installed Successfully.\n"

[ -f "$HOME/.gf/base64.json" ] && printf "${Green}gf patterns by tomnomnom already installed.\n${Nc}"
[ ! -f "$HOME/.gf/base64.json" ] && git clone https://github.com/tomnomnom/gf /tmp/gf && mv /tmp/gf/examples/* ~/.gf/ && printf "gf patterns by tomnomnom Installed Successfully.\n"





# ===================================PYTHON======================== 

#PIPX
#[ -f "/usr/bin/pipx" ] && printf "${Green}PIPX already installed${Nc}\n"
#[ ! -f "/usr/bin/pipx" ] && apt install pipx && pipx ensurepath  && pipx ensurepath --global  && printf "${Purple}PIPX Installed Successfully\n${Nc}"
# pipx install sublist3r && pipx install hashid && pipx install dirsearch  && pipx install pwntools && pipx install arsenal-cli && pipx install sqlmap -global


# Upgrade pip and install tools

printf "\n${Cyan}Installing Python Tools for user ROOT.${Nc}\n"
sleep 1

#apt -qq install python3-debian -y > /dev/null 2>&1 #removing warning 1

python3 -m pip install --upgrade pip -q &> /dev/null

# List of packages to install
packages=(
    "pipenv"
    "sublist3r"
    "hashid"
    "dirsearch"
    "pwntools"
    "arsenal-cli"
)

# Function to install package if not already installed
install_package() {
    local package=$1
    if ! python3 -c "import $package" &> /dev/null; then
        printf "Installing $package...\n"
        python3 -m pip install --quiet --upgrade "$package" &> /dev/null
    else
        printf "$package is already installed.\n"
    fi
}

# Install packages
for pkg in "${packages[@]}"; do
    install_package "$pkg"
done

# python tool installation
function pygitinstall {
yes | python3 -m pip install $2 --quiet --root-user-action=ignore
echo "python3 -m $1 \$@" >/usr/local/bin/$1
chmod +x /usr/local/bin/$1
}
# pythongit array
declare -A pygitarray=( [wafw00f]="https://github.com/EnableSecurity/wafw00f/archive/master.zip" )
# pygitloop
for i in "${!pygitarray[@]}"
do
  pygitinstall $i ${pygitarray[$i]}
done


# ======SQLMap======
[ -d /opt/sqlmap ] || { sudo apt-get remove -y sqlmap; python3 -m pip uninstall -y sqlmap; sudo rm -f /usr/local/bin/sqlmap /usr/bin/sqlmap; sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap; echo -e '#!/bin/bash\npython3 /opt/sqlmap/sqlmap.py "$@"' | sudo tee /usr/local/bin/sqlmap > /dev/null; sudo chmod +x /usr/local/bin/sqlmap; printf "\033[0;35mSQLMap Installed Successfully\033[0m'\n";}
grep -q 'MAX_NUMBER_OF_THREADS = 500' /opt/sqlmap/lib/core/settings.py || sudo sed -i 's/MAX_NUMBER_OF_THREADS = [0-9]\+/MAX_NUMBER_OF_THREADS = 500/' /opt/sqlmap/lib/core/settings.py


# =======youtube_dl  [youtube-dl]="https://github.com/ytdl-org/youtube-dl/archive/master.zip"
apt purge youtube-dl -y -qq > /dev/null 2>&1
[ ! -f "/usr/local/bin/youtube-dl" ] && yes | python3 -m pip install https://github.com/ytdl-org/youtube-dl/archive/master.zip --quiet --root-user-action=ignore && echo "python3 -m youtube_dl \$@" >/usr/local/bin/youtube-dl && chmod +x /usr/local/bin/youtube-dl && printf "${Purple}Youtube-dl Installed Successfully\n${Nc}"


# ===================================RUBY======================== 

# wget -O /tmp/ruby.tar.gz https://cache.ruby-lang.org/pub/ruby/3.3/ruby-3.3.4.tar.gz && tar -xzvf ruby.tar.gz -C /tmp/ruby && cd /tmp/ruby && 

[ ! -f "/usr/bin/ruby" ] && apt-get install ruby-full >/dev/null
gem sources --add https://rubygems.org/ > /dev/null
gem cleanup > /dev/null


# =====Ruby Based Tools======
# =====WPScan Installation======
[ -f "/usr/local/bin/wpscan" ] && printf "${Green}WPScan already installed${Nc}\n"
[ ! -f "/usr/local/bin/wpscan" ] && sudo apt install -y curl git libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 autoconf libgdbm-dev libncurses5-dev automake libtool bison pkg-config ruby ruby-bundler ruby-dev > /dev/null && sudo gem install wpscan 


# =====metasploit installation======

if ! command -v msfconsole &> /dev/null
then
  curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
  rm msfinstall
  rm /etc/apt/sources.list.d/metasploit-framework.list
  apt update -y && apt upgrade -y
fi



# ===================================OTHER======================== 

# exploitdb and searchsploit
[ ! -d "/opt/exploit-database" ] && git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database && ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit && printf "${Purple}exploitDB Installed Successfully\n${Nc}"

# ======NMap======
[ -f "/usr/local/bin/nmap" ] && printf "${Green}NMap already installed${Nc}\n"
[ ! -f "/usr/local/bin/nmap" ] && wget https://nmap.org/dist/nmap-7.94.tar.bz2 --directory-prefix=/tmp/ && cd /tmp && tar xvjf /tmp/nmap-7.94.tar.bz2 && cd /tmp/nmap-7.94 && /tmp/nmap-7.94/configure && make install -C /tmp/nmap-7.94 && cp /usr/local/bin/nmap && /usr/bin/nmap && rm -rf /tmp/nmap-7.94 && printf "${Purple}NMap Installed Successfully\n${Nc}"

# ======john======
# [ ! -f "/usr/local/bin/nmap" ] && wget https://github.com/openwall/john/archive/refs/tags/1.9.0-Jumbo-1.zip --directory-prefix=/opt/ && cd /opt && unzip 1.9.0-Jumbo-1.zip

# ====JoomScan Joomla Scanner=======
[ -f "/usr/local/bin/joomscan" ] && printf "${Green}JoomScan already installed${Nc}\n"
[ ! -f "/usr/local/bin/joomscan" ] && git clone https://github.com/OWASP/joomscan /opt/joomscan && echo "perl /opt/joomscan/joomscan.pl \$@" >/usr/local/bin/joomscan && chmod +x /usr/local/bin/joomscan && printf "${Purple}JoomScan Installed Successfully\n${Nc}"


# ====ARES cipher tool https://github.com/bee-san/Ares =======
[ -f "/usr/local/bin/ares" ] && printf "${Green}Ares already installed${Nc}\n"
[ ! -f "/usr/local/bin/ares" ] && apt install cargo -y && cargo install project_ares && cp /root/.cargo/bin/ares /usr/local/bin/ares && printf "${Purple}ARES Installed Successfully\n${Nc}"


#=======ACTIVE Directory 
#======Impacket========
#[ ! -f "/usr/bin/impacket-wmiexec" ] && sudo git clone https://github.com/SecureAuthCorp/impacket.git /tmp/impacket && sudo pip3 install -r /tmp/impacket/requirements.txt && cd /tmp/impacket && sudo pip3 install . && sudo python3 setup.py install && printf "${Purple}Impacket Installed Successfully\n${Nc}"
[ -f "/usr/bin/impacket-netview" ] && printf "${Green}ImPacker already installed${Nc}\n"
[ ! -f "/usr/bin/impacket-netview" ] && sudo git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket && sudo pip3 install -r /opt/impacket/requirements.txt && cd /opt/impacket && sudo pip3 install . && sudo python3 setup.py install && printf "${Purple}Impacket Installed Successfully\n${Nc}"
#=====mitm6======
[ -f "/usr/local/bin/mitm6" ] && printf "${Green}MITM6 already installed${Nc}\n"
[ ! -f "/usr/local/bin/mitm6" ] && sudo git clone https://github.com/dirkjanm/mitm6 /opt/mitm6 && sudo pip3 install -r /opt/mitm6/requirements.txt && cd /opt/mitm6 && sudo pip3 install . && sudo python3 setup.py install && printf "${Purple}Impacket Installed Successfully\n${Nc}"
#======crackmapexec netexec======= 
#[ -f "/usr/local/bin/crackmapexec" ] && printf "${Green}CrackMapExec already installed${Nc}\n"
#[ ! -f "/usr/local/bin/crackmapexec" ] && python3 -m pip install git+https://github.com/byt3bl33d3r/CrackMapExec && printf "${Purple}CrackMapExec Installed Successfully\n${Nc}"
[ -f "/usr/local/bin/nxc" ] && printf "${Green}NetExec already installed${Nc}\n"
[ ! -f "/usr/local/bin/nxc" ] && python3 -m pip install git+https://github.com/Pennyw0rth/NetExec && printf "${Purple}NetExec Installed Successfully\n${Nc}"
#======evil-winrm======= 
[ -f "/usr/local/bin/evil-winrm" ] && printf "${Green}evil-winrm.rb already installed${Nc}\n"
[ ! -f "/usr/local/bin/evil-winrm" ] && gem install evil-winrm && printf "${Purple}evil-winrm Installed Successfully\n${Nc}"
#======Enum4Linux======= 
[ -f "/usr/bin/enum4linux" ] && printf "${Green}Enum4Linux already installed${Nc}\n"
[ ! -f "/usr/bin/enum4linux" ] && curl https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -s -k > /usr/bin/enum4linux && chmod +x /usr/bin/enum4linux && printf "${Purple}Enum4Linux Installed Successfully\n${Nc}"
#======Certipy======= 
[ -f "/usr/local/bin/certipy" ] && printf "${Green}Certipy already installed${Nc}\n"
[ ! -f "/usr/local/bin/certipy" ] && python3 -m pip install certipy-ad &> /dev/null && printf "${Purple}Certipy Installed Successfully\n${Nc}"
#======ldap3======= 
package=ldap3
python3 -c "import $package" &> /dev/null && printf "${Green}${package} already installed${Nc}\n" || { python3 -m pip install $package &> /dev/null && printf "${Purple}${package} Installed Successfully.${Nc}\n"; }

#======rpcclient======= 
[ -f "/usr/bin/rpcclient" ] && printf "${Green}rpcclient already installed${Nc}\n"
[ ! -f "/usr/bin/rpcclient" ] && apt install samba-common-bin smbclient -y &> /dev/null && printf "${Purple}rpcclient Installed Successfully\n${Nc}"

#======responder======= 
[ -d "/opt/responder" ] && printf "${Green}Responder already installed${Nc}\n" || { git clone https://github.com/lgandx/Responder.git /opt/responder &> /dev/null &&  echo "python3 /opt/responder/Responder.py \$@" >/usr/local/bin/responder && chmod +x /usr/local/bin/responder && printf "${Purple}Responder Installed Successfully.${Nc}\n"; }


#======bloodhound======= 

# echo 'deb https://debian.neo4j.com stable 4' | sudo tee /etc/apt/sources.list.d/neo4j.list > /dev/null && apt update && systemctl start neo4j.service && curl -sSL -o /tmp/bloodhound.zip https://github.com/SpecterOps/BloodHound/archive/refs/tags/v5.11.0.zip && unzip /tmp/bloodhound.zip -d /tmp/bloodhound && mv /tmp/bloodhound /opt/bloodhound && cd /opt/bloodhound && npm cache clean --force && npm install --legacy-peer-deps && npm run build:linux && mv /tmp/bloodhound/BloodHound-5.11.0 /opt/bloodhound && rm /etc/apt/sources.list.d/neo4j.list && add-apt-repository --remove "deb https://debian.neo4j.com stable 4.4" -y && apt update -y





printf "\n${Cyan}Stage 3 Finished!\nOne by One Installation Finished.\nRun this script 4-5 times. ${Red}WITH REOPENING TERMINAL AS ROOT. \n${Cyan}Check for missing tools in output and manually install.${Nc}\n\n"

printf "${Green}Thank you for using.\nHackify by ZɪsʜᴀɴAᴅTʜᴀɴᴅᴀʀ\n\n${nc}"
