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
            
# one liner bash if loop to check root user
[ "$EUID" -ne 0 ] && printf "\n\033[30;5;41mPlease run as root.${Nc}\n" && sudo su



# ========================APT========================  

apt install docker.io -y >/dev/null 2>&1


declare -a aptarray=("aircrack-ng" "audacity" "axiom" "beef" "binwalk" "braa" "bully" "cargo" "cewl" "cherrytree" "cowpatty" "crunch" "dirb" "dnsenum" "dnsmap" "dnsrecon" "fcrackzip" "figlet" "ffmpeg" "firejail" "git" "hashcat" "hcxdumptool" "httrack" "hydra" "jq" "lolcat" "ltrace" "masscan" "macchanger" "nbtscan" "ndiff" "nikto" "onesixtyone" "openvpn" "parcellite" "pipx" "pixiewps" "pngcheck" "proxychains" "python3" "rdesktop" "reaver" "rlwrap" "smbmap" "sshpass" "sshuttle" "stegcracker" "steghide" "strace" "tmux" "tor" "toilet" "tree" "whatweb" "whois" "wifite" "wireshark")

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
declare -A aptarray1=( [/usr/bin/exiftool]="libimage-exiftool-perl" [/usr/bin/pip3]="python3-pip" [/usr/bin/uget-gtk]="uget" [/usr/share/doc/libpcap0.8-dev/copyright]="libpcap-dev" [/usr/sbin/ntpdate]="ntpsec-ntpdate")
for i in "${!aptarray1[@]}"
do
  aptinstall1 $i ${aptarray1[$i]}
done


# ========================Custom Script Installation========================

# subauto by ZishanAdThandar
[ -f "/usr/local/bin/subauto" ] && printf "${Nc}${Green}SubAuto already installed.\n${Nc}" 
[ ! -f "/usr/local/bin/subauto" ] && curl -ks https://raw.githubusercontent.com/ZishanAdThandar/pentest/main/scripts/subauto.sh > /usr/local/bin/subauto && chmod +x /usr/local/bin/subauto  && printf "${Purple}SubAuto Installed Successfully.\n${nc}"

# NmapAutomator by Ziyad
[ -f "/usr/local/bin/nmapAutomator" ] && printf "${Nc}${Green}NmapAutomator already installed.\n${Nc}" 
[ ! -f "/usr/local/bin/nmapAutomator" ] && curl -ks https://raw.githubusercontent.com/21y4d/nmapAutomator/refs/heads/master/nmapAutomator.sh > /usr/local/bin/nmapAutomator && chmod +x /usr/local/bin/nmapAutomator  && printf "${Purple}NmapAutomator Installed Successfully.\n${nc}"

# docker-compose install
[ -f "/usr/local/bin/docker-compose" ] &&  printf "${Nc}${Green}docker-compose already installed.\n${Nc}" 
[ ! -f "/usr/local/bin/docker-compose" ] &&  rm /usr/bin/docker-compose && curl -L "https://github.com/docker/compose/releases/download/v2.32.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && chmod +x /usr/local/bin/docker-compose && printf "${Purple}docker-compose Installed Successfully.\n${nc}"


# ==============NODEJS NPM REACT =======================
[ -x "$(command -v npm)" ] && printf "${Green}nodejs already installed${Nc}\n" || { sudo apt purge -y nodejs && sudo rm -f /usr/bin/npm /usr/bin/nodejs /usr/local/bin/npm /usr/local/bin/nodejs && sudo apt autoremove -y && sudo apt autoclean && curl -fsSL https://deb.nodesource.com/setup_current.x | sudo -E bash - && sudo apt install -y nodejs && sudo rm -f /etc/apt/sources.list.d/nodesource.list && sudo apt update -y && sudo npm install -g electron-packager && printf "${Purple}nodejs Installed Successfully.${Nc}\n"; }



# ===================================GO LANG======================== 


# installing and setting up Golang
#[ -f "/usr/local/go/bin/go" ] && echo -e "\n${Green}GoLang already downloaded${Nc}\n" || (cd /tmp && wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && sudo tar -C /usr/local/ -xzf go1.23.0.linux-amd64.tar.gz && echo 'export PATH=$PATH:/usr/local/go/bin:/usr/local/go/bin' >> ~/.bashrc && echo 'export GOROOT=/usr/local/go' >> ~/.bashrc && source ~/.bashrc && sudo bash -c 'for i in /home/*; do echo "export PATH=\$PATH:/usr/local/go/bin:/usr/local/go/bin" >> $i/.bashrc && echo "export GOROOT=/usr/local/go" >> $i/.bashrc; done')
[ -f "/usr/local/go/bin/go" ] && echo -e "${Green}GoLang already downloaded${Nc}\n" || (cd /tmp && wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz && sudo tar -C /usr/local/ -xzf go1.24.0.linux-amd64.tar.gz && sudo bash -c 'for i in /home/*; do echo "export PATH=\$PATH:/usr/local/go/bin:/usr/local/go/bin" >> $i/.bashrc && echo "export GOROOT=/usr/local/go" >> $i/.bashrc && echo "export GOBIN=/usr/local/go/bin" >> $i/.bashrc && source $i/.bashrc; done' && sudo bash -c 'echo "export PATH=\$PATH:/usr/local/go/bin:/usr/local/go/bin" >> /root/.bashrc && echo "export GOROOT=/usr/local/go" >> /root/.bashrc && echo "export GOBIN=/usr/local/go/bin" >> /root/.bashrc && source /root/.bashrc' && printf "${Purple}GoLang Installed Successfully.${Nc}\n" )
sudo chmod -R 755 /usr/local/go/bin

export GO111MODULE="on" #Go Module on
# Installing GoLang tools
printf "\n${Cyan}Installing Go Tools for user ${Red}ROOT${Nc}${Cyan} (Current User).${Nc}\n\n"


function goinstall {
[ -f "/usr/local/go/bin/$1" ] && printf "${Green}$1 already installed.\n${Nc}"
[ ! -f "/usr/local/go/bin/$1" ] &&  go install -v $2 && printf "$1 Installed Successfully.\n"
}
declare -A goinstallarray=( [afrog]="github.com/zan8in/afrog/v3/cmd/afrog@latest" [amass]="github.com/owasp-amass/amass/v3/...@master" [assetfinder]="github.com/tomnomnom/assetfinder@latest" [chaos]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest" [crlfuzz]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest" [dalfox]="github.com/hahwul/dalfox@latest" [ffuf]="github.com/ffuf/ffuf@latest" [gau]="github.com/lc/gau/v2/cmd/gau@latest" [gauplus]="github.com/bp0lr/gauplus@latest" [gf]="github.com/tomnomnom/gf@latest" [git-hound]="github.com/tillson/git-hound@latest" [getJS]="github.com/003random/getJS/v2@latest" [gobuster]="github.com/OJ/gobuster/v3@latest" [hakrawler]="github.com/hakluke/hakrawler@latest" [httprobe]="github.com/tomnomnom/httprobe@master" [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest" [interactsh-client]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" [katana]="github.com/projectdiscovery/katana/cmd/katana@latest" [kerbrute]="github.com/ropnop/kerbrute@latest" [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" [qsreplace]="github.com/tomnomnom/qsreplace@latest" [waybackurls]="github.com/tomnomnom/waybackurls@latest" [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" [subzy]="github.com/PentestPad/subzy@latest" [tlsx]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest" )

for i in "${!goinstallarray[@]}"
do
  goinstall $i ${goinstallarray[$i]}
done


#Manual GoTOOLS starts here
#Manual GoTOOLS ends here

# setting gf patterns by 1ndianl33t
[ -d "$HOME/.gf" ] && printf "${Green}gf patterns by 1ndianl33t already installed.\n${Nc}"
[ ! -d "$HOME/.gf" ] && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf && printf "${Purple}gf patterns by 1ndianl33t Installed Successfully.\n${Nc}"

[ -f "$HOME/.gf/base64.json" ] && printf "${Green}gf patterns by tomnomnom already installed.\n${Nc}"
[ ! -f "$HOME/.gf/base64.json" ] && git clone https://github.com/tomnomnom/gf /tmp/gf && mv /tmp/gf/examples/* ~/.gf/ && printf "${Purple}gf patterns by tomnomnom Installed Successfully.\n${Nc}"





# ===================================PYTHON======================== 
# Upgrade pip and install tools

printf "\n${Cyan}Installing Python Tools for user ROOT.${Nc}\n"

[ ! -f "/usr/bin/python3" ] && apt install python3 -y  

#python3 -m pip install --upgrade pip -q #&> /dev/null
#python3 -m pip install --upgrade setuptools wheel twine check-wheel-contents # -q &> /dev/null
python3 -m pip cache purge  &> /dev/null 



#python3 -m pip install setuptools==60.0.0 &> /dev/null
# setup error fixing, setuptools, each module needs proper setuptools version to avoid build error
#python3 -m pip install setuptools==60.0.0 # &> /dev/null # Replace with a version that works TO AVOID SETUP.PY error


# Function to check and install a Python module (separate import and install names)
install_python_module() {
  local import_name="$1"    # Module to import (e.g., "pwn")
  local install_name="$2"   # Module to install (e.g., "pwntools")

  # Check if the Python module is already installed
  python3 -c "import $import_name" 2>/dev/null && \
    printf "\e[32m%s is already installed\e[0m\n" "$import_name" || \
    (python3 -m pip install "$install_name" --break-system-packages && printf "\e[35m%s Installed Successfully\e[0m\n" "$install_name")
}


# Function to check and install a tool from git
install_git_tool() {
  local tool_path="$1"      
  local tool_source="$2"      
  local tool_name="$3"      
  if [ -f "$tool_path" ]; then
    printf "\e[32m%s already installed\e[0m\n" "$tool_name"
  else
    printf "Installing %s...\n" "$tool_name"
    python3 -m pip install "$tool_source" --break-system-packages
    if [ -f "$tool_path" ]; then
      printf "\e[35m%s Installed Successfully\e[0m\n" "$tool_name"
    fi
  fi
}

# Function to check and install a tool via filename
install_tool() {
  local tool_path="$1"      
  local tool_name="$2"      
  if [ -f "$tool_path" ]; then
    printf "\e[32m%s already installed\e[0m\n" "$tool_name"
  else
    printf "Installing %s...\n" "$tool_name"
    python3 -m pip install "$tool_name" --break-system-packages
    if [ -f "$tool_path" ]; then
      printf "\e[35m%s Installed Successfully\e[0m\n" "$tool_name"
    fi
  fi
}


     
install_tool "/usr/local/bin/arjun" "arjun" 
install_tool "/usr/local/bin/bloodyAD" "bloodyad"  
install_tool "/usr/local/bin/certipy" "certipy-ad" 
install_tool "/usr/local/bin/git-dumper" "git-dumper"    
install_tool "/usr/local/bin/mitm6" "mitm6"    
install_tool "/usr/local/bin/pwncat" "pwncat"    
install_tool "/usr/local/bin/sherlock" "sherlock-project" 
install_tool "/usr/local/bin/smtp-user-enum" "smtp-user-enum" 
install_tool "/usr/local/bin/uro" "uro"
install_tool "/usr/local/bin/wafw00f" "wafw00f"   
install_tool "/usr/bin/wapiti" "wapiti3"   
install_tool "/usr/local/bin/waymore" "waymore"  

# install_tool "/usr/local/bin/autobloody" "autobloody" 


install_python_module "dirsearch" "dirsearch"
install_python_module "hashid" "hashid"
install_python_module "ldap3" "ldap3"
install_python_module "lfimap" "lfimap"
install_python_module "pwn" "pwntools"
install_python_module "sublist3r" "sublist3r"


install_git_tool "/usr/local/bin/paramspider" "https://github.com/devanshbatham/ParamSpider/archive/master.zip" "paramspider"
install_git_tool "/usr/local/bin/ghauri" "https://github.com/r0oth3x49/ghauri/archive/master.zip" "ghauri"


# youtube-dl   
install_git_tool "/usr/local/bin/youtube-dl" "https://github.com/ytdl-org/youtube-dl/archive/master.zip" "youtube-dl" && echo "python3 -m youtube_dl \$@" >/usr/local/bin/youtube-dl && chmod +x /usr/local/bin/youtube-dl  

# yt-dlp
install_git_tool "/usr/bin/yt-dlp" "yt-dlp[default] @ https://github.com/yt-dlp/yt-dlp/archive/master.tar.gz" "yt-dlp"

# linkfinder
[ -f "/usr/local/bin/linkfinder" ] && printf "${Green}linkfinder already installed${Nc}\n"
[ ! -f "/usr/local/bin/linkfinder" ] && install_tool "/usr/local/bin/linkfinder" "git+https://github.com/GerbenJavado/LinkFinder" && echo "python3 -m linkfinder \$@" >/usr/local/bin/linkfinder && chmod +x /usr/local/bin/linkfinder  && printf "${Purple}linkfinder Installed Successfully\n${Nc}"

# Reconspider
[ -f "/usr/local/bin/ReconSpider.py" ] && printf "${Green}ReconSpider.py already installed${Nc}\n"
[ ! -f "/usr/local/bin/ReconSpider.py" ] && curl -ks https://gist.githubusercontent.com/ZishanAdThandar/27217f687e742293ce54f67b97101e0a/raw/860bccc9808627c2ae45e2f469b2f3094347fdaf/ReconSpider.py >/usr/local/bin/ReconSpider.py && chmod +x /usr/local/bin/ReconSpider.py  && printf "${Purple}ReconSpider.py Installed Successfully\n${Nc}"


#======responder======= 
[ -d "/opt/responder" ] && printf "${Green}Responder already installed${Nc}\n" || { git clone https://github.com/lgandx/Responder.git /opt/responder &> /dev/null &&  echo "python3 /opt/responder/Responder.py \$@" >/usr/local/bin/responder && chmod +x /usr/local/bin/responder && printf "${Purple}Responder Installed Successfully.${Nc}\n"; }

#======AutoRecon Tib3rus======= 
[ -f "/usr/local/bin/autorecon" ] && printf "${Green}AutoRecon already installed${Nc}\n"
[ ! -f "/usr/local/bin/autorecon" ] && python3 -m pip install git+https://github.com/Tib3rius/AutoRecon.git --ignore-installed --break-system-packages  && printf "${Purple}AutoRecon Installed Successfully\n${Nc}"

#======crackmapexec netexec======= 

[ -f "/usr/local/bin/crackmapexec" ] && printf "${Green}CrackMapExec already installed${Nc}\n"
[ ! -f "/usr/local/bin/crackmapexec" ] && python3 -m pip install git+https://github.com/byt3bl33d3r/CrackMapExec --ignore-installed --break-system-packages  && printf "${Purple}CrackMapExec Installed Successfully\n${Nc}"

[ -f "/usr/local/bin/nxc" ] && printf "${Green}NetExec already installed${Nc}\n"
[ ! -f "/usr/local/bin/nxc" ] && python3 -m pip install git+https://github.com/Pennyw0rth/NetExec.git --ignore-installed --break-system-packages  && printf "${Purple}NetExec Installed Successfully\n${Nc}"

#======Impacket========
[ -f "/usr/local/bin/owneredit.py" ] && printf "${Green}ImPacket already installed${Nc}\n"  
[ ! -f "/usr/local/bin/owneredit.py" ] && python3 -m pip install git+https://github.com/fortra/impacket --ignore-installed --break-system-packages && printf "${Purple}Impacket Installed Successfully\n${Nc}"
# [ ! -f "/usr/bin/impacket-netview" ] && python3 -m pip install git+https://github.com/fortra/impacket --ignore-installed --break-system-packages && python3 -m pip install impacket --ignore-installed --break-system-packages && apt install python3-impacket -y && printf "${Purple}Impacket Installed Successfully\n${Nc}"

# SQLMap
[ -d /opt/sqlmap ] && printf "${Green}SQLMap already installed${Nc}\n" || { sudo apt-get remove -y sqlmap; python3 -m pip uninstall -y sqlmap; sudo rm -f /usr/local/bin/sqlmap /usr/bin/sqlmap; sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap; echo -e '#!/bin/bash\npython3 /opt/sqlmap/sqlmap.py "$@"' | sudo tee /usr/local/bin/sqlmap > /dev/null; sudo chmod +x /usr/local/bin/sqlmap; printf "\033[0;35mSQLMap Installed Successfully\033[0m'\n";}
grep -q 'MAX_NUMBER_OF_THREADS = 500' /opt/sqlmap/lib/core/settings.py || sudo sed -i 's/MAX_NUMBER_OF_THREADS = [0-9]\+/MAX_NUMBER_OF_THREADS = 500/' /opt/sqlmap/lib/core/settings.py



#=======waymore==========
#python3 -m pip install --upgrade pip setuptools > /dev/null && python3 -m pip install git+https://github.com/xnl-h4ck3r/waymore.git


# ========================RUBY======================== 

[ ! -f "/usr/bin/ruby" ] && apt-get install ruby-full >/dev/null
gem sources --add https://rubygems.org/ > /dev/null
gem cleanup > /dev/null


# ========================Ruby Based Tools========================
# WPScan Installation
[ -f "/usr/local/bin/wpscan" ] && printf "${Green}WPScan already installed${Nc}\n"
[ ! -f "/usr/local/bin/wpscan" ] && sudo apt install -y curl git libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 autoconf libgdbm-dev libncurses5-dev automake libtool bison pkg-config ruby ruby-bundler ruby-dev > /dev/null && sudo gem install wpscan 


# evil-winrm 
[ -f "/usr/local/bin/evil-winrm" ] && printf "${Green}evil-winrm.rb already installed${Nc}\n"
[ ! -f "/usr/local/bin/evil-winrm" ] && gem install evil-winrm && printf "${Purple}evil-winrm Installed Successfully\n${Nc}"

# arachni https://github.com/Arachni/arachni

#[ -f "/usr/local/bin/arachni" ] && printf "${Green}arachni already installed${Nc}\n"
#[ ! -f "/usr/local/bin/arachni" ] && gem install arachni && printf "${Purple}arachni Installed Successfully\n${Nc}"


# metasploit installation

if ! command -v msfconsole &> /dev/null
then
  curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
  rm msfinstall
  rm /etc/apt/sources.list.d/metasploit-framework.list
  apt update -y && apt upgrade -y
fi





# ========================C TOOLS======================== 
# NMap
[ -f "/usr/local/bin/nmap" ] && printf "${Green}NMap already installed${Nc}\n"
[ ! -f "/usr/local/bin/nmap" ] && wget https://nmap.org/dist/nmap-7.95.tar.bz2 --directory-prefix=/tmp/ && cd /tmp && tar xvjf /tmp/nmap-7.95.tar.bz2 && cd /tmp/nmap-7.95 && /tmp/nmap-7.95/configure && make install -C /tmp/nmap-7.95 && cp /usr/local/bin/nmap && /usr/bin/nmap && rm -rf /tmp/nmap-7.95 && printf "${Purple}NMap Installed Successfully\n${Nc}"

# john
## Crafted for Ubuntu based OS, Source https://github.com/openwall/john/blob/bleeding-jumbo/doc/INSTALL-UBUNTU 
[ -f "/opt/john/run/john" ] && printf "${Green}john already installed${Nc}\n"
[ ! -f "/opt/john/run/john" ] && apt purge john -y  &> /dev/null && git clone https://github.com/openwall/john -b bleeding-jumbo /opt/john && cd /opt/john/src && ./configure && make -s clean && make -sj4 && make shell-completion && chmod +x /opt/john/run/john && echo -e '#!/bin/bash\n/opt/john/run/john "$@"' | sudo tee /usr/local/bin/john > /dev/null && chmod +x /usr/local/bin/john && printf "${Purple}John Installed Successfully\n${Nc}"


# ========================PERL TOOLS======================== 

# JoomScan Joomla Scanner
[ -f "/usr/local/bin/joomscan" ] && printf "${Green}JoomScan already installed${Nc}\n"
[ ! -f "/usr/local/bin/joomscan" ] && git clone https://github.com/OWASP/joomscan /opt/joomscan && echo "perl /opt/joomscan/joomscan.pl \$@" >/usr/local/bin/joomscan && chmod +x /usr/local/bin/joomscan && printf "${Purple}JoomScan Installed Successfully\n${Nc}"


#Enum4Linux 
[ -f "/usr/bin/enum4linux" ] && printf "${Green}Enum4Linux already installed${Nc}\n"
[ ! -f "/usr/bin/enum4linux" ] && curl https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl -s -k > /usr/bin/enum4linux && chmod +x /usr/bin/enum4linux && printf "${Purple}Enum4Linux Installed Successfully\n${Nc}"
[ -f "/usr/bin/enum4linux-ng" ] && printf "${Green}enum4linux-ng already installed${Nc}\n"
[ ! -f "/usr/bin/enum4linux-ng" ] && curl https://raw.githubusercontent.com/cddmp/enum4linux-ng/refs/heads/master/enum4linux-ng.py -s -k > /usr/bin/enum4linux-ng && chmod +x /usr/bin/enum4linux-ng && printf "${Purple}enum4linux-ng Installed Successfully\n${Nc}"



# ========================RUST TOOLS========================

# RUST installation command incase of issue of installing # curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


# ====ARES cipher tool https://github.com/bee-san/Ares =======
[ -f "/usr/local/bin/ares" ] && printf "${Green}Ares already installed${Nc}\n"
[ ! -f "/usr/local/bin/ares" ] && cargo install project_ares && cp /root/.cargo/bin/ares /usr/local/bin/ares && printf "${Purple}ARES Installed Successfully\n${Nc}"
# ====RUSTSCAN port scanner https://github.com/RustScan/RustScan =======
[ -f "/usr/local/bin/rustscan" ] && printf "${Green}Rustscan already installed${Nc}\n"
[ ! -f "/usr/local/bin/rustscan" ] && cargo install rustscan && cp /root/.cargo/bin/rustscan /usr/local/bin/rustscan && printf "${Purple}RUSTSCAN Installed Successfully\n${Nc}"
# ====x8 parameter discovery https://github.com/Sh1Yo/x8 =======
[ -f "/usr/local/bin/x8" ] && printf "${Green}x8 already installed${Nc}\n"
[ ! -f "/usr/local/bin/x8" ] && cargo install x8 && cp /root/.cargo/bin/x8 /usr/local/bin/x8 && printf "${Purple}x8 Installed Successfully\n${Nc}"
# ==========FeroxBuster=============
[ -f "/usr/local/bin/feroxbuster" ] && printf "${Green}feroxbuster already installed${Nc}\n"
[ ! -f "/usr/local/bin/feroxbuster" ] && cd /usr/local/bin && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash && printf "${Purple}feroxbuster Installed Successfully\n${Nc}"




#======bloodhound======= 

#echo 'deb https://debian.neo4j.com stable 4' | sudo tee /etc/apt/sources.list.d/neo4j.list > /dev/null && apt update && systemctl start neo4j.service && git clone https://github.com/BloodHoundAD/BloodHound /opt/bloodhound && cd /opt/bloodhound && npm cache clean --force && npm install --legacy-peer-deps && npm run build:linux && mv /tmp/bloodhound/BloodHound-5.11.0 /opt/bloodhound && rm /etc/apt/sources.list.d/neo4j.list && add-apt-repository --remove "deb https://debian.neo4j.com stable 4.4" -y && apt update -y

# ===================================OTHER======================== 

# exploitdb and searchsploit
[ ! -d "/opt/exploit-database" ] && git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database && ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit && printf "${Purple}exploitDB Installed Successfully\n${Nc}"


#rpcclient 
[ -f "/usr/bin/rpcclient" ] && printf "${Green}rpcclient already installed${Nc}\n"
[ ! -f "/usr/bin/rpcclient" ] && apt install samba-common-bin smbclient -y &> /dev/null && printf "${Purple}rpcclient Installed Successfully\n${Nc}"



printf "\n${Cyan}Stage 3 Finished!\nOne by One Installation Finished.\nRun this script 4-5 times. ${Red}WITH REOPENING TERMINAL AS ROOT. \n${Cyan}Check for missing tools in output and manually install.${Nc}\n\n"

printf "${Green}Thank you for using.\nHackify by ZishanAdThandar\n\n${nc}"
