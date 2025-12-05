#!/usr/bin/env bash

# =============================================================================
# HACKIFY - Ultimate Penetration Testing Tools Installer
# Author: Zishan Ahamed Thandar
# Description: Automated installation of 200+ hacking tools for penetration testing
# =============================================================================

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

# Banner and ASCII Art
show_banner() {
    clear
    printf "\n\n${GREEN}Hacking Tools and Wordlist Installer written by,\n\n\n"
    printf "${RED}"
    cat << "EOF"
  _____    _                _      _ _____ _                 _          
 |_  (_)__| |_  __ _ _ _   /_\  __| |_   _| |_  __ _ _ _  __| |__ _ _ _ 
  / /| (_-| ' \/ _` | ' \ / _ \/ _` | | | | ' \/ _` | ' \/ _` / _` | '_|
 /___|_/__|_||_\__,_|_||_/_/ \_\__,_| |_| |_||_\__,_|_||_\__,_\__,_|_|  
 
EOF
    printf "\n\n${CYAN}Profile: https://zishanadthandar.github.io\n"
    printf "LinkTree: https://zishanadthandar.github.io/linktree\n"
    printf "LinkedIn: https://linkedin.com/in/zishanadthandar${NC}\n\n"
}

# Utility Functions
print_status() { printf "${CYAN}[*]${NC} %s\n" "$1"; }
print_success() { printf "${GREEN}[+]${NC} %s\n" "$1"; }
print_warning() { printf "${YELLOW}[!]${NC} %s\n" "$1"; }
print_error() { printf "${RED}[-]${NC} %s\n" "$1"; }
print_info() { printf "${BLUE}[i]${NC} %s\n" "$1"; }

# Check Root Privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Please run as root. Elevating privileges..."
        exec sudo "$0" "$@"
    fi
    print_success "Running with root privileges"
}

# System Preparation
prepare_system() {
    print_status "Updating system packages..."
    apt update -qq && apt upgrade -y -qq
    print_success "System updated successfully"
}

# =============================================================================
# STAGE 1: Package Manager Installations
# =============================================================================

install_apt_packages() {
    local -a core_packages=(
        "docker.io" "aircrack-ng" "apktool" "audacity" "axiom" "beef" "braa" 
        "bully" "cargo" "cewl" "cherrytree" "cowpatty" "crunch" "dirb" "dnsenum" 
        "dnsmap" "dnsrecon" "fcrackzip" "figlet" "ffmpeg" "firejail" "git" 
        "hashcat" "hcxdumptool" "httrack" "hydra" "jq" "lolcat" "ltrace" 
        "masscan" "macchanger" "nbtscan" "ndiff" "nikto" "onesixtyone" 
        "openvpn" "parcellite" "pipx" "pixiewps" "pngcheck" "proxychains" 
        "python3" "rdesktop" "reaver" "redis-tools" "rlwrap" "smbmap" "sshpass" "sshuttle" 
        "stegcracker" "steghide" "stegseek" "strace" "tmux" "tor" "toilet" 
        "tree" "whatweb" "whois" "wifite" "wireshark"
    )

    local installed_count=0
    local failed_packages=()
    
    print_status "Installing ${#core_packages[@]} core packages via APT..."

    for pkg in "${core_packages[@]}"; do
        if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
            print_info "Already installed: $pkg"
            ((installed_count++))
            continue
        fi
        
        print_status "Installing: $pkg"
        if apt install -y "$pkg" >/dev/null 2>&1; then
            print_success "Successfully installed: $pkg"
            ((installed_count++))
        else
            print_error "Failed to install: $pkg"
            failed_packages+=("$pkg")
        fi
    done

    # Additional specific packages with verbose output
    print_status "Installing additional specific packages..."
    declare -A special_packages=(
        ["/usr/bin/exiftool"]="libimage-exiftool-perl"
        ["/usr/bin/pip3"]="python3-pip"
        ["/usr/bin/uget-gtk"]="uget"
        ["/usr/share/doc/libpcap0.8-dev/copyright"]="libpcap-dev"
        ["/usr/sbin/ntpdate"]="ntpsec-ntpdate"
    )

    for bin_path in "${!special_packages[@]}"; do
        if [[ ! -f "$bin_path" ]]; then
            local pkg_name="${special_packages[$bin_path]}"
            print_status "Installing: $pkg_name"
            if apt install -y "$pkg_name" >/dev/null 2>&1; then
                print_success "Successfully installed: $pkg_name"
            else
                print_error "Failed to install: $pkg_name"
                failed_packages+=("$pkg_name")
            fi
        else
            print_info "Already available: $(basename "$bin_path")"
        fi
    done

    # Summary report
    print_success "APT installation completed: $installed_count/${#core_packages[@]} packages installed"
    
    if [ ${#failed_packages[@]} -gt 0 ]; then
        print_warning "The following packages failed to install and may need manual installation:"
        for failed_pkg in "${failed_packages[@]}"; do
            print_error "  - $failed_pkg"
        done
        print_info "You can try installing them manually with: sudo apt install -y <package-name>"
    fi
}

# =============================================================================
# STAGE 2: Custom Scripts & Docker Setup
# =============================================================================

install_custom_scripts() {
    print_status "Installing custom automation scripts..."

    local -A scripts=(
        ["subauto"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/subauto.sh"
        ["gitpull"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/gitpull.sh"
        ["gitpush"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/gitpush.sh"
        ["nmapAutomator"]="https://raw.githubusercontent.com/21y4d/nmapAutomator/refs/heads/master/nmapAutomator.sh"
        ["xsspy"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/xsspy.py"
        ["winrmexec"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/winrmexec.py"
        ["ReconSpider.py"]="https://raw.githubusercontent.com/ZishanAdThandar/hackify/refs/heads/main/scripts/ReconSpider.py"
    )


    for script_name in "${!scripts[@]}"; do
        local script_path="/usr/local/bin/$script_name"
        if [[ ! -f "$script_path" ]]; then
            if curl -ks "${scripts[$script_name]}" > "$script_path" 2>/dev/null; then
                chmod +x "$script_path"
                print_success "Installed: $script_name"
            else
                print_error "Failed to install: $script_name"
            fi
        fi
    done

    # Docker Compose
    if [[ ! -f "/usr/local/bin/docker-compose" ]]; then
        rm -f /usr/bin/docker-compose
        local arch_suffix="$(uname -s)-$(uname -m)"
        if curl -ks -L "https://github.com/docker/compose/releases/download/v2.32.1/docker-compose-$arch_suffix" \
            -o /usr/local/bin/docker-compose; then
            chmod +x /usr/local/bin/docker-compose
            print_success "Installed: docker-compose"
        fi
    fi
}

setup_nodejs() {
    if command -v npm >/dev/null 2>&1; then
        print_success "Node.js already installed"
        return
    fi

    print_status "Setting up Node.js environment..."
    
    # Clean existing installations
    apt purge -y nodejs && rm -f /usr/bin/npm /usr/bin/nodejs /usr/local/bin/npm /usr/local/bin/nodejs
    apt autoremove -y && apt autoclean

    # Install latest Node.js
    curl -fsSL https://deb.nodesource.com/setup_current.x | bash - >/dev/null 2>&1
    apt install -y nodejs >/dev/null 2>&1
    rm -f /etc/apt/sources.list.d/nodesource.list
    apt update -y >/dev/null 2>&1
    npm install -g electron-packager >/dev/null 2>&1

    print_success "Node.js environment configured"
}

# =============================================================================
# STAGE 3: Programming Language Environments
# =============================================================================

setup_golang() {
    local go_version="1.25.4"
    local go_tarball="go${go_version}.linux-amd64.tar.gz"

    if [[ -f "/usr/local/go/bin/go" ]]; then
        print_success "GoLang already installed"
        return
    fi

    print_status "Installing GoLang $go_version..."
    
    cd /tmp && wget -q "https://go.dev/dl/$go_tarball"
    tar -C /usr/local/ -xzf "$go_tarball" >/dev/null 2>&1

    # Set up environment for all users
    local go_paths=('export PATH=$PATH:/usr/local/go/bin' 
                    'export GOROOT=/usr/local/go' 
                    'export GOBIN=/usr/local/go/bin')

    for user_dir in /home/* /root; do
        [[ -d "$user_dir" ]] || continue
        for path_cmd in "${go_paths[@]}"; do
            grep -q "$path_cmd" "$user_dir/.bashrc" 2>/dev/null || echo "$path_cmd" >> "$user_dir/.bashrc"
        done
        source "$user_dir/.bashrc" 2>/dev/null || true
    done

    chmod -R 755 /usr/local/go/bin
    export GO111MODULE="on"
    
    print_success "GoLang $go_version installed and configured"
}

install_go_tools() {
    print_status "Installing Go-based security tools..."

    declare -A go_tools=(
        ["afrog"]="github.com/zan8in/afrog/v3/cmd/afrog@latest"
        ["amass"]="github.com/owasp-amass/amass/v3/...@master"
        ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
        ["chaos"]="github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
        ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        ["dalfox"]="github.com/hahwul/dalfox@latest"
        ["ffuf"]="github.com/ffuf/ffuf@latest"
        ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
        ["gauplus"]="github.com/bp0lr/gauplus@latest"
        ["gf"]="github.com/tomnomnom/gf@latest"
        ["git-hound"]="github.com/tillson/git-hound@latest"
        ["getJS"]="github.com/003random/getJS/v2@latest"
        ["gobuster"]="github.com/OJ/gobuster/v3@latest"
        ["hakoriginfinder"]="github.com/hakluke/hakoriginfinder@latest"
        ["hakrawler"]="github.com/hakluke/hakrawler@latest"
        ["httprobe"]="github.com/tomnomnom/httprobe@master"
        ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["interactsh-client"]="github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
        ["kerbrute"]="github.com/ropnop/kerbrute@latest"
        ["misconfig-mapper"]="github.com/intigriti/misconfig-mapper/cmd/misconfig-mapper@latest"
        ["naabu"]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
        ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
        ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["subzy"]="github.com/PentestPad/subzy@latest"
        ["tlsx"]="github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    )

    local installed_count=0
    local failed_tools=()

    for tool in "${!go_tools[@]}"; do
        if [[ -f "/usr/local/go/bin/$tool" ]] || command -v "$tool" >/dev/null 2>&1; then
            print_info "Already installed: $tool"
            ((installed_count++))
            continue
        fi
        
        print_status "Installing: $tool"
        if go install -v "${go_tools[$tool]}" >/dev/null 2>&1; then
            print_success "Successfully installed: $tool"
            ((installed_count++))
        else
            print_warning "Failed to install: $tool"
            failed_tools+=("$tool")
        fi
    done

    # GF Patterns
    if [[ ! -d "$HOME/.gf" ]]; then
        git clone -q https://github.com/1ndianl33t/Gf-Patterns ~/.gf
        git clone -q https://github.com/tomnomnom/gf /tmp/gf && cp /tmp/gf/examples/* ~/.gf/
        rm -rf /tmp/gf
        print_success "GF patterns configured"
    fi

    # Summary
    print_success "Go tools installation completed: $installed_count/${#go_tools[@]} tools installed"
    if [ ${#failed_tools[@]} -gt 0 ]; then
        print_warning "Some Go tools failed to install. You can try installing them manually later."
    fi
}

# =============================================================================
# STAGE 3: Python Tools Installation (Improved Version)
# =============================================================================

install_python_tools() {
    printf "\n${CYAN}Installing Python Tools for user ROOT.${NC}\n"

    # Basic Python setup
    [ ! -f "/usr/bin/python3" ] && apt install python3 -y  
    python3 -m pip cache purge &> /dev/null 

    # Function to check and install a Python module (separate import and install names)
    install_python_module() {
        local import_name="$1"    # Module to import (e.g., "pwn")
        local install_name="$2"   # Module to install (e.g., "pwntools")

        # Check if the Python module is already installed
        if python3 -c "import $import_name" 2>/dev/null; then
            print_info "Already installed: $import_name"
        else
            if python3 -m pip install "$install_name" --break-system-packages >/dev/null 2>&1; then
                print_success "$install_name installed successfully"
            else
                print_warning "Failed to install: $install_name"
            fi
        fi
    }

    # Function to check and install a tool from git
    install_git_tool() {
        local tool_path="$1"      
        local tool_source="$2"      
        local tool_name="$3"      
        
        if [ -f "$tool_path" ]; then
            print_info "Already installed: $tool_name"
        else
            print_status "Installing $tool_name..."
            if python3 -m pip install "$tool_source" --break-system-packages >/dev/null 2>&1; then
                if [ -f "$tool_path" ]; then
                    print_success "$tool_name installed successfully"
                else
                    # Try to create the tool manually if it doesn't auto-install
                    local module_name=$(basename "$tool_source" | sed 's/\.zip//' | sed 's/-master//')
                    if python3 -c "import $module_name" 2>/dev/null; then
                        echo "#!/usr/bin/env python3\npython3 -m $module_name \"\$@\"" > "$tool_path"
                        chmod +x "$tool_path"
                        print_success "$tool_name created manually"
                    fi
                fi
            else
                print_warning "Failed to install: $tool_name"
            fi
        fi
    }

    # Function to check and install a tool via filename
    install_tool() {
        local tool_path="$1"      
        local tool_name="$2"      
        
        if [ -f "$tool_path" ]; then
            print_info "Already installed: $tool_name"
        else
            print_status "Installing $tool_name..."
            if python3 -m pip install "$tool_name" --break-system-packages >/dev/null 2>&1; then
                if [ -f "$tool_path" ]; then
                    print_success "$tool_name installed successfully"
                else
                    print_warning "$tool_name installed but binary not found at $tool_path"
                fi
            else
                print_warning "Failed to install: $tool_name"
            fi
        fi
    }

    # Install tools with binary checks
    print_status "Installing Python tools with binary verification..."
    
    # Tools that install binaries in /usr/local/bin
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
    install_tool "/usr/local/bin/waymore" "waymore"  
    install_tool "/usr/local/bin/wdp" "website-dorker-pro"  

    # Python modules (import-based check)
    print_status "Installing Python modules..."
    install_python_module "dirsearch" "dirsearch"
    install_python_module "hashid" "hashid"
    install_python_module "ldap3" "ldap3"
    install_python_module "lfimap" "lfimap"
    install_python_module "pwn" "pwntools"
    install_python_module "sublist3r" "sublist3r"

    # Git-based tools
    print_status "Installing Git-based Python tools..."
    install_git_tool "/usr/local/bin/paramspider" "https://github.com/devanshbatham/ParamSpider/archive/master.zip" "paramspider"
    install_git_tool "/usr/local/bin/ghauri" "https://github.com/r0oth3x49/ghauri/archive/master.zip" "ghauri"
    install_git_tool "/usr/local/bin/powerview" "git+https://github.com/aniqfakhrul/powerview.py" "powerview"
    install_git_tool "/usr/local/bin/wifiphisher" "git+https://github.com/wifiphisher/wifiphisher/archive/master.zip" "wifiphisher"

    # Special tools with custom handling
    print_status "Installing special tools..."
    
    # yt-dlp
    if [ ! -f "/usr/local/bin/yt-dlp" ]; then
        apt purge yt-dlp -y >/dev/null 2>&1
        rm -f /usr/bin/yt-dlp /usr/local/bin/yt-dlp
        if python3 -m pip install --force-reinstall "yt-dlp[default]" --break-system-packages >/dev/null 2>&1; then
            print_success "yt-dlp installed successfully"
        else
            # Fallback to direct download
            curl -L https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp -o /usr/local/bin/yt-dlp 2>/dev/null
            chmod +x /usr/local/bin/yt-dlp
            print_success "yt-dlp installed via direct download"
        fi
    else
        print_info "Already installed: yt-dlp"
    fi

    # LinkFinder
    if [ ! -f "/usr/local/bin/linkfinder" ]; then
        if python3 -m pip install "git+https://github.com/GerbenJavado/LinkFinder" --break-system-packages >/dev/null 2>&1; then
            echo "#!/usr/bin/env python3\npython3 -m linkfinder \"\$@\"" > /usr/local/bin/linkfinder
            chmod +x /usr/local/bin/linkfinder
            print_success "linkfinder installed successfully"
        fi
    else
        print_info "Already installed: linkfinder"
    fi


    # Install advanced Python tools (SQLMap, Impacket, etc.)
    install_advanced_python_tools

    print_success "Python tools installation completed"
}

install_advanced_python_tools() {
    print_status "Installing advanced Python tools..."

    # SQLMap
    if [[ ! -d "/opt/sqlmap" ]]; then
        apt-get remove -y sqlmap >/dev/null 2>&1
        python3 -m pip uninstall -y sqlmap >/dev/null 2>&1
        rm -f /usr/local/bin/sqlmap /usr/bin/sqlmap
        
        git clone -q --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
        echo '#!/bin/bash\npython3 /opt/sqlmap/sqlmap.py "$@"' > /usr/local/bin/sqlmap
        chmod +x /usr/local/bin/sqlmap
        
        # Optimize SQLMap configuration
        sed -i 's/MAX_NUMBER_OF_THREADS = [0-9]\+/MAX_NUMBER_OF_THREADS = 500/' /opt/sqlmap/lib/core/settings.py
        print_success "SQLMap installed and optimized"
    fi

    # Impacket
    if [[ ! -f "/usr/local/bin/GetNPUsers.py" ]]; then
        if python3 -m pip install "git+https://github.com/fortra/impacket" --break-system-packages >/dev/null 2>&1; then
            git clone -q https://github.com/fortra/impacket /tmp/impacket
            chmod +x /tmp/impacket/examples/*.py 
            cp /tmp/impacket/examples/*.py /usr/local/bin/
            rm -rf /tmp/impacket
            print_success "Impacket toolkit installed"
        fi
    fi

    # Responder
    if [[ ! -d "/opt/responder" ]]; then
        git clone -q https://github.com/lgandx/Responder.git /opt/responder
        echo '#!/bin/bash\npython3 /opt/responder/Responder.py "$@"' > /usr/local/bin/responder
        chmod +x /usr/local/bin/responder
        print_success "Responder installed"
    fi

    # AutoRecon
    if [[ ! -f "/usr/local/bin/autorecon" ]]; then
        if python3 -m pip install "git+https://github.com/Tib3rius/AutoRecon.git" --break-system-packages >/dev/null 2>&1; then
            print_success "AutoRecon installed"
        fi
    fi

    # CrackMapExec/NetExec
    if [[ ! -f "/usr/local/bin/crackmapexec" ]]; then
        if python3 -m pip install "git+https://github.com/byt3bl33d3r/CrackMapExec" --break-system-packages >/dev/null 2>&1; then
            print_success "CrackMapExec installed"
        fi
    fi

    if [[ ! -f "/usr/local/bin/nxc" ]]; then
        if python3 -m pip install "git+https://github.com/Pennyw0rth/NetExec.git" --break-system-packages >/dev/null 2>&1; then
            print_success "NetExec installed"
        fi
    fi
}

# =============================================================================
# STAGE 4: Specialized Tools & Frameworks
# =============================================================================

install_ruby_tools() {
    print_status "Installing Ruby-based tools..."

    # Ruby environment
    command -v ruby >/dev/null || apt install -y ruby-full >/dev/null 2>&1
    gem sources --add https://rubygems.org/ >/dev/null && gem cleanup >/dev/null

    # WPScan
    if ! command -v wpscan >/dev/null 2>&1; then
        apt install -y curl git libcurl4-openssl-dev make zlib1g-dev gawk g++ gcc \
            libreadline6-dev libssl-dev libyaml-dev libsqlite3-dev sqlite3 autoconf \
            libgdbm-dev libncurses5-dev automake libtool bison pkg-config ruby \
            ruby-bundler ruby-dev >/dev/null 2>&1
        gem install wpscan >/dev/null 2>&1
        print_success "Installed: WPScan"
    fi

    # Evil-WinRM
    if ! command -v evil-winrm >/dev/null 2>&1; then
        gem install evil-winrm >/dev/null 2>&1
        print_success "Installed: Evil-WinRM"
    fi

    # Metasploit Framework
    if ! command -v msfconsole >/dev/null 2>&1; then
        curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
        chmod 755 msfinstall && ./msfinstall >/dev/null 2>&1
        rm msfinstall /etc/apt/sources.list.d/metasploit-framework.list
        apt update -y >/dev/null 2>&1
        print_success "Installed: Metasploit Framework"
    fi
}

install_compiled_tools() {
    print_status "Installing compiled tools from source..."

    # John the Ripper (bleeding-jumbo)
    if [[ ! -f "/opt/john/run/john" ]]; then
        apt purge john -y >/dev/null 2>&1
        git clone -q https://github.com/openwall/john -b bleeding-jumbo /opt/john
        cd /opt/john/src && ./configure >/dev/null 2>&1
        make -s clean && make -sj4 >/dev/null 2>&1 && make shell-completion >/dev/null 2>&1
        echo '#!/bin/bash\n/opt/john/run/john "$@"' > /usr/local/bin/john
        chmod +x /usr/local/bin/john /opt/john/run/john
        print_success "Installed: John the Ripper (optimized)"
    fi

    # JoomScan
    if [[ ! -f "/usr/local/bin/joomscan" ]]; then
        git clone -q https://github.com/OWASP/joomscan /opt/joomscan
        echo 'perl /opt/joomscan/joomscan.pl $@' > /usr/local/bin/joomscan
        chmod +x /usr/local/bin/joomscan
        print_success "Installed: JoomScan"
    fi

    # Enum4Linux & Enum4Linux-ng
    [[ ! -f "/usr/bin/enum4linux" ]] && {
        curl -s -k https://raw.githubusercontent.com/CiscoCXSecurity/enum4linux/master/enum4linux.pl > /usr/bin/enum4linux
        chmod +x /usr/bin/enum4linux
        print_success "Installed: Enum4Linux"
    }

    [[ ! -f "/usr/bin/enum4linux-ng" ]] && {
        curl -s -k https://raw.githubusercontent.com/cddmp/enum4linux-ng/refs/heads/master/enum4linux-ng.py > /usr/bin/enum4linux-ng
        chmod +x /usr/bin/enum4linux-ng
        print_success "Installed: Enum4Linux-ng"
    }

    # NMap from source
    if [[ ! -f "/usr/local/bin/nmap" ]]; then
        wget https://nmap.org/dist/nmap-7.95.tar.bz2 --directory-prefix=/tmp/ >/dev/null 2>&1
        cd /tmp && tar xvjf /tmp/nmap-7.95.tar.bz2 >/dev/null 2>&1
        cd /tmp/nmap-7.95 && ./configure >/dev/null 2>&1
        make install -C /tmp/nmap-7.95 >/dev/null 2>&1
        cp /usr/local/bin/nmap /usr/bin/nmap 2>/dev/null || true
        rm -rf /tmp/nmap-7.95* >/dev/null 2>&1
        print_success "Installed: NMap (from source)"
    fi
}

setup_rust_environment() {
    print_status "Setting up Rust environment..."

    if ! command -v rustup >/dev/null 2>&1; then
        RUSTUP_INIT_SKIP_PATH_CHECK=yes curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >/dev/null 2>&1
        source "$HOME/.cargo/env"
    fi

    rustup install stable >/dev/null 2>&1
    rustup default stable >/dev/null 2>&1
    rustup update >/dev/null 2>&1

    export PATH="$HOME/.cargo/bin:$PATH"
    export CARGO_TARGET_DIR="/usr/local/bin"

    # Install build dependencies
    local -a build_deps=("build-essential" "libssl-dev" "pkg-config" "liblzma-dev" "libfontconfig1-dev")
    for pkg in "${build_deps[@]}"; do
        dpkg -s "$pkg" >/dev/null 2>&1 || apt install -y "$pkg" >/dev/null 2>&1
    done

    install_rust_tool "binwalk" "cargo install binwalk --locked"
    install_rust_tool "rustscan" "cargo install rustscan --locked"
    install_rust_tool "x8" "cargo install x8 --locked"
    install_rust_tool "rcat" "cargo install rustcat --locked"
    install_rust_tool "rusthound-ce" "cargo install rusthound-ce --locked"

    # FeroxBuster
    if [[ ! -f "/usr/local/bin/feroxbuster" ]]; then
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash >/dev/null 2>&1
        [[ -f "$HOME/.cargo/bin/feroxbuster" ]] && cp "$HOME/.cargo/bin/feroxbuster" "/usr/local/bin/feroxbuster"
        print_success "Installed: FeroxBuster"
    fi

    # Permanent PATH setup
    grep -q "\.cargo/bin" "$HOME/.bashrc" || echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$HOME/.bashrc"
}

install_rust_tool() {
    local tool=$1 cmd=$2
    if [[ -f "/usr/local/bin/$tool" ]]; then
        return
    fi
    if eval "$cmd" >/dev/null 2>&1; then
        [[ -f "$HOME/.cargo/bin/$tool" ]] && cp "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool"
        print_success "Installed: $tool"
    else
        # Try without --locked flag
        if eval "${cmd//--locked/}" >/dev/null 2>&1; then
            [[ -f "$HOME/.cargo/bin/$tool" ]] && cp "$HOME/.cargo/bin/$tool" "/usr/local/bin/$tool"
            print_success "Installed: $tool (without --locked)"
        else
            print_warning "Failed to install: $tool"
        fi
    fi
}

# =============================================================================
# STAGE 5: Additional Tools & Post-Installation
# =============================================================================

install_additional_tools() {
    print_status "Installing additional security tools..."

    # Exploit-DB
    [[ ! -d "/opt/exploit-database" ]] && {
        git clone -q https://gitlab.com/exploit-database/exploitdb.git /opt/exploit-database
        ln -sf /opt/exploit-database/searchsploit /usr/local/bin/searchsploit
        print_success "Installed: Exploit-DB"
    }

    # RPCClient
    if ! command -v rpcclient >/dev/null 2>&1; then
        apt install -y samba-common-bin smbclient >/dev/null 2>&1
        print_success "Installed: Samba tools (rpcclient)"
    fi
}

# =============================================================================
# STAGE 6: Pentest Tools Download Section
# =============================================================================

download_pentest_tools() {
    print_status "Downloading additional pentest tools..."

    TOOLS_DIR="/opt/pentest-tools"
    LINUX_DIR="$TOOLS_DIR/linux"
    WINDOWS_DIR="$TOOLS_DIR/windows"
    MISC_DIR="$TOOLS_DIR/misc"

    mkdir -p "$LINUX_DIR" "$WINDOWS_DIR" "$MISC_DIR"

    # Enhanced download functions with silent operation
    download_executable() {
        if [[ ! -f "$2" ]]; then
            printf "${PURPLE}Downloading $(basename "$2")...${NC}\n"
            curl -s -L -o "$2" "$1"
            chmod +x "$2"
        fi
    }

    download_file() {
        if [[ ! -f "$2" ]]; then
            printf "${PURPLE}Downloading $(basename "$2")...${NC}\n"
            curl -s -L -o "$2" "$1"
        fi
    }

    download_and_extract() {
        local target_dir="$2"
        local archive_name="$3"
        
        if [[ ! -d "$target_dir" ]]; then
            printf "${PURPLE}Downloading and extracting $archive_name...${NC}\n"
            curl -s -L -o temp.archive "$1"
            mkdir -p "$target_dir"
            if [[ "$1" == *.tar.gz ]]; then
                tar -xzf temp.archive -C "$target_dir" --strip-components=1
            elif [[ "$1" == *.zip ]]; then
                unzip -qq temp.archive -d "$target_dir"
            fi
            rm -f temp.archive
        fi
    }

    clone_repo() {
        if [[ ! -d "$2" ]]; then
            printf "${PURPLE}Cloning $(basename "$2")...${NC}\n"
            git clone --quiet "$1" "$2"
        fi
    }

    download_linux_tools() {
        print_info "Downloading Linux tools..."
        cd "$LINUX_DIR"

        download_executable "https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh" "LinEnum.sh"
        download_executable "https://raw.githubusercontent.com/redcode-labs/Bashark/refs/heads/master/bashark.sh" "bashark.sh"
        download_executable "https://raw.githubusercontent.com/urbanadventurer/username-anarchy/refs/heads/master/username-anarchy" "username-anarchy"
        download_executable "https://raw.githubusercontent.com/sosdave/KeyTabExtract/refs/heads/master/keytabextract.py" "keytabextract.py"
        download_executable "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh" "linux-exploit-suggester.sh"
        download_executable "https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl" "linux-exploit-suggester-2.pl"
        download_executable "https://raw.githubusercontent.com/enjoiz/XXEinjector/refs/heads/master/XXEinjector.rb" "XXEinjector.rb"
        ln -sf "$LINUX_DIR/XXEinjector.rb" "/usr/local/bin/XXEinjector" 2>/dev/null || true
        
        download_executable "https://raw.githubusercontent.com/Pwnistry/Windows-Exploit-Suggester-python3/refs/heads/master/windows-exploit-suggester.py" "windows-exploit-suggester.py"
        download_executable "https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64" "pspy64"
        download_executable "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" "linpeas.sh"
        
        if [[ ! -f "chisel-linux" ]]; then
            download_file "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_linux_amd64.gz" "chisel-linux.gz"
            gunzip -f chisel-linux.gz && chmod +x chisel-linux
        fi

        download_and_extract "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz" "ligolo" "ligolo-ng"
        if [[ -d "ligolo" ]]; then
            rm -rf ligolo/LICENSE ligolo/README.md
            [[ -f "ligolo/proxy" ]] && mv ligolo/proxy ligolo/ligolo-proxy && chmod +x ligolo/ligolo-proxy
        fi

        download_and_extract "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz" "ligolo" "ligolo-ng agent"
        if [[ -d "ligolo" ]]; then
            rm -rf ligolo/LICENSE ligolo/README.md
            [[ -f "ligolo/agent" ]] && mv ligolo/agent ligolo/ligolo-agent && chmod +x ligolo/ligolo-agent
        fi

        if [[ ! -f "kr" ]]; then
            download_and_extract "https://github.com/assetnote/kiterrunner/releases/download/v1.0.2/kiterrunner_1.0.2_linux_amd64.tar.gz" "." "kiterrunner"
            chmod +x kr 2>/dev/null || true
            ln -sf "$LINUX_DIR/kr" "/usr/local/bin/kr" 2>/dev/null || true
        fi
        
        download_and_extract "https://github.com/huntergregal/mimipenguin/releases/download/2.0-release/mimipenguin_2.0-release.tar.gz" "mimipenguin" "mimipenguin"
        if [[ -d "mimipenguin" ]]; then
            chmod +x mimipenguin/mimipenguin.py 2>/dev/null || true
        fi
        
        clone_repo "https://github.com/JlSakuya/Linux-Privilege-Escalation-Exploits.git" "Linux-Privilege-Escalation-Exploits"
        clone_repo "https://github.com/TH3xACE/SUDO_KILLER.git" "SUDO_KILLER"
        clone_repo "https://github.com/klsecservices/rpivot.git" "rpivot"

        print_success "Linux tools download complete"
    }

    download_windows_tools() {
        print_info "Downloading Windows tools..."
        cd "$WINDOWS_DIR"

        download_file "https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1" "jaws-enum.ps1"
        download_file "https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1" "Sherlock.ps1"
        download_file "https://raw.githubusercontent.com/adrecon/ADRecon/refs/heads/master/ADRecon.ps1" "ADRecon.ps1"
        download_file "https://raw.githubusercontent.com/leoloobeek/LAPSToolkit/refs/heads/master/LAPSToolkit.ps1" "LAPSToolkit.ps1"
        download_file "https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/refs/heads/master/dnscat2.ps1" "dnscat2.ps1"
        download_file "https://raw.githubusercontent.com/dafthack/DomainPasswordSpray/refs/heads/master/DomainPasswordSpray.ps1" "DomainPasswordSpray.ps1"
        download_file "https://raw.githubusercontent.com/danielbohannon/Invoke-DOSfuscation/refs/heads/master/Invoke-DOSfuscation.psd1" "Invoke-DOSfuscation.psd1"
        
        download_executable "https://raw.githubusercontent.com/ShutdownRepo/targetedKerberoast/refs/heads/main/targetedKerberoast.py" "targetedKerberoast.py"
        ln -sf "$WINDOWS_DIR/targetedKerberoast.py" "/usr/local/bin/targetedKerberoast" 2>/dev/null || true
        
        download_file "https://github.com/AlessandroZ/LaZagne/releases/download/v2.4.7/LaZagne.exe" "LaZagne.exe"
        download_file "https://github.com/SnaffCon/Snaffler/releases/download/1.0.212/Snaffler.exe" "Snaffler.exe"
        download_file "https://github.com/klsecservices/rpivot/releases/download/v1.0/client.exe" "rpivot-client.exe"
        download_file "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe" "winPEASany.exe"
        download_file "https://github.com/tevora-threat/SharpView/raw/refs/heads/master/Compiled/SharpView.exe" "SharpView.exe"
        
        if [[ ! -f "chisel-windows.exe" ]]; then
            download_file "https://github.com/jpillora/chisel/releases/download/v1.10.1/chisel_1.10.1_windows_amd64.gz" "chisel-windows.gz"
            gunzip -f chisel-windows.gz && mv chisel-windows chisel-windows.exe
        fi
        
        if [[ ! -f "ligolo-agent.exe" ]]; then
            download_file "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_windows_amd64.zip" "ligolo-agent.zip"
            unzip -qq -o ligolo-agent.zip && rm -f ligolo-agent.zip LICENSE README.md
            [[ -f "agent.exe" ]] && mv agent.exe ligolo-agent.exe
        fi
        
        download_and_extract "https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip" "RunasCs" "RunasCs"

        download_and_extract "https://github.com/Kevin-Robertson/Inveigh/releases/download/v2.0.11/Inveigh-net8.0-win-x64-trimmed-single-v2.0.11.zip" "inveigh" "Inveigh"
        download_file "https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/refs/heads/master/Inveigh.ps1" "inveigh/Inveigh.ps1"

        mkdir -p socat
        download_file "https://github.com/3ndG4me/socat/releases/download/v1.7.3.3/socatx64.exe" "socat/socatx64.exe"
        download_file "https://github.com/3ndG4me/socat/releases/download/v1.7.3.3/socatx86.exe" "socat/socatx86.exe"

        mkdir -p uacme
        download_file "https://github.com/yuyudhn/UACME-bin/raw/refs/heads/main/Akagi32.exe" "uacme/Akagi32.exe"
        download_file "https://github.com/yuyudhn/UACME-bin/raw/refs/heads/main/Akagi64.exe" "uacme/Akagi64.exe"

        clone_repo "https://github.com/dirkjanm/PKINITtools.git" "PKINITtools"
        clone_repo "https://github.com/davehardy20/sysinternals.git" "sysinternals"

        print_success "Windows tools download complete"
    }

    download_misc_tools() {
        print_info "Downloading miscellaneous tools..."

        # BloodHound CE Docker Compose
        mkdir -p /opt/bloodhoundce
        download_file "https://raw.githubusercontent.com/SpecterOps/BloodHound/main/examples/docker-compose/docker-compose.yml" "/opt/bloodhoundce/bloodhound-docker-compose.yml"
        
        # Network and tunneling tools
        clone_repo "https://github.com/iagox86/dnscat2.git" "$MISC_DIR/dnscat2"
        clone_repo "https://github.com/utoni/ptunnel-ng.git" "$MISC_DIR/ptunnel-ng"
        clone_repo "https://github.com/nccgroup/SocksOverRDP.git" "$MISC_DIR/SocksOverRDP"
        
        # OSINT and reconnaissance
        clone_repo "https://github.com/sm00v/Dehashed.git" "Dehashed"
        

        print_success "Miscellaneous tools download complete"
    }

    create_symlinks() {
        print_info "Creating symlinks in /usr/local/bin..."
        
        # ln -sf "$LINUX_DIR/linpeas.sh" "/usr/local/bin/linpeas" 2>/dev/null || true
        
        print_success "Symlinks creation completed"
    }

    # Main execution for pentest tools
    case "$1" in
        linux) 
            download_linux_tools
            create_symlinks
            ;;
        windows) 
            download_windows_tools
            ;;
        misc) 
            download_misc_tools
            ;;
        *)
            download_linux_tools
            download_windows_tools
            download_misc_tools
            create_symlinks
            ;;
    esac

    print_success "Tools downloaded to: $TOOLS_DIR"
    print_info "  - Linux tools: $LINUX_DIR"
    print_info "  - Windows tools: $WINDOWS_DIR"
    print_info "  - Miscellaneous tools: $MISC_DIR"
}

# =============================================================================
# MAIN EXECUTION FLOW
# =============================================================================

main() {
    show_banner
    check_privileges "$@"
    prepare_system

    print_status "Starting comprehensive tool installation..."
    
    # Stage 1: System Packages
    print_info "STAGE 1: Installing system packages..."
    install_apt_packages

    # Stage 2: Custom Scripts & Environments
    print_info "STAGE 2: Setting up custom scripts and environments..."
    install_custom_scripts
    setup_nodejs

    # Stage 3: Programming Languages & Tools
    print_info "STAGE 3: Installing language-specific tools..."
    setup_golang
    install_go_tools
    install_python_tools

    # Stage 4: Specialized Frameworks
    print_info "STAGE 4: Installing specialized frameworks..."
    install_ruby_tools
    install_compiled_tools
    setup_rust_environment

    # Stage 5: Additional Tools
    print_info "STAGE 5: Installing additional tools..."
    install_additional_tools

    # Stage 6: Download Pentest Tools
    print_info "STAGE 6: Downloading pentest tools..."
    download_pentest_tools

    # Completion Message
    print_success "Hackify installation completed successfully!"
    printf "\n${YELLOW}Recommendations:${NC}\n"
    printf "  • Run this script multiple times for complete installation\n"
    printf "  • Restart your terminal or run: ${GREEN}source ~/.bashrc${NC}\n"
    printf "  • Check individual tools with: ${GREEN}tool_name --help${NC}\n"
    printf "  • Pentest tools are available in: ${GREEN}/opt/pentest-tools/${NC}\n"
    printf "\n${GREEN}Happy Hacking! 🚀${NC}\n\n"
}

# Execute main function
main "$@"
