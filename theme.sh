











# Terminal Eyecare Theme

p=$$; while [ $p -gt 1 ]; do t=$(ps -o comm= -p $p); if [[ "$t" =~ (gnome-terminal|mate-terminal|xfce4-terminal|qterminal|kitty|alacritty) ]]; then break; fi; p=$(ps -o ppid= -p $p | tr -d " "); done; echo "[*] Detected: $t"; F="JetBrains Mono"; fc-list | grep -qi "$F" || (echo "[+] Installing $F..." && sudo apt-get update && sudo apt-get install -y fonts-jetbrains-mono); if [[ "$t" == *"gnome-terminal"* ]]; then d=$(gsettings get org.gnome.Terminal.ProfilesList default | tr -d "'"); gsettings set org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles/:$d/ use-theme-colors false; gsettings set org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles/:$d/ background-color "'#282828'"; gsettings set org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles/:$d/ foreground-color "'#EBDBB2'"; gsettings set org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles/:$d/ use-system-font false; gsettings set org.gnome.Terminal.Legacy.Profile:/org/gnome/terminal/legacy/profiles/:$d/ font "'$F 14'"; elif [[ "$t" == *"mate-terminal"* ]]; then d=$(gsettings get org.mate.terminal.global default-profile | tr -d "'"); gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/$d/ use-theme-colors false; gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/$d/ background-color "'#282828'"; gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/$d/ foreground-color "'#EBDBB2'"; gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/$d/ use-system-font false; gsettings set org.mate.terminal.profile:/org/mate/terminal/profiles/$d/ font "'$F 14'"; elif [[ "$t" == *"xfce4-terminal"* ]]; then xfconf-query -c xfce4-terminal -p /color-use-theme -s false --create -t bool; xfconf-query -c xfce4-terminal -p /color-background -s "#282828" --create -t string; xfconf-query -c xfce4-terminal -p /color-foreground -s "#EBDBB2" --create -t string; xfconf-query -c xfce4-terminal -p /font-name -s "$F 14" --create -t string; elif [[ "$t" == *"qterminal"* ]]; then sed -i "/fontFamily/d; /fontSize/d; /colorScheme/d" ~/.config/qterminal.org/qterminal.ini 2>/dev/null; printf "\n[General]\nfontFamily=$F\nfontSize=14\n" >> ~/.config/qterminal.org/qterminal.ini; fi; echo "[✔] Eye-care settings applied."





