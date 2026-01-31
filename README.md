# Hackify by Zishan Ahamed Thandar

Hackify is an open-source script for Debian-based operating systems, coded in bash. This script streamlines the installation of pentesting wordlists and tools with a single command, making it easier for cybersecurity enthusiasts and professionals to set up their pentesting environment quickly and efficiently.

[![ZishanAdThandar's Hackify Repo stars](https://img.shields.io/github/stars/ZishanAdThandar/hackify)](https://github.com/ZishanAdThandar/hackify)
[![LinkTree](https://img.shields.io/badge/Link-Tree-bbd343)](https://zishanhack.com/links)

![Banner Hackify](./banner.png)

- [Installation Command (Tools and Wordlist)](#installation-command)
- [Dockers](#dockers)
- [Manual Install](#manual-install)
- [Firefox Themes](#firefox-themes)
- [Firefox Addon](#firefox-addon)

## Installation Command

```bash
git clone https://github.com/ZishanAdThandar/hackify.git
cd hackify
chmod +x hackify.sh
bash hackify.sh
# To install wordlists
chmod +x wordlist.sh
bash wordlist.sh
```

## Dockers
- [https://hub.docker.com/r/kasmweb/remnux-focal-desktop](https://github.com/ZishanAdThandar/hacknotes/tree/main/RevEng)
- BloodHound
  - Goto the folder `sudo cd /opt/bloodhoundce`
  - pull images `sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml pull`
  - Start Docker `sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml up` # first time tun will give temp password
  - To remove and start over `sudo docker-compose -f /opt/bloodhoundce/docker-compose.yml down`

- Ciphey `docker run -it --rm remnux/ciphey`

## Manual Install
- Crypto Graphy: [Ciphey](https://github.com/bee-san/Ciphey), [Katana](https://github.com/JohnHammond/katana) 
- Web: [Arachni](https://github.com/Arachni/arachni/wiki/Installation#linux), Acunetix, BurpSuitePro
- OSINT and Recon: [theHarvester](https://github.com/laramies/theHarvester), [FinalRecon](https://github.com/thewhiteh4t/FinalRecon), [Recon-ng](https://github.com/lanmaster53/recon-ng), [SpiderFoot](https://github.com/smicallef/spiderfoot)
- Reverse: [ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.3.2_build), [radare GUI](https://github.com/radareorg/iaito)
- AD: [bloodhound](https://github.com/SpecterOps/BloodHound), [BaldHead: AD Automate](https://github.com/ahmadallobani/BaldHead)
- Mobile: Android Studio, MobSF, Frida, 

## Firefox Themes
- [CyberTerminus Theme](https://addons.mozilla.org/en-US/firefox/addon/zishanadthandar-cyberterminus/)
- [MrRobot Theme](https://addons.mozilla.org/en-US/firefox/addon/mrrobothacker/)

## Firefox Addon
- [Burp Suite Proxy Switch](https://addons.mozilla.org/en-US/firefox/addon/burp-proxy-toggler-lite/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search)

## Theme (Personal peference)
- Plank Dock
- Dark Background Solid color wallpaper
- add generic monitor `apt install xfce4-genmon-plugin -y` (for xfce desktop) to the panel to get ips with code `sh -c 'ip a | grep -q "tun0" && ip -4 addr show tun0 | awk "/inet/ {print \$2}" | cut -d/ -f1 || curl -s ifconfig.me'`

- Conky Clock
  - Conky install with `apt install conky-all -y` or `apt install conky -y`
  - Replace alignment for position, location for weather of particular area and timezones if you need
  - `~/.conkyrc`, `/etc/conky/conky.conf`, ` ~/.config/conky/conky.conf`
  - [Sample Conky.conf](configs/conky.conf)

---

⚠️ **Warning** Use this tool at your own risk. 

⚠️ **Warning** Misuse of this tool or installed tool can lead to legal complications.



