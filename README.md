# Hackify by Zishan Ahamed Thandar

Hackify is an open-source script for Debian-based operating systems, coded in bash. This script streamlines the installation of pentesting wordlists and tools with a single command, making it easier for cybersecurity enthusiasts and professionals to set up their pentesting environment quickly and efficiently.

[![Sponser](https://img.shields.io/github/sponsors/ZishanAdThandar)](https://github.com/sponsors/ZishanAdThandar)
[![ZishanAdThandar's Hackify Repo stars](https://img.shields.io/github/stars/ZishanAdThandar/hackify)](https://github.com/ZishanAdThandar/hackify)
[![LinkTree](https://img.shields.io/badge/Link-Tree-bbd343)](https://zishanadthandar.github.io/linktree/)

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
    - `wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz && tar -xzf ./bloodhound-cli-linux-amd64.tar.gz && rm bloodhound-cli-linux-amd64.tar.gz`
    - `./bloodhound-cli install`
- Ciphey `docker run -it --rm remnux/ciphey`

## Manual Install
- Crypto Graphy: [Ciphey](https://github.com/bee-san/Ciphey), [Katana](https://github.com/JohnHammond/katana) 
- Web: [Arachni](https://github.com/Arachni/arachni/wiki/Installation#linux), Acunetix, BurpSuitePro
- OSINT and Recon: [theHarvester](https://github.com/laramies/theHarvester), [FinalRecon](https://github.com/thewhiteh4t/FinalRecon), [Recon-ng](https://github.com/lanmaster53/recon-ng), [SpiderFoot](https://github.com/smicallef/spiderfoot)
- Reverse: [ghidra](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_11.3.2_build), [radare GUI](https://github.com/radareorg/iaito)
- AD: [bloodhound](https://github.com/SpecterOps/BloodHound), [BaldHead: AD Automate](https://github.com/ahmadallobani/BaldHead)
- Mobile: Android Studio, MobSF, Frida, 

## Firefox Themes
- [CyebrTerminus Theme](https://addons.mozilla.org/en-US/firefox/addon/zishanadthandar-cyberterminus/)
- [MrRobot Theme](https://addons.mozilla.org/en-US/firefox/addon/mrrobothacker/)

## Firefox Addon
- [Burp Suite Proxy Switch](https://addons.mozilla.org/en-US/firefox/addon/burp-proxy-toggler-lite/?utm_source=addons.mozilla.org&utm_medium=referral&utm_content=search)

## Theme (Personal peference)
- Plank Dock
- Dark Background Solid color wallpaper
- add generic monitor `apt install xfce4-genmon-plugin -y` to the panel to get ips with code `sh -c 'ip a | grep -q "tun0" && ip -4 addr show tun0 | awk "/inet/ {print \$2}" | cut -d/ -f1 || curl -s ifconfig.me'`

- Conky Clock
  - Conky install with `apt install conky-all -y` or `apt install conky -y`
  - Replace alignment for position, location for weather of particular area and timezones if you need
  - `~/.conkyrc`, `/etc/conky/conky.conf`, ` ~/.config/conky/conky.conf`
```python
conky.config = {
    alignment = 'middle_right',
    background = false,
    update_interval = 1,
    double_buffer = true,
    no_buffers = true,
    own_window = true,
    own_window_type = 'desktop',
    own_window_transparent = false,
    own_window_argb_visual = true,
    own_window_argb_value = 150,
    own_window_hints = 'undecorated,below,sticky,skip_taskbar,skip_pager', 
    draw_shades = false,
    draw_outline = false,
    draw_borders = false,
    draw_graph_borders = false,
    use_xft = true,
    font = 'dejavu sans:size=11',
    minimum_width = 300,
    minimum_height = 200,
    gap_x = 20,
    gap_y = 20,
    border_inner_margin = 5,
    border_outer_margin = 5,
    cpu_avg_samples = 2,
    net_avg_samples = 2,
    override_utf8_locale = true,
    default_color = '9fef00',
    color1 = '9fef00'
};

conky.text = [[
${alignc}${font Serif:bold:size=25}${color1}${time %H:%M:%S}${font}
${alignc}${time %A, %d %B %Y}

${voffset 10}IP $alignr ${if_existing /sys/class/net/eth0/operstate up}${addr eth0}${else}${if_existing /sys/class/net/wlan0/operstate up}${addr wlan0}${else}${execpi 1800 curl -s ifconfig.me}${endif}${endif}
Weather $alignr ${execpi 1800 curl -ks 'https://wttr.in/Kolkata?format=%C+%t\nAir$alignr%w+\nPressure$alignr+%P\nHumidity$alignr+%h\nMoon+$alignr+%m\nSunrise+$alignr+%S\nSunset+$alignr+%s'}

${font bold:size=9}CPU ${cpu}% ${cpubar 8}
RAM ${mem} / ${memmax} ${membar 8}
${font}
Temp $alignr ${execpi 60 sensors | grep -m 1 'Package id 0:' | awk '{print $4}'}

Memory Stats $alignr RAM       CPU 
${top_mem name 1} $alignr${top_mem cpu 1} % ${top_mem mem 1} %
${top_mem name 2} $alignr${top_mem cpu 2} % ${top_mem mem 2} %
${top_mem name 3} $alignr${top_mem cpu 3} % ${top_mem mem 3} %
${top_mem name 4} $alignr${top_mem cpu 4} % ${top_mem mem 4} %

Location $alignr Time  
Sydney $alignr${execpi 1 TZ="Australia/Sydney" date '+%H:%M:%S'}
Dhaka $alignr${execpi 1 TZ="Asia/Dhaka" date '+%H:%M:%S'}
Islamabad $alignr${execpi 1 TZ="Asia/Karachi" date '+%H:%M:%S'}
Madina $alignr${execpi 1 TZ="Asia/Riyadh" date '+%H:%M:%S'}

${voffset 10}${execpi 10 bash -c '
iface=$(ip route get 1.1.1.1 | awk '\''/dev/{print $5; exit}'\'');
echo "Net \$alignr \${upspeed $iface} ⬆️ \${downspeed $iface} ⬇️"
'}
Uptime $alignr $uptime
${color}
]];

```

---

⚠️ **Warning** Use this tool at your own risk. 

⚠️ **Warning** Misuse of this tool or installed tool can lead to legal complications.


# Be a Sponsor  

1. https://github.com/sponsors/ZishanAdThandar
2. https://ZishanAdThandar.github.io/sponsor/

<!--
1. BTC `bc1q0qhgw5pdys7qqw07rcsyudu5wmv6208nhp5xtn`
2. ETH `0x8cdc24eeb9d1bf46929b2106e3535e0d1953fe1b`
3. ~~USDT (TRC20) `TGW1c7hzyszQNhQHM3aGa1nEKDNuyPueNE`~~ [Invalid]
-->

