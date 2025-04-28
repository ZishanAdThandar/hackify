# Hackify by Zishan Ahamed Thandar

Hackify is an open-source script for Debian-based operating systems, coded in bash. This script streamlines the installation of pentesting wordlists and tools with a single command, making it easier for cybersecurity enthusiasts and professionals to set up their pentesting environment quickly and efficiently.

[![Sponser](https://img.shields.io/github/sponsors/ZishanAdThandar)](https://github.com/sponsors/ZishanAdThandar)
[![ZishanAdThandar's Hackify Repo stars](https://img.shields.io/github/stars/ZishanAdThandar/hackify)](https://github.com/ZishanAdThandar/hackify)
[![License: GPL v3](https://img.shields.io/github/license/ZishanAdThandar/pentest)](https://www.gnu.org/licenses/gpl-3.0)
[![YouTube](https://img.shields.io/youtube/channel/subscribers/UChgqXa2j7ZKkHX2Y76tSxoA)](https://youtube.com/@hackerstation)
![made-with-bash](https://img.shields.io/badge/Made_with-Bash-1f425f.svg)
[![LinkTree](https://img.shields.io/badge/Link-Tree-bbd343)](https://zishanadthandar.github.io/linktree/)

![Banner Hackify](./banner.png)

- [Installation Command (Tools and Wordlist)](#installation-command)
- [Dockers](#dockers)
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
 - install `apt install conky-cli conky-all conky -y`
 - Replace alignment for position and location for weather
 - `~/.conkyrc`, `/etc/conky/conky.conf`, ` ~/.config/conky/conky.conf`
```conf
conky.config = {
    alignment = 'middle_left',
    background = false,
    update_interval = 1,
    double_buffer = true,
    no_buffers = true,
    own_window = true,
    own_window_type = 'desktop',
    own_window_transparent = true,
    own_window_hints = 'undecorated,below,sticky,skip_taskbar,skip_pager',
    draw_shades = false,
    draw_outline = false,
    draw_borders = false,
    draw_graph_borders = false,
    use_xft = true,
    font = 'DejaVu Sans:size=20',
    minimum_width = 300,
    minimum_height = 200,
    gap_x = 10,
    gap_y = 10,
    border_inner_margin = 5,
    border_outer_margin = 5,
    cpu_avg_samples = 2,
    net_avg_samples = 2,
    override_utf8_locale = true,
    default_color = 'FFFFFF', -- white
    color1 = 'FFA500',         -- orange (Clock)
    color2 = '00FFFF',         -- cyan (Weather)
    color3 = '00FF00',         -- lime green (CPU/RAM bars)
    color4 = 'FF69B4',         -- hot pink (IP)
    color5 = 'FF0000',         -- red (Temp warning if needed later)
};

conky.text = [[
${alignc}${font DejaVu Sans:bold:size=48}${color1}${time %H:%M:%S}${color}${font}
${alignc}${font DejaVu Sans:size=20}${color}${time %A, %d %B %Y}${color}${font}

${voffset 10}${alignc}${color4}IP: ${execpi 1800 bash -c 'ip a | grep -q "tun0" && ip -4 addr show tun0 | awk "/inet/ {print \$2}" | cut -d/ -f1 || curl -s ifconfig.me'}${color}

${alignc}${color2}Weather: ${execpi 1800 curl -s 'https://wttr.in/Kolkata?format=1'}${color}

${voffset 20}${color3}${font DejaVu Sans:bold:size=15}CPU: ${cpu}% ${cpubar 8}${color}
${color3}RAM: ${mem} / ${memmax} ${membar 8}${color}

${alignc}${color3}System Temp: ${hwmon 0 temp 1}°C${goto 150}${if_match ${hwmon 0 temp 1} >= 80}${color5}OVERHEAT!${color3}${endif}

${alignc}${voffset 10}${color5}${execpi 10 bash -c '
iface=$(ip route get 1.1.1.1 | awk '\''/dev/{print $5; exit}'\'');
echo "Net: \${upspeed $iface} ⬆️ \${downspeed $iface} ⬇️"
'}${color}
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

