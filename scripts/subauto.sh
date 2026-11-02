#!/bin/bash

# ============================================
# Subdomain Enumeration - Final Solid Version
# - subs.txt : DNS-live subdomains only
# - urls.txt : HTTP-live URLs (any status, HTTPS preferred)
# - ips.txt  : IPv4 A records
# - dns_records.txt : A/AAAA/CNAME
# - takeover.json   : subzy results (optional)
# ============================================

if [[ $# -eq 0 ]]; then
    echo "[-] Domain not supplied [-]"
    echo "[+] Example: >_ $0 domain.com [+]"
    exit 1
fi

if [[ $# -gt 1 ]]; then
    echo "[-] Unnecessary Arguments [-]"
    exit 1
fi

D="${1,,}"
regex='^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
if ! [[ "$D" =~ $regex ]]; then
    echo "[-] Argument is not a domain. [-]"
    exit 1
fi

OUT="${D}_enum"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# Persistent resolver cache
CACHE_DIR="$HOME/.cache/subdomain-enum/${D}"
mkdir -p "$CACHE_DIR"
RESOLVERS="$CACHE_DIR/resolvers.txt"

# SecLists wordlist (try common paths)
WORDLIST=""
for p in \
    "/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt" \
    "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt"; do
    if [[ -f "$p" ]]; then WORDLIST="$p"; break; fi
done
if [[ -z "$WORDLIST" ]]; then
    echo "[-] SecLists subdomains wordlist not found."
    exit 1
fi

mkdir -p "$OUT"
: > "$OUT/subs.txt"
: > "$OUT/urls.txt"
: > "$OUT/ips.txt"
: > "$OUT/dns_records.txt"
: > "$OUT/takeover.json"

echo "[+]------ Starting Subdomain Enumeration ------[+]"
echo "[+] Target: $D"
echo "[+] Output: $OUT/"
echo "[+] Wordlist: $WORDLIST"

DOMAIN_RE="^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)*${D//./\\.}$"

# ---------- 1. Subfinder ----------
echo "[+] Running Subfinder [+]"
touch "$WORKDIR/subfinder.txt"
if command -v subfinder >/dev/null 2>&1; then
    subfinder -silent -d "$D" -all -o "$WORKDIR/subfinder.txt" >/dev/null 2>&1
    echo "    Found: $(wc -l < "$WORKDIR/subfinder.txt")"
else
    echo "    [!] subfinder not found"
fi

# ---------- 2. crt.sh (retry + JSON validation) ----------
echo "[+] Querying crt.sh [+]"
touch "$WORKDIR/crtsh.txt"
for attempt in 1 2 3; do
    resp=$(curl -fsS --max-time 120 -H 'Accept: application/json' \
        "https://crt.sh/?q=%25.${D}&output=json" 2>/dev/null || true)
    if printf '%s' "$resp" | jq -e 'type == "array"' >/dev/null 2>&1; then
        printf '%s' "$resp" | jq -r '.[].name_value' 2>/dev/null \
            | tr ',' '\n' | sed 's/^\*\.//' | tr 'A-Z' 'a-z' | tr -d '\r' \
            | grep -E "$DOMAIN_RE" | sort -u > "$WORKDIR/crtsh.txt"
        break
    fi
    echo "    attempt $attempt failed, retrying..."
    sleep 5
done
echo "    Found: $(wc -l < "$WORKDIR/crtsh.txt")"

# ---------- 3. Wayback ----------
echo "[+] Querying Wayback Machine [+]"
touch "$WORKDIR/wayback.txt"
curl -fsS --max-time 180 \
    "https://web.archive.org/cdx/search/cdx?url=*.${D}/*&fl=original&collapse=urlkey&limit=50000" \
    | sed -E 's#https?://##' | cut -d'/' -f1 | tr 'A-Z' 'a-z' | tr -d '\r' \
    | grep -E "$DOMAIN_RE" | sort -u > "$WORKDIR/wayback.txt" 2>/dev/null || true
echo "    Found: $(wc -l < "$WORKDIR/wayback.txt")"

# ---------- 4. Amass ----------
AMASS_TIMEOUT="${AMASS_TIMEOUT:-30}"
echo "[+] Running Amass (timeout: ${AMASS_TIMEOUT}m) [+]"
touch "$WORKDIR/amass.txt"
if command -v amass >/dev/null 2>&1; then
    amass enum -active -brute -min-for-recursive 1 -timeout "$AMASS_TIMEOUT" \
        -d "$D" -o "$WORKDIR/amass.txt" \
        -r 8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1 >/dev/null 2>&1
else
    echo "    [!] amass not found, skipping"
fi
echo "    Found: $(wc -l < "$WORKDIR/amass.txt")"

# ---------- 5. Combine passive ----------
echo "[+] Combining passive results [+]"
cat "$WORKDIR/subfinder.txt" "$WORKDIR/crtsh.txt" \
    "$WORKDIR/wayback.txt" "$WORKDIR/amass.txt" 2>/dev/null \
    | tr -d '\r' | tr 'A-Z' 'a-z' | grep -E "$DOMAIN_RE" | sort -u > "$WORKDIR/all_passive.txt"
echo "    Unique: $(wc -l < "$WORKDIR/all_passive.txt")"

# ---------- 6. Resolvers ----------
RESOLVERS_READY=0
if [[ -s "$RESOLVERS" ]]; then
    echo "[+] Using cached resolvers: $RESOLVERS"
    RESOLVERS_READY=1
else
    echo "[+] Downloading resolvers -> $RESOLVERS"
    if curl -fsS --max-time 60 "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" -o "$RESOLVERS" \
        && [[ -s "$RESOLVERS" ]]; then
        RESOLVERS_READY=1
    else
        printf '8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n' > "$RESOLVERS"
        RESOLVERS_READY=1
    fi
fi

# ---------- 7. puredns brute-force ----------
BRUTE_FILE="$WORKDIR/bruteforced.txt"
touch "$BRUTE_FILE"
if [[ $RESOLVERS_READY -eq 1 ]] && command -v puredns >/dev/null 2>&1; then
    echo "[+] puredns brute-force [+]"
    puredns bruteforce "$WORDLIST" "$D" -r "$RESOLVERS" --rate-limit 500 -q \
        > "$BRUTE_FILE" 2>/dev/null
    echo "    Found: $(wc -l < "$BRUTE_FILE")"
else
    echo "    [!] puredns/resolvers unavailable, skipping"
fi

# ---------- 8. AlterX permutations ----------
PERM_FILE="$WORKDIR/permuted.txt"
touch "$PERM_FILE"
{ cat "$WORKDIR/all_passive.txt" 2>/dev/null; cat "$BRUTE_FILE" 2>/dev/null; } | sort -u > "$WORKDIR/seed.txt"
if command -v alterx >/dev/null 2>&1 && [[ -s "$WORKDIR/seed.txt" ]]; then
    echo "[+] Generating AlterX permutations [+]"
    alterx -list "$WORKDIR/seed.txt" -silent -o "$PERM_FILE" 2>/dev/null
    echo "    Generated: $(wc -l < "$PERM_FILE")"
fi

# ---------- 9. Resolve permutations ----------
RESOLVED_FILE="$WORKDIR/resolved_permutations.txt"
touch "$RESOLVED_FILE"
if [[ $RESOLVERS_READY -eq 1 ]] && [[ -s "$PERM_FILE" ]] && command -v puredns >/dev/null 2>&1; then
    echo "[+] Resolving permutations [+]"
    puredns resolve "$PERM_FILE" -r "$RESOLVERS" --rate-limit 500 -q \
        > "$RESOLVED_FILE" 2>/dev/null
    echo "    Resolved: $(wc -l < "$RESOLVED_FILE")"
fi

# ---------- 10. Candidate list ----------
echo "[+] Building candidate list [+]"
{
    printf '%s\n' "$D"
    cat "$WORKDIR/all_passive.txt" 2>/dev/null
    cat "$BRUTE_FILE" 2>/dev/null
    cat "$RESOLVED_FILE" 2>/dev/null
} | tr -d '\r' | sed '/^$/d' | grep -E "$DOMAIN_RE" | sort -u > "$WORKDIR/candidates.txt"
echo "    Candidates: $(wc -l < "$WORKDIR/candidates.txt")"

# ---------- 11. DNS-live filter (subs.txt = only resolving hosts) ----------
echo "[+] Filtering to DNS-live subdomains [+]"
: > "$OUT/subs.txt"
: > "$OUT/dns_records.txt"
: > "$OUT/ips.txt"

if command -v dnsx >/dev/null 2>&1 && [[ -s "$WORKDIR/candidates.txt" ]]; then
    dnsx -l "$WORKDIR/candidates.txt" -a -aaaa -cname -resp -wd "$D" -silent \
        -o "$OUT/dns_records.txt" 2>/dev/null

    awk '{print $1}' "$OUT/dns_records.txt" | sort -u > "$OUT/subs.txt"

    dnsx -l "$OUT/subs.txt" -a -resp-only -silent 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -u > "$OUT/ips.txt"

    echo "    DNS-live subdomains: $(wc -l < "$OUT/subs.txt")"
    echo "    DNS records: $(wc -l < "$OUT/dns_records.txt"), IPv4s: $(wc -l < "$OUT/ips.txt")"
else
    echo "    [!] dnsx not found, falling back to dig"
    while read -r dom; do
        if dig +short +time=4 +tries=2 A "$dom" 2>/dev/null | grep -qE '^[0-9]+\.'; then
            echo "$dom"
        fi
    done < "$WORKDIR/candidates.txt" | sort -u > "$OUT/subs.txt"

    while read -r dom; do
        dig +short +time=4 +tries=2 A "$dom" 2>/dev/null
    done < "$OUT/subs.txt" \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -u > "$OUT/ips.txt"
    echo "    DNS-live subdomains (dig fallback): $(wc -l < "$OUT/subs.txt")"
fi

# ---------- 12. httpx (HTTP-live, any status, HTTPS-preferred) ----------
echo "[+] Probing with httpx [+]"
RAW_URLS="$WORKDIR/httpx_raw.txt"
touch "$RAW_URLS"

if command -v httpx >/dev/null 2>&1 && [[ -s "$OUT/subs.txt" ]]; then
    httpx -l "$OUT/subs.txt" -silent -no-color \
        -ports 80,443,8080,8443,8000,8888,3000,4000,5000,9000 \
        -nf \
        -mc 100-599 \
        -o "$RAW_URLS"

    awk '
        {
            url = $0
            key = url
            sub(/^https?:\/\//, "", key)
            sub(/\/.*$/, "", key)
            scheme = (url ~ /^https:/) ? "https" : "http"
            if (!(key in chosen) || scheme == "https")
                chosen[key] = url
        }
        END {
            for (k in chosen) print chosen[k]
        }
    ' "$RAW_URLS" | sort -u > "$OUT/urls.txt"

    echo "    HTTP-live URLs: $(wc -l < "$OUT/urls.txt")"
else
    echo "    [!] httpx not found or no DNS-live subs"
fi

# ---------- 13. subzy (optional) ----------
if command -v subzy >/dev/null 2>&1 && [[ -s "$OUT/subs.txt" ]]; then
    echo "[+] Running subzy takeover detection [+]"
    subzy run --targets "$OUT/subs.txt" --hide_fails --output "$OUT/takeover.json" >/dev/null 2>&1
    echo "    Takeover results: $OUT/takeover.json"
else
    echo "[!] subzy not found, skipping takeover detection"
fi

# ---------- Done ----------
echo "[+] Done"
echo "    Subdomains (DNS-live): $OUT/subs.txt ($(wc -l < "$OUT/subs.txt"))"
echo "    URLs (HTTP-live)     : $OUT/urls.txt ($(wc -l < "$OUT/urls.txt"))"
echo "    IPs                  : $OUT/ips.txt ($(wc -l < "$OUT/ips.txt"))"
echo "    DNS records          : $OUT/dns_records.txt"
[[ -s "$OUT/takeover.json" ]] && echo "    Takeover             : $OUT/takeover.json"
