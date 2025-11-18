#!/bin/bash

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly DOMAIN_REGEX='^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

# Dependency check
check_dependencies() {
    local deps=("subfinder" "assetfinder" "amass" "httprobe" "subzy" "dig")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        log_info "Please install missing tools before running this script"
        exit 1
    fi
}

# Input validation
validate_input() {
    if [[ $# -eq 0 ]]; then
        log_error "Domain not supplied"
        show_usage
        exit 1
    fi

    if [[ $# -gt 1 ]]; then
        log_error "Too many arguments provided"
        show_usage
        exit 1
    fi

    if ! [[ $1 =~ $DOMAIN_REGEX ]]; then
        log_error "Invalid domain format: $1"
        show_usage
        exit 1
    fi
}

show_usage() {
    cat << EOF
# Script: Advanced Subdomain Enumeration
# Author: Zishan Ahamed Thandar
# Website: https://ZishanAdThandar.GitHub.io/linktree
# Description: Comprehensive subdomain discovery and analysis tool

Usage: $0 <domain>
Example: $0 example.com

Required Tools:
  - subfinder    : Fast passive subdomain enumeration
  - assetfinder  : Find domains and subdomains potentially related to a target
  - amass        : In-depth attack surface mapping and asset discovery
  - httprobe     : Take a list of domains and probe for working HTTP and HTTPS servers
  - subzy        : Subdomain takeover vulnerability detector
  - dig          : DNS lookup utility

Output Files:
  - <domain>_subs.txt     : Final list of unique subdomains
  - <domain>_https.txt    : Active HTTP/HTTPS subdomains
  - <domain>_ips.txt      : Resolved IP addresses
  - <domain>_Takeover.txt : Subdomain takeover results
EOF
}

# Initialize workspace - FIXED
setup_workspace() {
    local domain=$1
    # Use current directory or home directory instead of /usr/local/bin/
    if [[ -w "." ]]; then
        readonly WORK_DIR="$(pwd)"
    else
        readonly WORK_DIR="${HOME}/subdomain_scan"
        mkdir -p "$WORK_DIR"
    fi
    
    cd "$WORK_DIR"
    
    log_info "Created workspace: $WORK_DIR"
}

# Run subdomain discovery tools - FIXED file creation
run_subdomain_discovery() {
    local domain=$1
    
    log_info "Starting subdomain enumeration for: $domain"
    
    # Run tools in parallel for better performance
    log_info "Running subfinder, assetfinder, and amass..."
    
    local subfinder_out="${domain}_subfinder.txt"
    local assetfinder_out="${domain}_assetfinder.txt" 
    local amass_out="${domain}_amass.txt"
    
    # Check if we can write to current directory
    if ! touch "${domain}_test.txt" 2>/dev/null; then
        log_error "Cannot write to directory: $WORK_DIR"
        log_error "Please run in a directory where you have write permissions"
        exit 1
    fi
    rm -f "${domain}_test.txt"
    
    (
        if subfinder -silent -d "$domain" -all -o "$subfinder_out" >/dev/null 2>&1; then
            log_success "Subfinder completed: $(wc -l < "$subfinder_out" 2>/dev/null || echo 0) subdomains"
        else
            log_warning "Subfinder failed or found no results"
            touch "$subfinder_out"
        fi
    ) &
    
    (
        if assetfinder "$domain" > "$assetfinder_out" 2>/dev/null; then
            log_success "Assetfinder completed: $(wc -l < "$assetfinder_out" 2>/dev/null || echo 0) subdomains"
        else
            log_warning "Assetfinder failed or found no results"
            touch "$assetfinder_out"
        fi
    ) &
    
    (
        if amass enum -active -timeout 5 -brute -min-for-recursive 2 \
                  -max-dns-queries 500 -d "$domain" -o "$amass_out" \
                  -r 8.8.8.8,1.1.1.1,8.8.4.4,1.0.0.1 >/dev/null 2>&1; then
            log_success "Amass completed: $(wc -l < "$amass_out" 2>/dev/null || echo 0) subdomains"
        else
            log_warning "Amass failed or found no results"
            touch "$amass_out"
        fi
    ) &
    
    wait  # Wait for all background jobs to complete
}

# Process and combine results - FIXED file handling
process_results() {
    local domain=$1
    
    log_info "Combining and deduplicating results..."
    
    local combined="${domain}_combined.txt"
    local unique="${domain}_subdomains.txt"
    
    # Create combined file safely
    touch "$combined"
    for file in "${domain}"_*finder.txt "${domain}_amass.txt"; do
        if [[ -f "$file" && -s "$file" ]]; then
            cat "$file" >> "$combined" 2>/dev/null || true
        fi
    done
    
    if [[ ! -s "$combined" ]]; then
        log_error "No subdomains found. Please check your input and tools."
        exit 1
    fi
    
    # Advanced deduplication and sorting
    sort -u "$combined" | \
    awk '{
        # Convert to lowercase and remove http(s)://
        gsub(/^https?:\/\//, "", $0);
        sub(/\/$/, "", $0);  # Remove trailing slashes
        print $0
    }' | \
    sort -u > "$unique"
    
    local total_count=$(wc -l < "$unique" 2>/dev/null || echo 0)
    if [[ $total_count -gt 0 ]]; then
        log_success "Found $total_count unique subdomains"
    else
        log_error "No valid subdomains found after processing"
        exit 1
    fi
}

# Find active HTTP/HTTPS services
find_active_services() {
    local domain=$1
    local subdomains_file="${domain}_subdomains.txt"
    
    log_info "Probing for active HTTP/HTTPS services..."
    
    local httprobe_out="${domain}_httprobe.txt"
    local active_https="${domain}_https.txt"
    local final_subs="${domain}_subs.txt"
    
    if [[ ! -s "$subdomains_file" ]]; then
        log_warning "No subdomains to probe"
        touch "$active_https" "$final_subs"
        return
    fi
    
    # Probe with timeout and parallel processing
    cat "$subdomains_file" | \
    xargs -P 10 -I {} timeout 5s httprobe -c 50 {} 2>/dev/null > "$httprobe_out" || true
    
    if [[ ! -s "$httprobe_out" ]]; then
        log_warning "No active HTTP/HTTPS services found"
        touch "$active_https" "$final_subs"
        return
    fi
    
    # Process results - prefer HTTPS over HTTP
    awk '{
        sub(/^https?:\/\//, "", $0);
        hosts[$0]++
    } END {
        for (host in hosts) {
            print "https://" host  # Always prefer HTTPS
        }
    }' "$httprobe_out" | sort -u > "$active_https"
    
    # Create clean subdomain list
    sed 's|^https://||' "$active_https" | sort -u > "$final_subs"
    
    local active_count=$(wc -l < "$active_https" 2>/dev/null || echo 0)
    log_success "Found $active_count active services"
}

# Resolve IP addresses
resolve_ips() {
    local domain=$1
    local subs_file="${domain}_subs.txt"
    local ips_file="${domain}_ips.txt"
    
    log_info "Resolving IP addresses..."
    
    if [[ ! -s "$subs_file" ]]; then
        log_warning "No subdomains to resolve"
        touch "$ips_file"
        return
    fi
    
    # Parallel DNS resolution with timeout
    cat "$subs_file" | \
    xargs -P 20 -I {} sh -c \
        'ip=$(dig +timeout=3 +short "$1" 2>/dev/null | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$" | head -1); [ -n "$ip" ] && echo "$ip"' _ {} | \
    sort -u > "$ips_file"
    
    local ip_count=$(wc -l < "$ips_file" 2>/dev/null || echo 0)
    log_success "Resolved $ip_count unique IP addresses"
}

# Check for subdomain takeovers
check_takeovers() {
    local domain=$1
    local subs_file="${domain}_subs.txt"
    local takeover_file="${domain}_Takeover.txt"
    
    log_info "Checking for subdomain takeovers..."
    
    if [[ ! -s "$subs_file" ]]; then
        log_warning "No subdomains to check for takeover"
        return
    fi
    
    # Run subzy with comprehensive output
    subzy run --targets "$subs_file" --hide_fails --output "$takeover_file" 2>/dev/null || true
    
    if [[ -s "$takeover_file" ]]; then
        local vuln_count=$(grep -c "VULNERABLE\|Vulnerable" "$takeover_file" 2>/dev/null || echo 0)
        if [[ $vuln_count -gt 0 ]]; then
            log_warning "Found $vuln_count potential subdomain takeovers!"
        else
            log_success "No subdomain takeovers detected"
        fi
    else
        log_info "Subdomain takeover check completed - no results to report"
    fi
}

# Generate summary report
generate_report() {
    local domain=$1
    
    log_info "Generating summary report..."
    
    local report_file="${domain}_report_${TIMESTAMP}.txt"
    
    cat > "$report_file" << EOF
Subdomain Enumeration Report
============================
Domain: $domain
Scan Date: $(date)
Total Subdomains: $(wc -l < "${domain}_subs.txt" 2>/dev/null || echo 0)
Active Services: $(wc -l < "${domain}_https.txt" 2>/dev/null || echo 0)
Unique IPs: $(wc -l < "${domain}_ips.txt" 2>/dev/null || echo 0)

Output Files:
- Subdomains: ${domain}_subs.txt
- Active Services: ${domain}_https.txt  
- IP Addresses: ${domain}_ips.txt
- Takeover Results: ${domain}_Takeover.txt

Tools Used:
- Subfinder, Assetfinder, Amass, httprobe, subzy

Note: Always verify results manually and follow responsible disclosure practices.
EOF

    log_success "Report generated: $report_file"
}

# Cleanup temporary files
cleanup() {
    local domain=$1
    
    log_info "Cleaning up temporary files..."
    
    # Remove intermediate files, keep only final results
    rm -f "${domain}"_*finder.txt \
          "${domain}_amass.txt" \
          "${domain}_combined.txt" \
          "${domain}_subdomains.txt" \
          "${domain}_httprobe.txt" 2>/dev/null || true
}

main() {
    local domain="${1,,}"  # Convert to lowercase
    
    echo -e "${GREEN}[+]------ Starting Subdomain Enumeration ------[+]${NC}"
    echo -e "${BLUE}[+] https://ZishanAdThandar.GitHub.io/linktree [+]
${NC}"
    
    # Pre-flight checks
    check_dependencies
    validate_input "$domain"
    setup_workspace "$domain"
    
    # Execution pipeline
    run_subdomain_discovery "$domain"
    process_results "$domain"
    find_active_services "$domain"
    resolve_ips "$domain"
    check_takeovers "$domain"
    cleanup "$domain"
    generate_report "$domain"
    
    # Final output
    echo
    log_success "Enumeration completed for: $domain"
    log_info "Results location: $WORK_DIR"
    log_warning "Always manually verify subdomain takeover results:"
    log_info "https://github.com/EdOverflow/can-i-take-over-xyz"
    
    echo
    log_info "Final files:"
    ls -la "${domain}"_*.txt 2>/dev/null | awk '{print " - " $9 " (" $5 " bytes)"}' || log_warning "No output files found"
}

# Script entry point
main "$@"
