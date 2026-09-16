sudo bash -c '
# Function to set config value idempotently
set_config() {
    local key="$1"
    local value="$2"
    local file="/etc/systemd/resolved.conf"
    
    # Remove the key if it exists (commented or uncommented)
    sed -i "/^#*${key}=/d" "$file"
    
    # Add the key with the desired value
    echo "${key}=${value}" >> "$file"
}

# Set DNS server set_config "DNS" "1.1.1.1"

# Enable DNS over TLS set_config "DNSOverTLS" "yes"

# Restart the service systemctl restart systemd-resolved

echo "DNS configuration updated successfully"
'
