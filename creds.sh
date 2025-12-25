#!/bin/bash
# Ultimate Credential Scanner v4.0 - Enhanced
# Usage: ./creds.sh [--quick|--deep|--path /path|--remote|--report]

set -euo pipefail
IFS=$'\n\t'

# ========== CONFIGURATION ==========
VERSION="4.0"
AUTHOR="Security Team"
LOG_FILE="/tmp/creds_scan_$(date +%Y%m%d_%H%M%S).log"
REPORT_FILE="creds_report_$(date +%Y%m%d_%H%M%S).html"
TEMP_DIR="/tmp/creds_scan_$(date +%s)"
MAX_FILE_SIZE=10485760  # 10MB
EXCLUDE_PATHS=("/proc/*" "/sys/*" "/dev/*" "/run/*" "*.min.js" "*.bundle.js" "*.min.css")
THREAT_LEVELS=("LOW" "MEDIUM" "HIGH" "CRITICAL")

# Database for known false positives
declare -A FALSE_POSITIVE_PATTERNS=(
    ["EXAMPLE_KEY"]="example|demo|test|dummy|changeme|123456"
    ["AWS_EXAMPLE"]="AKIAEXAMPLE"
    ["GOOGLE_EXAMPLE"]="AIzaSyExample"
)

# ========== ENHANCED COLOR SCHEME ==========
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
CYAN='\033[0;96m'
MAGENTA='\033[0;95m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
NC='\033[0m'

# ========== ENHANCED PATTERN DATABASE ==========
declare -A PATTERNS=(
    # Cloud Services
    ["AWS_ACCESS_KEY"]="(AKIA|ASIA)[0-9A-Z]{16}"
    ["AWS_SECRET_KEY"]="[a-zA-Z0-9+/]{40}"
    ["AWS_SESSION_TOKEN"]="FQoGZXIvYXdz[^\\s]{200,}"
    
    # Google Cloud
    ["GOOGLE_API_KEY"]="AIza[0-9A-Za-z\\-_]{35}"
    ["GOOGLE_OAUTH"]="ya29\\.[0-9A-Za-z\\-_]+"
    ["GOOGLE_CLOUD_KEY"]="[0-9a-fA-F]{40}"
    
    # Microsoft Azure
    ["AZURE_KEY"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    ["AZURE_CONNECTION_STRING"]="DefaultEndpointsProtocol=[^;]+;AccountName=[^;]+;AccountKey=[^;]+"
    
    # Social Media & APIs
    ["TWITTER_BEARER"]="AAAAAAAAA[^\\s]{100,}"
    ["FACEBOOK_TOKEN"]="EAAC[0-9A-Za-z]+"
    ["INSTAGRAM_TOKEN"]="IG[0-9A-Za-z\\-\\.]+"
    ["LINKEDIN_TOKEN"]="AQU[0-9A-Za-z\\-]+"
    
    # Payment Processors
    ["STRIPE_KEY"]="(sk|pk)_(live|test)_[a-zA-Z0-9]{24,}"
    # FIXED: Removed undefined variable reference
    ["SQUARE_TOKEN"]="sq0atp-[0-9A-Za-z\\-]{22}"
    
    # Database Connection Strings (enhanced)
    ["POSTGRES_URL"]="postgres(ql)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["MYSQL_URL"]="mysql://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["MONGODB_URL"]="mongodb(\\+srv)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["REDIS_URL"]="redis(s)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["ELASTICSEARCH_URL"]="http(s)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    
    # Cryptocurrency (enhanced)
    ["BITCOIN_WALLET"]="[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[ac-hj-np-z02-9]{11,87}"
    ["ETHEREUM_WALLET"]="0x[a-fA-F0-9]{40}"
    ["PRIVATE_KEY_HEX"]="[a-fA-F0-9]{64}"
    ["MNEMONIC_PHRASE"]="([a-z]+\\s){11,23}[a-z]+"
    
    # Enhanced JWT/Token detection
    ["JWT_TOKEN"]="eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}"
    ["BEARER_TOKEN"]="Bearer\\s+[a-zA-Z0-9\\-._~+/]+=*"
    ["OAUTH_TOKEN"]="[A-Za-z0-9\\-._~+/]+=*"
    
    # File-based credentials
    ["PEM_PRIVATE_KEY"]="-----BEGIN.*PRIVATE KEY-----"
    ["OPENSSH_PRIVATE_KEY"]="-----BEGIN OPENSSH PRIVATE KEY-----"
    ["RSA_PRIVATE_KEY"]="-----BEGIN RSA PRIVATE KEY-----"
    ["DSA_PRIVATE_KEY"]="-----BEGIN DSA PRIVATE KEY-----"
    ["EC_PRIVATE_KEY"]="-----BEGIN EC PRIVATE KEY-----"
    ["CERTIFICATE"]="-----BEGIN CERTIFICATE-----"
    ["CSR"]="-----BEGIN CERTIFICATE REQUEST-----"
    
    # Generic patterns with entropy detection
    ["HIGH_ENTROPY_KEY"]="[A-Za-z0-9+/=]{40,}"
    ["BASE64_ENCODED"]="[A-Za-z0-9+/]{20,}={0,2}"
    ["HEX_ENCODED"]="[a-fA-F0-9]{32,}"
    
    # Configuration files
    ["CONFIG_PASSWORD"]="(password|passwd|pwd|secret|token|key|credential)[\\s]*[=:][\\s]*[\"'][^\"']{4,}[\"']"
    ["ENV_VARIABLE"]="export\\s+[A-Z_]+=[\"'][^\"']{4,}[\"']"
    
    # CI/CD and Deployment
    ["DOCKER_CONFIG"]="\\.dockerconfigjson"
    ["KUBERNETES_TOKEN"]="eyJhbGciOiJ[^\\s]{100,}"
    ["TRAVIS_TOKEN"]="[a-z0-9]{22}"
    ["CIRCLE_TOKEN"]="[a-f0-9]{40}"
    
    # Infrastructure as Code
    # FIXED: Better Terraform pattern without undefined variables
    ["TERRAFORM_TFSTATE"]="[\"']?(password|secret|token)[\"']?\\s*[:=]\\s*[\"'][^\"']+[\"']"
    ["ANSIBLE_VAULT"]="\\\$ANSIBLE_VAULT"
)

# ========== THREAT SCORING SYSTEM ==========
declare -A THREAT_SCORES=(
    ["AWS_SECRET_KEY"]=90
    ["SSH_PRIVATE_KEY"]=85
    ["DATABASE_URL"]=80
    ["GOOGLE_API_KEY"]=75
    ["STRIPE_KEY_LIVE"]=95
    ["JWT_TOKEN"]=70
    ["BEARER_TOKEN"]=65
    ["GENERIC_PASSWORD"]=50
    ["EXAMPLE_KEY"]=0
)

# ========== LOGGING SYSTEM ==========
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "FOUND")
            echo -e "${RED}[FOUND]${NC} $message"
            ;;
        "DEBUG")
            [[ "${DEBUG:-false}" == "true" ]] && echo -e "${CYAN}[DEBUG]${NC} $message"
            ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# ========== UTILITY FUNCTIONS ==========
is_binary_file() {
    local file="$1"
    if [[ $(file -b "$file" | grep -q "text") ]]; then
        return 1
    fi
    return 0
}

calculate_entropy() {
    local string="$1"
    echo "$string" | tr -d '[:space:]' | \
        fold -w1 | sort | uniq -c | \
        awk '{
            p = $1 / length(string); 
            entropy -= p * log(p) / log(2);
        } END {print entropy}'
}

is_false_positive() {
    local pattern="$1"
    local match="$2"
    
    # Check against known false positive patterns
    for fp_pattern in "${!FALSE_POSITIVE_PATTERNS[@]}"; do
        if echo "$match" | grep -qi "${FALSE_POSITIVE_PATTERNS[$fp_pattern]}"; then
            return 0
        fi
    done
    
    # Check if it's a low entropy string (likely not a real secret)
    local entropy=$(calculate_entropy "$match")
    if (( $(echo "$entropy < 3.0" | bc -l) )); then
        return 0
    fi
    
    # Check common patterns that look like secrets but aren't
    if [[ "$match" =~ ^[0-9]+$ ]] || [[ "$match" =~ ^[a-zA-Z]+$ ]]; then
        return 0
    fi
    
    return 1
}

# ========== ENHANCED SCAN FUNCTIONS ==========
scan_file_advanced() {
    local file="$1"
    [[ ! -f "$file" ]] && return 1
    
    # Skip conditions
    for exclude in "${EXCLUDE_PATHS[@]}"; do
        [[ "$file" == $exclude ]] && return 0
    done
    
    local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    [[ $size -gt $MAX_FILE_SIZE ]] && {
        log "DEBUG" "Skipping large file: $file (${size} bytes)"
        return 0
    }
    
    is_binary_file "$file" && {
        log "DEBUG" "Skipping binary file: $file"
        return 0
    }
    
    # Context-aware scanning
    local file_extension="${file##*.}"
    local line_number=0
    local context_before=""
    local context_after=""
    
    while IFS= read -r line; do
        ((line_number++))
        
        for pattern_name in "${!PATTERNS[@]}"; do
            if echo "$line" | grep -qi -E "${PATTERNS[$pattern_name]}"; then
                local match=$(echo "$line" | grep -o -E -i "${PATTERNS[$pattern_name]}" | head -1)
                
                # Skip false positives
                is_false_positive "$pattern_name" "$match" && continue
                
                # Get context (3 lines before and after)
                local start=$((line_number > 3 ? line_number - 3 : 1))
                local end=$((line_number + 3))
                local context=$(sed -n "${start},${end}p" "$file" 2>/dev/null)
                
                # Threat scoring
                local score=${THREAT_SCORES[$pattern_name]:-60}
                local threat_level="MEDIUM"
                
                if [[ $score -ge 85 ]]; then
                    threat_level="CRITICAL"
                elif [[ $score -ge 70 ]]; then
                    threat_level="HIGH"
                elif [[ $score -ge 50 ]]; then
                    threat_level="MEDIUM"
                else
                    threat_level="LOW"
                fi
                
                # Log finding with context
                log "FOUND" "$threat_level - $pattern_name in: $file (Line $line_number)"
                echo "  Match: $match"
                echo "  Score: $score/100"
                echo "  Context:"
                echo "$context" | sed "s/^/    | /"
                echo ""
                
                # Add to findings array
                FINDINGS+=("$threat_level:$pattern_name:$file:$line_number:$match")
            fi
        done
    done < "$file"
}

scan_directory() {
    local dir="${1:-.}"
    local depth="${2:-5}"
    
    log "INFO" "Scanning directory: $dir (max depth: $depth)"
    
    find "$dir" -type f \( \
        -name "*.env*" -o \
        -name "*config*" -o \
        -name "*secret*" -o \
        -name "*credential*" -o \
        -name "*.json" -o \
        -name "*.yaml" -o \
        -name "*.yml" -o \
        -name "*.xml" -o \
        -name "*.ini" -o \
        -name "*.cfg" -o \
        -name "*.conf" -o \
        -name "*.properties" -o \
        -name "*.sh" -o \
        -name "*.bash" -o \
        -name "*.py" -o \
        -name "*.js" -o \
        -name "*.ts" -o \
        -name "*.jsx" -o \
        -name "*.tsx" -o \
        -name "*.java" -o \
        -name "*.php" -o \
        -name "*.rb" -o \
        -name "*.go" -o \
        -name "*.rs" -o \
        -name "*.cpp" -o \
        -name "*.c" -o \
        -name "*.h" -o \
        -name "*.txt" -o \
        -name "*.log" -o \
        -name "*.sql" -o \
        -name "*.pem" -o \
        -name "*.key" -o \
        -name "*.crt" -o \
        -name "*.cer" -o \
        -name "*.pfx" -o \
        -name "*.p12" -o \
        -name "*.jks" -o \
        -name "*.der" -o \
        -name "*.csr" -o \
        -name "id_rsa" -o \
        -name "id_dsa" -o \
        -name "id_ecdsa" -o \
        -name "id_ed25519" -o \
        -name "known_hosts" -o \
        -name "authorized_keys" \
    \) ! -path "*/.git/*" ! -path "*/.svn/*" ! -path "*/.hg/*" \
      ! -path "*/node_modules/*" ! -path "*/vendor/*" ! -path "*/target/*" \
      ! -path "*/build/*" ! -path "*/.idea/*" ! -path "*/.vscode/*" \
      -maxdepth "$depth" 2>/dev/null | \
    while read -r file; do
        scan_file_advanced "$file"
    done
}

# ========== ENHANCED SPECIAL CHECKS ==========
check_aws_enhanced() {
    log "INFO" "Performing enhanced AWS checks..."
    
    # Check for AWS CLI configuration
    local aws_dirs=("$HOME/.aws" "/etc/aws" "/root/.aws")
    for aws_dir in "${aws_dirs[@]}"; do
        [[ -d "$aws_dir" ]] && {
            find "$aws_dir" -type f \( -name "credentials" -o -name "config" -o -name "*.json" \) | \
            while read file; do
                scan_file_advanced "$file"
            done
        }
    done
    
    # Check environment variables
    env | grep -i aws | while read line; do
        for pattern in "AWS_ACCESS_KEY_ID" "AWS_SECRET_ACCESS_KEY" "AWS_SESSION_TOKEN"; do
            if echo "$line" | grep -q "$pattern"; then
                log "FOUND" "AWS credential in environment: ${line%%=*}"
            fi
        done
    done
    
    # Check running processes for AWS keys
    ps aux | grep -i aws | grep -v grep | while read proc; do
        if echo "$proc" | grep -q -E "(AKIA|ASIA)[0-9A-Z]{16}"; then
            log "FOUND" "AWS key in process: $proc"
        fi
    done
}

check_containers() {
    log "INFO" "Checking container environments..."
    
    # Docker
    command -v docker &>/dev/null && {
        log "INFO" "Checking Docker..."
        docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || true
        
        # Check docker config
        [[ -f "$HOME/.docker/config.json" ]] && {
            if grep -q "auths" "$HOME/.docker/config.json"; then
                log "FOUND" "Docker registry credentials found"
            fi
        }
    }
    
    # Kubernetes
    command -v kubectl &>/dev/null && {
        log "INFO" "Checking Kubernetes..."
        kubectl get secrets 2>/dev/null | grep -v NAME | while read line; do
            local name=$(echo "$line" | awk '{print $1}')
            log "INFO" "Kubernetes secret found: $name"
        done
    }
    
    # Podman
    command -v podman &>/dev/null && {
        log "INFO" "Checking Podman..."
        podman ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}" 2>/dev/null || true
    }
}

check_ci_cd() {
    log "INFO" "Checking CI/CD configurations..."
    
    local ci_files=(
        ".travis.yml"
        ".gitlab-ci.yml"
        ".circleci/config.yml"
        "Jenkinsfile"
        "azure-pipelines.yml"
        "github/workflows/*.yml"
        ".drone.yml"
        "bitbucket-pipelines.yml"
    )
    
    for ci_file in "${ci_files[@]}"; do
        find /home /root /opt -name "$ci_file" -type f 2>/dev/null | \
        while read file; do
            scan_file_advanced "$file"
        done
    done
}

check_version_control() {
    log "INFO" "Checking version control systems..."
    
    # Git
    find /home /root /opt -type d -name ".git" 2>/dev/null | head -10 | \
    while read git_dir; do
        local repo=$(dirname "$git_dir")
        log "INFO" "Git repository found: $repo"
        
        # Check git config
        [[ -f "$repo/.git/config" ]] && {
            if grep -q -i "token" "$repo/.git/config"; then
                log "FOUND" "Git token found in: $repo/.git/config"
            fi
        }
        
        # Check for leaked secrets in git history
        command -v git &>/dev/null && {
            cd "$repo" 2>/dev/null && {
                git log --all -p | grep -i -E "(password|token|key|secret)" | head -5 | \
                while read commit; do
                    log "FOUND" "Potential secret in git history: $repo"
                    echo "  $commit"
                done
                cd - >/dev/null
            }
        }
    done
}

# ========== NETWORK AND REMOTE CHECKS ==========
check_network_services() {
    log "INFO" "Checking network services..."
    
    # Check listening services
    if command -v ss &>/dev/null; then
        ss -tulpn | grep -E ":(3306|5432|27017|6379|9200|11211|5984)" | \
        while read line; do
            log "INFO" "Database service listening: $line"
        done
    elif command -v netstat &>/dev/null; then
        netstat -tulpn 2>/dev/null | grep -E ":(3306|5432|27017|6379|9200|11211|5984)" | \
        while read line; do
            log "INFO" "Database service listening: $line"
        done
    fi
    
    # Check for exposed services
    local services=("mysql" "postgres" "redis" "mongod" "memcached" "couchdb")
    for service in "${services[@]}"; do
        if pgrep -x "$service" >/dev/null; then
            log "INFO" "Service running: $service"
        fi
    done
}

# ========== REPORT GENERATION ==========
generate_report() {
    log "INFO" "Generating scan report..."
    
    local total_findings=${#FINDINGS[@]}
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    
    # Count findings by severity
    for finding in "${FINDINGS[@]}"; do
        local severity=$(echo "$finding" | cut -d: -f1)
        case "$severity" in
            "CRITICAL") ((critical_count++)) ;;
            "HIGH") ((high_count++)) ;;
            "MEDIUM") ((medium_count++)) ;;
            "LOW") ((low_count++)) ;;
        esac
    done
    
    # Generate HTML report
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Credential Scanner Report - $(date)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .summary { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .critical { color: #e74c3c; font-weight: bold; }
        .high { color: #e67e22; }
        .medium { color: #f1c40f; }
        .low { color: #27ae60; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Credential Scanner Report</h1>
        <p class="timestamp">Generated: $(date)</p>
        <p>Scanner Version: $VERSION</p>
    </div>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total Findings: $total_findings</p>
        <p class="critical">Critical: $critical_count</p>
        <p class="high">High: $high_count</p>
        <p class="medium">Medium: $medium_count</p>
        <p class="low">Low: $low_count</p>
    </div>
    
    <h2>Detailed Findings</h2>
EOF
    
    # Add findings to report
    for finding in "${FINDINGS[@]}"; do
        IFS=':' read -r severity pattern file line match <<< "$finding"
        
        local severity_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
        
        cat >> "$REPORT_FILE" << EOF
    <div class="finding">
        <h3 class="$severity_class">$severity: $pattern</h3>
        <p><strong>File:</strong> $file (Line: $line)</p>
        <p><strong>Match:</strong> <code>$match</code></p>
        <p><strong>Recommendation:</strong> $(get_recommendation "$pattern")</p>
    </div>
EOF
    done
    
    cat >> "$REPORT_FILE" << EOF
</body>
</html>
EOF
    
    log "INFO" "Report generated: $REPORT_FILE"
}

get_recommendation() {
    local pattern="$1"
    case "$pattern" in
        *AWS*)
            echo "Rotate AWS keys immediately. Use IAM roles where possible."
            ;;
        *SSH*|*PRIVATE_KEY*)
            echo "Generate new SSH key pair. Restrict key permissions."
            ;;
        *DATABASE*|*URL*)
            echo "Change database credentials. Use connection pooling with limited permissions."
            ;;
        *API*|*TOKEN*)
            echo "Revoke and regenerate API tokens. Implement token rotation policy."
            ;;
        *)
            echo "Review and secure the exposed credential. Consider using a secrets manager."
            ;;
    esac
}

# ========== BANNER AND INITIALIZATION ==========
show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║    ██████╗ ██████╗ ███████╗██████╗ ███████╗ ██████╗     ║"
    echo "║   ██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝     ║"
    echo "║   ██║   ██║██████╔╝█████╗  ██║  ██║███████╗██║          ║"
    echo "║   ██║   ██║██╔══██╗██╔══╝  ██║  ██║╚════██║██║          ║"
    echo "║   ╚██████╔╝██║  ██║███████╗██████╔╝███████║╚██████╗     ║"
    echo "║    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝     ║"
    echo "║                                                          ║"
    echo "║            ULTIMATE CREDENTIAL SCANNER v$VERSION          ║"
    echo "║           Enterprise Security Assessment Tool            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Author: $AUTHOR${NC}"
    echo -e "${YELLOW}Date: $(date)${NC}"
    echo ""
}

# ========== LEGAL WARNING ==========
legal_warning() {
    echo -e "${RED}${BOLD}⚠️  IMPORTANT LEGAL NOTICE ⚠️${NC}"
    echo -e "${RED}=============================================${NC}"
    echo -e "${YELLOW}This tool is for authorized security assessments only.${NC}"
    echo -e "${YELLOW}You must have explicit permission to scan the target system.${NC}"
    echo ""
    echo -e "${RED}Unauthorized use is illegal and punishable by law.${NC}"
    echo ""
    
    read -p "Do you have authorization to perform this security scan? (yes/NO): " auth
    auth=$(echo "$auth" | tr '[:upper:]' '[:lower:]')
    
    if [[ "$auth" != "yes" ]]; then
        echo -e "${RED}Scan aborted. Authorization required.${NC}"
        exit 1
    fi
    
    echo ""
    read -p "Enter authorization ticket/reference number: " ticket
    echo "Authorization: $ticket" >> "$LOG_FILE"
    echo ""
}

# ========== MAIN SCAN MODES ==========
deep_scan() {
    log "INFO" "Starting DEEP scan mode"
    
    # Create temp directory
    mkdir -p "$TEMP_DIR"
    
    # System-wide scan with different depths
    local scan_dirs=(
        "/home:5"
        "/root:5"
        "/etc:3"
        "/opt:5"
        "/var:3"
        "/tmp:2"
        "/usr/local:3"
        "/srv:3"
        "/boot:1"
    )
    
    for dir_spec in "${scan_dirs[@]}"; do
        local dir=$(echo "$dir_spec" | cut -d: -f1)
        local depth=$(echo "$dir_spec" | cut -d: -f2)
        
        [[ -d "$dir" ]] && {
            log "INFO" "Scanning $dir with depth $depth"
            scan_directory "$dir" "$depth"
        }
    done
    
    # Enhanced special checks
    check_aws_enhanced
    check_containers
    check_ci_cd
    check_version_control
    check_network_services
    
    # Additional checks
    check_processes_enhanced
    check_cron_jobs
    check_backup_files
    
    log "INFO" "Deep scan completed"
}

quick_scan() {
    log "INFO" "Starting QUICK scan mode"
    
    # Scan current and home directories
    scan_directory "." 2
    [[ -d "$HOME" ]] && scan_directory "$HOME" 3
    
    # Common configuration files
    local config_files=(
        "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"
        "$HOME/.bash_profile" "$HOME/.bash_logout"
        "$HOME/.env" "$HOME/.config"
        "/etc/profile" "/etc/bash.bashrc"
    )
    
    for file in "${config_files[@]}"; do
        [[ -f "$file" ]] && scan_file_advanced "$file"
    done
    
    # Quick special checks
    check_aws_enhanced
    check_containers
    check_network_services
    
    log "INFO" "Quick scan completed"
}

targeted_scan() {
    local target="$1"
    log "INFO" "Starting TARGETED scan of: $target"
    
    if [[ -d "$target" ]]; then
        scan_directory "$target" 10
    elif [[ -f "$target" ]]; then
        scan_file_advanced "$target"
    else
        log "ERROR" "Target not found: $target"
        return 1
    fi
}

# ========== ADDITIONAL CHECKS ==========
check_processes_enhanced() {
    log "INFO" "Checking running processes..."
    
    # Look for processes with potential secrets in command line
    ps aux | grep -v "grep" | while read proc; do
        # Check for common patterns in process arguments
        if echo "$proc" | grep -q -E "(password|passwd|pwd|secret|token|key)=[^ ]+"; then
            local pid=$(echo "$proc" | awk '{print $2}')
            local cmd=$(echo "$proc" | cut -d' ' -f11-)
            log "FOUND" "Potential credential in process command line (PID: $pid)"
            echo "  Command: $cmd"
        fi
    done
}

check_cron_jobs() {
    log "INFO" "Checking cron jobs..."
    
    # System cron
    [[ -f "/etc/crontab" ]] && scan_file_advanced "/etc/crontab"
    
    # User crons
    for user in $(getent passwd | cut -d: -f1); do
        local user_cron="/var/spool/cron/crontabs/$user"
        [[ -f "$user_cron" ]] && scan_file_advanced "$user_cron"
    done
    
    # Cron directories
    for cron_dir in "/etc/cron.d" "/etc/cron.daily" "/etc/cron.hourly" "/etc/cron.monthly" "/etc/cron.weekly"; do
        [[ -d "$cron_dir" ]] && {
            find "$cron_dir" -type f | while read file; do
                scan_file_advanced "$file"
            done
        }
    done
}

check_backup_files() {
    log "INFO" "Checking backup files..."
    
    find /home /root /etc /opt -type f \( \
        -name "*.bak" -o \
        -name "*~" -o \
        -name "*.old" -o \
        -name "*.orig" -o \
        -name "*.save" -o \
        -name "*.backup" \
    \) 2>/dev/null | head -50 | while read file; do
        scan_file_advanced "$file"
    done
}

# ========== CLEANUP ==========
cleanup() {
    log "INFO" "Cleaning up temporary files..."
    [[ -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    echo -e "${GREEN}Cleanup completed.${NC}"
}

# ========== MAIN EXECUTION ==========
main() {
    # Initialize findings array
    declare -a FINDINGS=()
    
    # Show banner
    show_banner
    
    # Legal warning
    legal_warning
    
    # Parse arguments
    case "${1:-}" in
        "--deep")
            deep_scan
            ;;
        "--quick"|"")
            quick_scan
            ;;
        "--path")
            [[ -n "$2" ]] && targeted_scan "$2"
            ;;
        "--report")
            quick_scan
            generate_report
            ;;
        "--clean")
            cleanup
            exit 0
            ;;
        "--help"|"-h")
            echo "Usage: ./creds.sh [OPTION]"
            echo ""
            echo "Options:"
            echo "  --quick       Quick scan (default)"
            echo "  --deep        Deep system scan"
            echo "  --path DIR    Scan specific directory/file"
            echo "  --report      Generate HTML report"
            echo "  --clean       Clean temporary files"
            echo "  --help, -h    Show this help"
            echo ""
            echo "Examples:"
            echo "  ./creds.sh --deep"
            echo "  ./creds.sh --path /etc"
            echo "  ./creds.sh --report"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
    
    # Final summary
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║              SCAN SUMMARY                     ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    local total=${#FINDINGS[@]}
    if [[ $total -eq 0 ]]; then
        echo -e "${GREEN}✅ No credentials found.${NC}"
    else
        echo -e "${YELLOW}Found $total potential credential(s)${NC}"
        echo ""
        echo -e "${BOLD}Recommendations:${NC}"
        echo "1. Immediately rotate any exposed credentials"
        echo "2. Review findings in: $LOG_FILE"
        [[ -f "$REPORT_FILE" ]] && echo "3. View HTML report: $REPORT_FILE"
        echo "4. Implement secrets management solution"
        echo "5. Schedule regular security scans"
    fi
    
    echo ""
    echo -e "${CYAN}Scan completed at: $(date)${NC}"
    echo -e "${CYAN}Log file: $LOG_FILE${NC}"
}

# Trap for cleanup on exit
trap cleanup EXIT INT TERM

# Start main function
main "$@"
