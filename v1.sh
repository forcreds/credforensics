#!/bin/bash
# Ultimate Credential Scanner - All-in-One
# Usage: ./creds.sh [--quick|--deep|--path /path]

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════╗"
echo "║      ULTIMATE CREDENTIAL SCANNER v3.0        ║"
echo "║     All-in-One Security Scanner              ║"
echo "╚═══════════════════════════════════════════════╝"
echo -e "${NC}"

# Legal notice
echo -e "${RED}⚠️  LEGAL WARNING: For authorized security assessments only!${NC}"
read -p "Confirm you have authorization (y/N): " auth
[[ "$auth" != "y" && "$auth" != "Y" ]] && exit 0

# ========== CREDENTIAL PATTERNS ==========
declare -A PATTERNS=(
    # AWS
    ["AWS_ACCESS_KEY"]="(AKIA|ASIA)[0-9A-Z]{16}"
    ["AWS_SECRET_KEY"]="[a-zA-Z0-9+/]{40}"
    
    # Google
    ["GOOGLE_API_KEY"]="AIza[0-9A-Za-z\\-_]{35}"
    ["GOOGLE_OAUTH"]="ya29\\.[0-9A-Za-z\\-_]+"
    
    # Azure
    ["AZURE_KEY"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    
    # API Keys
    ["STRIPE_KEY"]="(sk|pk)_(live|test)_[a-zA-Z0-9]{24}"
    ["TWILIO_KEY"]="SK[0-9a-f]{32}"
    ["SENDGRID_KEY"]="SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"
    ["MAILGUN_KEY"]="key-[a-zA-Z0-9]{32}"
    ["SLACK_TOKEN"]="xox[baprs]-[0-9a-zA-Z-]{10,48}"
    ["GITHUB_TOKEN"]="gh[pousr]_[A-Za-z0-9_]{36,255}"
    
    # Database
    ["POSTGRES_URL"]="postgres(ql)?://[^:\\s]+:[^@\\s]+@[^\\s]+"
    ["MYSQL_URL"]="mysql://[^:\\s]+:[^@\\s]+@[^\\s]+"
    ["MONGODB_URL"]="mongodb(\\+srv)?://[^:\\s]+:[^@\\s]+@[^\\s]+"
    ["REDIS_URL"]="redis://[^:\\s]+:[^@\\s]+@[^\\s]+"
    
    # SSH & SSL
    ["SSH_PRIVATE_KEY"]="-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----"
    ["SSL_PRIVATE_KEY"]="-----BEGIN PRIVATE KEY-----"
    ["SSL_CERT"]="-----BEGIN CERTIFICATE-----"
    
    # JWT & Tokens
    ["JWT_TOKEN"]="eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9._-]*\\.[A-Za-z0-9._-]*"
    ["BEARER_TOKEN"]="Bearer [a-zA-Z0-9\\-._~+/]+=*"
    
    # Crypto
    ["BITCOIN_WALLET"]="[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    ["ETHEREUM_WALLET"]="0x[a-fA-F0-9]{40}"
    ["PRIVATE_KEY_HEX"]="[a-fA-F0-9]{64}"
    
    # Generic
    ["API_KEY_GENERIC"]="[a-zA-Z0-9]{32,}"
    ["PASSWORD_IN_CODE"]="(password|passwd|pwd|secret|token|key)[\\s]*[=:][\\s]*[\"'][^\"']{4,}[\"']"
)

# ========== SCAN FUNCTIONS ==========
scan_file() {
    local file="$1"
    [[ ! -f "$file" ]] && return
    
    # Skip large/binary files
    local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    [[ $size -gt 10485760 ]] && return
    file "$file" | grep -qi "binary" && return
    
    for pattern in "${!PATTERNS[@]}"; do
        if grep -q -i -E "${PATTERNS[$pattern]}" "$file" 2>/dev/null; then
            echo -e "${RED}[FOUND] ${pattern} in: $file${NC}"
            grep -i -E -n "${PATTERNS[$pattern]}" "$file" 2>/dev/null | head -2 | sed 's/^/  /'
        fi
    done
}

scan_dir() {
    local dir="${1:-.}"
    echo -e "${BLUE}[SCANNING] $dir${NC}"
    
    find "$dir" -type f \( \
        -name "*.env*" -o \
        -name "*config*" -o \
        -name "*.json" -o \
        -name "*.yaml" -o \
        -name "*.yml" -o \
        -name "*.ini" -o \
        -name "*.cfg" -o \
        -name "*.sh" -o \
        -name "*.py" -o \
        -name "*.js" -o \
        -name "*.php" -o \
        -name "*.txt" -o \
        -name "*.log" -o \
        -name "*.sql" -o \
        -name "*.pem" -o \
        -name "*.key" -o \
        -name "*.crt" \
    \) 2>/dev/null | while read file; do
        scan_file "$file"
    done
}

# ========== SPECIAL CHECKS ==========
check_aws() {
    echo -e "${YELLOW}[AWS CHECK]${NC}"
    [[ -f "$HOME/.aws/credentials" ]] && {
        echo "Found AWS credentials: $HOME/.aws/credentials"
        grep -E "aws_(access_key_id|secret_access_key)" "$HOME/.aws/credentials" 2>/dev/null || true
    }
    env | grep -i aws | grep -iE "(key|token|secret)" || true
}

check_ssh() {
    echo -e "${YELLOW}[SSH CHECK]${NC}"
    [[ -d "$HOME/.ssh" ]] && {
        find "$HOME/.ssh" -type f ! -name "*.pub" -exec grep -l "PRIVATE KEY" {} \; 2>/dev/null | \
        while read key; do echo "SSH Private Key: $key"; done
    }
}

check_docker() {
    echo -e "${YELLOW}[DOCKER CHECK]${NC}"
    command -v docker &>/dev/null && {
        echo "Running containers:"
        docker ps --format "{{.Names}}" 2>/dev/null || true
    }
    [[ -f "$HOME/.docker/config.json" ]] && grep -i "auth" "$HOME/.docker/config.json" && \
        echo "Docker auth config found"
}

check_env() {
    echo -e "${YELLOW}[ENV CHECK]${NC}"
    printenv | grep -iE "(key|token|secret|password|cred)" | grep -v "LESS_TERMCAP" || true
}

check_history() {
    echo -e "${YELLOW}[HISTORY CHECK]${NC}"
    [[ -f "$HOME/.bash_history" ]] && {
        grep -iE "(curl.*-u|wget.*--password|passwd|ssh.*-i|mysql.*-p)" "$HOME/.bash_history" | tail -5 || true
    }
}

check_processes() {
    echo -e "${YELLOW}[PROCESS CHECK]${NC}"
    ps aux | grep -iE "(redis|mysql|postgres|mongod|elastic)" | grep -v grep | head -5 || true
}

check_network() {
    echo -e "${YELLOW}[NETWORK CHECK]${NC}"
    command -v netstat &>/dev/null && {
        netstat -tulpn 2>/dev/null | grep -E ":(3306|5432|27017|6379|9200)" | head -5 || true
    }
}

check_git() {
    echo -e "${YELLOW}[GIT CHECK]${NC}"
    find /home /root -type d -name ".git" 2>/dev/null | head -3 | while read gitdir; do
        repo=$(dirname "$gitdir")
        echo "Git repo: $repo"
        [[ -f "$repo/.git/config" ]] && grep -i "token" "$repo/.git/config" && echo "  Contains token!"
    done
}

# ========== MAIN SCAN ==========
deep_scan() {
    echo -e "${MAGENTA}[STARTING DEEP SCAN]${NC}"
    
    # System-wide scan
    for dir in /home /root /etc /var /opt /tmp /usr/local; do
        [[ -d "$dir" ]] && scan_dir "$dir"
    done
    
    # Special checks
    check_aws
    check_ssh
    check_docker
    check_env
    check_history
    check_processes
    check_network
    check_git
    
    echo -e "${GREEN}[DEEP SCAN COMPLETE]${NC}"
}

quick_scan() {
    echo -e "${MAGENTA}[STARTING QUICK SCAN]${NC}"
    
    # Current directory
    scan_dir "."
    
    # Home directory
    scan_dir "$HOME"
    
    # Common configs
    for file in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile" "$HOME/.env" "$HOME/.config"; do
        [[ -f "$file" ]] && scan_file "$file"
    done
    
    # Special checks
    check_aws
    check_ssh
    check_env
    
    echo -e "${GREEN}[QUICK SCAN COMPLETE]${NC}"
}

# ========== ARGUMENT HANDLING ==========
case "${1:-}" in
    "--deep")
        deep_scan
        ;;
    "--quick"|"")
        quick_scan
        ;;
    "--path")
        [[ -n "$2" ]] && scan_dir "$2"
        ;;
    "--help")
        echo "Usage:"
        echo "  ./creds.sh          # Quick scan (default)"
        echo "  ./creds.sh --deep   # Deep system scan"
        echo "  ./creds.sh --path /dir  # Scan specific directory"
        echo "  ./creds.sh --help   # Show this help"
        ;;
    *)
        echo "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac

# Final summary
echo -e "${CYAN}"
echo "========================================"
echo "       SCAN COMPLETED SUCCESSFULLY"
echo "========================================"
echo -e "${NC}"
echo -e "${YELLOW}Remember:${NC}"
echo "1. Review all findings carefully"
echo "2. Remove or secure exposed credentials"
echo "3. Use secrets management tools"
echo "4. Regular scanning is recommended"
