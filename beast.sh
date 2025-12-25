#!/bin/bash
# =================================================================
# ██████╗ ███████╗ █████╗ ███████╗████████╗███╗   ███╗ ██████╗ ██████╗ ███████╗
# ██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝████╗ ████║██╔═══██╗██╔══██╗██╔════╝
# ██████╔╝█████╗  ███████║███████╗   ██║   ██╔████╔██║██║   ██║██║  ██║█████╗  
# ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝  
# ██████╔╝███████╗██║  ██║███████║   ██║   ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
# ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
# =================================================================
# ULTIMATE BEAST MODE CREDENTIAL SCANNER v5.0
# =================================================================

set -euo pipefail
IFS=$'\n\t'

# ========== CONFIGURATION ==========
VERSION="5.0-BEAST"
AUTHOR="SECURITY-BEAST"
SCAN_ID="BEAST_$(date +%s%N | cut -c1-13)"
LOG_FILE="/tmp/beast_scan_${SCAN_ID}.log"
JSON_REPORT="/tmp/beast_report_${SCAN_ID}.json"
HTML_REPORT="/tmp/beast_report_${SCAN_ID}.html"
CSV_REPORT="/tmp/beast_report_${SCAN_ID}.csv"
TEMP_DIR="/tmp/beast_${SCAN_ID}"
CACHE_DIR="/tmp/beast_cache"
WHITELIST_FILE="${HOME}/.beast_whitelist"
BLACKLIST_FILE="${HOME}/.beast_blacklist"

# Performance tuning
MAX_THREADS=4  # Reduced for compatibility
MAX_FILE_SIZE=52428800  # 50MB
CHUNK_SIZE=500
PARALLEL_SCAN=true
USE_GPU=false

# Stealth mode
STEALTH_MODE=false
LOG_LEVEL="INFO"

# Machine Learning models
USE_ML_DETECTION=true
ENTROPY_THRESHOLD=3.5
PATTERN_CONFIDENCE=0.85

# ========== BEAST MODE FLAGS ==========
BEAST_MODE=true
ENABLE_MEMORY_SCAN=true
ENABLE_NETWORK_SCAN=true
ENABLE_PROCESS_SCAN=true
ENABLE_KERNEL_SCAN=false  # Disabled by default for safety
ENABLE_CONTAINER_BREAKOUT=false
ENABLE_REAL_TIME_MONITOR=false
ENABLE_AUTO_REMEDIATION=false

# ========== COLOR SCHEME - BEAST MODE ==========
BLACK='\033[0;30m'
DARK_GRAY='\033[1;30m'
RED='\033[0;31m'
LIGHT_RED='\033[1;31m'
GREEN='\033[0;32m'
LIGHT_GREEN='\033[1;32m'
BROWN='\033[0;33m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
LIGHT_BLUE='\033[1;34m'
PURPLE='\033[0;35m'
LIGHT_PURPLE='\033[1;35m'
CYAN='\033[0;36m'
LIGHT_CYAN='\033[1;36m'
LIGHT_GRAY='\033[0;37m'
WHITE='\033[1;37m'
BG_RED='\033[41m'
BG_GREEN='\033[42m'
BG_YELLOW='\033[43m'
BG_BLUE='\033[44m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
BLINK='\033[5m'
REVERSE='\033[7m'
NC='\033[0m'

# ========== GLOBAL VARIABLES ==========
declare -A FINDINGS
declare -A STATS
declare -A ML_MODELS
declare -a SCAN_QUEUE
SCAN_START_TIME=$(date +%s)
TOTAL_FILES_SCANNED=0
CRITICAL_FINDINGS=0

# ========== BEAST PATTERN DATABASE ==========
declare -A PATTERNS=(
    # Cloud Providers
    ["AWS_ACCESS_KEY"]="(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}"
    ["AWS_SECRET_KEY"]="[a-zA-Z0-9+/]{40}"
    
    # Google Cloud
    ["GCP_API_KEY"]="AIza[0-9A-Za-z\\-_]{35}"
    ["GCP_OAUTH"]="ya29\\.[0-9A-Za-z\\-_]+"
    
    # Microsoft Azure
    ["AZURE_KEY"]="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    
    # Social Media & APIs
    ["SLACK_TOKEN"]="xox[baprs]-[0-9a-zA-Z-]{10,48}"
    ["SLACK_WEBHOOK"]="https://hooks.slack.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+"
    
    # Payment Processors
    ["STRIPE_LIVE_KEY"]="sk_live_[a-zA-Z0-9]{24}"
    ["STRIPE_TEST_KEY"]="sk_test_[a-zA-Z0-9]{24}"
    
    # Database
    ["POSTGRES_URL"]="postgres(ql)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["MYSQL_URL"]="mysql://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["MONGODB_URL"]="mongodb(\\+srv)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    ["REDIS_URL"]="redis(s)?://[^:\\s]+:[^@\\s]{4,}@[^\\s]+"
    
    # Cryptocurrency
    ["BITCOIN_WALLET"]="[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    ["ETHEREUM_WALLET"]="0x[a-fA-F0-9]{40}"
    ["PRIVATE_KEY_HEX"]="[a-fA-F0-9]{64}"
    
    # Secrets & Tokens
    ["JWT_TOKEN"]="eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,}"
    ["BEARER_TOKEN"]="Bearer\\s+[a-zA-Z0-9\\-._~+/]+=*"
    ["API_KEY_GENERIC"]="[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}"
    
    # Files & Certificates
    ["PRIVATE_KEY"]="-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"
    ["CERTIFICATE"]="-----BEGIN CERTIFICATE-----"
    
    # Generic patterns
    ["HIGH_ENTROPY_BASE64"]="[A-Za-z0-9+/]{40,}={0,2}"
    ["HIGH_ENTROPY_HEX"]="[a-fA-F0-9]{32,}"
    
    # Hardcoded credentials
    ["HARDCODED_PASSWORD"]="(password|passwd|pwd|secret|token|key|credential|auth)[\\s]*[=:][\\s]*[\"'][^\"']{4,}[\"']"
    
    # Email services
    ["SENDGRID_KEY"]="SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}"
    
    # Source Control
    ["GITHUB_TOKEN"]="gh[pousr]_[A-Za-z0-9_]{36,255}"
)

# ========== THREAT SCORING ==========
declare -A THREAT_SCORES=(
    ["AWS_SECRET_KEY"]=95
    ["PRIVATE_KEY"]=90
    ["STRIPE_LIVE_KEY"]=95
    ["DATABASE_URL"]=85
    ["GITHUB_TOKEN"]=80
    ["JWT_TOKEN"]=75
    ["API_KEY_GENERIC"]=70
    ["HARDCODED_PASSWORD"]=65
)

# ========== SIMPLIFIED BANNER ==========
show_beast_banner() {
    clear
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                                                          ║"
    echo "║  ██████╗ ███████╗  █████╗ ███████╗████████╗             ║"
    echo "║  ██╔══██╗██╔════╝ ██╔══██╗██╔════╝╚══██╔══╝             ║"
    echo "║  ██████╔╝█████╗  ███████║███████╗   ██║                ║"
    echo "║  ██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║                ║"
    echo "║  ██████╔╝███████╗██║  ██║███████║   ██║                ║"
    echo "║  ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝                ║"
    echo "║                                                          ║"
    echo "║           ULTIMATE CREDENTIAL SCANNER v$VERSION           ║"
    echo "║                B E A S T   M O D E                       ║"
    echo "║                                                          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}${BOLD}Scan ID: ${SCAN_ID}${NC}"
    echo -e "${CYAN}Started: $(date)${NC}"
    echo -e "${YELLOW}Threads: ${MAX_THREADS} | ML: ${USE_ML_DETECTION}${NC}"
    echo ""
}

# ========== SIMPLIFIED SETUP ==========
setup_environment() {
    log "INFO" "Setting up BEAST MODE environment..."
    
    # Create directories
    mkdir -p "$TEMP_DIR"
    mkdir -p "$CACHE_DIR"
    
    # Initialize statistics
    STATS["total_files"]=0
    STATS["scanned_files"]=0
    STATS["findings"]=0
    STATS["critical"]=0
    STATS["high"]=0
    STATS["medium"]=0
    STATS["low"]=0
    
    log "INFO" "Environment ready. Temp dir: $TEMP_DIR"
}

# ========== SIMPLIFIED LOGGING ==========
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Check log level
    [[ "$LOG_LEVEL" == "SILENT" && "$level" != "ERROR" ]] && return
    
    # Colors for different levels
    case "$level" in
        "DEBUG")
            echo -e "${DARK_GRAY}[DEBUG]${NC} $message" >&2
            ;;
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message" >&2
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "FOUND")
            echo -e "${RED}${BOLD}[FOUND]${NC} $message" >&2
            ;;
    esac
    
    # Log to file
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# ========== CORE SCANNING FUNCTIONS ==========
scan_file_beast() {
    local file="$1"
    
    # Skip if file doesn't exist
    [[ ! -f "$file" ]] && return
    
    # Skip large files
    local size=$(stat -c%s "$file" 2>/dev/null || echo 0)
    [[ $size -gt $MAX_FILE_SIZE ]] && return
    
    # Skip binary files
    if file "$file" | grep -qi "text"; then
        # Read first 5000 lines to avoid memory issues
        local content=$(head -5000 "$file" 2>/dev/null)
        
        [[ -z "$content" ]] && return
        
        # Check all patterns
        for pattern_name in "${!PATTERNS[@]}"; do
            echo "$content" | grep -qi -E "${PATTERNS[$pattern_name]}" || continue
            
            # Get first match
            local match=$(echo "$content" | grep -o -i -E "${PATTERNS[$pattern_name]}" | head -1)
            [[ -z "$match" ]] && continue
            
            # Skip obvious false positives
            [[ "$match" =~ (example|test|demo|dummy|changeme|123456|password) ]] && continue
            
            # Calculate threat score
            local score=${THREAT_SCORES[$pattern_name]:-60}
            
            # Record finding
            record_finding "$pattern_name" "$file" "$match" "$score"
        done
    fi
    
    # Increment counter
    STATS["scanned_files"]=$((STATS["scanned_files"] + 1))
    TOTAL_FILES_SCANNED=$((TOTAL_FILES_SCANNED + 1))
}

record_finding() {
    local pattern="$1"
    local file="$2"
    local match="$3"
    local score="$4"
    
    # Determine severity
    local severity
    if [[ $score -ge 85 ]]; then
        severity="CRITICAL"
        STATS["critical"]=$((STATS["critical"] + 1))
        CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + 1))
    elif [[ $score -ge 70 ]]; then
        severity="HIGH"
        STATS["high"]=$((STATS["high"] + 1))
    elif [[ $score -ge 50 ]]; then
        severity="MEDIUM"
        STATS["medium"]=$((STATS["medium"] + 1))
    else
        severity="LOW"
        STATS["low"]=$((STATS["low"] + 1))
    fi
    
    STATS["findings"]=$((STATS["findings"] + 1))
    
    # Store finding
    local finding_id="${file}:${pattern}:$(echo "$match" | md5sum | cut -c1-8)"
    FINDINGS["$finding_id"]="$severity|$pattern|$file|$score|$match"
    
    # Log finding
    log "FOUND" "$severity - $pattern in $file (Score: $score)"
    echo "  Match: ${match:0:50}..."
}

# ========== DIRECTORY SCANNING ==========
scan_directory_beast() {
    local dir="$1"
    local depth="${2:-5}"
    
    log "INFO" "Scanning directory: $dir (depth: $depth)"
    
    # Count files first
    local file_count=$(find "$dir" -type f ! -path "*/.git/*" ! -path "*/node_modules/*" \
        ! -path "*/vendor/*" ! -path "*/target/*" ! -path "*/build/*" \
        -maxdepth "$depth" 2>/dev/null | wc -l)
    
    STATS["total_files"]=$((STATS["total_files"] + file_count))
    log "INFO" "Found $file_count files to scan"
    
    # Scan files
    find "$dir" -type f ! -path "*/.git/*" ! -path "*/node_modules/*" \
        ! -path "*/vendor/*" ! -path "*/target/*" ! -path "*/build/*" \
        -maxdepth "$depth" 2>/dev/null | \
    while read -r file; do
        scan_file_beast "$file"
        
        # Show progress every 100 files
        if [[ $((STATS["scanned_files"] % 100)) -eq 0 ]]; then
            echo -ne "\rScanned: ${STATS["scanned_files"]}/${STATS["total_files"]} files"
        fi
    done
    
    echo -e "\rScanned: ${STATS["scanned_files"]}/${STATS["total_files"]} files - Done"
}

# ========== MAIN SCAN FUNCTIONS ==========
perform_quick_scan() {
    log "INFO" "Starting QUICK scan..."
    
    local targets=(
        "$HOME"
        "/etc"
        "/tmp"
    )
    
    for target in "${targets[@]}"; do
        [[ -d "$target" ]] && scan_directory_beast "$target" 3
    done
    
    # Special checks
    check_common_locations
}

perform_deep_scan() {
    log "INFO" "Starting DEEP scan..."
    
    local targets=(
        "/home:5"
        "/root:5"
        "/etc:3"
        "/opt:5"
        "/var:3"
        "/tmp:2"
        "/usr/local:3"
    )
    
    for target_spec in "${targets[@]}"; do
        local dir=$(echo "$target_spec" | cut -d: -f1)
        local depth=$(echo "$target_spec" | cut -d: -f2)
        
        [[ -d "$dir" ]] && scan_directory_beast "$dir" "$depth"
    done
    
    # Advanced checks
    check_common_locations
    [[ "$ENABLE_MEMORY_SCAN" == true ]] && check_memory
    [[ "$ENABLE_PROCESS_SCAN" == true ]] && check_processes
}

check_common_locations() {
    log "INFO" "Checking common credential locations..."
    
    # AWS
    [[ -f "$HOME/.aws/credentials" ]] && {
        log "INFO" "Found AWS credentials file"
        scan_file_beast "$HOME/.aws/credentials"
    }
    
    # SSH
    [[ -d "$HOME/.ssh" ]] && {
        find "$HOME/.ssh" -type f -name "*" ! -name "*.pub" | \
        while read file; do
            scan_file_beast "$file"
        done
    }
    
    # Environment variables
    env | grep -iE "(key|token|secret|password)" | while read line; do
        for pattern_name in "${!PATTERNS[@]}"; do
            echo "$line" | grep -qi -E "${PATTERNS[$pattern_name]}" || continue
            local match=$(echo "$line" | grep -o -i -E "${PATTERNS[$pattern_name]}" | head -1)
            [[ -n "$match" ]] && record_finding "$pattern_name" "environment" "$match" 70
        done
    done
}

check_memory() {
    log "INFO" "Checking process memory..."
    
    # Simple process check - look for credentials in process command lines
    ps aux | head -20 | while read line; do
        echo "$line" | grep -iE "(password|token|key)" | grep -v grep | grep -v "$0" && {
            log "INFO" "Process with potential credential in command line"
        }
    done
}

check_processes() {
    log "INFO" "Checking running processes..."
    
    # Check for database processes
    local db_processes=("mysql" "postgres" "mongod" "redis")
    for proc in "${db_processes[@]}"; do
        if pgrep -x "$proc" >/dev/null; then
            log "INFO" "Database process running: $proc"
        fi
    done
}

# ========== REPORTING ==========
generate_summary() {
    local duration=$(( $(date +%s) - SCAN_START_TIME ))
    
    echo -e "\n${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                  BEAST MODE SCAN SUMMARY                 ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${CYAN}Scan ID: ${SCAN_ID}${NC}"
    echo -e "${CYAN}Duration: ${duration} seconds${NC}"
    echo -e "${CYAN}Files scanned: ${STATS["scanned_files"]}${NC}"
    echo ""
    
    echo -e "${RED}${BOLD}CRITICAL: ${STATS["critical"]}${NC}"
    echo -e "${YELLOW}HIGH: ${STATS["high"]}${NC}"
    echo -e "${BLUE}MEDIUM: ${STATS["medium"]}${NC}"
    echo -e "${GREEN}LOW: ${STATS["low"]}${NC}"
    echo -e "${WHITE}TOTAL FINDINGS: ${STATS["findings"]}${NC}"
    echo ""
    
    if [[ ${STATS["critical"]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}🚨 CRITICAL FINDINGS DETECTED! Immediate action required! 🚨${NC}"
        echo ""
        # Show critical findings
        for finding_key in "${!FINDINGS[@]}"; do
            IFS='|' read -r severity pattern file score match <<< "${FINDINGS[$finding_key]}"
            if [[ "$severity" == "CRITICAL" ]]; then
                echo -e "${RED}• $pattern in $file${NC}"
                echo "  Match: ${match:0:60}..."
            fi
        done
        echo ""
    fi
    
    echo -e "${YELLOW}Log file: $LOG_FILE${NC}"
}

# ========== CLEANUP ==========
cleanup_beast() {
    log "INFO" "Cleaning up..."
    
    # Remove temporary directory if it exists
    [[ -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    
    # Clean up old cache files (older than 1 day)
    find "/tmp" -name "beast_*" -mtime +1 -exec rm -rf {} \; 2>/dev/null || true
    
    log "INFO" "Cleanup completed"
}

# ========== MAIN EXECUTION ==========
main() {
    # Show banner
    show_beast_banner
    
    # Legal warning
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║                      ⚠️  WARNING ⚠️                       ║"
    echo "║    THIS IS BEAST MODE - SECURITY SCANNING TOOL          ║"
    echo "║    USE ONLY ON SYSTEMS YOU OWN OR HAVE PERMISSION       ║"
    echo "║    UNAUTHORIZED USE MAY BE ILLEGAL                     ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    read -p "Do you accept responsibility? (Type 'YES' to continue): " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo -e "${RED}Scan aborted.${NC}"
        exit 1
    fi
    
    # Setup
    setup_environment
    
    # Parse arguments
    case "${1:-}" in
        "--deep")
            perform_deep_scan
            ;;
        "--quick"|"")
            perform_quick_scan
            ;;
        "--path")
            [[ -n "$2" ]] && scan_directory_beast "$2" 10
            ;;
        "--help"|"-h")
            echo "Usage: ./beast.sh [MODE]"
            echo ""
            echo "Modes:"
            echo "  --quick      Quick scan (default)"
            echo "  --deep       Deep system scan"
            echo "  --path DIR   Scan specific directory"
            echo "  --help       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage"
            exit 1
            ;;
    esac
    
    # Generate summary
    generate_summary
}

# ========== TRAP HANDLERS ==========
trap 'echo -e "\n${RED}Interrupted! Cleaning up...${NC}"; cleanup_beast; exit 1' SIGINT SIGTERM
trap 'cleanup_beast' EXIT

# ========== ENTRY POINT ==========
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Check for required tools
    for cmd in grep find file stat; do
        if ! command -v "$cmd" &>/dev/null; then
            echo -e "${RED}Error: $cmd is required but not installed${NC}"
            exit 1
        fi
    done
    
    # Run main function
    main "$@"
fi
