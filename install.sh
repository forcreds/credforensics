#!/bin/bash
# CREDFORENSICS Installer - One-liner installation
# For authorized security assessments and incident response only

set -euo pipefail

# Configuration
REPO_URL="https://github.com/YOUR_USERNAME/credforensics"
INSTALL_DIR="$HOME/.credforensics"
BIN_DIR="$HOME/.local/bin"
TOOL_NAME="credforensics"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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
    
    for cmd in curl grep awk sed find; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Missing dependencies:${NC} ${missing[*]}"
        echo "Please install missing commands and try again."
        exit 1
    fi
}

# Download and install
install_credforensics() {
    echo -e "${BLUE}Installing CREDFORENSICS...${NC}"
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BIN_DIR"
    
    # Download main script
    echo -e "${YELLOW}Downloading credential forensics toolkit...${NC}"
    curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics/main/credforensics.sh" \
        -o "$INSTALL_DIR/credforensics.sh"
    
    # Download pattern database
    echo -e "${YELLOW}Downloading credential patterns...${NC}"
    curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics/main/patterns.json" \
        -o "$INSTALL_DIR/patterns.json"
    
    # Download modules
    echo -e "${YELLOW}Downloading forensic modules...${NC}"
    for module in cloud browser memory network docker; do
        curl -sSL "https://raw.githubusercontent.com/YOUR_USERNAME/credforensics/main/modules/${module}.sh" \
            -o "$INSTALL_DIR/modules/${module}.sh" 2>/dev/null || true
    done
    
    # Make executable
    chmod +x "$INSTALL_DIR/credforensics.sh"
    
    # Create symlink
    ln -sf "$INSTALL_DIR/credforensics.sh" "$BIN_DIR/$TOOL_NAME"
    
    # Update PATH if needed
    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.bashrc"
        echo "export PATH=\"\$PATH:$BIN_DIR\"" >> "$HOME/.zshrc" 2>/dev/null || true
    fi
}

# Install quick commands
install_quick_commands() {
    cat << 'EOF' >> "$INSTALL_DIR/quick_commands.sh"
#!/bin/bash
# Quick credential discovery commands

# Quick scan current directory
quick_scan() {
    find . -type f -size -10M \( \
        -name "*.env*" -o \
        -name "*config*" -o \
        -name "*.json" -o \
        -name "*.yaml" -o \
        -name "*.yml" \
        \) -exec grep -lE "(AKIA|SG\.|sk_|xox|eyJ|Bearer)" {} \;
}

# Check for AWS keys
check_aws() {
    grep -rE "(AKIA|ASIA)[A-Z0-9]{16}" . 2>/dev/null || true
}

# Check for API keys
check_api_keys() {
    grep -rE "[a-zA-Z0-9]{32,}" . 2>/dev/null | grep -vE "(node_modules|\.git|\.min\.js)" || true
}

# Check environment
check_env() {
    printenv | grep -E "(KEY|TOKEN|SECRET|PASS)" | grep -v "LESS_TERMCAP"
}

# Quick memory scan
quick_memory() {
    if command -v strings &> /dev/null; then
        strings /proc/$1/mem 2>/dev/null | grep -E "(AKIA|SG\.|sk_)" | head -20 || true
    fi
}

# List active services with creds
list_services() {
    netstat -tulpn 2>/dev/null | grep -E ":(25|465|587|993|143|3306|5432|27017)" || true
}
EOF
    
    chmod +x "$INSTALL_DIR/quick_commands.sh"
}

# Install shell integration
install_shell_integration() {
    cat << 'EOF' >> "$INSTALL_DIR/shell_integration.sh"
# CREDFORENSICS Shell Integration
alias cfscan='credforensics --quick'
alias cfaws='credforensics --module aws'
alias cfmem='credforensics --module memory'
alias cfnet='credforensics --module network'
alias cfreport='credforensics --report'

# Auto-completion for credforensics
_cf_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--quick --deep --module --output --report --help"
    
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}
complete -F _cf_completion credforensics

# Function to add credforensics to PATH if needed
cf_path() {
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$PATH:$HOME/.local/bin"
    fi
}
EOF
}

# Show banner
show_banner() {
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║    ██████╗██████╗ ███████╗██████╗ ███████╗███╗   ██╗ ▕║
    ║   ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║ ▕║
    ║   ██║     ██████╔╝█████╗  ██║  ██║█████╗  ██╔██╗ ██║ ▕║
    ║   ██║     ██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║╚██╗██║ ▕║
    ║   ╚██████╗██║  ██║███████╗██████╔╝███████╗██║ ╚████║ ▕║
    ║    ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═══╝ ▕║
    ║                                                       ║
    ║           C R E D E N T I A L   F O R E N S I C S     ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    
    For authorized security assessments only.
    Use responsibly and in compliance with applicable laws.
    
EOF
}

# Main installation
main() {
    show_banner
    
    # Legal disclaimer
    echo -e "${RED}LEGAL NOTICE:${NC}"
    echo "This tool is for authorized security assessments only."
    echo "Unauthorized use may violate laws and regulations."
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
    install_credforensics
    install_quick_commands
    install_shell_integration
    
    # Source for current shell
    if [ -f "$INSTALL_DIR/shell_integration.sh" ]; then
        source "$INSTALL_DIR/shell_integration.sh"
    fi
    
    echo -e "${GREEN}Installation complete!${NC}"
    echo
    echo -e "${BLUE}Usage:${NC}"
    echo "  credforensics                 # Interactive mode"
    echo "  credforensics --quick         # Quick scan"
    echo "  credforensics --deep /path    # Deep forensic scan"
    echo "  cfscan                        # Alias for quick scan"
    echo
    echo -e "${BLUE}Documentation:${NC} $REPO_URL"
    echo -e "${BLUE}Installed to:${NC} $INSTALL_DIR"
    echo -e "${BLUE}Binary location:${NC} $BIN_DIR/$TOOL_NAME"
    
    # Add to shell config
    echo -e "\n${YELLOW}Adding to shell configuration...${NC}"
    if [ -f "$HOME/.bashrc" ]; then
        echo "source $INSTALL_DIR/shell_integration.sh" >> "$HOME/.bashrc"
    fi
    if [ -f "$HOME/.zshrc" ]; then
        echo "source $INSTALL_DIR/shell_integration.sh" >> "$HOME/.zshrc"
    fi
}

# Run installation
main "$@"
