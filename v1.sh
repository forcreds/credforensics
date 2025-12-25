#!/bin/bash
# CredScan Installation Script

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_banner() {
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ██████╗██████╗ ███████╗██████╗     ███████╗ ██████╗ █████╗   ║
║   ██╔════╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝██╔══██╗  ║
║   ██║     ██████╔╝█████╗  ██║  ██║    ███████╗██║     ███████║  ║
║   ██║     ██╔══██╗██╔══╝  ██║  ██║    ╚════██║██║     ██╔══██║  ║
║   ╚██████╗██║  ██║███████╗██████╔╝    ███████║╚██████╗██║  ██║  ║
║    ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝  ║
║                                                                  ║
║                C R E D S C A N   I N S T A L L E R              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
EOF
}

check_dependencies() {
    echo -e "${BLUE}Checking dependencies...${NC}"
    
    local missing=()
    
    for cmd in grep awk sed find file curl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${YELLOW}Missing dependencies:${NC} ${missing[*]}"
        echo "Please install missing commands and try again."
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependencies satisfied${NC}"
}

install_credscan() {
    local install_dir="/usr/local/bin"
    local config_dir="$HOME/.config/credscan"
    
    echo -e "${BLUE}Installing CredScan...${NC}"
    
    # Copy main script
    sudo cp credscan.sh "$install_dir/credscan"
    sudo chmod +x "$install_dir/credscan"
    
    # Create config directory
    mkdir -p "$config_dir"
    
    # Create alias for convenience
    if ! grep -q "alias credscan" "$HOME/.bashrc" 2>/dev/null; then
        echo "alias cs='credscan'" >> "$HOME/.bashrc"
    fi
    
    echo -e "${GREEN}✓ Installation complete!${NC}"
}

install_completion() {
    echo -e "${BLUE}Installing shell completion...${NC}"
    
    # Bash completion
    if [[ -d "/etc/bash_completion.d" ]]; then
        sudo cat > /etc/bash_completion.d/credscan << 'EOF'
_credscan_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="--quick --full --scan --modules --output --report --config --verbose --dry-run --clean --update --version --help"
    
    case "${prev}" in
        --scan|--output|--config)
            COMPREPLY=( $(compgen -d -- "${cur}") )
            return 0
            ;;
        --modules)
            COMPREPLY=( $(compgen -W "aws ssh docker memory network git all" -- "${cur}") )
            return 0
            ;;
        --report)
            COMPREPLY=( $(compgen -W "text json html all" -- "${cur}") )
            return 0
            ;;
    esac
    
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}
complete -F _credscan_completion credscan
EOF
        echo -e "${GREEN}✓ Bash completion installed${NC}"
    fi
    
    # Zsh completion
    if [[ -d "/usr/local/share/zsh/site-functions" ]]; then
        sudo cat > /usr/local/share/zsh/site-functions/_credscan << 'EOF'
#compdef credscan

_credscan() {
    local state
    _arguments \
        '--quick[Quick scan]' \
        '--full[Full system scan]' \
        '--scan[Scan specific directory]:directory:_files -/' \
        '--modules[Specify modules]:modules:(aws ssh docker memory network git all)' \
        '--output[Output directory]:directory:_files -/' \
        '--report[Report format]:format:(text json html all)' \
        '--config[Config file]:file:_files' \
        '--verbose[Verbose output]' \
        '--dry-run[Dry run]' \
        '--clean[Clean previous scans]' \
        '--update[Update patterns]' \
        '--version[Show version]' \
        '--help[Show help]'
}

_credscan "$@"
EOF
        echo -e "${GREEN}✓ Zsh completion installed${NC}"
    fi
}

show_usage() {
    echo -e "${BLUE}Usage:${NC}"
    echo "  ./install.sh [OPTIONS]"
    echo
    echo -e "${BLUE}Options:${NC}"
    echo "  --system    Install system-wide (requires sudo)"
    echo "  --user      Install for current user only"
    echo "  --help      Show this help"
    echo
    echo -e "${BLUE}Examples:${NC}"
    echo "  ./install.sh --system  # Install system-wide"
    echo "  ./install.sh --user    # Install for current user"
}

main() {
    show_banner
    
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
    check_dependencies
    
    # Parse arguments
    local install_type="system"
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --system)
                install_type="system"
                shift
                ;;
            --user)
                install_type="user"
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Install
    if [[ "$install_type" == "system" ]]; then
        install_credscan
        install_completion
    else
        # User installation
        local user_bin="$HOME/.local/bin"
        mkdir -p "$user_bin"
        cp credscan.sh "$user_bin/credscan"
        chmod +x "$user_bin/credscan"
        
        # Add to PATH
        if ! grep -q "$user_bin" "$HOME/.bashrc" 2>/dev/null; then
            echo "export PATH=\"\$PATH:$user_bin\"" >> "$HOME/.bashrc"
        fi
        
        echo -e "${GREEN}✓ Installed to $user_bin/credscan${NC}"
    fi
    
    echo
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}     INSTALLATION SUCCESSFUL${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo
    echo -e "${BLUE}Usage:${NC}"
    echo "  credscan --quick           # Quick scan"
    echo "  credscan --full            # Full system scan"
    echo "  credscan --scan /path      # Scan specific directory"
    echo "  cs --quick                 # Using alias"
    echo
    echo -e "${BLUE}Documentation:${NC}"
    echo "  https://github.com/forcreds/credforensics"
    echo
}

main "$@"
