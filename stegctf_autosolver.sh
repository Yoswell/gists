#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Log functions
success() { 
    echo -e "${GREEN}[✓]${NC} :: $1" 
}

info() { 
    echo -e "${BLUE}[i]${NC} :: $1" 
}

warning() { 
    echo -e "${YELLOW}[!]${NC} :: $1" 
}

error() { 
    echo -e "${RED}[✗]${NC} :: $1" 
}

section() { 
    echo -e "${CYAN}[ $1 ]${NC}" 
}

# Steg CTF Autosolver - Specialized CTF Challenge Automator
# Description: Automated tool for solving steganography and forensics CTF challenges
# Features:
#   * Auto-detects file type and applies appropriate analysis
#   * Supports multiple steganography and forensics file formats
#   * Automated flag detection with regex patterns
#   * Tool dependency checking and fallback methods

# Function to print usage information
print_usage() {
    echo -e "${CYAN}[ Usage ]${NC}"
    echo "Usage: $0 <file> [category]"
    echo ""
    echo "Arguments:"
    echo "  file     # Path to the file to analyze"
    echo "  category # Optional: Specific analysis category"
    echo ""
    echo "Categories:"
    echo "  steganography # Images and audio files (auto-detected: jpg, png, wav, mp3)"
    echo "  binary        # Executables and binaries (auto-detected: exe, elf, bin)"
    echo "  macro_docs    # Office and PDF documents (auto-detected: doc, pdf, ppt)"
    echo "  forensics     # PCAPs and archives (auto-detected: pcap, zip, rar)"
    echo ""
    echo "Examples:"
    echo "  $0 challenge.png                  # Auto-detect category"
    echo "  $0 secret.jpg steganography       # Force steganography analysis"
    echo "  $0 traffic.pcap forensics         # Force forensics analysis"
    echo "  $0 document.pdf macro_docs        # Force macro document analysis"
    echo ""
    echo "Supported file extensions:"
    echo "  Images: jpg, jpeg, png, bmp, gif, tiff"
    echo "  Audio: wav, mp3, flac, aiff, aac, ogg, m4a"
    echo "  Binaries: exe, bin, elf, dll, so"
    echo "  Documents: doc, docx, xls, xlsx, ppt, pptx, pdf"
    echo "  Forensics: pcap, pcapng, cap, zip, rar, 7z, tar, gz"
}

# Check for help flag or no arguments
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

# Supported file extensions
SUPPORTED_EXTENSIONS=(
    # Steganography
    "jpg" "jpeg" "png" "bmp" "gif" "tiff" "wav" "mp3" "flac" "aiff"
    # Forensics
    "exe" "bin" "elf" "dll" "so" "doc" "docx" "xls" "xlsx" "ppt" "pptx" 
    "pdf" "pcap" "pcapng" "cap" "zip" "rar" "7z" "tar" "gz"
    # Audio (for stego)
    "mp3" "wav" "flac" "aac" "ogg" "m4a"
)

# Flag patterns
FLAG_FORMATS=(
    "CTF{.*}"
    "FLAG{.*}"
    "flag{.*}"
    "picoCTF{.*}"
    "HTB{.*}"
    "THM{.*}"
    "cyberchef{.*}"
    ".*[0-9a-f]{32}.*"
    ".*[0-9a-z]{32}.*"
)

# Check if file is supported
is_supported_file() {
    local file="$1"
    local ext="${file##*.}"
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    for supported in "${SUPPORTED_EXTENSIONS[@]}"; do
        if [ "$ext" = "$supported" ]; then
            return 0
        fi
    done
    return 1
}

# Get file category
get_file_category() {
    local file="$1"
    local ext="${file##*.}"
    ext=$(echo "$ext" | tr '[:upper:]' '[:lower:]')
    
    case $ext in
        jpg|jpeg|png|bmp|gif|tiff|wav|mp3|flac|aiff|aac|ogg|m4a)
            echo "steganography"
            ;;
        exe|bin|elf|dll|so)
            echo "binary"
            ;;
        doc|docx|xls|xlsx|ppt|pptx|pdf)
            echo "macro_docs"
            ;;
        pcap|pcapng|cap|zip|rar|7z|tar|gz)
            echo "forensics"
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

# Search for flags
search_flags() {
    local target="$1"
    local category="$2"
    
    section "Flag Detection"
    info "Searching for flags in $category file..."
    
    local found=0
    
    for pattern in "${FLAG_FORMATS[@]}"; do
        if [ -f "$target" ]; then
            while read -r flag; do
                if [ ! -z "$flag" ]; then
                    found=1
                    success "Flag found: $flag"
                fi
            done < <(grep -E -o -a "$pattern" "$target" 2>/dev/null)
        fi
    done
    
    # Special searches based on category
    case $category in
        "macro_docs")
            info "Searching for Base64 encoded data..."
            grep -E -o -a '[A-Za-z0-9+/]{20,}={0,2}' "$target" | head -5 | while read -r b64; do
                warning "Possible Base64: $b64"
                echo "$b64" | base64 -d 2>/dev/null | strings | head -3
            done
            ;;
        "binary")
            info "Searching in binary strings..."
            strings "$target" | grep -E -i 'flag|ctf|key|secret' | head -10
            ;;
    esac
    
    if [ $found -eq 0 ]; then
        warning "No standard flags found"
    fi
}

# Analyze steganography files
analyze_steganography() {
    local file="$1"
    
    section "Steganography Analysis"
    info "File: $file"
    
    # Basic info
    info "File information:"
    file "$file"
    echo ""
    
    # Metadata
    info "Metadata extraction:"
    if command -v exiftool &> /dev/null; then
        exiftool "$file" | grep -E -i 'comment|description|artist|copyright|software|creator' | head -20
        if [ $? -ne 0 ]; then
            echo "No interesting metadata found"
        fi
    else
        warning "exiftool not installed"
    fi
    echo ""
    
    # Steghide for images/audio
    if [[ "$file" =~ \.(jpg|jpeg|png|wav|bmp|mp3)$ ]]; then
        info "Checking for steghide embedded data..."
        if command -v steghide &> /dev/null; then
            steghide info "$file" 2>/dev/null || info "No steghide data found"
        else
            warning "steghide not installed"
        fi
        echo ""
    fi
    
    # Zsteg for PNG
    if [[ "$file" =~ \.png$ ]]; then
        info "Running zsteg on PNG..."
        if command -v zsteg &> /dev/null; then
            zsteg "$file" | grep -E -i 'b1|b2|b4|lsb|rgb|extradata' | head -20
        fi
    fi
    
    # WavSteg for audio files
    if [[ "$file" =~ \.wav$ ]]; then
        info "Checking WAV file for LSB steganography..."
        if command -v xxd &> /dev/null; then
            # Check file header
            xxd "$file" | head -2
            info "WAV file analysis - check for unusual file size"
        fi
    fi
    
    # MP3stego check
    if [[ "$file" =~ \.mp3$ ]]; then
        info "MP3 file - potential MP3stego usage"
        info "Check for: mp3stego_decode -P pass -X $file"
    fi
    
    # Strings in file
    info "Raw strings extraction (first 150):"
    strings "$file" | head -150
    echo ""
    
    search_flags "$file" "steganography"
}

# Analyze binary files
analyze_binary() {
    local file="$1"
    
    section "Binary Analysis"
    info "File: $file"
    
    # File type
    info "Binary information:"
    file "$file"
    echo ""
    
    # Security checks
    info "Security protections:"
    if command -v checksec &> /dev/null; then
        checksec --file="$file"
    else
        readelf -h "$file" 2>/dev/null | head -10
    fi
    echo ""
    
    # Strings analysis
    info "Interesting strings:"
    strings "$file" | grep -E -i \
        'flag|ctf|key|secret|pass|admin|user|login|debug|test|win|shell|bin/sh|system' | \
        sort -u | head -30
    echo ""
    
    # All strings (limited)
    info "All strings (first 200):"
    strings "$file" | head -200
    echo ""
    
    # Hex dump of header
    info "File header (hex):"
    xxd "$file" | head -5
    echo ""
    
    search_flags "$file" "binary"
}

# Analyze macro documents
analyze_macro_docs() {
    local file="$1"
    
    section "Macro Document Analysis"
    info "File: $file"
    
    # File info
    info "Document information:"
    file "$file"
    echo ""
    
    # Check for macros
    info "Checking for macro content..."
    
    # For Office documents
    if [[ "$file" =~ \.(doc|docx|xls|xlsx|ppt|pptx)$ ]]; then
        if command -v olevba &> /dev/null; then
            info "Running olevba for VBA macro analysis..."
            olevba "$file" | grep -E -i 'vba|macro|auto|shell|execute|run' | head -30
        elif command -v strings &> /dev/null; then
            info "Extracting strings (look for VBA keywords)..."
            strings "$file" | grep -E -i \
                'vba|macro|auto_open|autoexec|document_open|workbook_open|shell|wscript|exec' | \
                head -30
        fi
        echo ""
    fi
    
    # For PDF files
    if [[ "$file" =~ \.pdf$ ]]; then
        info "PDF analysis..."
        if command -v pdfinfo &> /dev/null; then
            pdfinfo "$file" | head -20
        fi
        if command -v strings &> /dev/null; then
            info "PDF strings extraction..."
            strings "$file" | grep -E -i 'javascript|js|/aa|/openaction|/launch' | head -20
        fi
        echo ""
    fi
    
    # Extract embedded objects
    info "Checking for embedded objects..."
    if command -v binwalk &> /dev/null; then
        binwalk "$file" | head -20
    fi
    echo ""
    
    # Search for encoded data
    info "Searching for encoded/obfuscated data..."
    strings "$file" | grep -E \
        'base64|hex|rot13|xor|obfuscate|encode|decode' | \
        head -15
    echo ""
    
    search_flags "$file" "macro_docs"
}

# Analyze forensic files
analyze_forensics() {
    local file="$1"
    
    section "Forensics Analysis"
    info "File: $file"
    
    # File info
    info "File information:"
    file "$file"
    echo ""
    
    # Network captures
    if [[ "$file" =~ \.(pcap|pcapng|cap)$ ]]; then
        info "Network capture analysis..."
        if command -v tshark &> /dev/null; then
            info "Capture summary:"
            tshark -r "$file" -z io,phs 2>/dev/null | head -15
            echo ""
            info "HTTP requests:"
            tshark -r "$file" -Y "http.request" 2>/dev/null | head -10
            echo ""
            info "DNS queries:"
            tshark -r "$file" -Y "dns" 2>/dev/null | head -10
        else
            warning "tshark not installed"
        fi
    fi
    
    # Archives
    if [[ "$file" =~ \.(zip|rar|7z|tar|gz)$ ]]; then
        info "Archive analysis..."
        if [[ "$file" =~ \.zip$ ]] && command -v unzip &> /dev/null; then
            info "ZIP file contents:"
            unzip -l "$file" | head -20
        elif [[ "$file" =~ \.tar\.gz$ ]] || [[ "$file" =~ \.tar$ ]]; then
            info "TAR file contents:"
            tar -tvf "$file" | head -20
        fi
        echo ""
        
        info "Checking for password protection..."
        if [[ "$file" =~ \.zip$ ]]; then
            unzip -t "$file" 2>&1 | grep -i "password"
        fi
    fi
    
    # General strings analysis
    info "File strings (first 200):"
    strings "$file" | head -200
    echo ""
    
    search_flags "$file" "forensics"
}

# Main execution
main() {
    section "Steg CTF Autosolver"
    
    # Parse arguments
    local file="$1"
    local category="${2:-}"
    
    #== Validations
    info "Validating parameters..."
    
    # Check if file exists
    if [ ! -f "$file" ]; then
        error "File not found: $file"
        print_usage
        exit 1
    fi
    
    # Check if file is supported
    if ! is_supported_file "$file"; then
        error "Unsupported file type: $file"
        info "Supported extensions: ${SUPPORTED_EXTENSIONS[*]}"
        print_usage
        exit 1
    fi
    
    # Auto-detect category if not provided
    if [ -z "$category" ]; then
        category=$(get_file_category "$file")
        info "Auto-detected category: $category"
    else
        # Validate provided category
        case $category in
            "steganography"|"binary"|"macro_docs"|"forensics")
                info "Using specified category: $category"
                ;;
            *)
                error "Invalid category: $category"
                echo "Valid categories: steganography, binary, macro_docs, forensics"
                print_usage
                exit 1
                ;;
        esac
    fi
    
    info "File: $file"
    info "Category: $category"
    
    # Execute based on category
    case $category in
        "steganography")
            analyze_steganography "$file"
            ;;
        "binary")
            analyze_binary "$file"
            ;;
        "macro_docs")
            analyze_macro_docs "$file"
            ;;
        "forensics")
            analyze_forensics "$file"
            ;;
    esac
    
    section "Analysis Complete"
    info "File analyzed: $file"
    info "Category: $category"
    success "Analysis completed successfully!"
}

# Run main function with all arguments
main "$@"
