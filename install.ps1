<#
.SYNOPSIS
    Installation script for CISA BDSCA tool

.DESCRIPTION
    This script installs the CISA BDSCA package and sets up the environment.
    It checks for Python 3.10+, optionally creates a virtual environment,
    installs the package in editable mode, and verifies the installation.

.PARAMETER VirtualEnv
    Create and use a virtual environment (recommended)

.PARAMETER SkipVerify
    Skip installation verification

.PARAMETER Clean
    Clean installation artifacts (virtual environment, cache, build files) and exit

.EXAMPLE
    .\install.ps1
    Install with default settings (creates virtual environment)

.EXAMPLE
    .\install.ps1 -VirtualEnv:$false
    Install without creating a virtual environment

.EXAMPLE
    .\install.ps1 -SkipVerify
    Install and skip verification step

.EXAMPLE
    .\install.ps1 -Clean
    Remove all installation artifacts and clean up
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$VirtualEnv = $true,
    
    [Parameter()]
    [switch]$SkipVerify = $false,
    
    [Parameter()]
    [switch]$Clean = $false
)

# Color output functions (defined first to be available in Clean block)
function Write-Success { param($Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Info { param($Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Warning { param($Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }
function Write-Error { param($Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

# Script configuration
$ErrorActionPreference = "Stop"
$MinPythonVersion = [Version]"3.10"
$VenvName = ".venv"

# Handle clean operation
if ($Clean) {
    Write-Host "`n============================================================" -ForegroundColor Cyan
    Write-Host "  CISA BDSCA Tool - Clean Installation" -ForegroundColor Cyan
    Write-Host "============================================================`n" -ForegroundColor Cyan
    
    $itemsToClean = @()
    
    # Check what exists
    if (Test-Path $VenvName) { $itemsToClean += "Virtual environment ($VenvName)" }
    if (Test-Path "build") { $itemsToClean += "Build directory" }
    if (Test-Path "dist") { $itemsToClean += "Distribution directory" }
    if (Test-Path "*.egg-info") { $itemsToClean += "Egg-info directories" }
    if (Test-Path "__pycache__") { $itemsToClean += "Python cache (__pycache__)" }
    if (Test-Path "src/**/__pycache__") { $itemsToClean += "Source cache files" }
    if (Test-Path ".pytest_cache") { $itemsToClean += "Pytest cache" }
    
    if ($itemsToClean.Count -eq 0) {
        Write-Host "[INFO] Nothing to clean - installation is already clean" -ForegroundColor Cyan
        exit 0
    }
    
    Write-Host "[INFO] The following items will be removed:" -ForegroundColor Cyan
    foreach ($item in $itemsToClean) {
        Write-Host "  - $item" -ForegroundColor Gray
    }
    Write-Host ""
    
    $response = Read-Host "Do you want to continue? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-Host "[INFO] Clean operation cancelled" -ForegroundColor Cyan
        exit 0
    }
    
    Write-Host "[INFO] Cleaning installation artifacts..." -ForegroundColor Cyan
    
    # Remove virtual environment
    if (Test-Path $VenvName) {
        Remove-Item -Recurse -Force $VenvName -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed virtual environment" -ForegroundColor Green
    }
    
    # Remove build artifacts
    if (Test-Path "build") {
        Remove-Item -Recurse -Force "build" -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed build directory" -ForegroundColor Green
    }
    
    if (Test-Path "dist") {
        Remove-Item -Recurse -Force "dist" -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed dist directory" -ForegroundColor Green
    }
    
    # Remove egg-info
    Get-ChildItem -Path . -Filter "*.egg-info" -Directory | ForEach-Object {
        Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed $($_.Name)" -ForegroundColor Green
    }
    
    # Remove Python cache
    Get-ChildItem -Path . -Recurse -Filter "__pycache__" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue
    }
    Write-Host "[OK] Removed Python cache files" -ForegroundColor Green
    
    # Remove pytest cache
    if (Test-Path ".pytest_cache") {
        Remove-Item -Recurse -Force ".pytest_cache" -ErrorAction SilentlyContinue
        Write-Host "[OK] Removed pytest cache" -ForegroundColor Green
    }
    
    Write-Host "`n============================================================" -ForegroundColor Green
    Write-Host "  Clean Complete!" -ForegroundColor Green
    Write-Host "============================================================`n" -ForegroundColor Green
    
    Write-Host "[INFO] Run .\install.ps1 to reinstall" -ForegroundColor Cyan
    exit 0
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  CISA BDSCA Tool - Installation Script" -ForegroundColor Cyan
Write-Host "============================================================`n" -ForegroundColor Cyan

# Step 1: Check Python installation
Write-Info "Checking Python installation..."

try {
    $pythonCmd = Get-Command python -ErrorAction Stop
    $pythonVersion = python --version 2>&1
    $versionMatch = $pythonVersion -match "Python (\d+\.\d+\.\d+)"
    
    if ($versionMatch) {
        $installedVersion = [Version]$matches[1]
        Write-Success "Found Python $installedVersion at $($pythonCmd.Source)"
        
        if ($installedVersion -lt $MinPythonVersion) {
            Write-Error "Python $MinPythonVersion or higher is required. Found: $installedVersion"
            Write-Info "Please install Python $MinPythonVersion+ from https://www.python.org/downloads/"
            exit 1
        }
    } else {
        Write-Error "Could not determine Python version"
        exit 1
    }
} catch {
    Write-Error "Python not found in PATH"
    Write-Info "Please install Python $MinPythonVersion+ from https://www.python.org/downloads/"
    exit 1
}

# Step 2: Create virtual environment (optional)
if ($VirtualEnv) {
    Write-Info "Creating virtual environment..."
    
    if (Test-Path $VenvName) {
        Write-Warning "Virtual environment '$VenvName' already exists"
        $response = Read-Host "Do you want to recreate it? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Write-Info "Removing existing virtual environment..."
            Remove-Item -Recurse -Force $VenvName
        } else {
            Write-Info "Using existing virtual environment"
        }
    }
    
    if (-not (Test-Path $VenvName)) {
        python -m venv $VenvName
        Write-Success "Virtual environment created: $VenvName"
    }
    
    # Activate virtual environment
    Write-Info "Activating virtual environment..."
    $activateScript = Join-Path $VenvName "Scripts\Activate.ps1"
    
    if (Test-Path $activateScript) {
        & $activateScript
        Write-Success "Virtual environment activated"
    } else {
        Write-Error "Could not find activation script: $activateScript"
        exit 1
    }
}

# Step 3: Upgrade pip
Write-Info "Upgrading pip..."
python -m pip install --upgrade pip --quiet
Write-Success "pip upgraded"

# Step 4: Install package in editable mode
Write-Info "Installing cisa-bdsca package..."
Write-Host ""

try {
    python -m pip install -e .
    Write-Host ""
    Write-Success "Package installed successfully"
} catch {
    Write-Error "Installation failed: $_"
    exit 1
}

# Step 5: Verify installation
if (-not $SkipVerify) {
    Write-Info "Verifying installation..."
    
    try {
        $version = python -m cisa_bdsca --version 2>&1
        Write-Success "Installation verified: cisa-bdsca $version"
    } catch {
        Write-Warning "Could not verify installation: $_"
    }
    
    # Check if command is available
    try {
        $cmd = Get-Command cisa-bdsca -ErrorAction Stop
        Write-Success "CLI command available: $($cmd.Source)"
    } catch {
        Write-Warning "CLI command 'cisa-bdsca' not found in PATH"
        Write-Info "You may need to restart your terminal or add the Scripts directory to PATH"
    }
}

# Step 6: Setup configuration
Write-Info "Setting up configuration..."

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
        Write-Success "Created .env file from template"
        Write-Warning "Please edit .env file with your Black Duck credentials"
    } else {
        Write-Warning ".env.example not found"
    }
} else {
    Write-Info ".env file already exists"
}

# Step 7: Display next steps
Write-Host "`n============================================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================================`n" -ForegroundColor Green

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Edit .env file with your Black Duck credentials:" -ForegroundColor White
Write-Host "     notepad .env" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Verify configuration:" -ForegroundColor White
Write-Host "     cisa-bdsca config-check" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Collect CISA data:" -ForegroundColor White
Write-Host "     cisa-bdsca collect --ids `"CVE-2021-44228`" -o results.json" -ForegroundColor Gray
Write-Host ""

if ($VirtualEnv) {
    Write-Host "Virtual Environment:" -ForegroundColor Cyan
    Write-Host "  Activate:   .venv\Scripts\Activate.ps1" -ForegroundColor Gray
    Write-Host "  Deactivate: deactivate" -ForegroundColor Gray
    Write-Host ""
}

Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  README:     README.md" -ForegroundColor Gray
Write-Host "  Quick Start: QUICKSTART.md" -ForegroundColor Gray
Write-Host ""

Write-Success "Ready to use!"
