# AI-Assisted API Automation POC Setup Script
# Run this script in PowerShell

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "AI-Assisted API Automation POC Setup" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python installation
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Python found: $pythonVersion" -ForegroundColor Green
    } else {
        throw "Python not found"
    }
} catch {
    Write-Host "ERROR: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.13+ and try again" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# Create virtual environment
Write-Host "`nCreating virtual environment..." -ForegroundColor Yellow
if (Test-Path "venv") {
    Write-Host "Virtual environment already exists. Removing..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force "venv"
}

python -m venv venv
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to create virtual environment" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "Virtual environment created successfully!" -ForegroundColor Green

# Activate virtual environment
Write-Host "`nActivating virtual environment..." -ForegroundColor Yellow
& ".\venv\Scripts\Activate.ps1"

# Install dependencies
Write-Host "`nInstalling dependencies..." -ForegroundColor Yellow
Write-Host "Trying minimal requirements first (Python 3.13 compatible)..." -ForegroundColor Gray
pip install -r requirements-minimal.txt

if ($LASTEXITCODE -ne 0) {
    Write-Host "WARNING: Minimal requirements failed, trying full requirements..." -ForegroundColor Yellow
    pip install -r requirements.txt
}

# Verify installation
Write-Host "`nVerifying installation..." -ForegroundColor Yellow
python -m pytest --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: PyTest installation failed" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Next steps:" -ForegroundColor White
Write-Host "1. Activate virtual environment: .\venv\Scripts\Activate.ps1" -ForegroundColor Cyan
Write-Host "2. Run tests: python -m pytest tests/ -v" -ForegroundColor Cyan
Write-Host "3. Generate reports: python -m pytest --html=reports/report.html" -ForegroundColor Cyan
Write-Host "4. Use interactive runner: python run_tests.py" -ForegroundColor Cyan
Write-Host ""

Write-Host "For detailed instructions, see README.md" -ForegroundColor Gray
Write-Host ""

# Test run
Write-Host "Running quick test to verify everything works..." -ForegroundColor Yellow
python -m pytest tests/ --collect-only -q
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ All tests discovered successfully!" -ForegroundColor Green
} else {
    Write-Host "⚠️  Some issues with test discovery" -ForegroundColor Yellow
}

Read-Host "Press Enter to exit"
