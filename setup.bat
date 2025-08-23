@echo off
echo ========================================
echo AI-Assisted API Automation POC Setup
echo ========================================
echo.

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.13+ and try again
    pause
    exit /b 1
)

echo Python found. Checking version...
python --version

echo.
echo Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo ERROR: Failed to create virtual environment
    pause
    exit /b 1
)

echo Virtual environment created successfully!
echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo Installing dependencies...
pip install -r requirements-minimal.txt
if errorlevel 1 (
    echo WARNING: Some dependencies failed to install
    echo Trying alternative requirements file...
    pip install -r requirements.txt
)

echo.
echo Verifying installation...
python -m pytest --version
if errorlevel 1 (
    echo ERROR: PyTest installation failed
    pause
    exit /b 1
)

echo.
echo ========================================
echo Setup Complete!
echo ========================================
echo.
echo Next steps:
echo 1. Activate virtual environment: venv\Scripts\activate.bat
echo 2. Run tests: python -m pytest tests/ -v
echo 3. Generate reports: python -m pytest --html=reports/report.html
echo 4. Use interactive runner: python run_tests.py
echo.
echo For detailed instructions, see README.md
echo.
pause
