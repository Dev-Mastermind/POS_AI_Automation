#!/usr/bin/env python3
"""
Test Runner Script for API Automation POC
Provides easy execution of different test suites
"""
import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
            print(f"\n>>> {description}")
    print(f"Running: {command}")
    print("-" * 50)
    
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print("Success!")
        if result.stdout:
            print("Output:", result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: {e}")
        if e.stdout:
            print("Stdout:", e.stdout)
        if e.stderr:
            print("STDERR:", e.stderr)
        return False

def check_venv():
    """Check if virtual environment is activated"""
    venv_path = os.environ.get('VIRTUAL_ENV')
    if not venv_path:
        print("⚠️  WARNING: Virtual environment not detected!")
        print("Please activate your virtual environment first:")
        print("  Windows PowerShell: .\\venv\\Scripts\\Activate.ps1")
        print("  Windows CMD: .\\venv\\Scripts\\activate.bat")
        print("  Linux/Mac: source venv/bin/activate")
        print()
        return False
    
    print(f"Virtual environment active: {venv_path}")
    return True

def check_dependencies():
    """Check if key dependencies are available"""
    try:
        import pytest
        import matplotlib
        import requests
        print("All key dependencies are available")
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Please install dependencies: pip install -r requirements.txt")
        return False

def main():
    """Main test runner function"""
    print("AI-Assisted API Automation POC - Test Runner")
    print("=" * 60)
    
    # Check environment
    if not check_venv():
        return
    
    if not check_dependencies():
        return
    
    print("\n📋 Available Test Commands:")
    print("1. Run all tests")
    print("2. Run specific test file")
    print("3. Run tests by marker")
    print("4. Generate HTML report")
    print("5. Generate coverage report")
    print("6. Run full test suite with reports")
    print("7. Generate metrics dashboard")
    print("8. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-8): ").strip()
            
            if choice == "1":
                run_command("python -m pytest tests/ -v", "Running all tests")
                
            elif choice == "2":
                test_file = input("Enter test file path (e.g., tests/test_users.py): ").strip()
                if test_file:
                    run_command(f"python -m pytest {test_file} -v", f"Running {test_file}")
                else:
                    print("❌ No test file specified")
                    
            elif choice == "3":
                print("Available markers: integration, security, schemathesis")
                marker = input("Enter marker: ").strip()
                if marker:
                    run_command(f"python -m pytest -m {marker} -v", f"Running tests with marker: {marker}")
                else:
                    print("❌ No marker specified")
                    
            elif choice == "4":
                run_command("python -m pytest tests/ --html=reports/report.html --self-contained-html", 
                          "Generating HTML report")
                
            elif choice == "5":
                run_command("python -m pytest tests/ --cov=tests --cov-report=html:reports/coverage", 
                          "Generating coverage report")
                
            elif choice == "6":
                print("🔄 Running full test suite with all reports...")
                commands = [
                    ("python -m pytest tests/ --html=reports/report.html --self-contained-html", "HTML Report"),
                    ("python -m pytest tests/ --json-report --json-report-file=reports/report.json", "JSON Report"),
                    ("python -m pytest tests/ --cov=tests --cov-report=html:reports/coverage", "Coverage Report")
                ]
                
                for cmd, desc in commands:
                    if not run_command(cmd, f"Generating {desc}"):
                        print(f"⚠️  {desc} generation failed, continuing...")
                
                print("✅ Full test suite completed!")
                
            elif choice == "7":
                if os.path.exists("scripts/generate_metrics_simple.py"):
                    run_command("python scripts/generate_metrics_simple.py", "Generating metrics dashboard")
                elif os.path.exists("scripts/generate_metrics.py"):
                    run_command("python scripts/generate_metrics.py", "Generating metrics dashboard (full version)")
                else:
                    print("Metrics script not found")
                    
            elif choice == "8":
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-8.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Test runner interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    # Ensure we're in the right directory
    if not os.path.exists("tests/"):
        print("❌ Error: 'tests/' directory not found!")
        print("Please run this script from the project root directory.")
        sys.exit(1)
    
    # Create reports directory if it doesn't exist
    Path("reports").mkdir(exist_ok=True)
    
    main()
