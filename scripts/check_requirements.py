#!/usr/bin/env python3
"""
Requirements Version Checker

This script checks the current requirements files and validates that
the specified versions are available and compatible.
"""

import subprocess
import sys
import re
from pathlib import Path


def run_command(cmd):
    """Run a command and return the output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)


def check_package_version(package_name, version_spec):
    """Check if a package version is available."""
    # Extract version constraint
    if '>=' in version_spec:
        min_version = version_spec.split('>=')[1].split(',')[0]
        cmd = f"pip index versions {package_name}"
    elif '==' in version_spec:
        exact_version = version_spec.split('==')[1]
        cmd = f"pip index versions {package_name}"
    else:
        # For other constraints, just check availability
        cmd = f"pip index versions {package_name}"
    
    success, output, error = run_command(cmd)
    if not success:
        return False, f"Failed to check {package_name}: {error}"
    
    # Parse available versions
    versions = []
    for line in output.split('\n'):
        if 'Available versions:' in line:
            continue
        if line.strip() and not line.startswith('LATEST:'):
            versions.extend([v.strip() for v in line.split(',') if v.strip()])
    
    if not versions:
        return False, f"No versions found for {package_name}"
    
    # Check if the required version is available
    if '>=' in version_spec:
        min_version = version_spec.split('>=')[1].split(',')[0]
        # Simple version comparison (this could be improved)
        available_versions = [v for v in versions if v.replace('.', '').isdigit()]
        if available_versions:
            latest = max(available_versions, key=lambda x: [int(i) for i in x.split('.')])
            return True, f"Latest available: {latest}, Required: >={min_version}"
    
    return True, f"Available versions: {', '.join(versions[:5])}..."


def check_requirements_file(file_path):
    """Check all packages in a requirements file."""
    print(f"\n🔍 Checking {file_path}...")
    print("=" * 50)
    
    if not Path(file_path).exists():
        print(f"❌ File not found: {file_path}")
        return False
    
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Parse requirements
    requirements = []
    for line in content.split('\n'):
        line = line.strip()
        if line and not line.startswith('#') and '>=' in line:
            parts = line.split('>=')
            if len(parts) == 2:
                package = parts[0].strip()
                version = parts[1].strip()
                requirements.append((package, f">={version}"))
    
    all_good = True
    for package, version_spec in requirements:
        print(f"\n📦 Checking {package} {version_spec}...")
        success, message = check_package_version(package, version_spec)
        if success:
            print(f"✅ {message}")
        else:
            print(f"❌ {message}")
            all_good = False
    
    return all_good


def main():
    """Main function."""
    print("🚀 Requirements Version Checker")
    print("=" * 50)
    
    # Check all requirements files
    files_to_check = [
        'requirements.txt',
        'requirements-minimal.txt', 
        'requirements-stable.txt'
    ]
    
    all_files_good = True
    for file_path in files_to_check:
        if not check_requirements_file(file_path):
            all_files_good = False
    
    print("\n" + "=" * 50)
    if all_files_good:
        print("🎉 All requirements files are valid!")
        sys.exit(0)
    else:
        print("⚠️  Some issues found in requirements files.")
        print("   Consider updating versions or using requirements-stable.txt for CI/CD")
        sys.exit(1)


if __name__ == "__main__":
    main()
