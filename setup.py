#!/usr/bin/env python3
"""
Setup script for SBOM Vulnerability Scanner
Installs dependencies and configures the environment
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd: list, description: str) -> bool:
    """Run a command and return success status"""
    print(f"📦 {description}...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"❌ Command not found: {' '.join(cmd)}")
        return False

def check_python_version():
    """Check Python version compatibility"""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"❌ Python 3.7+ required, found {version.major}.{version.minor}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_python_dependencies():
    """Install Python dependencies"""
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    return run_command([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], 
                      "Installing Python dependencies")

def install_osv_scanner():
    """Install Google OSV Scanner"""
    # Check if already installed
    try:
        result = subprocess.run(["osv-scanner", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ OSV Scanner already installed")
            return True
    except FileNotFoundError:
        pass
    
    # Try to install via Homebrew (macOS)
    if sys.platform == "darwin":
        if run_command(["brew", "install", "osv-scanner"], "Installing OSV Scanner via Homebrew"):
            return True
    
    # Fallback: manual installation instructions
    print("❌ Could not auto-install OSV Scanner")
    print("📋 Manual installation required:")
    print("   macOS: brew install osv-scanner")
    print("   Linux: Download from https://github.com/google/osv-scanner/releases")
    print("   Windows: Download from https://github.com/google/osv-scanner/releases")
    return False

def setup_mail_command():
    """Check and setup mail command"""
    try:
        result = subprocess.run(["which", "mail"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Mail command available")
            return True
    except FileNotFoundError:
        pass
    
    print("⚠️  Mail command not found")
    if sys.platform == "darwin":
        print("📋 Mail should be available by default on macOS")
        print("   If not working, try: sudo postfix start")
    elif sys.platform.startswith("linux"):
        print("📋 Install mail command:")
        print("   Ubuntu/Debian: sudo apt-get install mailutils")
        print("   CentOS/RHEL: sudo yum install mailx")
    
    return False

def create_sample_env_file():
    """Create sample environment file"""
    env_file = Path(".env.example")
    
    env_content = """# SBOM Vulnerability Scanner Configuration
# Copy this file to .env and customize

# Email Configuration (Optional - uses system mail command if not set)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
FROM_EMAIL=security-scanner@company.com
TO_EMAIL=security-team@company.com
SMTP_TLS=true

# Scanner Configuration
SBOM_DIR=sbom
OUTPUT_FILE=/tmp/combined-vuln-scan.json
EMAIL_ALERTS=true
MIN_EMAIL_SEVERITY=MEDIUM

# API Configuration (Optional)
NVD_API_KEY=your-nvd-api-key
REQUEST_TIMEOUT=30
"""
    
    with open(env_file, 'w') as f:
        f.write(env_content)
    
    print(f"✅ Sample environment file created: {env_file}")
    print("📋 Copy .env.example to .env and customize your settings")
    return True

def create_sample_sbom():
    """Create sample SBOM if none exists"""
    sbom_dir = Path("sbom")
    sbom_dir.mkdir(exist_ok=True)
    
    # Check if any SBOM files exist
    existing_sboms = list(sbom_dir.glob("*.cdx.json"))
    if existing_sboms:
        print(f"✅ Found {len(existing_sboms)} existing SBOM files")
        return True
    
    # Create sample SBOM
    sample_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "example-component",
                "version": "1.0.0",
                "purl": "pkg:generic/example-component@1.0.0"
            }
        ]
    }
    
    sample_file = sbom_dir / "sample.cdx.json"
    with open(sample_file, 'w') as f:
        import json
        json.dump(sample_sbom, f, indent=2)
    
    print(f"✅ Sample SBOM created: {sample_file}")
    print("📋 Replace with your actual SBOM files")
    return True

def run_test_scan():
    """Run a test scan to verify setup"""
    print("🧪 Running test scan...")
    
    try:
        result = subprocess.run([sys.executable, "combined-vuln-scanner.py"], 
                              capture_output=True, text=True, timeout=60)
        
        if "Combined Vulnerability Scan Starting" in result.stdout:
            print("✅ Test scan completed successfully")
            return True
        else:
            print("❌ Test scan failed:")
            print(result.stdout)
            print(result.stderr)
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ Test scan timed out")
        return False
    except Exception as e:
        print(f"❌ Test scan error: {e}")
        return False

def main():
    """Main setup function"""
    print("🚀 SBOM Vulnerability Scanner Setup")
    print("=" * 50)
    
    success_count = 0
    total_steps = 7
    
    # Check Python version
    if check_python_version():
        success_count += 1
    
    # Install Python dependencies
    if install_python_dependencies():
        success_count += 1
    
    # Install OSV Scanner
    if install_osv_scanner():
        success_count += 1
    
    # Check mail command
    if setup_mail_command():
        success_count += 1
    
    # Create sample environment file
    if create_sample_env_file():
        success_count += 1
    
    # Create sample SBOM
    if create_sample_sbom():
        success_count += 1
    
    # Run test scan
    if run_test_scan():
        success_count += 1
    
    print("\n" + "=" * 50)
    print(f"📊 Setup completed: {success_count}/{total_steps} steps successful")
    
    if success_count == total_steps:
        print("🎉 Setup completed successfully!")
        print("\n📋 Next steps:")
        print("1. Add your SBOM files to the sbom/ directory")
        print("2. Configure email settings in .env (optional)")
        print("3. Run: python3 combined-vuln-scanner.py")
    else:
        print("⚠️  Setup completed with some issues")
        print("📋 Please review the errors above and install missing components")
    
    return success_count == total_steps

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
