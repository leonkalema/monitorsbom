#!/bin/bash
# Production-ready SBOM vulnerability scanner runner
# Handles logging, error reporting, and email alerts

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/sbom-scan-$(date +%Y%m%d-%H%M%S).log"
LOCK_FILE="/tmp/sbom-scan.lock"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

cleanup() {
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE"
    fi
}

trap cleanup EXIT

main() {
    log "🚀 Starting SBOM Vulnerability Scan"
    log "📁 Working directory: $SCRIPT_DIR"
    log "📝 Log file: $LOG_FILE"
    
    # Check for lock file (prevent concurrent runs)
    if [[ -f "$LOCK_FILE" ]]; then
        error "Another scan is already running (lock file exists: $LOCK_FILE)"
        exit 1
    fi
    
    # Create lock file
    echo $$ > "$LOCK_FILE"
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Check prerequisites
    log "🔍 Checking prerequisites..."
    
    if ! command -v python3 &> /dev/null; then
        error "Python 3 is not installed"
        exit 1
    fi
    
    if [[ ! -f "combined-vuln-scanner.py" ]]; then
        error "combined-vuln-scanner.py not found"
        exit 1
    fi
    
    if [[ ! -d "sbom" ]]; then
        warning "SBOM directory not found, creating..."
        mkdir -p sbom
    fi
    
    # Count SBOM files
    SBOM_COUNT=$(find sbom -name "*.cdx.json" | wc -l | tr -d ' ')
    if [[ "$SBOM_COUNT" -eq 0 ]]; then
        warning "No SBOM files found in sbom/ directory"
        log "📋 Add your .cdx.json files to the sbom/ directory"
    else
        log "📦 Found $SBOM_COUNT SBOM files"
    fi
    
    # Run the scanner
    log "🔍 Running vulnerability scan..."
    
    if python3 combined-vuln-scanner.py 2>&1 | tee -a "$LOG_FILE"; then
        SCAN_EXIT_CODE=${PIPESTATUS[0]}
    else
        SCAN_EXIT_CODE=$?
    fi
    
    # Handle results
    if [[ $SCAN_EXIT_CODE -eq 0 ]]; then
        success "✅ Scan completed - No vulnerabilities found"
    elif [[ $SCAN_EXIT_CODE -eq 1 ]]; then
        warning "⚠️  Scan completed - Vulnerabilities detected!"
        log "📧 Email alerts should have been sent (if configured)"
        log "📄 Check detailed report: /tmp/combined-vuln-scan.json"
    else
        error "❌ Scan failed with exit code $SCAN_EXIT_CODE"
        exit $SCAN_EXIT_CODE
    fi
    
    # Show summary
    log "📊 Scan Summary:"
    if [[ -f "/tmp/combined-vuln-scan.json" ]]; then
        if command -v jq &> /dev/null; then
            TOTAL_VULNS=$(jq -r '.summary.total // 0' /tmp/combined-vuln-scan.json)
            NVD_VULNS=$(jq -r '.summary.nvd // 0' /tmp/combined-vuln-scan.json)
            OSV_VULNS=$(jq -r '.summary.osv // 0' /tmp/combined-vuln-scan.json)
            
            log "   Total Vulnerabilities: $TOTAL_VULNS"
            log "   NVD Database: $NVD_VULNS"
            log "   OSV Database: $OSV_VULNS"
        else
            log "   Install 'jq' for detailed JSON parsing"
        fi
    fi
    
    success "🏁 Scan process completed"
    log "📝 Full log available at: $LOG_FILE"
    
    exit $SCAN_EXIT_CODE
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [--help|--test-email]"
        echo ""
        echo "Options:"
        echo "  --help        Show this help message"
        echo "  --test-email  Test email configuration"
        echo ""
        echo "Environment variables:"
        echo "  TO_EMAIL      Override default email recipient"
        echo "  SBOM_DIR      Override default SBOM directory (default: sbom)"
        exit 0
        ;;
    --test-email)
        log "🧪 Testing email configuration..."
        python3 -c "from email_sender import test_email_config; test_email_config()"
        exit 0
        ;;
    "")
        main
        ;;
    *)
        error "Unknown option: $1"
        echo "Use --help for usage information"
        exit 1
        ;;
esac
