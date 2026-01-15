#!/bin/bash
OUTPUT="/tmp/sbom-scan-report.txt"
EMAIL="${TO_EMAIL:-}"
if [ -z "$EMAIL" ]; then
  echo "TO_EMAIL is not set; refusing to send email." >&2
  echo "Set TO_EMAIL to an approved internal address if you want email alerts." >&2
fi

echo "SBOM Vulnerability Scan – $(date)" > "$OUTPUT"
echo "=================================" >> "$OUTPUT"

HAS_VULNS=false

for sbom in sbom/*.cdx.json; do
  if [ -f "$sbom" ]; then
    echo "Scanning: $sbom" >> "$OUTPUT"
    RESULT=$(osv-scanner --sbom "$sbom" 2>&1)
    echo "$RESULT" >> "$OUTPUT"
    echo "" >> "$OUTPUT"
    
    # Check if any CVEs found
    if echo "$RESULT" | grep -q "Vulnerability"; then
      HAS_VULNS=true
    fi
  fi
done

# Send email only if vulnerabilities found
if [ "$HAS_VULNS" = true ]; then
  if [ -n "$EMAIL" ]; then
    cat "$OUTPUT" | mail -s "🚨 SBOM Vulnerabilities Detected!" "$EMAIL"
    echo "Alert email sent."
  else
    echo "Vulnerabilities found, but email not sent (TO_EMAIL not configured)." >&2
  fi
else
  echo "No vulnerabilities found."
fi