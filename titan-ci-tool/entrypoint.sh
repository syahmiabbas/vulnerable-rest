#!/bin/bash

set -e

# Validate required environment variables
if [ -z "$API_BASE_URL" ]; then
  echo "Error: API_BASE_URL environment variable is required."
  exit 1
fi

# Validate API_BASE_URL format (should be a valid URL)
if [[ ! "$API_BASE_URL" =~ ^https?:// ]]; then
  echo "Error: API_BASE_URL must be a valid HTTP/HTTPS URL. Got: $API_BASE_URL"
  exit 1
fi

# Test connectivity to the API base URL
echo "Testing connectivity to API base URL..."
BASE_URL_TEST=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$API_BASE_URL")
if [ "$BASE_URL_TEST" = "000" ]; then
  echo "Error: Cannot connect to API base URL $API_BASE_URL"
  echo "Possible issues:"
  echo "  - Invalid URL"
  echo "  - Network connectivity problems"
  echo "  - API service is down"
  echo "  - Firewall blocking the connection"
  exit 1
fi
echo "Base URL connectivity test passed (HTTP $BASE_URL_TEST)"

# Set default values for optional variables
if [ -z "$REPORT_FORMAT" ]; then
  REPORT_FORMAT="md"
fi

if [ -z "$TIMEOUT_SECONDS" ]; then
  TIMEOUT_SECONDS=300
fi

if [ -z "$BLOCK_PERCENTAGE" ]; then
  BLOCK_PERCENTAGE=50
fi

if [ -z "$BLOCKING" ]; then
  BLOCKING="true"
fi

echo "Starting security scan with Server-Sent Events..."
echo "API Base URL: $API_BASE_URL"

# Get repository URL
REPO_URL="https://github.com/${GITHUB_REPOSITORY}"

echo "Repository URL: $REPO_URL"

# Construct SSE endpoint
SSE_ENDPOINT="${API_BASE_URL%/}/chat?stream=true"

echo "Connecting to SSE endpoint: $SSE_ENDPOINT"
echo "Request data: {\"content\": \"$REPO_URL\"}"

# Initialize variables for collecting findings
FINDINGS_JSON=""
FINDINGS_COUNT=0
JOB_ID=""
ALL_FINDINGS_JSON="[]"
TOTAL_FINDINGS_COUNT=0

# Create temporary file for storing SSE data
TEMP_SSE_FILE="/tmp/sse_output_$$"
TEMP_FINDINGS_FILE="/tmp/findings_$$"

# Create temporary file to store raw SSE output
TEMP_RAW_SSE="/tmp/raw_sse_$$"

# Start SSE connection and save to temp file
echo "Starting SSE connection and collecting events..."
curl -s --max-time "$TIMEOUT_SECONDS" -X POST "$SSE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  --data "{\"content\": \"$REPO_URL\"}" \
  -N > "$TEMP_RAW_SSE"

# Check if curl command was successful
CURL_EXIT_CODE=$?
if [ $CURL_EXIT_CODE -ne 0 ]; then
  echo "Error: SSE connection failed with exit code $CURL_EXIT_CODE"
  echo "This could indicate network issues, invalid URL, or API service unavailable"
  rm -f "$TEMP_SSE_FILE" "$TEMP_FINDINGS_FILE" "$TEMP_RAW_SSE"
  exit 1
fi

echo "SSE connection completed, processing collected events..."

# Process SSE events from the saved file
while IFS= read -r line; do
  # Process SSE event lines
  if [[ "$line" =~ ^data:\ (.*)$ ]]; then
    event_data="${BASH_REMATCH[1]}"
    
    # Skip empty data lines
    if [ -z "$event_data" ] || [ "$event_data" = " " ]; then
      continue
    fi

    echo "Processing event: ${event_data:0:200}..." # Show first 200 chars

    # Check if this event contains findings
    if echo "$event_data" | grep -q '"findings"'; then
      echo "[DATA] Findings event detected, collecting findings..."
      
      # Extract findings from this event and append to global collection
      if command -v jq >/dev/null 2>&1; then
        echo "Using jq for findings extraction"
        EVENT_FINDINGS_COUNT=$(echo "$event_data" | jq -r '.count // 0' 2>/dev/null || echo "0")
        EVENT_FINDINGS=$(echo "$event_data" | jq -c '.findings[]?' 2>/dev/null || echo "")
        
        if [ -n "$EVENT_FINDINGS" ] && [ "$EVENT_FINDINGS" != "" ]; then
          echo "echo "[SUCCESS] Found $EVENT_FINDINGS_COUNT findings in this event""
          TOTAL_FINDINGS_COUNT=$((TOTAL_FINDINGS_COUNT + EVENT_FINDINGS_COUNT))
          
          # Append findings to temp file (one per line)
          echo "$EVENT_FINDINGS" >> "$TEMP_FINDINGS_FILE"
          echo "📈 Total findings collected so far: $TOTAL_FINDINGS_COUNT"
        else
          echo "echo "[WARNING] No valid findings data in this event""
        fi
      else
        echo "jq not available, using sed fallback for findings"
        EVENT_FINDINGS_COUNT=$(echo "$event_data" | sed -n 's/.*"count":\s*\([0-9]*\).*/\1/p')
        if [ -n "$EVENT_FINDINGS_COUNT" ] && [ "$EVENT_FINDINGS_COUNT" != "0" ]; then
          TOTAL_FINDINGS_COUNT=$((TOTAL_FINDINGS_COUNT + EVENT_FINDINGS_COUNT))
          echo "Found $EVENT_FINDINGS_COUNT findings (sed parsing)"
          # For sed fallback, save the whole findings section
          echo "$event_data" >> "$TEMP_FINDINGS_FILE"
        fi
      fi
    fi
    
    # Check if this is the "done" event indicating completion
    if echo "$event_data" | grep -q '"status":\s*"completed"'; then
      echo "[SUCCESS] Scan completed, extracting job ID..."
      
      # Extract job ID from the done event
      if command -v jq >/dev/null 2>&1; then
        echo "Using jq for JSON parsing"
        JOB_ID=$(echo "$event_data" | jq -r '.job_id // ""')
      else
        echo "jq not available, using sed fallback"
        JOB_ID=$(echo "$event_data" | sed -n 's/.*"job_id":\s*"\([^"]*\)".*/\1/p')
      fi
      
      if [ -n "$JOB_ID" ]; then
        echo "🎉 Job completed successfully. Job ID: $JOB_ID"
        echo "[DATA] Total findings collected from SSE: $TOTAL_FINDINGS_COUNT"
        echo "$JOB_ID" > "$TEMP_SSE_FILE"
        break
      else
        echo "Warning: Could not extract job ID from completion event"
      fi
    else
      # Display progress messages from other events
      if echo "$event_data" | grep -q '"message"'; then
        if command -v jq >/dev/null 2>&1; then
          MESSAGE=$(echo "$event_data" | jq -r '.message // ""')
        else
          MESSAGE=$(echo "$event_data" | sed -n 's/.*"message":\s*"\([^"]*\)".*/\1/p')
        fi
        if [ -n "$MESSAGE" ]; then
          echo "📝 Progress: $MESSAGE"
        fi
      fi
    fi
  fi
done < "$TEMP_RAW_SSE"

# Clean up raw SSE file
rm -f "$TEMP_RAW_SSE"

# Check if we got job completion
if [ ! -f "$TEMP_SSE_FILE" ] || [ ! -s "$TEMP_SSE_FILE" ]; then
  echo "Error: No job completion data received from SSE stream"
  rm -f "$TEMP_SSE_FILE" "$TEMP_FINDINGS_FILE"
  exit 1
fi

# Get job ID from temp file
JOB_ID=$(cat "$TEMP_SSE_FILE")
rm -f "$TEMP_SSE_FILE"

if [ -z "$JOB_ID" ]; then
  echo "Error: No job ID received from completion event"
  rm -f "$TEMP_FINDINGS_FILE"
  exit 1
fi

echo "Processing findings collected from SSE stream for job ID: $JOB_ID"

# Use findings collected from SSE events instead of separate API call
FINDINGS_COUNT=$TOTAL_FINDINGS_COUNT

echo "Processing $FINDINGS_COUNT findings collected from SSE stream..."

# Now process the findings data to generate the report
# Parse findings array from collected SSE data
echo "Parsing scan results from collected SSE findings..."

# Read findings from temp file (if exists and has content)
if [ -f "$TEMP_FINDINGS_FILE" ] && [ -s "$TEMP_FINDINGS_FILE" ]; then
  echo "[SUCCESS] Using findings collected from SSE events"
  echo "[INFO] Findings file size: $(wc -l < "$TEMP_FINDINGS_FILE") lines"
  FINDINGS_DATA=$(cat "$TEMP_FINDINGS_FILE")
  rm -f "$TEMP_FINDINGS_FILE"
  echo "[DATA] FINDINGS_DATA length: ${#FINDINGS_DATA}"
  echo "[PREVIEW] FINDINGS_DATA preview: $(echo "$FINDINGS_DATA" | head -c 300)"
else
  echo "[ERROR] No findings file found or file is empty"
  if [ -f "$TEMP_FINDINGS_FILE" ]; then
    echo "[INFO] File exists but is empty (size: $(stat -c%s "$TEMP_FINDINGS_FILE" 2>/dev/null || echo "unknown"))"
    rm -f "$TEMP_FINDINGS_FILE"
  else
    echo "[INFO] File does not exist at: $TEMP_FINDINGS_FILE"
  fi
  echo "[SEARCH] Checking for empty scan result..."
  FINDINGS_DATA=""
fi

ISSUE_COUNT=0
TOTAL_FILES=0
RESULTS_DETAILS=""
RESULTS_DETAILS_XML=""
VULNERABLE_RESULTS=""
CLEAN_RESULTS=""

# Process each finding (only if we have findings)
if [ -n "$FINDINGS_DATA" ] && [ "$FINDINGS_COUNT" != "0" ]; then
while IFS= read -r finding; do
  if [ -z "$finding" ]; then
    continue
  fi
  
  # Extract finding information
  if command -v jq >/dev/null 2>&1; then
    FINDING_ID=$(echo "$finding" | jq -r '.finding_id // ""')
    FILE_PATH=$(echo "$finding" | jq -r '.file_path // ""')
    FUNCTION_NAME=$(echo "$finding" | jq -r '.function_name // ""')
    START_LINE=$(echo "$finding" | jq -r '.start_line // 0')
    END_LINE=$(echo "$finding" | jq -r '.end_line // 0')
    PREDICTION=$(echo "$finding" | jq -r '.prediction // 0')
    SCORE=$(echo "$finding" | jq -r '.score // 0')
    SEVERITY=$(echo "$finding" | jq -r '.severity // "UNKNOWN"')
    VULN_TYPE=$(echo "$finding" | jq -r '.vuln_type // ""')
    CWE_ID=$(echo "$finding" | jq -r '.cwe_id // ""')
    MESSAGE=$(echo "$finding" | jq -r '.message // ""')
  else
    # Fallback sed parsing
    FINDING_ID=$(echo "$finding" | sed -n 's/.*"finding_id":\s*"\([^"]*\)".*/\1/p')
    FILE_PATH=$(echo "$finding" | sed -n 's/.*"file_path":\s*"\([^"]*\)".*/\1/p')
    FUNCTION_NAME=$(echo "$finding" | sed -n 's/.*"function_name":\s*"\([^"]*\)".*/\1/p')
    START_LINE=$(echo "$finding" | sed -n 's/.*"start_line":\s*\([0-9]*\).*/\1/p')
    END_LINE=$(echo "$finding" | sed -n 's/.*"end_line":\s*\([0-9]*\).*/\1/p')
    PREDICTION=$(echo "$finding" | sed -n 's/.*"prediction":\s*\([0-9]*\).*/\1/p')
    SCORE=$(echo "$finding" | sed -n 's/.*"score":\s*\([0-9.]*\).*/\1/p')
    SEVERITY=$(echo "$finding" | sed -n 's/.*"severity":\s*"\([^"]*\)".*/\1/p')
    VULN_TYPE=$(echo "$finding" | sed -n 's/.*"vuln_type":\s*"\([^"]*\)".*/\1/p')
    CWE_ID=$(echo "$finding" | sed -n 's/.*"cwe_id":\s*"\([^"]*\)".*/\1/p')
    MESSAGE=$(echo "$finding" | sed -n 's/.*"message":\s*"\([^"]*\)".*/\1/p')
  fi
  
  TOTAL_FILES=$((TOTAL_FILES + 1))
  
  # Determine if this is a vulnerability based on prediction
  if [ "$PREDICTION" = "1" ]; then
    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    
    # Truncate message if too long (max 800 chars for readability)
    if [ ${#MESSAGE} -gt 800 ]; then
      TRUNCATED_MESSAGE=$(echo "$MESSAGE" | cut -c1-800)
      TRUNCATED_MESSAGE="${TRUNCATED_MESSAGE}..."
    else
      TRUNCATED_MESSAGE="$MESSAGE"
    fi
    
    VULNERABLE_RESULTS+="### 🚨 Vulnerability Found: $FILE_PATH"$'\n'
    VULNERABLE_RESULTS+="- **Finding ID:** \`$FINDING_ID\`"$'\n'
    VULNERABLE_RESULTS+="- **Function:** \`$FUNCTION_NAME\`"$'\n'
    VULNERABLE_RESULTS+="- **Lines:** $START_LINE-$END_LINE"$'\n'
    VULNERABLE_RESULTS+="- **Severity:** $SEVERITY"$'\n'
    VULNERABLE_RESULTS+="- **Score:** $SCORE"$'\n'
    VULNERABLE_RESULTS+="- **Prediction:** $PREDICTION (Vulnerable)"$'\n'
    if [ -n "$VULN_TYPE" ] && [ "$VULN_TYPE" != "null" ]; then
      VULNERABLE_RESULTS+="- **Vulnerability Type:** $VULN_TYPE"$'\n'
    fi
    if [ -n "$CWE_ID" ] && [ "$CWE_ID" != "null" ]; then
      VULNERABLE_RESULTS+="- **CWE ID:** $CWE_ID"$'\n'
    fi
    if [ -n "$TRUNCATED_MESSAGE" ] && [ "$TRUNCATED_MESSAGE" != "null" ] && [ "$TRUNCATED_MESSAGE" != "empty" ]; then
      VULNERABLE_RESULTS+="- **Analysis:** $TRUNCATED_MESSAGE"$'\n'
    fi
    VULNERABLE_RESULTS+=""$'\n'
    
    RESULTS_DETAILS_XML+="<vulnerability><findingId>$FINDING_ID</findingId><file>$FILE_PATH</file><function>$FUNCTION_NAME</function><lines>$START_LINE-$END_LINE</lines><severity>$SEVERITY</severity><score>$SCORE</score><prediction>$PREDICTION</prediction><vulnType>$VULN_TYPE</vulnType><cweId>$CWE_ID</cweId><analysis><![CDATA[$MESSAGE]]></analysis></vulnerability>"
  else
    # Truncate message for clean functions too
    if [ ${#MESSAGE} -gt 800 ]; then
      TRUNCATED_MESSAGE=$(echo "$MESSAGE" | cut -c1-800)
      TRUNCATED_MESSAGE="${TRUNCATED_MESSAGE}..."
    else
      TRUNCATED_MESSAGE="$MESSAGE"
    fi
    
    CLEAN_RESULTS+="### ✅ Clean: $FILE_PATH"$'\n'
    CLEAN_RESULTS+="- **Finding ID:** \`$FINDING_ID\`"$'\n'
    CLEAN_RESULTS+="- **Function:** \`$FUNCTION_NAME\`"$'\n'
    CLEAN_RESULTS+="- **Lines:** $START_LINE-$END_LINE"$'\n'
    CLEAN_RESULTS+="- **Score:** $SCORE"$'\n'
    CLEAN_RESULTS+="- **Prediction:** $PREDICTION (Safe)"$'\n'
    CLEAN_RESULTS+="- **Status:** No security issues detected"$'\n'
    if [ -n "$TRUNCATED_MESSAGE" ] && [ "$TRUNCATED_MESSAGE" != "null" ] && [ "$TRUNCATED_MESSAGE" != "empty" ]; then
      CLEAN_RESULTS+="- **Analysis:** $TRUNCATED_MESSAGE"$'\n'
    fi
    CLEAN_RESULTS+=""$'\n'
    
    RESULTS_DETAILS_XML+="<file><findingId>$FINDING_ID</findingId><path>$FILE_PATH</path><function>$FUNCTION_NAME</function><lines>$START_LINE-$END_LINE</lines><status>clean</status><score>$SCORE</score><prediction>$PREDICTION</prediction><analysis><![CDATA[$MESSAGE]]></analysis></file>"
  fi
done < <(echo "$FINDINGS_DATA")
fi

# Generate report based on format
echo "Generating security report in $REPORT_FORMAT format..."

PERCENT=0
if [ $TOTAL_FILES -gt 0 ]; then
  PERCENT=$((ISSUE_COUNT * 100 / TOTAL_FILES))
fi

# Combine results with vulnerabilities first, then clean functions
# Only update RESULTS_DETAILS if we processed findings (otherwise it was set above for clean scans)
if [ -n "$FINDINGS_DATA" ] && [ "$FINDINGS_COUNT" != "0" ]; then
  RESULTS_DETAILS=""
  if [ -n "$VULNERABLE_RESULTS" ]; then
    RESULTS_DETAILS+="## 🚨 Vulnerable Functions"$'\n'$'\n'
    RESULTS_DETAILS+="$VULNERABLE_RESULTS"
  fi

  if [ -n "$CLEAN_RESULTS" ]; then
    if [ -n "$VULNERABLE_RESULTS" ]; then
      RESULTS_DETAILS+=$'\n'"---"$'\n'$'\n'
    fi
    RESULTS_DETAILS+="## ✅ Clean Functions"$'\n'$'\n'
    RESULTS_DETAILS+="$CLEAN_RESULTS"
  fi
fi

if [ "$REPORT_FORMAT" == "md" ]; then
  # Save results to a beautifully formatted Markdown report file
  cat > security_report.md << EOF
# 🛡️ TITAN Security Scan Report

---

## 📊 Scan Summary

| Metric | Value |
|--------|-------|
| **Scan Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **API Endpoint** | $API_BASE_URL |
| **Job ID** | $JOB_ID |
| **Total Functions Processed** | $TOTAL_FILES |
| **Vulnerable Functions** | $ISSUE_COUNT |
| **Clean Functions** | $((TOTAL_FILES - ISSUE_COUNT)) |
| **Vulnerability Rate** | $PERCENT% |

---

## 📁 Detailed Results

$RESULTS_DETAILS

---

## 🔍 Scan Configuration

- **Excluded Files**: ${EXCLUDE_FILES:-"None"}
- **Blocking Mode**: $BLOCKING
- **Block Percentage Threshold**: $BLOCK_PERCENTAGE%
- **Timeout**: $TIMEOUT_SECONDS seconds

---

*Report generated by TITAN Security Scanner*
EOF

  # Sanitize the markdown report to fix formatting issues
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  MARKDOWN_SANITIZER="$SCRIPT_DIR/sanitize-markdown.js"
  
  if [ -f "$MARKDOWN_SANITIZER" ] && command -v node >/dev/null 2>&1; then
    echo "Sanitizing markdown report for better formatting..."
    node "$MARKDOWN_SANITIZER" security_report.md
    echo "Markdown report sanitized successfully"
  else
    echo "Markdown sanitizer not available, keeping original formatting"
  fi
  
  echo "Report saved as security_report.md"

elif [ "$REPORT_FORMAT" == "pdf" ]; then
  # Generate comprehensive markdown report first
  cat > security_report.md << EOF
# 🛡️ TITAN Security Scan Report

---

## 📊 Scan Summary

| Metric | Value |
|--------|-------|
| **Scan Date** | $(date '+%Y-%m-%d %H:%M:%S') |
| **API Endpoint** | $API_BASE_URL |
| **Job ID** | $JOB_ID |
| **Total Functions Processed** | $TOTAL_FILES |
| **Vulnerable Functions** | $ISSUE_COUNT |
| **Clean Functions** | $((TOTAL_FILES - ISSUE_COUNT)) |
| **Vulnerability Rate** | $PERCENT% |

---

## 📁 Detailed Results

$RESULTS_DETAILS

---

## 🔍 Scan Configuration

- **Excluded Files**: ${EXCLUDE_FILES:-"None"}
- **Blocking Mode**: $BLOCKING
- **Block Percentage Threshold**: $BLOCK_PERCENTAGE%
- **Timeout**: $TIMEOUT_SECONDS seconds

---

*Report generated by TITAN Security Scanner*
EOF

  # Sanitize the markdown report to fix formatting issues
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  MARKDOWN_SANITIZER="$SCRIPT_DIR/sanitize-markdown.js"
  
  if [ -f "$MARKDOWN_SANITIZER" ] && command -v node >/dev/null 2>&1; then
    echo "Sanitizing markdown report for better formatting..."
    if node "$MARKDOWN_SANITIZER" security_report.md; then
      echo "Markdown report sanitized successfully"
    else
      echo "Warning: Sanitization failed, keeping original formatting"
    fi
  else
    echo "Markdown sanitizer not available (Node.js not found), keeping original formatting"
  fi

  # Convert markdown to PDF using our lightweight Node.js script
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  PDF_GENERATOR="$SCRIPT_DIR/generate-pdf.js"
  
  if [ -f "$PDF_GENERATOR" ]; then
    echo "Converting report to PDF using Node.js converter..."
    if command -v node >/dev/null 2>&1; then
      echo "[TIMER] Starting PDF generation with 60-second timeout..."
      
      # Use timeout command to prevent hanging (available on most systems)
      if command -v timeout >/dev/null 2>&1; then
        if timeout 60 node "$PDF_GENERATOR" security_report.md security_report.pdf 2>&1; then
          echo "[SUCCESS] PDF report saved as security_report.pdf"
        else
          PDF_EXIT_CODE=$?
          echo "[ERROR] PDF generation failed (exit code: $PDF_EXIT_CODE) or timed out after 60 seconds"
          echo "[INFO] Markdown report saved as security_report.md"
          echo "[TIP] PDF generation may fail if Chrome/Chromium is not available or accessible"
        fi
      else
        # Fallback without timeout for systems that don't have it
        echo "[WARNING] No timeout command available, trying PDF generation without timeout protection..."
        if node "$PDF_GENERATOR" security_report.md security_report.pdf 2>&1; then
          echo "[SUCCESS] PDF report saved as security_report.pdf"
        else
          echo "[ERROR] PDF generation failed, keeping markdown report"
          echo "[INFO] Markdown report saved as security_report.md"
          echo "[TIP] If this hangs, PDF generation may be waiting for Chrome/Chromium"
        fi
      fi
    else
      echo "[ERROR] Node.js not available. Saving as markdown only."
      echo "[INFO] Markdown report saved as security_report.md"
      echo "[TIP] To generate PDF: install Node.js, then run: node generate-pdf.js security_report.md security_report.pdf"
    fi
  else
    echo "[ERROR] PDF generator script not found, saving as markdown only"
    echo "[INFO] Markdown report saved as security_report.md"
  fi

elif [ "$REPORT_FORMAT" == "xml" ]; then
  # Generate structured XML report
  cat > security_report.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<TitanSecurityReport>
  <metadata>
    <scanDate>$(date -Iseconds)</scanDate>
    <apiEndpoint>$API_BASE_URL</apiEndpoint>
    <jobId>$JOB_ID</jobId>
    <totalFunctionsProcessed>$TOTAL_FILES</totalFunctionsProcessed>
    <issuesFound>$ISSUE_COUNT</issuesFound>
    <successRate>$((100 - PERCENT))</successRate>
    <issueRate>$PERCENT</issueRate>
  </metadata>
  
  <configuration>
    <excludedFiles>${EXCLUDE_FILES:-"None"}</excludedFiles>
    <blockingMode>$BLOCKING</blockingMode>
    <blockPercentageThreshold>$BLOCK_PERCENTAGE</blockPercentageThreshold>
    <timeoutSeconds>$TIMEOUT_SECONDS</timeoutSeconds>
  </configuration>
  
  <findings>
    $RESULTS_DETAILS_XML
  </findings>
  
  <summary>
    <riskLevel>$(if [ $PERCENT -eq 0 ]; then echo "LOW"; elif [ $PERCENT -lt 25 ]; then echo "MEDIUM"; elif [ $PERCENT -lt 50 ]; then echo "HIGH"; else echo "CRITICAL"; fi)</riskLevel>
    <recommendation>$(if [ $ISSUE_COUNT -eq 0 ]; then echo "No immediate action required"; else echo "Review and address identified security issues"; fi)</recommendation>
    <generatedBy>TITAN Security Scanner</generatedBy>
    <generatedAt>$(date -Iseconds)</generatedAt>
  </summary>
</TitanSecurityReport>
EOF
  echo "Report saved as security_report.xml"

else
  echo "Error: Unsupported report format '$REPORT_FORMAT'. Supported formats: md, pdf, xml"
  exit 1
fi

echo "Issues found: $ISSUE_COUNT / $TOTAL_FILES ($PERCENT%)"

if [ "$BLOCKING" == "true" ]; then
  if [ $PERCENT -ge $BLOCK_PERCENTAGE ]; then
    echo "Security issues detected ($PERCENT% >= threshold $BLOCK_PERCENTAGE%). Failing the step."
    exit 1
  fi
fi

echo "Security scan completed successfully. Found $ISSUE_COUNT vulnerable functions out of $TOTAL_FILES total functions ($PERCENT%)."

# Clean up temporary files
rm -f "$TEMP_SSE_FILE" "$TEMP_FINDINGS_FILE" 2>/dev/null || true

exit 0