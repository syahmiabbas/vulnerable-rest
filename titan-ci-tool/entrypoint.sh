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

# Create temporary file for storing SSE data
TEMP_SSE_FILE="/tmp/sse_output_$$"

# Start SSE connection and process events
curl -s --max-time "$TIMEOUT_SECONDS" -X POST "$SSE_ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "Accept: text/event-stream" \
  --data "{\"content\": \"$REPO_URL\"}" \
  -N | while IFS= read -r line; do
    
    # Process SSE event lines
    if [[ "$line" =~ ^data:\ (.*)$ ]]; then
      event_data="${BASH_REMATCH[1]}"
      
      # Skip empty data lines
      if [ -z "$event_data" ] || [ "$event_data" = " " ]; then
        continue
      fi
      
      echo "Received event: ${event_data:0:100}..." # Show first 100 chars
      
      # Check if this is the findings event we need
      if echo "$event_data" | grep -q '"findings"'; then
        echo "Found findings data, processing..."
        
        # Extract findings data using multiple methods for robustness
        if command -v jq >/dev/null 2>&1; then
          echo "Using jq for JSON parsing"
          FINDINGS_JSON=$(echo "$event_data" | jq -r '.findings // empty')
          FINDINGS_COUNT=$(echo "$event_data" | jq -r '.count // 0')
          JOB_ID=$(echo "$event_data" | jq -r '.job_id // ""')
        else
          echo "jq not available, using sed fallback"
          FINDINGS_JSON=$(echo "$event_data" | sed -n 's/.*"findings":\s*\(\[.*\]\).*/\1/p')
          FINDINGS_COUNT=$(echo "$event_data" | sed -n 's/.*"count":\s*\([0-9]*\).*/\1/p')
          JOB_ID=$(echo "$event_data" | sed -n 's/.*"job_id":\s*"\([^"]*\)".*/\1/p')
        fi
        
        # Save findings to temp file for processing
        if [ -n "$FINDINGS_JSON" ]; then
          echo "$event_data" > "$TEMP_SSE_FILE"
          echo "Findings saved for processing. Count: $FINDINGS_COUNT, Job ID: $JOB_ID"
          
          # Break out of curl stream since we have our findings
          break
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
            echo "Progress: $MESSAGE"
          fi
        fi
      fi
    fi
done

# Check if curl command was successful
CURL_EXIT_CODE=$?
if [ $CURL_EXIT_CODE -ne 0 ]; then
  echo "Error: SSE connection failed with exit code $CURL_EXIT_CODE"
  echo "This could indicate network issues, invalid URL, or API service unavailable"
  rm -f "$TEMP_SSE_FILE"
  exit 1
fi

# Check if we got findings data
if [ ! -f "$TEMP_SSE_FILE" ] || [ ! -s "$TEMP_SSE_FILE" ]; then
  echo "Error: No findings data received from SSE stream"
  rm -f "$TEMP_SSE_FILE"
  exit 1
fi

echo "Processing findings data..."

# Parse the findings data from the temp file
FINAL_RESPONSE=$(cat "$TEMP_SSE_FILE")
rm -f "$TEMP_SSE_FILE"

echo "Scan completed. Processing $FINDINGS_COUNT findings..."

# Now process the findings data to generate the report
# Parse findings array to get detailed results
echo "Parsing scan results from findings..."

# Extract findings array
if command -v jq >/dev/null 2>&1; then
  echo "Using jq for JSON parsing"
  FINDINGS_DATA=$(echo "$FINAL_RESPONSE" | jq -r '.findings[] | @json')
else
  echo "jq not available, using sed fallback"
  FINDINGS_DATA=$(echo "$FINAL_RESPONSE" | sed -n '/"findings":\s*\[/,/]/p' | sed '1d;$d' | tr -d '\n' | sed 's/},/}\n/g')
fi

echo "FINDINGS_DATA length: ${#FINDINGS_DATA}"
echo "FINDINGS_DATA preview: $(echo "$FINDINGS_DATA" | head -c 200)"

ISSUE_COUNT=0
TOTAL_FILES=0
RESULTS_DETAILS=""
RESULTS_DETAILS_XML=""
VULNERABLE_RESULTS=""
CLEAN_RESULTS=""

# Process each finding
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

# Generate report based on format
echo "Generating security report in $REPORT_FORMAT format..."

PERCENT=0
if [ $TOTAL_FILES -gt 0 ]; then
  PERCENT=$((ISSUE_COUNT * 100 / TOTAL_FILES))
fi

# Combine results with vulnerabilities first, then clean functions
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
  echo "Report saved as security_report.md"

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
  echo "Error: Unsupported report format '$REPORT_FORMAT'. Supported formats: md, xml"
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
exit 0