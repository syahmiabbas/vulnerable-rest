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

      echo "${event_data:0:300}..." # Show first 300 chars

      # Check if this is the "done" event indicating completion
      if echo "$event_data" | grep -q '"status":\s*"completed"'; then
        echo "Scan completed, extracting job ID..."
        
        # Extract job ID from the done event
        if command -v jq >/dev/null 2>&1; then
          echo "Using jq for JSON parsing"
          JOB_ID=$(echo "$event_data" | jq -r '.job_id // ""')
        else
          echo "jq not available, using sed fallback"
          JOB_ID=$(echo "$event_data" | sed -n 's/.*"job_id":\s*"\([^"]*\)".*/\1/p')
        fi
        
        if [ -n "$JOB_ID" ]; then
          echo "Job completed successfully. Job ID: $JOB_ID"
          echo "$JOB_ID" > "$TEMP_SSE_FILE"
          
          # Break out of curl stream since scan is complete
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

# Check if we got job completion
if [ ! -f "$TEMP_SSE_FILE" ] || [ ! -s "$TEMP_SSE_FILE" ]; then
  echo "Error: No job completion data received from SSE stream"
  rm -f "$TEMP_SSE_FILE"
  exit 1
fi

# Get job ID from temp file
JOB_ID=$(cat "$TEMP_SSE_FILE")
rm -f "$TEMP_SSE_FILE"

if [ -z "$JOB_ID" ]; then
  echo "Error: No job ID received from completion event"
  exit 1
fi

echo "Fetching findings for job ID: $JOB_ID"

# Now fetch the findings using the job ID
FINDINGS_ENDPOINT="${API_BASE_URL%/}/results/$JOB_ID"
echo "Fetching findings from: $FINDINGS_ENDPOINT"

FINAL_RESPONSE=$(curl -s --max-time "$TIMEOUT_SECONDS" -X GET "$FINDINGS_ENDPOINT" \
  -H "Content-Type: application/json")

# Check if curl command was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to fetch findings - curl command failed"
  exit 1
fi

if [ -z "$FINAL_RESPONSE" ]; then
  echo "Error: Empty response received from findings endpoint"
  exit 1
fi

echo "Findings response received, processing data..."

# Extract findings count for display
if command -v jq >/dev/null 2>&1; then
  FINDINGS_COUNT=$(echo "$FINAL_RESPONSE" | jq -r '.count // 0')
else
  FINDINGS_COUNT=$(echo "$FINAL_RESPONSE" | sed -n 's/.*"count":\s*\([0-9]*\).*/\1/p')
fi

echo "Processing $FINDINGS_COUNT findings..."

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
    echo "Converting report to PDF using lightweight converter..."
    if command -v node >/dev/null 2>&1; then
      node "$PDF_GENERATOR" security_report.md security_report.pdf
    else
      echo "Node.js not available, trying alternative lightweight converters..."
      
      # Try wkhtmltopdf (lightweight alternative)
      if command -v wkhtmltopdf >/dev/null 2>&1; then
        echo "Using wkhtmltopdf for PDF conversion..."
        # First create a proper HTML version for wkhtmltopdf with TailwindCSS
        cat > security_report.html << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TITAN Security Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        'titan-blue': '#2c5aa0',
                        'titan-dark': '#1e3a8a',
                        'danger': '#ef4444',
                        'success': '#10b981',
                        'warning': '#f59e0b',
                    }
                }
            }
        }
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        .gradient-header {
            background: linear-gradient(135deg, #1e3a8a 0%, #2c5aa0 50%, #3b82f6 100%);
        }
        .vulnerability-card {
            background: linear-gradient(135deg, #fef2f2 0%, #fecaca 100%);
            border-left: 6px solid #ef4444;
        }
        .success-card {
            background: linear-gradient(135deg, #f0fdf4 0%, #bbf7d0 100%);
            border-left: 6px solid #10b981;
        }
        .warning-card {
            background: linear-gradient(135deg, #fffbeb 0%, #fed7aa 100%);
            border-left: 6px solid #f59e0b;
        }
        .code-block {
            background: linear-gradient(135deg, #1f2937 0%, #374151 100%);
        }
        @media print {
            .print\:shadow-none { box-shadow: none !important; }
            .print\:bg-white { background-color: white !important; }
        }
    </style>
</head>
<body class="bg-gray-50 font-sans leading-relaxed">
    <div class="max-w-5xl mx-auto p-8 bg-white shadow-lg rounded-lg print:shadow-none print:bg-white">
HTMLEOF

        # Add the main content using proper HTML structure
        cat >> security_report.html << HTMLEOF
        <h1 class="text-4xl font-bold text-white p-6 mb-8 rounded-lg gradient-header shadow-lg">🛡️ TITAN Security Scan Report</h1>
        
        <div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>
        
        <h2 class="text-3xl font-semibold text-titan-blue mt-12 mb-6 pb-3 border-b-2 border-titan-blue">📊 Scan Summary</h2>
        
        <div class="overflow-x-auto my-6">
            <table class="w-full bg-white rounded-lg shadow-lg overflow-hidden">
                <tr class="bg-titan-blue text-white">
                    <td class="px-4 py-3 font-semibold">Metric</td>
                    <td class="px-4 py-3 font-semibold">Value</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Scan Date</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$(date '+%Y-%m-%d %H:%M:%S')</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">API Endpoint</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$API_BASE_URL</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Job ID</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$JOB_ID</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Total Functions Processed</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$TOTAL_FILES</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Vulnerable Functions</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$ISSUE_COUNT</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Clean Functions</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$((TOTAL_FILES - ISSUE_COUNT))</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Vulnerability Rate</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$PERCENT%</td>
                </tr>
            </table>
        </div>
        
        <div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>
        
        <h2 class="text-3xl font-semibold text-titan-blue mt-12 mb-6 pb-3 border-b-2 border-titan-blue">📁 Detailed Results</h2>
HTMLEOF

        # Now add the detailed results with proper parsing
        # Use printf to properly handle the cleaned markdown
        printf '%s\n' "$RESULTS_DETAILS" | while IFS= read -r line; do
          if [[ "$line" =~ ^###\ 🚨 ]]; then
            # Start vulnerability card
            title="${line#*🚨 }"
            cat >> security_report.html << 'CARDEOF'
        <div class="vulnerability-card rounded-lg p-6 mb-6 shadow-md">
            <h3 class="text-xl font-semibold text-danger mb-4 flex items-center">
                <span class="text-2xl mr-2">🚨</span> 
CARDEOF
            printf '%s\n' "$title" >> security_report.html
            cat >> security_report.html << 'CARDEOF'
            </h3>
            <div class="space-y-3">
CARDEOF
          elif [[ "$line" =~ ^###\ ✅ ]]; then
            # Start success card
            title="${line#*✅ }"
            cat >> security_report.html << 'CARDEOF'
        <div class="success-card rounded-lg p-6 mb-6 shadow-md">
            <h3 class="text-xl font-semibold text-success mb-4 flex items-center">
                <span class="text-2xl mr-2">✅</span> 
CARDEOF
            printf '%s\n' "$title" >> security_report.html
            cat >> security_report.html << 'CARDEOF'
            </h3>
            <div class="space-y-3">
CARDEOF
          elif [[ "$line" =~ ^###\ ❌ ]]; then
            # Start warning card
            title="${line#*❌ }"
            cat >> security_report.html << 'CARDEOF'
        <div class="warning-card rounded-lg p-6 mb-6 shadow-md">
            <h3 class="text-xl font-semibold text-warning mb-4 flex items-center">
                <span class="text-2xl mr-2">❌</span> 
CARDEOF
            printf '%s\n' "$title" >> security_report.html
            cat >> security_report.html << 'CARDEOF'
            </h3>
            <div class="space-y-3">
CARDEOF
          elif [[ "$line" =~ ^-\ \*\*.*\*\*:.*$ ]]; then
            # Property line - extract property and value properly
            property=$(echo "$line" | sed 's/^- \*\*\([^*]*\)\*\*: .*/\1/')
            value=$(echo "$line" | sed 's/^- \*\*[^*]*\*\*: \(.*\)/\1/')
            
            # Handle code snippets in values
            if [[ "$value" =~ \`.*\` ]]; then
              value=$(echo "$value" | sed 's/`\([^`]*\)`/<code class="bg-gray-100 text-danger px-2 py-1 rounded text-sm font-mono">\1<\/code>/g')
            fi
            
            # Escape HTML characters
            value=$(printf '%s\n' "$value" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            property=$(printf '%s\n' "$property" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            
            cat >> security_report.html << PROPEOF
                <div class="flex items-start mb-3">
                    <span class="font-semibold text-titan-dark min-w-0 mr-2">$property:</span>
                    <span class="text-gray-700 flex-1">$value</span>
                </div>
PROPEOF
          elif [[ "$line" =~ ^\`\`\`$ ]]; then
            # Start or end code block
            if [[ "$in_code_block" == "true" ]]; then
              cat >> security_report.html << 'CODEEOF'
                    </pre>
                </div>
CODEEOF
              in_code_block="false"
            else
              cat >> security_report.html << 'CODEEOF'
                <div class="code-block rounded-lg p-4 my-4 overflow-x-auto shadow-inner">
                    <pre class="text-green-300 text-sm font-mono whitespace-pre-wrap">
CODEEOF
              in_code_block="true"
            fi
          elif [[ "$in_code_block" == "true" ]]; then
            # Code content - escape HTML and preserve formatting
            escaped_line=$(printf '%s\n' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')
            printf '%s\n' "$escaped_line" >> security_report.html
          elif [[ "$line" == "" ]]; then
            # Empty line - close current card if we're in one
            if [[ "$prev_line" =~ ^- ]] || [[ "$prev_line" =~ ^\`\`\`$ ]]; then
              cat >> security_report.html << 'CLOSEEOF'
            </div>
        </div>

CLOSEEOF
            fi
          fi
          prev_line="$line"
        done
        
        # Close any remaining open card
        cat >> security_report.html << 'FINALEOF'
            </div>
        </div>
FINALEOF

        # Add configuration section
        cat >> security_report.html << HTMLEOF
        
        <div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>
        
        <h2 class="text-3xl font-semibold text-titan-blue mt-12 mb-6 pb-3 border-b-2 border-titan-blue">🔍 Scan Configuration</h2>
        
        <div class="bg-gray-50 rounded-lg p-6">
            <ul class="space-y-2">
                <li class="flex"><span class="font-semibold text-titan-dark mr-2">Excluded Files:</span><span class="text-gray-700">${EXCLUDE_FILES:-"None"}</span></li>
                <li class="flex"><span class="font-semibold text-titan-dark mr-2">Blocking Mode:</span><span class="text-gray-700">$BLOCKING</span></li>
                <li class="flex"><span class="font-semibold text-titan-dark mr-2">Block Percentage Threshold:</span><span class="text-gray-700">$BLOCK_PERCENTAGE%</span></li>
                <li class="flex"><span class="font-semibold text-titan-dark mr-2">Timeout:</span><span class="text-gray-700">$TIMEOUT_SECONDS seconds</span></li>
            </ul>
        </div>
        
        <div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>
        
        <div class="text-center text-gray-500 italic mt-8">
            <em>Report generated by TITAN Security Scanner</em>
        </div>
        
    </div>
</body>
</html>
HTMLEOF
        wkhtmltopdf --page-size A4 --margin-top 15mm --margin-right 15mm --margin-bottom 15mm --margin-left 15mm security_report.html security_report.pdf 2>/dev/null && {
          echo "PDF report saved as security_report.pdf"
          rm -f security_report.html
        } || {
          echo "wkhtmltopdf conversion failed, keeping HTML and markdown versions"
          echo "HTML report saved as security_report.html"
          echo "Markdown report saved as security_report.md"
        }
      else
        echo "No PDF converters available. Saving as markdown only."
        echo "Markdown report saved as security_report.md"
        echo "To generate PDF: install wkhtmltopdf or Node.js, then run the conversion manually"
      fi
    fi
  else
    echo "PDF generator script not found, saving as markdown only"
    echo "Markdown report saved as security_report.md"
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
exit 0