#!/bin/bash

set -e

# Validate required environment variables
if [ -z "$API_BASE_URL" ]; then
  echo "Error: API_BASE_URL environment variable is required."
  exit 1
fi

if [ -z "$GROUP_ID" ]; then
  echo "Error: GROUP_ID environment variable is required."
  exit 1
fi

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

echo "Checking scan progress..."
echo "API Base URL: $API_BASE_URL"
echo "Group ID: $GROUP_ID"
echo "Report Format: $REPORT_FORMAT"
echo "Timeout: $TIMEOUT_SECONDS seconds"
echo "Exclude files patterns: $EXCLUDE_FILES"
echo "Blocking mode: $BLOCKING"
echo "Block percentage threshold: $BLOCK_PERCENTAGE%"

# Construct the progress endpoint URL
PROGRESS_ENDPOINT="${API_BASE_URL%/}/parser/groups/${GROUP_ID}/results"

echo "Polling progress endpoint: $PROGRESS_ENDPOINT"

# Poll until completed + failed == total
while true; do
  RESPONSE=$(curl -s --max-time "$TIMEOUT_SECONDS" -X GET "$PROGRESS_ENDPOINT" \
    -H "Content-Type: application/json")

  if [ $? -ne 0 ]; then
    echo "Error: Failed to check progress - API request timed out or failed"
    exit 1
  fi

  # Parse summary from response (nested in 'summary' object)
  COMPLETED=$(echo "$RESPONSE" | grep -o '"summary":\s*{' | sed 's/.*"summary":\s*{//' | grep -o '"completed":\s*[0-9]*' | sed 's/"completed":\s*//' || echo "")
  if [ -z "$COMPLETED" ]; then
    COMPLETED=$(echo "$RESPONSE" | grep -o '"completed":\s*[0-9]*' | sed 's/"completed":\s*//' | head -1)
  fi
  
  FAILED=$(echo "$RESPONSE" | grep -o '"summary":\s*{' | sed 's/.*"summary":\s*{//' | grep -o '"failed":\s*[0-9]*' | sed 's/"failed":\s*//' || echo "")
  if [ -z "$FAILED" ]; then
    FAILED=$(echo "$RESPONSE" | grep -o '"failed":\s*[0-9]*' | sed 's/"failed":\s*//' | head -1)
  fi
  
  TOTAL=$(echo "$RESPONSE" | grep -o '"summary":\s*{' | sed 's/.*"summary":\s*{//' | grep -o '"total":\s*[0-9]*' | sed 's/"total":\s*//' || echo "")
  if [ -z "$TOTAL" ]; then
    TOTAL=$(echo "$RESPONSE" | grep -o '"total":\s*[0-9]*' | sed 's/"total":\s*//' | head -1)
  fi

  if [ -z "$COMPLETED" ] || [ -z "$FAILED" ] || [ -z "$TOTAL" ]; then
    echo "Error: Failed to parse summary from response"
    echo "Response: $RESPONSE"
    exit 1
  fi

  echo "Progress: Completed: $COMPLETED, Failed: $FAILED, Total: $TOTAL"

  if [ $((COMPLETED + FAILED)) -eq $TOTAL ]; then
    echo "Scan completed."
    FINAL_RESPONSE="$RESPONSE"
    break
  fi

  # Wait before next poll
  sleep 10
done

# Parse jobs array to get detailed results
echo "Parsing scan results..."

# Extract jobs array and count vulnerabilities
if command -v jq >/dev/null 2>&1; then
  echo "Using jq for JSON parsing"
  JOBS_DATA=$(echo "$FINAL_RESPONSE" | jq -r '.jobs[] | @json')
else
  echo "jq not available, using sed fallback"
  JOBS_DATA=$(echo "$FINAL_RESPONSE" | sed -n '/"jobs":\s*\[/,/]/p' | sed '1d;$d' | tr -d '\n' | sed 's/},/}\n/g')
fi

echo "JOBS_DATA length: ${#JOBS_DATA}"
echo "JOBS_DATA preview: $(echo "$JOBS_DATA" | head -c 200)"

ISSUE_COUNT=0
TOTAL_FILES=0
FAILED_FILES=0
RESULTS_DETAILS=""
RESULTS_DETAILS_XML=""
VULNERABLE_RESULTS=""
CLEAN_RESULTS=""

# Process each job
while IFS= read -r job; do
  if [ -z "$job" ]; then
    continue
  fi
  
  # Extract job status
  if command -v jq >/dev/null 2>&1; then
    JOB_STATUS=$(echo "$job" | jq -r '.status // "unknown"')
  else
    JOB_STATUS=$(echo "$job" | grep -o '"status":\s*"[^"]*"' | sed 's/"status":\s*"//' | sed 's/".*//' | head -1)
  fi
  
  # Extract detailed information from input and result objects
  if command -v jq >/dev/null 2>&1; then
    FILE_PATH=$(echo "$job" | jq -r '.input.filePath // empty')
    FUNCTION_NAME=$(echo "$job" | jq -r '.input.functionName // empty')
    START_LINE=$(echo "$job" | jq -r '.input.startLine // empty')
    END_LINE=$(echo "$job" | jq -r '.input.endLine // empty')
    CODE_SNIPPET=$(echo "$job" | jq -r '.input.code // empty')
    
    IS_VULNERABLE=$(echo "$job" | jq -r '.result.is_vulnerable // false')
    SCORE=$(echo "$job" | jq -r '.result.score // 0')
    CONFIDENCE=$(echo "$job" | jq -r '.result.confidence_percent // "0%"')
    SEVERITY=$(echo "$job" | jq -r '.result.severity // "UNKNOWN"')
    INFERENCE_TIME=$(echo "$job" | jq -r '.result.inference_time_seconds // 0')
    CODE_LENGTH=$(echo "$job" | jq -r '.result.code_length // 0')
    ANALYSIS=$(echo "$job" | jq -r '.result.analysis // empty')
    PREDICTION=$(echo "$job" | jq -r '.result.prediction // 0')
    THRESHOLD=$(echo "$job" | jq -r '.result.threshold // 0.6')
  else
    # Fallback sed parsing (less reliable)
    FILE_PATH=$(echo "$job" | grep -o '"input":\s*{[^}]*"filePath":\s*"[^"]*"' | sed 's/.*"filePath":\s*"//' | sed 's/".*//')
    FUNCTION_NAME=$(echo "$job" | grep -o '"input":\s*{[^}]*"functionName":\s*"[^"]*"' | sed 's/.*"functionName":\s*"//' | sed 's/".*//')
    START_LINE=$(echo "$job" | grep -o '"input":\s*{[^}]*"startLine":\s*[0-9]*' | sed 's/.*"startLine":\s*//' | head -1)
    END_LINE=$(echo "$job" | grep -o '"input":\s*{[^}]*"endLine":\s*[0-9]*' | sed 's/.*"endLine":\s*//' | head -1)
    CODE_SNIPPET=$(echo "$job" | sed -n 's/.*"input":\s*{[^}]*"code":\s*"\([^"]*\)".*/\1/p' | head -1)
    
    IS_VULNERABLE=$(echo "$job" | grep -o '"result":\s*{[^}]*"is_vulnerable":\s*\(true\|false\)' | sed 's/.*"is_vulnerable":\s*//' | head -1)
    SCORE=$(echo "$job" | grep -o '"result":\s*{[^}]*"score":\s*[0-9.]*' | sed 's/.*"score":\s*//' | head -1)
    CONFIDENCE=$(echo "$job" | grep -o '"result":\s*{[^}]*"confidence_percent":\s*"[^"]*"' | sed 's/.*"confidence_percent":\s*"//' | sed 's/".*//' | head -1)
    SEVERITY=$(echo "$job" | grep -o '"result":\s*{[^}]*"severity":\s*"[^"]*"' | sed 's/.*"severity":\s*"//' | sed 's/".*//' | head -1)
    INFERENCE_TIME=$(echo "$job" | grep -o '"result":\s*{[^}]*"inference_time_seconds":\s*[0-9.]*' | sed 's/.*"inference_time_seconds":\s*//' | head -1)
    CODE_LENGTH=$(echo "$job" | grep -o '"result":\s*{[^}]*"code_length":\s*[0-9]*' | sed 's/.*"code_length":\s*//' | head -1)
    ANALYSIS=$(echo "$job" | grep -o '"result":\s*{[^}]*"analysis":\s*"[^"]*"' | sed 's/.*"analysis":\s*"//' | sed 's/".*//' | head -1)
    PREDICTION=$(echo "$job" | grep -o '"result":\s*{[^}]*"prediction":\s*[0-9]*' | sed 's/.*"prediction":\s*//' | head -1)
    THRESHOLD=$(echo "$job" | grep -o '"result":\s*{[^}]*"threshold":\s*[0-9.]*' | sed 's/.*"threshold":\s*//' | head -1)
  fi
  
  # Handle failed jobs separately
  if [ "$JOB_STATUS" != "completed" ]; then
    FAILED_FILES=$((FAILED_FILES + 1))
    RESULTS_DETAILS+="### ❌ Failed to Scan: $FILE_PATH"$'\n'
    RESULTS_DETAILS+="- **Function:** \`$FUNCTION_NAME\`"$'\n'
    RESULTS_DETAILS+="- **Lines:** $START_LINE-$END_LINE"$'\n'
    RESULTS_DETAILS+="- **Status:** Scan failed"$'\n'$'\n'
    
    RESULTS_DETAILS_XML+="<failed><file>$FILE_PATH</file><function>$FUNCTION_NAME</function><lines>$START_LINE-$END_LINE</lines><status>failed</status></failed>"
    continue
  fi
  
  # Only count completed jobs for scoring
  TOTAL_FILES=$((TOTAL_FILES + 1))
  
  if [ "$IS_VULNERABLE" = "true" ]; then
    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    
    # Clean up code snippet - remove escape sequences and handle long code
    CLEAN_CODE=$(echo "$CODE_SNIPPET" | sed 's/\\n/\n/g' | sed 's/\\t/    /g' | sed 's/\\"/"/g')
    
    # Truncate code snippet if too long (max 500 chars for better readability)
    if [ ${#CLEAN_CODE} -gt 500 ]; then
      TRUNCATED_CODE=$(echo "$CLEAN_CODE" | cut -c1-500)
      TRUNCATED_CODE="${TRUNCATED_CODE}..."
    else
      TRUNCATED_CODE="$CLEAN_CODE"
    fi
    
    VULNERABLE_RESULTS+="### 🚨 Vulnerability Found: $FILE_PATH"$'\n'
    VULNERABLE_RESULTS+="- **Function:** \`$FUNCTION_NAME\`"$'\n'
    VULNERABLE_RESULTS+="- **Lines:** $START_LINE-$END_LINE"$'\n'
    VULNERABLE_RESULTS+="- **Severity:** $SEVERITY"$'\n'
    VULNERABLE_RESULTS+="- **Score:** $SCORE ($CONFIDENCE confidence)"$'\n'
    VULNERABLE_RESULTS+="- **Prediction:** $PREDICTION (threshold: $THRESHOLD)"$'\n'
    if [ -n "$ANALYSIS" ] && [ "$ANALYSIS" != "null" ] && [ "$ANALYSIS" != "empty" ]; then
      # Truncate analysis if too long (max 800 chars for readability)
      if [ ${#ANALYSIS} -gt 800 ]; then
        TRUNCATED_ANALYSIS=$(echo "$ANALYSIS" | cut -c1-800)
        TRUNCATED_ANALYSIS="${TRUNCATED_ANALYSIS}..."
      else
        TRUNCATED_ANALYSIS="$ANALYSIS"
      fi
      VULNERABLE_RESULTS+="- **Analysis:** $TRUNCATED_ANALYSIS"$'\n'
    fi
    VULNERABLE_RESULTS+="- **Code Length:** $CODE_LENGTH characters"$'\n'
    VULNERABLE_RESULTS+="- **Inference Time:** ${INFERENCE_TIME}s"$'\n'
    VULNERABLE_RESULTS+="- **Code Snippet:**"$'\n'
    VULNERABLE_RESULTS+="\`\`\`"$'\n'
    VULNERABLE_RESULTS+="$TRUNCATED_CODE"$'\n'
    VULNERABLE_RESULTS+="\`\`\`"$'\n'$'\n'
    
    RESULTS_DETAILS_XML+="<vulnerability><file>$FILE_PATH</file><function>$FUNCTION_NAME</function><lines>$START_LINE-$END_LINE</lines><severity>$SEVERITY</severity><score>$SCORE</score><confidence>$CONFIDENCE</confidence><prediction>$PREDICTION</prediction><threshold>$THRESHOLD</threshold><analysis><![CDATA[$ANALYSIS]]></analysis><codeLength>$CODE_LENGTH</codeLength><inferenceTime>$INFERENCE_TIME</inferenceTime><codeSnippet><![CDATA[$CODE_SNIPPET]]></codeSnippet></vulnerability>"
  else
    # Clean up code snippet for clean functions too
    CLEAN_CODE=$(echo "$CODE_SNIPPET" | sed 's/\\n/\n/g' | sed 's/\\t/    /g' | sed 's/\\"/"/g')
    
    # Truncate code snippet if too long (max 500 chars for better readability)
    if [ ${#CLEAN_CODE} -gt 500 ]; then
      TRUNCATED_CODE=$(echo "$CLEAN_CODE" | cut -c1-500)
      TRUNCATED_CODE="${TRUNCATED_CODE}..."
    else
      TRUNCATED_CODE="$CLEAN_CODE"
    fi
    
    CLEAN_RESULTS+="### ✅ Clean: $FILE_PATH"$'\n'
    CLEAN_RESULTS+="- **Function:** \`$FUNCTION_NAME\`"$'\n'
    CLEAN_RESULTS+="- **Lines:** $START_LINE-$END_LINE"$'\n'
    CLEAN_RESULTS+="- **Score:** $SCORE ($CONFIDENCE confidence)"$'\n'
    CLEAN_RESULTS+="- **Status:** No security issues detected"$'\n'
    CLEAN_RESULTS+="- **Code Length:** $CODE_LENGTH characters"$'\n'
    CLEAN_RESULTS+="- **Inference Time:** ${INFERENCE_TIME}s"$'\n'
    CLEAN_RESULTS+="- **Code Snippet:**"$'\n'
    CLEAN_RESULTS+="\`\`\`"$'\n'
    CLEAN_RESULTS+="$TRUNCATED_CODE"$'\n'
    CLEAN_RESULTS+="\`\`\`"$'\n'$'\n'
    
    RESULTS_DETAILS_XML+="<file><path>$FILE_PATH</path><function>$FUNCTION_NAME</function><lines>$START_LINE-$END_LINE</lines><status>clean</status><score>$SCORE</score><confidence>$CONFIDENCE</confidence><codeLength>$CODE_LENGTH</codeLength><inferenceTime>$INFERENCE_TIME</inferenceTime><codeSnippet><![CDATA[$CODE_SNIPPET]]></codeSnippet></file>"
  fi
done < <(echo "$JOBS_DATA")

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
| **Group ID** | $GROUP_ID |
| **Total Functions Processed** | $((TOTAL_FILES + FAILED_FILES)) |
| **Successfully Scanned Functions** | $TOTAL_FILES |
| **Failed to Scan Functions** | $FAILED_FILES |
| **Vulnerable Functions** | $ISSUE_COUNT |
| **Clean Functions** | $((TOTAL_FILES - ISSUE_COUNT)) |
| **Vulnerability Rate** | $PERCENT% |
| **Average Inference Time** | $(echo "$JOBS_DATA" | grep -o '"inference_time_seconds":\s*[0-9.]*' | sed 's/"inference_time_seconds":\s*//' | awk '{sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "0.00"}')s |

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
| **Group ID** | $GROUP_ID |
| **Total Functions Processed** | $((TOTAL_FILES + FAILED_FILES)) |
| **Successfully Scanned Functions** | $TOTAL_FILES |
| **Failed to Scan Functions** | $FAILED_FILES |
| **Vulnerable Functions** | $ISSUE_COUNT |
| **Clean Functions** | $((TOTAL_FILES - ISSUE_COUNT)) |
| **Vulnerability Rate** | $PERCENT% |
| **Average Inference Time** | $(echo "$JOBS_DATA" | grep -o '"inference_time_seconds":\s*[0-9.]*' | sed 's/"inference_time_seconds":\s*//' | awk '{sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "0.00"}')s |

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
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Group ID</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$GROUP_ID</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Total Functions Processed</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$((TOTAL_FILES + FAILED_FILES))</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Successfully Scanned Functions</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$TOTAL_FILES</td>
                </tr>
                <tr class="hover:bg-blue-50 transition-colors duration-200">
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200"><span class="font-semibold text-titan-dark">Failed to Scan Functions</span></td>
                    <td class="px-4 py-3 text-gray-700 border-b border-gray-200">$FAILED_FILES</td>
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
    <groupId>$GROUP_ID</groupId>
    <totalFunctionsProcessed>$((TOTAL_FILES + FAILED_FILES))</totalFunctionsProcessed>
    <successfullyScannedFunctions>$TOTAL_FILES</successfullyScannedFunctions>
    <failedFunctions>$FAILED_FILES</failedFunctions>
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
    <scanDetails>
      <totalFunctionsProcessed>$((TOTAL_FILES + FAILED_FILES))</totalFunctionsProcessed>
      <successfullyScannedFunctions>$TOTAL_FILES</successfullyScannedFunctions>
      <failedFunctions>$FAILED_FILES</failedFunctions>
      <vulnerableFunctions>$ISSUE_COUNT</vulnerableFunctions>
      <cleanFunctions>$((TOTAL_FILES - ISSUE_COUNT))</cleanFunctions>
      <averageInferenceTime>$(echo "$JOBS_DATA" | grep -o '"inference_time_seconds":\s*[0-9.]*' | sed 's/"inference_time_seconds":\s*//' | awk '{sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count; else print "0.00"}')s</averageInferenceTime>
    </scanDetails>
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

echo "Security scan completed successfully. Found $ISSUE_COUNT vulnerable functions out of $TOTAL_FILES successfully scanned functions ($PERCENT%), with $FAILED_FILES functions that failed to scan."
exit 0