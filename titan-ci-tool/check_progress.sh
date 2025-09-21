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

  # Wait before next poll
  sleep 10
done

# Parse jobs array to get detailed results
echo "Parsing scan results..."

# Extract jobs array and count vulnerabilities
JOBS_DATA=$(echo "$FINAL_RESPONSE" | sed -n '/"jobs":\s*\[/,/]/p' | sed '1d;$d' | tr -d '\n' | sed 's/},/}\n/g')

ISSUE_COUNT=0
TOTAL_FILES=0
RESULTS_DETAILS=""
RESULTS_DETAILS_XML=""

# Process each job
echo "$JOBS_DATA" | while IFS= read -r job; do
  if [ -z "$job" ]; then
    continue
  fi
  
  TOTAL_FILES=$((TOTAL_FILES + 1))
  
  # Extract file path
  FILE_PATH=$(echo "$job" | grep -o '"filePath":\s*"[^"]*"' | sed 's/"filePath":\s*"//' | sed 's/"$//')
  
  # Extract vulnerability status
  IS_VULNERABLE=$(echo "$job" | grep -o '"is_vulnerable":\s*\(true\|false\)' | sed 's/"is_vulnerable":\s*//')
  
  # Extract score
  SCORE=$(echo "$job" | grep -o '"score":\s*[0-9.]*' | sed 's/"score":\s*//')
  
  # Extract severity
  SEVERITY=$(echo "$job" | grep -o '"severity":\s*"[^"]*"' | sed 's/"severity":\s*"//' | sed 's/"$//')
  
  if [ "$IS_VULNERABLE" = "true" ]; then
    ISSUE_COUNT=$((ISSUE_COUNT + 1))
    RESULTS_DETAILS+="### $FILE_PATH\n- **Issue:** Security vulnerability detected (Score: $SCORE, Severity: $SEVERITY)\n\n"
    RESULTS_DETAILS_XML+="<file><path>$FILE_PATH</path><status>issue_found</status><details>Security vulnerability detected (Score: $SCORE, Severity: $SEVERITY)</details></file>"
  else
    RESULTS_DETAILS+="### $FILE_PATH\n- No issues found (Score: $SCORE)\n\n"
    RESULTS_DETAILS_XML+="<file><path>$FILE_PATH</path><status>clean</status><details>No security issues detected (Score: $SCORE)</details></file>"
  fi
done

# Generate report based on format
echo "Generating security report in $REPORT_FORMAT format..."

PERCENT=0
if [ $TOTAL_FILES -gt 0 ]; then
  PERCENT=$((ISSUE_COUNT * 100 / TOTAL_FILES))
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
| **Total Files Scanned** | $TOTAL_FILES |
| **Issues Found** | $ISSUE_COUNT |
| **Success Rate** | $((100 - PERCENT))% |
| **Issue Rate** | $PERCENT% |

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
  # Simple PDF generation
  cat > security_report.md << EOF
# TITAN Security Scan Report

Scan Date: $(date '+%Y-%m-%d %H:%M:%S')
API Endpoint: $API_BASE_URL
Group ID: $GROUP_ID
Total Files Scanned: $TOTAL_FILES
Issues Found: $ISSUE_COUNT
Success Rate: $((100 - PERCENT))%
Issue Rate: $PERCENT%

$RESULTS_DETAILS
EOF
  echo "Report saved as security_report.md (PDF conversion not implemented)"

elif [ "$REPORT_FORMAT" == "xml" ]; then
  # Generate structured XML report
  cat > security_report.xml << EOF
<?xml version="1.0" encoding="UTF-8"?>
<TitanSecurityReport>
  <metadata>
    <scanDate>$(date -Iseconds)</scanDate>
    <apiEndpoint>$API_BASE_URL</apiEndpoint>
    <groupId>$GROUP_ID</groupId>
    <totalFiles>$TOTAL_FILES</totalFiles>
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

echo "Security scan completed successfully. Issues found: $ISSUE_COUNT / $TOTAL_FILES ($PERCENT%)"
exit 0