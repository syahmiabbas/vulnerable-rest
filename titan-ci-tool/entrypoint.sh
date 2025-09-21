#!/bin/bash

set -e

# Function to read YAML config file
# Validate API_BASE_URL format (should be a valid URL)
if [[ ! "$API_BASE_URL" =~ ^http?:// ]]; then
  echo "Error: API_BASE_URL must be a valid HTTP/HTTPS URL. Got: $API_BASE_URL"
  exit 1
fi

# Test basic connectivity to the API base URL
echo "Testing basic connectivity to API base URL..."
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
echo "Base URL connectivity test passed (HTTP $BASE_URL_TEST)"y# Initiate scan by posting repository URL
INITIATE_ENDPOINT="${API_BASE_URL%/}/initiate"

echo "Posting to initiate endpoint: $INITIATE_ENDPOINT"
echo "Request data: {\"url\": \"$REPO_URL\"}"

# Try the request with verbose output first to debug
echo "Testing API connectivity..."
CURL_TEST=$(curl -v --max-time 10 -X POST "$INITIATE_ENDPOINT" \
  -H "Content-Type: application/json" \
  --data "{\"url\": \"$REPO_URL\"}" 2>&1)

echo "Curl verbose output:"
echo "$CURL_TEST"

# Now make the actual request
RESPONSE=$(curl -s --max-time "$TIMEOUT_SECONDS" -X POST "$INITIATE_ENDPOINT" \
  -H "Content-Type: application/json" \
  --data "{\"url\": \"$REPO_URL\"}")

# Check if curl command was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to initiate scan - curl command failed with exit code $?"
  echo "This could indicate network issues, invalid URL, or API service unavailable"
  exit 1
fi
  if [ -f "scan_config.yml" ]; then
    echo "Reading configuration from scan_config.yml..."
    
    # Simple YAML parser for basic key-value pairs
    while IFS=':' read -r key value; do
      # Remove leading/trailing whitespace and quotes
      key=$(echo "$key" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')
      value=$(echo "$value" | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | sed 's/^"//' | sed 's/"$//')
      
      # Skip comments and empty lines
      [[ $key =~ ^# ]] && continue
      [[ -z $key ]] && continue
      
      # Set environment variable if not already set (environment variables take precedence)
      if [ -z "${!key}" ]; then
        export "$key"="$value"
        echo "Set $key=$value from config file"
      fi
    done < scan_config.yml
  fi
}

# Read config file to provide defaults (environment variables from action inputs take precedence)
read_yaml_config()

# Validate required environment variables
if [ -z "$API_BASE_URL" ]; then
  echo "Error: API_BASE_URL environment variable is required."
  exit 1
fi

# Validate API_BASE_URL format (should be a valid URL)
if [[ ! "$API_BASE_URL" =~ ^http?:// ]]; then
  echo "Error: API_BASE_URL must be a valid HTTP/HTTPS URL. Got: $API_BASE_URL"
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

echo "Initiating security scan..."
echo "API Base URL: $API_BASE_URL"

# Get repository URL
REPO_URL="https://github.com/${GITHUB_REPOSITORY}"

echo "Repository URL: $REPO_URL"

# Initiate scan by posting repository URL
INITIATE_ENDPOINT="${API_BASE_URL}"

echo "Posting to initiate endpoint: $INITIATE_ENDPOINT"

RESPONSE=$(curl -s --max-time "$TIMEOUT_SECONDS" -X POST "$INITIATE_ENDPOINT" \
  -H "Content-Type: application/json" \
  --data "{\"url\": \"$REPO_URL\"}")

# Check if curl command was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to initiate scan - API request timed out or failed"
  exit 1
fi

echo "API Response: $RESPONSE"

# Check if response is empty
if [ -z "$RESPONSE" ]; then
  echo "Error: Empty response from API"
  exit 1
fi

# Check if response contains an error
if echo "$RESPONSE" | grep -q '"error"' || echo "$RESPONSE" | grep -q '"status"[[:space:]]*:[[:space:]]*"error"'; then
  echo "Error: API returned an error response"
  echo "Full Response: $RESPONSE"
  exit 1
fi

# Parse groupId from response using multiple methods for robustness
GROUP_ID=""

# Try method 1: grep with sed (original method)
if [ -z "$GROUP_ID" ]; then
  GROUP_ID=$(echo "$RESPONSE" | grep -o '"groupId"[^"]*"[^"]*"' | sed 's/.*"groupId"[^"]*"//' | sed 's/".*//')
fi

# Try method 2: simpler grep approach
if [ -z "$GROUP_ID" ]; then
  GROUP_ID=$(echo "$RESPONSE" | sed -n 's/.*"groupId"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

# Try method 3: awk approach
if [ -z "$GROUP_ID" ]; then
  GROUP_ID=$(echo "$RESPONSE" | awk -F'"groupId"[[:space:]]*:[[:space:]]*"' '{print $2}' | awk -F'"' '{print $1}')
fi

if [ -z "$GROUP_ID" ]; then
  echo "Error: Failed to retrieve groupId from response"
  echo "Full Response: $RESPONSE"
  exit 1
fi

echo "Scan initiated successfully. Group ID: $GROUP_ID"

# Output groupId for next step using new syntax
echo "groupId=$GROUP_ID" >> $GITHUB_OUTPUT

echo "Initiation completed."
