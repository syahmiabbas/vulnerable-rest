#!/bin/bash

set -e

# Function to read YAML config file
read_yaml_config() {
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
INITIATE_ENDPOINT="${API_BASE_URL%/}/initiate"

echo "Posting to initiate endpoint: $INITIATE_ENDPOINT"

RESPONSE=$(curl -s --max-time "$TIMEOUT_SECONDS" -X POST "$INITIATE_ENDPOINT" \
  -H "Content-Type: application/json" \
  --data "{\"url\": \"$REPO_URL\"}")

# Check if curl command was successful
if [ $? -ne 0 ]; then
  echo "Error: Failed to initiate scan - API request timed out or failed"
  exit 1
fi

# Check HTTP status (assuming curl -s doesn't show it, but we can check response)
# For simplicity, assume if response is not empty and contains groupId, it's 200

# Parse groupId from response (assume JSON with 'groupId')
GROUP_ID=$(echo "$RESPONSE" | grep -o '"groupId": *"[^"]*"' | sed 's/"groupId": *"//;s/"$//')

if [ -z "$GROUP_ID" ]; then
  echo "Error: Failed to retrieve groupId from response"
  echo "Response: $RESPONSE"
  exit 1
fi

echo "Scan initiated successfully. Group ID: $GROUP_ID"

# Output groupId for next step
echo "::set-output name=groupId::$GROUP_ID"

echo "Initiation completed."

# Output groupId for next step
echo "::set-output name=groupId::$GROUP_ID"

echo "Initiation completed."
