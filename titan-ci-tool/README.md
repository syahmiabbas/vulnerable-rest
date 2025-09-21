# TITAN Repository Security Scan Tool

This tool automates security scanning of your repository using the TITAN API endpoints. It initiates a scan job and monitors progress, generating security reports in multiple formats without requiring API tokens.

## How It Works
- Initiates a security scan by sending the repository URL to the TITAN API
- Monitors scan progress until completion
- Generates reports in Markdown, PDF, or XML format
- Provides configurable timeout and blocking behavior
- No API tokens required for authentication

## Setup
1. **Add the Tool to Your Repository**
   - Copy the contents of the `titan-ci-tool` folder into your repository.

2. **Configure Your API Settings**
   - Set up your API base URL as a GitHub secret or environment variable.

## Publishing as a Reusable GitHub Action

This tool can be published as a reusable GitHub Action. To do so:

1. Ensure your repository contains the `titan-ci-tool` folder with `action.yml`, `entrypoint.sh`, and other required files.
2. Push your repository to GitHub (public or private).
3. Reference the action in your workflow using the `uses:` syntax.

### Example Workflow Usage
```yaml
name: Security Scan
on:
   push:
      branches: [ main ]
   pull_request:
      branches: [ main ]

jobs:
   security-scan:
      runs-on: ubuntu-latest
      steps:
         - name: Checkout repository
            uses: actions/checkout@v4

         - name: Run TITAN Security Scan
            uses: <your-org>/<your-repo>/titan-ci-tool@main
            with:
               api_base_url: 'https://your-titan-api.com/parser/async'
               report_format: 'md'
               timeout_seconds: 300
               exclude_files: '*.md,tests/*'
               blocking: true
               block_percentage: 50

         - name: Upload security report
            uses: actions/upload-artifact@v4
            with:
               name: security-report
               path: security_report.*
```

Replace `<your-org>/<your-repo>` with your actual GitHub organization and repository name.

### Inputs
- `api_base_url` (required): URL for the backend API
- `report_format` (optional): The report output format type (md|pdf|xml). Default: md
- `timeout_seconds` (optional): Timeout to call the API before failing (in seconds). Default: 300
- `exclude_files` (optional): Comma-separated list of file patterns to exclude from scanning (glob)
- `blocking` (optional): Whether this step is blocking (fail on issues) or non-blocking. Default: true
- `block_percentage` (optional): Percentage of files with issues required to block. Default: 50

## Output
- The scan results are saved in the specified format (`security_report.md`, `security_report.pdf`, or `security_report.xml`).
- **Enhanced Formatting**: All formats include risk assessment, detailed findings, and actionable recommendations
- **Markdown**: Clean formatting with emoji icons, tables, and sections
- **PDF**: Professional layout with table of contents, executive summary, and styling (requires pandoc)
- **XML**: Structured format for tool integration and automated processing
- If blocking mode is enabled and issues exceed the threshold, the step will fail.
- Detailed logs show which files are scanned and any issues found.

## Customization
- The tool uses two API endpoints: `/initiate` for starting scans and `/progress/{groupId}` for monitoring
- Initiates scan by posting repository URL to the initiate endpoint
- Polls progress endpoint until scan completion
- **PDF generation** requires `pandoc` and `xelatex` for optimal formatting
- **Report formats** include professional styling and risk assessment levels
- **XML output** provides structured data for integration with security tools and CI/CD pipelines

## Report Features

### Markdown Format (md)
- 🛡️ Professional header with emoji icons
- 📊 Summary table with scan metrics
- 📁 Detailed findings section
- 🔍 Configuration overview
- Clean, readable formatting for GitHub/GitLab

### PDF Format (pdf) 
- Executive summary with risk assessment
- Professional layout with headers and footers
- Table of contents for easy navigation
- Color-coded risk levels (🟢 LOW, 🟡 MEDIUM, 🟠 HIGH, 🔴 CRITICAL)
- Actionable recommendations section
- Requires `pandoc` and `xelatex` for optimal rendering

### XML Format (xml)
- Structured data format for tool integration
- Machine-readable findings and metadata
- CDATA sections for safe content handling
- Suitable for CI/CD pipeline automation
- Easy parsing for security dashboards

## Example Usage

```yaml
- name: Run TITAN Security Scan
  uses: <your-org>/<your-repo>/titan-ci-tool@main
  with:
    api_base_url: 'https://your-titan-api.com/api'
    report_format: 'pdf'
    timeout_seconds: 600
    exclude_files: '*.md,tests/*,docs/*'
    blocking: true
    block_percentage: 25
```

The configuration will:
- Generate a professional PDF report with risk assessment
- Set a 10-minute timeout for API calls
- Exclude Markdown files, tests, and docs folders
- Block the pipeline if 25% or more of files have issues
