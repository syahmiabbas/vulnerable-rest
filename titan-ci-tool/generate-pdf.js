#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// Check if proper arguments are provided
if (process.argv.length < 4) {
  console.log('Usage: node generate-pdf.js <markdown-file> <output-pdf-file>');
  process.exit(1);
}

const markdownFile = process.argv[2];
const outputPdfFile = process.argv[3];

// Check if markdown file exists
if (!fs.existsSync(markdownFile)) {
  console.error(`Error: Markdown file '${markdownFile}' not found.`);
  process.exit(1);
}

// Read markdown content
const markdownContent = fs.readFileSync(markdownFile, 'utf8');

// Enhanced HTML template for PDF generation with TailwindCSS
function markdownToHtml(markdownContent) {
  // Clean up the content first - handle escaped newlines and improve formatting
  const cleanedContent = markdownContent
    .replace(/\\n/g, '\n')  // Convert literal \n to actual newlines
    .replace(/\\t/g, '    ') // Convert tabs to spaces
    .replace(/\\"/g, '"')    // Fix escaped quotes
    .replace(/\n\n+/g, '\n\n'); // Normalize multiple newlines
  
  // Split content into lines for better processing
  const lines = cleanedContent.split('\n');
  let html = '';
  let inCodeBlock = false;
  let inCard = false;
  let cardType = '';
  let inTable = false;
  let tableRows = [];

  for (let i = 0; i < lines.length; i++) {
    let line = lines[i];
    
    // Handle code blocks
    if (line.trim() === '```') {
      if (inCodeBlock) {
        html += '</pre></div>';
        inCodeBlock = false;
      } else {
        html += '<div class="code-block rounded-lg p-4 my-4 overflow-x-auto shadow-inner"><pre class="text-green-300 text-sm font-mono whitespace-pre-wrap">';
        inCodeBlock = true;
      }
      continue;
    }
    
    if (inCodeBlock) {
      // Escape HTML characters in code and preserve formatting
      html += line.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') + '\n';
      continue;
    }
    
    // Handle headers
    if (line.startsWith('# ')) {
      html += `<h1 class="text-4xl font-bold text-white p-6 mb-8 rounded-lg gradient-header shadow-lg">🛡️ ${line.substring(2)}</h1>`;
    } else if (line.startsWith('## 🚨')) {
      html += `<h2 class="text-3xl font-semibold text-danger mt-12 mb-6 pb-3 border-b-2 border-danger">🚨 ${line.substring(5)}</h2>`;
    } else if (line.startsWith('## ✅')) {
      html += `<h2 class="text-3xl font-semibold text-success mt-12 mb-6 pb-3 border-b-2 border-success">✅ ${line.substring(5)}</h2>`;
    } else if (line.startsWith('## ')) {
      html += `<h2 class="text-3xl font-semibold text-titan-blue mt-12 mb-6 pb-3 border-b-2 border-titan-blue">${line.substring(3)}</h2>`;
    } else if (line.startsWith('### 🚨')) {
      // Close previous card if any
      if (inCard) {
        html += '</div></div>';
      }
      html += `<div class="vulnerability-card rounded-lg p-6 mb-6 shadow-md">
                 <h3 class="text-xl font-semibold text-danger mb-4 flex items-center">
                   <span class="text-2xl mr-2">🚨</span>${line.substring(6)}
                 </h3>
                 <div class="space-y-3">`;
      inCard = true;
      cardType = 'vulnerability';
    } else if (line.startsWith('### ✅')) {
      // Close previous card if any
      if (inCard) {
        html += '</div></div>';
      }
      html += `<div class="success-card rounded-lg p-6 mb-6 shadow-md">
                 <h3 class="text-xl font-semibold text-success mb-4 flex items-center">
                   <span class="text-2xl mr-2">✅</span>${line.substring(6)}
                 </h3>
                 <div class="space-y-3">`;
      inCard = true;
      cardType = 'success';
    } else if (line.startsWith('### ❌')) {
      // Close previous card if any
      if (inCard) {
        html += '</div></div>';
      }
      html += `<div class="warning-card rounded-lg p-6 mb-6 shadow-md">
                 <h3 class="text-xl font-semibold text-warning mb-4 flex items-center">
                   <span class="text-2xl mr-2">❌</span>${line.substring(6)}
                 </h3>
                 <div class="space-y-3">`;
      inCard = true;
      cardType = 'warning';
    } else if (line.startsWith('### ')) {
      // Close card for regular h3
      if (inCard) {
        html += '</div></div>';
        inCard = false;
      }
      html += `<h3 class="text-xl font-semibold text-gray-700 mt-8 mb-4">${line.substring(4)}</h3>`;
    } else if (line.startsWith('#### ')) {
      html += `<h4 class="text-lg font-medium text-gray-600 mt-6 mb-3">${line.substring(5)}</h4>`;
    }
    // Handle table rows
    else if (line.includes('|') && line.trim().startsWith('|') && line.trim().endsWith('|')) {
      if (!inTable) {
        inTable = true;
        tableRows = [];
      }
      
      const cells = line.split('|').map(cell => cell.trim()).filter(cell => cell);
      const isHeader = line.includes('**');
      
      if (isHeader) {
        const headerCells = cells.map(cell => `<td class="px-4 py-3 font-semibold">${cell.replace(/\*\*/g, '')}</td>`).join('');
        tableRows.push(`<tr class="bg-titan-blue text-white">${headerCells}</tr>`);
      } else if (!cells.every(cell => cell.match(/^[-\s]*$/))) { // Skip separator rows
        const bodyCells = cells.map(cell => `<td class="px-4 py-3 text-gray-700 border-b border-gray-200">${cell}</td>`).join('');
        tableRows.push(`<tr class="hover:bg-blue-50 transition-colors duration-200">${bodyCells}</tr>`);
      }
    }
    // Handle list items with better regex
    else if (line.match(/^- \*\*(.*?)\*\*:\s*(.*)$/)) {
      const match = line.match(/^- \*\*(.*?)\*\*:\s*(.*)$/);
      const property = match[1];
      let value = match[2];
      
      // Handle code in values
      value = value.replace(/`([^`]*)`/g, '<code class="bg-gray-100 text-danger px-2 py-1 rounded text-sm font-mono">$1</code>');
      
      html += `<div class="flex items-start mb-3">
                 <span class="font-semibold text-titan-dark min-w-0 mr-2">${property}:</span>
                 <span class="text-gray-700 flex-1">${value}</span>
               </div>`;
    }
    // Handle horizontal rules
    else if (line.trim() === '---') {
      // Close table if we were in one
      if (inTable) {
        html += `<div class="overflow-x-auto my-6">
                   <table class="w-full bg-white rounded-lg shadow-lg overflow-hidden">
                     ${tableRows.join('')}
                   </table>
                 </div>`;
        inTable = false;
        tableRows = [];
      }
      html += '<div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>';
    }
    // Handle empty lines
    else if (line.trim() === '') {
      // Close table if we were in one
      if (inTable) {
        html += `<div class="overflow-x-auto my-6">
                   <table class="w-full bg-white rounded-lg shadow-lg overflow-hidden">
                     ${tableRows.join('')}
                   </table>
                 </div>`;
        inTable = false;
        tableRows = [];
      }
      
      // Close card if we were in one and this appears to be end of card content
      if (inCard && i < lines.length - 1) {
        const nextLine = lines[i + 1];
        if (nextLine && nextLine.trim() !== '' && !nextLine.startsWith('- ') && !nextLine.trim() === '```') {
          html += '</div></div>';
          inCard = false;
        }
      }
    }
    // Handle regular text
    else if (line.trim() !== '') {
      // Apply text formatting
      let formattedLine = line
        .replace(/\*\*(.*?)\*\*/g, '<span class="font-semibold text-titan-dark">$1</span>')
        .replace(/\*(.*?)\*/g, '<span class="italic text-gray-600">$1</span>')
        .replace(/`([^`]*)`/g, '<code class="bg-gray-100 text-danger px-2 py-1 rounded text-sm font-mono">$1</code>');
      
      if (!inCard && !inTable) {
        html += `<p class="mb-4 text-gray-700">${formattedLine}</p>`;
      }
    }
  }

  // Close any remaining open elements
  if (inCodeBlock) {
    html += '</pre></div>';
  }
  if (inCard) {
    html += '</div></div>';
  }
  if (inTable) {
    html += `<div class="overflow-x-auto my-6">
               <table class="w-full bg-white rounded-lg shadow-lg overflow-hidden">
                 ${tableRows.join('')}
               </table>
             </div>`;
  }

  return html;
}

// Generate full HTML document
function createHtmlDocument(content) {
  return `<!DOCTYPE html>
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
        body { font-family: 'Inter', sans-serif; }
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
            .print\\:shadow-none { box-shadow: none !important; }
            .print\\:bg-white { background-color: white !important; }
        }
    </style>
</head>
<body class="bg-gray-50 font-sans leading-relaxed">
    <div class="max-w-5xl mx-auto p-8 bg-white shadow-lg rounded-lg print:shadow-none print:bg-white">
        ${content}
    </div>
</body>
</html>`;
}

// Convert markdown to HTML
const htmlContent = markdownToHtml(markdownContent);
const fullHtml = createHtmlDocument(htmlContent);

// Write HTML to temp file
const tempHtmlFile = path.join(path.dirname(outputPdfFile), 'temp_report.html');
fs.writeFileSync(tempHtmlFile, fullHtml);

console.log('✅ HTML file generated successfully');

// Try different PDF generation methods
let pdfGenerated = false;

// Method 1: Try Chrome/Chromium headless (good quality, but requires Chrome)
if (!pdfGenerated) {
  const chromeCommands = [
    'google-chrome',
    'chromium-browser', 
    'chromium',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe'
  ];
  
  for (const chromeCmd of chromeCommands) {
    try {
      execSync(`"${chromeCmd}" --headless --disable-gpu --print-to-pdf="${outputPdfFile}" --print-to-pdf-no-header "${tempHtmlFile}"`, { stdio: 'pipe' });
      console.log('✅ PDF generated using Chrome/Chromium');
      pdfGenerated = true;
      break;
    } catch (error) {
      // Try next Chrome command
    }
  }
}

// Method 2: Keep HTML as fallback
if (!pdfGenerated) {
  const htmlOutputFile = outputPdfFile.replace('.pdf', '.html');
  fs.copyFileSync(tempHtmlFile, htmlOutputFile);
  console.log(`⚠️  PDF generation failed, but HTML report saved as: ${htmlOutputFile}`);
  console.log('To generate PDF manually, use Chrome/Chromium');
}

// Clean up temp file
try {
  fs.unlinkSync(tempHtmlFile);
} catch (error) {
  // Ignore cleanup errors
}

process.exit(pdfGenerated ? 0 : 1);
