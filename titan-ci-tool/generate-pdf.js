#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Simple HTML template for PDF generation with TailwindCSS
function markdownToHtml(markdownContent) {
  // Basic markdown to HTML conversion with TailwindCSS classes
  let html = markdownContent
    // Headers with TailwindCSS styling
    .replace(/^# (.*$)/gm, '<h1 class="text-4xl font-bold text-white p-6 mb-8 rounded-lg gradient-header shadow-lg">🛡️ $1</h1>')
    .replace(/^## (.*$)/gm, '<h2 class="text-3xl font-semibold text-titan-blue mt-12 mb-6 pb-3 border-b-2 border-titan-blue">$1</h2>')
    .replace(/^### 🚨(.*$)/gm, '<div class="vulnerability-card rounded-lg p-6 mb-6 shadow-md"><h3 class="text-xl font-semibold text-danger mb-4 flex items-center"><span class="text-2xl mr-2">🚨</span>$1</h3>')
    .replace(/^### ✅(.*$)/gm, '<div class="success-card rounded-lg p-6 mb-6 shadow-md"><h3 class="text-xl font-semibold text-success mb-4 flex items-center"><span class="text-2xl mr-2">✅</span>$1</h3>')
    .replace(/^### ❌(.*$)/gm, '<div class="warning-card rounded-lg p-6 mb-6 shadow-md"><h3 class="text-xl font-semibold text-warning mb-4 flex items-center"><span class="text-2xl mr-2">❌</span>$1</h3>')
    .replace(/^### (.*$)/gm, '<h3 class="text-xl font-semibold text-gray-700 mt-8 mb-4">$1</h3>')
    .replace(/^#### (.*$)/gm, '<h4 class="text-lg font-medium text-gray-600 mt-6 mb-3">$1</h4>')
    // Bold and italic with TailwindCSS
    .replace(/\*\*(.*?)\*\*/g, '<span class="font-semibold text-titan-dark">$1</span>')
    .replace(/\*(.*?)\*/g, '<span class="italic text-gray-600">$1</span>')
    // Code styling
    .replace(/```([^`]*)```/g, '<div class="code-block rounded-lg p-4 my-4 overflow-x-auto shadow-inner"><pre class="text-green-300 text-sm font-mono whitespace-pre-wrap">$1</pre></div>')
    .replace(/`([^`]*)`/g, '<code class="bg-gray-100 text-danger px-2 py-1 rounded text-sm font-mono">$1</code>')
    // Tables with TailwindCSS
    .replace(/\|([^\n]+)\|/g, (match, content) => {
      const cells = content.split('|').map(cell => cell.trim()).filter(cell => cell);
      const isHeader = match.includes('**');
      if (isHeader) {
        return '<tr class="bg-titan-blue text-white">' + cells.map(cell => `<td class="px-4 py-3 font-semibold">${cell.replace(/\*\*/g, '')}</td>`).join('') + '</tr>';
      } else {
        return '<tr class="hover:bg-blue-50 transition-colors duration-200">' + cells.map(cell => `<td class="px-4 py-3 text-gray-700 border-b border-gray-200">${cell}</td>`).join('') + '</tr>';
      }
    })
    // Horizontal rules
    .replace(/^---$/gm, '<div class="my-8"><hr class="border-0 h-px bg-gradient-to-r from-titan-blue to-gray-300"></div>')
    // List items with TailwindCSS
    .replace(/^- \*\*(.*?)\*\*: (.*$)/gm, '<div class="flex items-start mb-3"><span class="font-semibold text-titan-dark min-w-0 mr-2">$1:</span><span class="text-gray-700 flex-1">$2</span></div>')
    // Line breaks
    .replace(/\n\n/g, '</div><div class="mb-4">')
    .replace(/\n/g, '<br>');

  // Wrap table rows in table tags with TailwindCSS styling
  html = html.replace(/(<tr>.*?<\/tr>)/g, (match) => {
    if (!match.includes('<table>')) {
      return `<div class="overflow-x-auto my-6"><table class="w-full bg-white rounded-lg shadow-lg overflow-hidden">${match}</table></div>`;
    }
    return match;
  });

  // Close any open vulnerability/success/warning cards
  html = html.replace(/(<div class="(?:vulnerability-card|success-card|warning-card)[^>]*>.*?)(<h[1-6]|<div class="(?:vulnerability-card|success-card|warning-card)|$)/g, '$1</div>$2');

  // Wrap content in main container
  html = '<div class="mb-4">' + html + '</div>';
  
  return html;
}

function generatePdfReport(markdownFile, outputFile) {
  try {
    // Read the markdown file
    const markdownContent = fs.readFileSync(markdownFile, 'utf8');
    
    // Convert markdown to HTML
    const htmlContent = markdownToHtml(markdownContent);
    
    // Create a complete HTML document with TailwindCSS
    const htmlDocument = `
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
                    },
                    fontFamily: {
                        'sans': ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                    },
                }
            }
        }
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
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
        .gradient-header {
            background: linear-gradient(135deg, #1e3a8a 0%, #2c5aa0 50%, #3b82f6 100%);
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
        ${htmlContent}
    </div>
</body>
</html>`;
    // Try to use wkhtmltopdf if available (lightweight alternative)
    const { exec } = require('child_process');
    
    // Save the HTML file first
    const htmlFile = outputFile.replace('.pdf', '.html');
    fs.writeFileSync(htmlFile, htmlDocument);
    
    // Try different lightweight PDF converters
    exec('which wkhtmltopdf', (error) => {
      if (!error) {
        // wkhtmltopdf is available
        exec(`wkhtmltopdf --page-size A4 --margin-top 15mm --margin-right 15mm --margin-bottom 15mm --margin-left 15mm "${htmlFile}" "${outputFile}"`, (error) => {
          if (error) {
            console.log('wkhtmltopdf failed, keeping HTML version');
            console.log(`HTML report saved as ${htmlFile}`);
          } else {
            console.log(`PDF report saved as ${outputFile}`);
            // Remove HTML file after successful PDF generation
            fs.unlinkSync(htmlFile);
          }
        });
      } else {
        // Check if chromium/google-chrome is available for headless PDF generation
        exec('which google-chrome || which chromium-browser || which chromium', (error, stdout) => {
          if (!error && stdout.trim()) {
            const browser = stdout.trim();
            exec(`"${browser}" --headless --disable-gpu --print-to-pdf="${outputFile}" --no-margins "${htmlFile}"`, (error) => {
              if (error) {
                console.log('Chrome/Chromium PDF generation failed, keeping HTML version');
                console.log(`HTML report saved as ${htmlFile}`);
              } else {
                console.log(`PDF report saved as ${outputFile}`);
                // Remove HTML file after successful PDF generation
                fs.unlinkSync(htmlFile);
              }
            });
          } else {
            // No PDF converters available, just keep the HTML
            console.log('No PDF converters available (wkhtmltopdf, chrome, chromium)');
            console.log(`Styled HTML report saved as ${htmlFile}`);
            console.log('You can open this HTML file in a browser and print to PDF manually');
          }
        });
      }
    });
    
  } catch (error) {
    console.error('Error generating PDF report:', error.message);
    process.exit(1);
  }
}

// Main execution
if (require.main === module) {
  const args = process.argv.slice(2);
  if (args.length !== 2) {
    console.error('Usage: node generate-pdf.js <markdown-file> <output-pdf-file>');
    process.exit(1);
  }
  
  const [markdownFile, outputFile] = args;
  
  if (!fs.existsSync(markdownFile)) {
    console.error(`Error: Markdown file "${markdownFile}" not found`);
    process.exit(1);
  }
  
  generatePdfReport(markdownFile, outputFile);
}

module.exports = { generatePdfReport };