package output

// HTML template for report generation
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Detection Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .timestamp {
            opacity: 0.9;
            font-size: 0.9em;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 2px solid #e9ecef;
        }
        .summary-item {
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-value {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }
        .summary-label {
            color: #6c757d;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        thead {
            background: #667eea;
            color: white;
        }
        th, td {
            padding: 15px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        th {
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        tr:hover {
            background: #f8f9fa;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-success {
            background: #d4edda;
            color: #155724;
        }
        .badge-danger {
            background: #f8d7da;
            color: #721c24;
        }
        .badge-warning {
            background: #fff3cd;
            color: #856404;
        }
        .confidence {
            font-weight: 600;
            color: #667eea;
        }
        footer {
            text-align: center;
            padding: 20px;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.9em;
        }
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ WAF Detection Report</h1>
            <p class="timestamp">Generated on {{ .Time }}</p>
        </header>

        <div class="summary">
            <div class="summary-item">
                <div class="summary-value">{{ .Summary.TotalScanned }}</div>
                <div class="summary-label">Total Scanned</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{{ .Summary.WAFsDetected }}</div>
                <div class="summary-label">WAFs Detected</div>
            </div>
            <div class="summary-item">
                <div class="summary-value">{{ .Summary.Errors }}</div>
                <div class="summary-label">Errors</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>URL</th>
                    <th>Status</th>
                    <th>WAF Name</th>
                    <th>Confidence</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {{ range .Results }}
                <tr>
                    <td><strong>{{ .URL }}</strong></td>
                    <td>
                        {{ if .Error }}
                            <span class="badge badge-danger">Error</span>
                        {{ else if .WAFFound }}
                            <span class="badge badge-success">WAF Detected</span>
                        {{ else }}
                            <span class="badge badge-warning">No WAF</span>
                        {{ end }}
                    </td>
                    <td>{{ if .WAFName }}{{ .WAFName }}{{ else }}-{{ end }}</td>
                    <td>
                        {{ if gt .Confidence 0.0 }}
                            <span class="confidence">{{ printf "%.0f" .Confidence }}%</span>
                        {{ else }}-{{ end }}
                    </td>
                    <td>
                        {{ if .Error }}
                            <span style="color: #dc3545;">{{ .Error }}</span>
                        {{ else if .Details }}
                            {{ .Details }}
                        {{ else }}-{{ end }}
                    </td>
                </tr>
                {{ end }}
            </tbody>
        </table>

        <footer>
            <p>Generated by WAF Detector - Professional Web Application Firewall Detection Tool</p>
        </footer>
    </div>
</body>
</html>`
