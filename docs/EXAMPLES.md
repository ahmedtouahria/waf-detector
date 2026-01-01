# Usage Examples

## Basic Usage

### Scan a Single URL

```bash
waf-detector -u https://example.com
```

Output:
```
✓ https://example.com - WAF Detected: Cloudflare
  Confidence: 95.0%
  Details: Detected via response headers
```

### Scan Multiple URLs from File

Create `targets.txt`:
```
https://example.com
https://cloudflare.com
https://aws.amazon.com
```

Run scan:
```bash
waf-detector -l targets.txt
```

## Advanced Usage

### Custom YAML Signatures

Use a custom signature file to detect specific WAFs or customize detection logic:

```bash
waf-detector -u https://example.com -s custom-waf-signatures.yml
```

**Example custom signature file (`custom-waf-signatures.yml`):**
```yaml
signatures:
  - name: "MyCustomWAF"
    enabled: true
    description: "Custom corporate WAF"
    vendor: "Internal"
    category: "Enterprise WAF"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        name: "X-Custom-Protection"
        condition: exists
        confidence: 0.7
      - type: header
        name: "Server"
        condition: contains
        value: "custom-waf"
        confidence: 0.6
      - type: body
        condition: contains
        value: "Request blocked by security policy"
        confidence: 0.8

  - name: "CloudFlare"
    enabled: true
    description: "Cloudflare Web Application Firewall"
    vendor: "Cloudflare"
    category: "CDN WAF"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        name: "CF-RAY"
        condition: exists
        confidence: 0.6
      - type: header
        name: "Server"
        condition: contains
        value: "cloudflare"
        confidence: 0.5
```

**Output with custom signatures:**
```
[INFO] Loaded 2 signatures from custom-waf-signatures.yml
✓ https://example.com - WAF Detected: MyCustomWAF
  Confidence: 87.5%
  Details: Detected via custom indicators
```

### Disable Specific Signatures

Create a YAML file with only the signatures you want to use, or set `enabled: false` for unwanted signatures:

```yaml
signatures:
  - name: "CloudFlare"
    enabled: true
    # ... indicators

  - name: "AWS WAF"
    enabled: false  # This signature will be skipped
    # ... indicators
```

### Custom Thread Count

Scan with 20 concurrent workers:
```bash
waf-detector -l targets.txt -t 20
```

### Custom Timeout

Set 30-second timeout per request:
```bash
waf-detector -u https://example.com --timeout 30
```

### Using a Proxy

Route traffic through proxy:
```bash
waf-detector -u https://example.com --proxy http://127.0.0.1:8080
```

With SOCKS5 proxy:
```bash
waf-detector -u https://example.com --proxy socks5://127.0.0.1:1080
```

### Custom User-Agent

```bash
waf-detector -u https://example.com --user-agent "MyScanner/1.0"
```

### Silent Mode

Only show results, no progress:
```bash
waf-detector -l targets.txt --silent
```

### Debug Mode

Show detailed debugging information:
```bash
waf-detector -u https://example.com --debug
```

## Output Formats

### JSON Output

```bash
waf-detector -u https://example.com -o results.json -f json
```

Output structure:
```json
{
  "results": [
    {
      "url": "https://example.com",
      "waf_found": true,
      "waf_name": "Cloudflare",
      "confidence": 95.0,
      "details": "Detected via headers",
      "scan_time": "125ms",
      "timestamp": "2025-12-31T10:30:45Z"
    }
  ],
  "summary": {
    "total_scanned": 1,
    "wafs_detected": 1,
    "errors": 0
  },
  "scan_time": "2025-12-31T10:30:45Z"
}
```

### CSV Output

```bash
waf-detector -l targets.txt -o results.csv -f csv
```

Output:
```csv
URL,WAF Detected,WAF Name,Confidence,Details,Error,Scan Time,Timestamp
https://example.com,true,Cloudflare,95.00,Detected via headers,,125ms,2025-12-31T10:30:45Z
https://test.com,false,,0.00,,,98ms,2025-12-31T10:30:46Z
```

### HTML Report

```bash
waf-detector -l targets.txt -o report.html -f html
```

Creates a beautiful HTML report with:
- Summary statistics
- Detailed results table
- Color-coded status indicators
- Printable layout

## Configuration Files

### Using YAML Config

Create `config.yml`:
```yaml
targets:
  - https://example.com
  - https://cloudflare.com

threads: 20
timeout: 15s
proxy: http://127.0.0.1:8080
user_agent: "MyScanner/1.0"
output_file: "results.json"
format: json
debug: false
silent: false
no_color: false
```

Run with config:
```bash
waf-detector -c config.yml
```

### Environment Variables

```bash
export WAF_DETECTOR_THREADS=20
export WAF_DETECTOR_TIMEOUT=15
export WAF_DETECTOR_FORMAT=json
export WAF_DETECTOR_OUTPUT=results.json
export WAF_DETECTOR_DEBUG=true

waf-detector -u https://example.com
```

## Docker Usage

### Basic Docker Run

```bash
docker run --rm waf-detector -u https://example.com
```

### Mount Targets File

```bash
docker run --rm \
  -v $(pwd)/targets.txt:/app/targets.txt \
  waf-detector -l /app/targets.txt
```

### Save Output

```bash
docker run --rm \
  -v $(pwd)/output:/app/output \
  waf-detector -u https://example.com -o /app/output/results.json -f json
```

### Using Docker Compose

```bash
# Edit docker-compose.yml with your targets
docker-compose up
```

### Custom Docker Run

```bash
docker run --rm \
  -e WAF_DETECTOR_THREADS=20 \
  -e WAF_DETECTOR_DEBUG=true \
  -v $(pwd)/targets.txt:/targets.txt \
  -v $(pwd)/output:/output \
  waf-detector -l /targets.txt -o /output/results.json -f json
```

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/scan.yml
name: WAF Scan

on:
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run WAF Detector
        run: |
          docker run --rm \
            -v $(pwd)/targets.txt:/targets.txt \
            -v $(pwd):/output \
            waf-detector -l /targets.txt -o /output/results.json -f json
      
      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: scan-results
          path: results.json
```

### Shell Script Automation

```bash
#!/bin/bash
# automated_scan.sh

TARGETS_FILE="targets.txt"
OUTPUT_DIR="./reports"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

# Run scan
waf-detector \
  -l "$TARGETS_FILE" \
  -t 20 \
  --timeout 15 \
  -o "$OUTPUT_DIR/scan_$DATE.html" \
  -f html \
  --silent

echo "Scan complete: $OUTPUT_DIR/scan_$DATE.html"

# Check for errors
if [ $? -ne 0 ]; then
  echo "Scan failed!"
  exit 1
fi
```

### Python Integration

```python
import subprocess
import json

def scan_url(url):
    """Scan a URL and return results"""
    result = subprocess.run(
        ['waf-detector', '-u', url, '-f', 'json', '-o', 'temp.json'],
        capture_output=True,
        text=True
    )
    
    with open('temp.json', 'r') as f:
        return json.load(f)

# Usage
results = scan_url('https://example.com')
print(f"WAF Found: {results['results'][0]['waf_found']}")
print(f"WAF Name: {results['results'][0].get('waf_name', 'N/A')}")
```

## Best Practices

1. **Rate Limiting**: Use appropriate thread count to avoid overwhelming targets
   ```bash
   waf-detector -l targets.txt -t 5 --timeout 10
   ```

2. **Error Handling**: Check exit codes in scripts
   ```bash
   if ! waf-detector -u https://example.com; then
       echo "Scan failed"
       exit 1
   fi
   ```

3. **Logging**: Use debug mode for troubleshooting
   ```bash
   waf-detector -u https://example.com --debug > debug.log 2>&1
   ```

4. **Batch Processing**: Split large target lists
   ```bash
   split -l 100 targets.txt batch_
   for file in batch_*; do
       waf-detector -l "$file" -o "results_$file.json" -f json
   done
   ```

5. **Monitoring**: Combine with monitoring tools
   ```bash
   waf-detector -l targets.txt | tee scan.log | grep "WAF Detected"
   ```
