# waf-detector

A fast and efficient Web Application Firewall (WAF) detection tool written in Go. This tool identifies the presence and type of WAF protecting web applications through intelligent probing and signature matching.

## Features

- 🚀 **Fast & Concurrent**: Multi-threaded scanning with configurable worker pools
- 🎯 **Accurate Detection**: Uses multiple probe types (normal, SQLi, XSS, malformed) for reliable WAF identification
- 📊 **Multiple Output Formats**: Support for both text and JSON output formats
- 🔍 **Signature-Based Fingerprinting**: Identifies specific WAF vendors based on response patterns
- 🌐 **Flexible Target Input**: Scan single URLs or bulk targets from file
- 🎨 **Colored Output**: Enhanced terminal output with color support (can be disabled)
- 🔧 **Configurable**: Extensive configuration options including timeout, proxy, user-agent, and more
- 🛡️ **Graceful Shutdown**: Handles interrupts cleanly with context-based cancellation

## Installation

### Prerequisites

- Go 1.21 or higher

### Build from Source

```bash
# Clone the repository
git clone https://github.com/wafw00f/waf-detector.git
cd waf-detector

# Build the binary
go build -o waf-detector

# Or use the build script
chmod +x build.sh
./build.sh
```

## Usage

### Basic Examples

Scan a single URL:
```bash
waf-detector -u https://example.com
```

Scan multiple URLs from a file:
```bash
waf-detector -l targets.txt
```

### Advanced Examples

Scan with custom threads and timeout:
```bash
waf-detector -u https://example.com -t 20 --timeout 15
```

Save output to JSON file:
```bash
waf-detector -l targets.txt -o results.json -f json
```

Silent mode (only results):
```bash
waf-detector -u https://example.com --silent
```

Debug mode for verbose output:
```bash
waf-detector -u https://example.com --debug
```

Using a proxy:
```bash
waf-detector -u https://example.com --proxy http://127.0.0.1:8080
```

Custom User-Agent:
```bash
waf-detector -u https://example.com --user-agent "Mozilla/5.0 Custom Agent"
```

## Command-Line Options

```
Options:
  -u, --url string          Single target URL
  -l, --list string         File with list of URLs
  -t, --threads int         Number of concurrent workers (default: 10)
  -o, --output string       Output file path
  -f, --format string       Output format: txt | json (default: txt)
  --timeout int             HTTP timeout per request in seconds (default: 10)
  --proxy string            HTTP proxy URL
  --user-agent string       Custom User-Agent (default: "waf-detector/1.0")
  --silent                  Only print results
  --no-color                Disable colored output
  --debug                   Verbose debug mode
```

## Output Format

### Text Output
```
[*] Checking https://example.com
[+] WAF Detected: Cloudflare
    Confidence: 95%
    Details: Detected via response headers and error pages
```

### JSON Output
```json
{
  "target": "https://example.com",
  "waf_detected": true,
  "waf_name": "Cloudflare",
  "confidence": 95.0,
  "details": "Detected via response headers and error pages",
  "scan_time": "2025-12-31T10:30:45Z"
}
```

## Project Structure

```
.
├── main.go              # Main application entry point
├── go.mod               # Go module dependencies
├── build.sh             # Build script
├── cli/
│   └── cli.go          # Command-line interface and configuration
├── detector/
│   └── detector.go     # WAF detection logic
├── scanner/
│   └── scanner.go      # HTTP probing and scanning
├── signatures/
│   └── signatures.go   # WAF signature definitions
├── output/
│   └── output.go       # Output formatting and writing
└── examples/
    ├── targets.txt     # Example target list
    ├── example-output.txt   # Example text output
    └── example-output.json  # Example JSON output
```

## How It Works

1. **Probing**: The tool sends multiple types of HTTP requests to the target:
   - Normal requests (baseline)
   - SQL injection payloads
   - XSS attack vectors
   - Malformed requests

2. **Behavior Analysis**: Analyzes response differences to detect WAF presence:
   - Status code changes
   - Response header patterns
   - Content modifications
   - Error pages

3. **Fingerprinting**: Matches response patterns against known WAF signatures:
   - Header analysis
   - Cookie patterns
   - Error message matching
   - Server behavior characteristics

4. **Confidence Scoring**: Assigns confidence scores based on match quality

## Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Add new WAF signatures
- Improve documentation
- Submit pull requests

## License

This project is open source. Please check the LICENSE file for more details.

## Disclaimer

This tool is intended for security professionals and researchers to test their own systems or systems they have permission to test. Unauthorized scanning of systems may be illegal in your jurisdiction. Use responsibly and ethically.

## Credits

Inspired by the original WAFW00F project.
