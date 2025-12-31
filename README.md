# waf-detector

[![CI](https://github.com/ahmedtouahria/waf-detector/workflows/CI/badge.svg)](https://github.com/ahmedtouahria/waf-detector/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ahmedtouahria/waf-detector)](https://goreportcard.com/report/github.com/ahmedtouahria/waf-detector)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/release/ahmedtouahria/waf-detector.svg)](https://github.com/ahmedtouahria/waf-detector/releases)

A fast, efficient, and professional Web Application Firewall (WAF) detection tool written in Go. This tool identifies the presence and type of WAF protecting web applications through intelligent probing and signature matching.

## Features

- 🚀 **Fast & Concurrent**: Multi-threaded scanning with configurable worker pools
- 🎯 **Accurate Detection**: Uses multiple probe types (normal, SQLi, XSS, malformed) for reliable WAF identification
- 📊 **Multiple Output Formats**: Support for text, JSON, CSV, and HTML output formats
- 🔍 **Signature-Based Fingerprinting**: Identifies specific WAF vendors based on response patterns
- 🌐 **Flexible Target Input**: Scan single URLs, bulk targets from file, or use config files
- 🎨 **Beautiful Output**: Enhanced terminal output with colors and progress bars
- ⚙️ **Configurable**: Extensive configuration via flags, config files, or environment variables
- 🔧 **Professional Logging**: Structured logging with multiple log levels
- 🛡️ **Graceful Shutdown**: Handles interrupts cleanly with context-based cancellation
- 🐳 **Docker Support**: Ready-to-use Docker images for containerized deployment
- 📈 **Progress Tracking**: Real-time progress bars for bulk scanning operations
- ✅ **Well Tested**: Comprehensive test suite with high coverage

## Installation

### Prerequisites

- Go 1.21 or higher

### Build from Source

```bash
# Clone the repository
git clone https://github.com/ahmedtouahria/waf-detector.git
cd waf-detector

# Build using Make
make build

# Or build directly with Go
go build -o waf-detector

# Or use the build script
chmod +x build.sh
./build.sh
```

### Using Docker

```bash
# Build Docker image
docker build -t waf-detector .

# Run with Docker
docker run --rm waf-detector -u https://example.com

# Or use docker-compose
docker-compose up
```

### Install via Make

```bash
make install
# Binary will be installed to $GOPATH/bin
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

Use config file:
```bash
waf-detector -c configs/example.yml
```

Generate HTML report:
```bash
waf-detector -l targets.txt -o report.html -f html
```

Generate CSV report:
```bash
waf-detector -l targets.txt -o results.csv -f csv
```

Show version:
```bash
waf-detector --version
```

## Configuration

### Config File (YAML)

Create a `config.yml` file:

```yaml
targets:
  - https://example.com
  - https://cloudflare.com

threads: 20
timeout: 15s
output_file: "results.json"
format: json
debug: false
```

Then run:
```bash
waf-detector -c config.yml
```

### Environment Variables

You can also use environment variables:

```bash
export WAF_DETECTOR_THREADS=20
export WAF_DETECTOR_TIMEOUT=15
export WAF_DETECTOR_FORMAT=json
export WAF_DETECTOR_DEBUG=true

waf-detector -u https://example.com
```

Available environment variables:
- `WAF_DETECTOR_THREADS`
- `WAF_DETECTOR_TIMEOUT`
- `WAF_DETECTOR_PROXY`
- `WAF_DETECTOR_USER_AGENT`
- `WAF_DETECTOR_OUTPUT`
- `WAF_DETECTOR_FORMAT`
- `WAF_DETECTOR_SILENT`
- `WAF_DETECTOR_NO_COLOR`
- `WAF_DETECTOR_DEBUG`

## Command-Line Options

```
Options:
  -u, --url string          Single target URL
  -l, --list string         File with list of URLs
  -c, --config string       Config file path (YAML)
  -t, --threads int         Number of concurrent workers (default: 10)
  -o, --output string       Output file path
  -f, --format string       Output format: txt | json | csv | html (default: txt)
  --timeout int             HTTP timeout per request in seconds (default: 10)
  --proxy string            HTTP proxy URL
  --user-agent string       Custom User-Agent (default: "waf-detector/1.0")
  --silent                  Only print results
  --no-color                Disable colored output
  --debug                   Verbose debug mode
  -v, --version             Show version information
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

### CSV Output
```csv
URL,WAF Detected,WAF Name,Confidence,Details,Error,Scan Time,Timestamp
https://example.com,true,Cloudflare,95.00,Detected via headers,,125ms,2025-12-31T10:30:45Z
```

## Project Structure

```
waf-detector/
├── main.go              # Application entry point
├── version.go           # Version information
├── go.mod               # Go module dependencies
├── go.sum               # Dependency checksums
├── Makefile             # Build automation
├── Dockerfile           # Docker image configuration
├── docker-compose.yml   # Docker Compose setup
├── build.sh             # Build script
├── .golangci.yml        # Linter configuration
├── .goreleaser.yml      # Release configuration
├── cli/
│   ├── cli.go          # Command-line interface and configuration
│   └── cli_test.go     # CLI tests
├── detector/
│   ├── detector.go     # WAF detection logic
│   └── detector_test.go # Detection tests
├── scanner/
│   ├── scanner.go      # HTTP probing and scanning
│   └── scanner_test.go # Scanner tests
├── signatures/
│   └── signatures.go   # WAF signature definitions
├── output/
│   ├── output.go       # Output formatting and writing
│   ├── template.go     # HTML template
│   └── output_test.go  # Output tests
├── logger/
│   ├── logger.go       # Structured logging
│   └── logger_test.go  # Logger tests
├── errors/
│   ├── errors.go       # Custom error types
│   └── errors_test.go  # Error tests
├── config/
│   └── config.go       # Config file support
├── configs/
│   └── example.yml     # Example configuration
├── examples/
│   ├── targets.txt     # Example target list
│   ├── example-output.txt
│   └── example-output.json
├── .github/
│   └── workflows/
│       ├── ci.yml      # CI pipeline
│       ├── release.yml # Release automation
│       └── security.yml # Security scanning
├── docs/               # Documentation
└── LICENSE             # MIT License
```

## Development

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run benchmarks
make bench
```

### Linting

```bash
# Run linter
make lint

# Format code
make fmt
```

### Building for Multiple Platforms

```bash
# Build for all platforms
make release

# Builds will be in bin/ directory:
# - waf-detector-linux-amd64
# - waf-detector-linux-arm64
# - waf-detector-darwin-amd64
# - waf-detector-darwin-arm64
# - waf-detector-windows-amd64.exe
```

### Using Docker for Development

```bash
# Build Docker image
make docker-build

# Run Docker container
make docker-run
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

Inspired by the original ahmedtouahria project.
