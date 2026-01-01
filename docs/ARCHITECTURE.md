# Architecture Overview

## System Design

WAF Detector follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────┐
│                         Main Entry Point                     │
│                          (main.go)                           │
└───────────────────────────────┬─────────────────────────────┘
                                │
                ┌───────────────┴───────────────┐
                │                               │
        ┌───────▼────────┐            ┌────────▼────────┐
        │   CLI Parser   │            │     Logger      │
        │   (cli/cli.go) │            │  (logger/*.go)  │
        └───────┬────────┘            └─────────────────┘
                │
        ┌───────▼────────┐
        │  Config Loader │
        │ (config/*.go)  │
        └───────┬────────┘
                │
        ┌───────▼────────────────────────────────────┐
        │          Target Collection                 │
        │  (collectTargets function)                 │
        └───────┬────────────────────────────────────┘
                │
        ┌───────▼────────────────────────────────────┐
        │      Worker Pool (Concurrent Scanner)      │
        │       (processTargets function)            │
        └───────┬────────────────────────────────────┘
                │
        ┌───────▼────────┬───────────────┬───────────┐
        │                │               │           │
   ┌────▼─────┐   ┌─────▼──────┐  ┌─────▼──────┐   │
   │ Scanner  │   │ Scanner    │  │ Scanner    │ ...│
   │ Worker 1 │   │ Worker 2   │  │ Worker N   │   │
   └────┬─────┘   └─────┬──────┘  └─────┬──────┘   │
        │               │               │           │
        └───────────────┴───────────────┴───────────┘
                        │
        ┌───────────────▼───────────────┐
        │       Scanner (scanner/)      │
        │  - HTTP Probes                │
        │  - Normal, SQLi, XSS          │
        │  - Malformed Requests         │
        └───────────────┬───────────────┘
                        │
        ┌───────────────▼───────────────┐
        │      Detector (detector/)     │
        │  - Behavior Analysis          │
        │  - Signature Matching         │
        │  - Confidence Scoring         │
        └───────────────┬───────────────┘
                        │
        ┌───────────────▼───────────────┐
        │        Output (output/)       │
        │  - Formatting (TXT/JSON/CSV)  │
        │  - HTML Report Generation     │
        │  - File Writing               │
        └───────────────────────────────┘
```

## Component Details

### 1. Main Entry Point (`main.go`)

**Responsibilities:**
- Initialize application
- Parse command-line flags
- Load WAF signatures (YAML or defaults)
- Set up logging
- Handle graceful shutdown
- Coordinate worker pool

**Key Functions:**
- `main()`: Application entry point
- `collectTargets()`: Gather URLs from various sources
- `processTargets()`: Manage concurrent scanning
- `processTarget()`: Process individual target

**Signature Loading Flow:**
```go
if config.SignaturesFile != "" {
    sigs := signatures.GetSignatures(config.SignaturesFile)
    d = detector.NewDetectorWithSignatures(sigs)
    logger.Infof("Loaded %d signatures from %s", len(sigs), config.SignaturesFile)
} else {
    d = detector.NewDetector() // Uses hardcoded signatures
}
```

### 2. CLI Parser (`cli/`)

**Responsibilities:**
- Parse command-line arguments
- Validate configuration
- Provide help text

**Key Structures:**
- `Config`: Holds all configuration options

**Key Flags:**
- `-u, --url`: Single target URL
- `-l, --list`: File with target URLs
- `-s, --signatures`: Custom WAF signatures file (YAML)
- `-t, --threads`: Number of concurrent workers
- `-o, --output`: Output file path
- `-f, --format`: Output format (txt|json|csv|html)

### 3. Scanner (`scanner/`)

**Responsibilities:**
- Execute HTTP probes
- Handle timeouts and errors
- Manage HTTP client configuration

**Probe Types:**
- Normal: Baseline request
- SQLi: SQL injection payload
- XSS: Cross-site scripting payload
- Malformed: Invalid HTTP request

**Key Functions:**
- `Scan()`: Execute all probes for a target
- `executeProbe()`: Send individual probe
- `buildProbeURL()`: Construct probe URL with payloads

### 4. Detector (`detector/`)

**Responsibilities:**
- Analyze probe results
- Match WAF signatures
- Calculate confidence scores
- Support custom signature injection

**Detection Strategy:**
1. **Behavior Analysis**: Compare probe responses
2. **Signature Matching**: Check headers, cookies, body
3. **Confidence Calculation**: Assign reliability score

**Key Functions:**
- `Detect()`: Main detection logic
- `detectWAFBehavior()`: Analyze response patterns
- `fingerprint()`: Match signatures

**Constructors:**
- `NewDetector()`: Creates detector with default hardcoded signatures
- `NewDetectorWithSignatures(sigs)`: Creates detector with custom signatures (YAML)

### 5. Signatures (`signatures/`)

**New Architecture: YAML-Based Signature System**

**Responsibilities:**
- Define WAF detection patterns
- Load signatures from YAML files
- Provide signature interface
- Fallback to hardcoded signatures

**Components:**

**5.1. Signature Interface:**
```go
type Signature interface {
    Name() string
    Match(probes map[ProbeType]*ProbeResult) float64
}
```

**5.2. YAML Signature Structure:**
```yaml
signatures:
  - name: "CloudFlare"
    enabled: true
    description: "Cloudflare Web Application Firewall"
    vendor: "Cloudflare"
    category: "CDN WAF"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        name: "Server"
        condition: contains
        value: "cloudflare"
        confidence: 0.5
      - type: header
        name: "CF-RAY"
        condition: exists
        confidence: 0.6
```

**5.3. Indicator Types:**
- `header`: Match HTTP response headers
- `cookie`: Match Set-Cookie patterns
- `body`: Match response body content
- `status_code`: Match HTTP status codes

**5.4. Indicator Conditions:**
- `exists`: Key/field exists
- `contains`: Value contains pattern (case-insensitive)
- `equals`: Exact match (case-insensitive)
- `regex`: Regular expression (future enhancement)

**5.5. Confidence Scoring:**
- Each indicator has weight (0.0 - 1.0)
- Scores accumulated across all matching indicators
- `minimum_indicators`: Required matches for reliable detection
- `confidence_multiplier`: Penalty factor when below minimum
- Final confidence capped at 1.0

**5.6. Key Files:**
- `signatures.go`: Interface definition and hardcoded fallback
- `loader.go`: YAML parsing and signature loading
- `waf-signatures.yml`: Default signature library (10+ WAFs)

**5.7. Key Functions:**
- `GetAllSignatures()`: Returns hardcoded default signatures
- `LoadSignaturesFromYAML(path)`: Parses YAML file into signatures
- `GetSignatures(yamlPath)`: Returns YAML or defaults with fallback
- `YAMLSignature.Match()`: Evaluates indicators against probes

**5.8. Benefits:**
- No recompilation for new WAF signatures
- Community-contributed signatures
- Easy customization per target
- Version control friendly
- Runtime configuration

### 6. Output (`output/`)

**Responsibilities:**
- Format results
- Generate reports
- Write to files

**Output Formats:**
- Text: Human-readable console output
- JSON: Machine-readable structured data
- CSV: Spreadsheet-compatible format
- HTML: Beautiful web reports

### 7. Logger (`logger/`)

**Responsibilities:**
- Structured logging
- Log level management
- Output formatting

**Log Levels:**
- Debug: Detailed debugging information
- Info: General informational messages
- Warn: Warning messages
- Error: Error messages
- Fatal: Fatal errors (exits program)

### 8. Config (`config/`)

**Responsibilities:**
- Load YAML config files
- Parse environment variables
- Merge configuration sources

### 9. Errors (`errors/`)

**Responsibilities:**
- Define custom error types
- Provide error context
- Enable error unwrapping

**Error Types:**
- Network errors
- Timeout errors
- Invalid URL errors
- Parsing errors

## Concurrency Model

The application uses a worker pool pattern for concurrent scanning:

1. **Target Channel**: Buffered channel containing all targets
2. **Worker Goroutines**: Fixed number of workers (configurable)
3. **Result Collection**: Thread-safe result aggregation
4. **Context Cancellation**: Graceful shutdown on interrupt

```go
// Worker pool pattern
for i := 0; i < threads; i++ {
    go worker(targetChan, resultChan)
}
```

## Signature Matching Flow

The YAML-based signature system follows this matching flow:

```
1. Load Signatures
   ├─ Check if custom YAML file provided (-s flag)
   │  ├─ YES: LoadSignaturesFromYAML(path)
   │  │  ├─ Parse YAML file
   │  │  ├─ Validate structure
   │  │  └─ Return YAMLSignature slice
   │  └─ NO: GetAllSignatures() (hardcoded)
   └─ Fallback to hardcoded on error

2. For Each Target
   └─ Scanner.Scan()
      ├─ ProbeNormal
      ├─ ProbeSQLi
      ├─ ProbeXSS
      └─ ProbeMalformed

3. For Each Signature
   └─ YAMLSignature.Match(probes)
      ├─ Check if signature enabled
      ├─ For each indicator:
      │  ├─ Match header (exists/contains/equals)
      │  ├─ Match cookie (exists/contains/equals)
      │  ├─ Match body (contains/equals)
      │  └─ Match status code (equals)
      ├─ Accumulate confidence scores
      ├─ Count matched indicators
      ├─ Check minimum_indicators requirement
      ├─ Apply confidence_multiplier if below minimum
      └─ Cap final confidence at 1.0

4. Select Best Match
   └─ Signature with highest confidence score
```

**Example Matching Logic:**
```go
// Header indicator: "Server" contains "cloudflare"
if indicator.Condition == "contains" {
    if strings.Contains(
        strings.ToLower(headerValue),
        strings.ToLower(indicator.Value),
    ) {
        confidence += indicator.Confidence
        matchedCount++
    }
}

// Apply penalty if below minimum
if matchedCount < y.MinimumIndicators {
    confidence *= y.ConfidenceMultiplier
}
```

## Error Handling

- Custom error types for different failure modes
- Error wrapping for context preservation
- Graceful degradation on non-critical errors
- Structured error logging

## Testing Strategy

- Unit tests for each package
- Integration tests for end-to-end flows
- Mock HTTP responses for deterministic testing
- Benchmark tests for performance validation
- Test coverage > 80%

## Performance Considerations

- Connection pooling via HTTP client
- Concurrent scanning with configurable threads
- Progress tracking without blocking
- Efficient memory usage
- Timeout management

## Security

- Input validation and sanitization
- Safe HTTP client configuration
- No credential storage
- Respect robots.txt (optional)
- Rate limiting capability
