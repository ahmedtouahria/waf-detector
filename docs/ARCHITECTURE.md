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
- Set up logging
- Handle graceful shutdown
- Coordinate worker pool

**Key Functions:**
- `main()`: Application entry point
- `collectTargets()`: Gather URLs from various sources
- `processTargets()`: Manage concurrent scanning
- `processTarget()`: Process individual target

### 2. CLI Parser (`cli/`)

**Responsibilities:**
- Parse command-line arguments
- Validate configuration
- Provide help text

**Key Structures:**
- `Config`: Holds all configuration options

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

**Detection Strategy:**
1. **Behavior Analysis**: Compare probe responses
2. **Signature Matching**: Check headers, cookies, body
3. **Confidence Calculation**: Assign reliability score

**Key Functions:**
- `Detect()`: Main detection logic
- `detectWAFBehavior()`: Analyze response patterns
- `fingerprint()`: Match signatures

### 5. Signatures (`signatures/`)

**Responsibilities:**
- Define WAF patterns
- Provide signature database

**Signature Components:**
- Name: WAF vendor/product name
- Patterns: Regex patterns for matching
- Headers: Expected HTTP headers
- Cookies: Expected cookies
- Body: Response body patterns

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
