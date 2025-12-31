# API Documentation

## Package: main

### Functions

#### `main()`
Application entry point. Initializes configuration, sets up logging, and orchestrates scanning.

#### `collectTargets(config *cli.Config) []string`
Collects target URLs from command-line or file input.

**Parameters:**
- `config`: Configuration object

**Returns:**
- `[]string`: List of target URLs

#### `processTargets(ctx context.Context, targets []string, config *cli.Config) []output.Result`
Manages concurrent scanning of targets using worker pool.

**Parameters:**
- `ctx`: Context for cancellation
- `targets`: List of URLs to scan
- `config`: Configuration object

**Returns:**
- `[]output.Result`: Scan results

#### `processTarget(ctx context.Context, target string, s *scanner.Scanner, d *detector.Detector, config *cli.Config) output.Result`
Scans a single target.

**Parameters:**
- `ctx`: Context for timeout/cancellation
- `target`: URL to scan
- `s`: Scanner instance
- `d`: Detector instance
- `config`: Configuration object

**Returns:**
- `output.Result`: Scan result

---

## Package: cli

### Types

#### `Config`
```go
type Config struct {
    URL         string
    ListFile    string
    ConfigFile  string
    Threads     int
    OutputFile  string
    Format      string
    Timeout     time.Duration
    Proxy       string
    UserAgent   string
    Silent      bool
    NoColor     bool
    Debug       bool
    ShowVersion bool
}
```

### Functions

#### `ParseFlags() *Config`
Parses command-line flags and returns configuration.

**Returns:**
- `*Config`: Parsed configuration

---

## Package: scanner

### Types

#### `Scanner`
```go
type Scanner struct {
    client *http.Client
    config *cli.Config
}
```

#### `ProbeType`
```go
type ProbeType string

const (
    ProbeNormal    ProbeType = "normal"
    ProbeSQLi      ProbeType = "sqli"
    ProbeXSS       ProbeType = "xss"
    ProbeMalformed ProbeType = "malformed"
)
```

#### `ProbeResult`
```go
type ProbeResult struct {
    StatusCode int
    Headers    map[string][]string
    Body       string
    Error      *ProbeError
}
```

### Functions

#### `NewScanner(config *cli.Config) *Scanner`
Creates a new scanner instance.

**Parameters:**
- `config`: Configuration object

**Returns:**
- `*Scanner`: Scanner instance

#### `(s *Scanner) Scan(ctx context.Context, url string) (map[ProbeType]*ProbeResult, error)`
Executes all probes against a target.

**Parameters:**
- `ctx`: Context for timeout/cancellation
- `url`: Target URL

**Returns:**
- `map[ProbeType]*ProbeResult`: Probe results by type
- `error`: Error if any

---

## Package: detector

### Types

#### `Detector`
```go
type Detector struct {
    signatures []signatures.Signature
}
```

#### `Detection`
```go
type Detection struct {
    WAFDetected bool
    WAFName     string
    Confidence  float64
    Details     string
}
```

### Functions

#### `NewDetector() *Detector`
Creates a new detector instance.

**Returns:**
- `*Detector`: Detector instance

#### `(d *Detector) Detect(probes map[scanner.ProbeType]*scanner.ProbeResult) Detection`
Analyzes probe results to detect WAF.

**Parameters:**
- `probes`: Probe results to analyze

**Returns:**
- `Detection`: Detection result

---

## Package: output

### Types

#### `Result`
```go
type Result struct {
    URL        string        `json:"url"`
    WAFFound   bool          `json:"waf_found"`
    WAFName    string        `json:"waf_name,omitempty"`
    Confidence float64       `json:"confidence,omitempty"`
    Details    string        `json:"details,omitempty"`
    Error      string        `json:"error,omitempty"`
    ScanTime   time.Duration `json:"scan_time"`
    Timestamp  time.Time     `json:"timestamp"`
}
```

### Functions

#### `WriteResults(results []Result, config *cli.Config) error`
Writes scan results to file in specified format.

**Parameters:**
- `results`: Scan results
- `config`: Configuration object

**Returns:**
- `error`: Error if any

#### `PrintResult(result Result, config *cli.Config)`
Prints single result to console.

**Parameters:**
- `result`: Scan result
- `config`: Configuration object

#### `PrintSummary(results []Result, config *cli.Config)`
Prints summary statistics.

**Parameters:**
- `results`: All scan results
- `config`: Configuration object

---

## Package: logger

### Functions

#### `Init(debug bool, silent bool)`
Initializes the logger.

**Parameters:**
- `debug`: Enable debug logging
- `silent`: Enable silent mode

#### `Debug(args ...interface{})`
Log debug message.

#### `Debugf(format string, args ...interface{})`
Log formatted debug message.

#### `Info(args ...interface{})`
Log info message.

#### `Infof(format string, args ...interface{})`
Log formatted info message.

#### `Warn(args ...interface{})`
Log warning message.

#### `Warnf(format string, args ...interface{})`
Log formatted warning message.

#### `Error(args ...interface{})`
Log error message.

#### `Errorf(format string, args ...interface{})`
Log formatted error message.

#### `Fatal(args ...interface{})`
Log fatal message and exit.

#### `Fatalf(format string, args ...interface{})`
Log formatted fatal message and exit.

---

## Package: errors

### Types

#### `ErrorType`
```go
type ErrorType string

const (
    ErrorTypeNetwork    ErrorType = "NETWORK"
    ErrorTypeTimeout    ErrorType = "TIMEOUT"
    ErrorTypeInvalidURL ErrorType = "INVALID_URL"
    ErrorTypeParsing    ErrorType = "PARSING"
    ErrorTypeUnknown    ErrorType = "UNKNOWN"
)
```

#### `WAFError`
```go
type WAFError struct {
    Type    ErrorType
    URL     string
    Message string
    Err     error
}
```

### Functions

#### `NewNetworkError(url string, err error) *WAFError`
Creates network error.

#### `NewTimeoutError(url string) *WAFError`
Creates timeout error.

#### `NewInvalidURLError(url string, err error) *WAFError`
Creates invalid URL error.

#### `NewParsingError(url string, err error) *WAFError`
Creates parsing error.

#### `NewUnknownError(url string, err error) *WAFError`
Creates unknown error.

---

## Package: config

### Functions

#### `LoadConfig(path string) (*FileConfig, error)`
Loads configuration from YAML file.

**Parameters:**
- `path`: Path to config file

**Returns:**
- `*FileConfig`: Configuration
- `error`: Error if any

#### `LoadFromEnv() *FileConfig`
Loads configuration from environment variables.

**Returns:**
- `*FileConfig`: Configuration
