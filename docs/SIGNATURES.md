# Custom WAF Signatures Guide

## Overview

WAF Detector now supports customizable WAF signatures through YAML configuration files. This allows you to add new WAF vendors, modify detection rules, and fine-tune confidence scoring without recompiling the application.

## Signature File Structure

```yaml
version: "1.0"

signatures:
  - name: "WAF Name"
    enabled: true
    description: "Description of the WAF"
    vendor: "Vendor Name"
    category: "cloud|appliance|plugin|opensource"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header|cookie|body|status_code
        key: "Header-Name"
        condition: exists|contains|equals|regex
        value: "pattern"
        confidence: 0.4
```

## Indicator Types

### 1. Header Indicators
Match specific HTTP response headers:

```yaml
- type: header
  key: "CF-Ray"
  condition: exists
  confidence: 0.35
```

```yaml
- type: header
  key: "Server"
  condition: contains
  value: "cloudflare"
  case_insensitive: true
  confidence: 0.3
```

### 2. Cookie Indicators
Match cookies in Set-Cookie headers:

```yaml
- type: cookie
  key: "__cfduid"
  condition: contains
  confidence: 0.25
```

### 3. Body Indicators
Match content in response body:

```yaml
- type: body
  condition: contains
  value: "cloudflare"
  case_insensitive: true
  confidence: 0.2
```

**With multiple values (any match):**
```yaml
- type: body
  condition: contains
  values: ["attention required", "ray id:", "cf-ray"]
  case_insensitive: true
  confidence: 0.3
```

**With status code filtering:**
```yaml
- type: body
  condition: contains
  values: ["request blocked", "aws waf"]
  status_codes: [403]
  confidence: 0.3
```

**Require all values:**
```yaml
- type: body
  condition: contains
  values: ["title", "forbidden", "aws"]
  require_all_values: true
  case_insensitive: true
  confidence: 0.25
```

### 4. Status Code Indicators
Match specific HTTP status codes:

```yaml
- type: status_code
  status_codes: [403, 406, 503]
  confidence: 0.15
```

## Indicator Conditions

| Condition | Description | Applicable To |
|-----------|-------------|---------------|
| `exists` | Header/cookie key exists | header, cookie |
| `contains` | Value contains pattern | header, cookie, body |
| `equals` | Value exactly matches | header |
| `regex` | Pattern matches regex | Future feature |

## Configuration Options

### Signature-Level Settings

- **name**: Display name of the WAF
- **enabled**: Enable/disable signature (true/false)
- **description**: Human-readable description
- **vendor**: Vendor/company name
- **category**: Type of WAF (cloud, appliance, plugin, opensource)
- **minimum_indicators**: Minimum indicators required for detection
- **confidence_multiplier**: Multiplier applied when below minimum (default: 0.5)

### Indicator-Level Settings

- **type**: Type of indicator (header, cookie, body, status_code)
- **key**: Header/cookie name (for header/cookie types)
- **condition**: Matching condition
- **value**: Single value to match
- **values**: Multiple values (any or all)
- **require_all_values**: All values must match (default: false)
- **status_codes**: Filter by status codes
- **case_insensitive**: Case-insensitive matching (default: false)
- **confidence**: Confidence score (0.0 - 1.0)

## Example: Creating a Custom Signature

Let's create a signature for a fictional WAF called "SecureShield":

```yaml
version: "1.0"

signatures:
  - name: "SecureShield WAF"
    enabled: true
    description: "SecureShield Enterprise Web Application Firewall"
    vendor: "SecureShield Inc"
    category: "cloud"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      # Strong indicator - specific header
      - type: header
        key: "X-SecureShield-ID"
        condition: exists
        confidence: 0.45
      
      # Server header contains vendor name
      - type: header
        key: "Server"
        condition: contains
        value: "SecureShield"
        case_insensitive: true
        confidence: 0.35
      
      # Cookie-based detection
      - type: cookie
        key: "ss_session"
        condition: contains
        confidence: 0.3
      
      # Body contains error page content
      - type: body
        condition: contains
        values: ["SecureShield", "Access Denied", "Request Blocked"]
        case_insensitive: true
        status_codes: [403, 503]
        confidence: 0.3
      
      # Via header detection
      - type: header
        key: "Via"
        condition: contains
        value: "SecureShield"
        case_insensitive: true
        confidence: 0.25
```

## Using Custom Signatures

### Command Line

```bash
# Use custom signatures file
waf-detector -u https://example.com -s my-signatures.yml

# Scan multiple targets with custom signatures
waf-detector -l targets.txt -s my-signatures.yml -o results.json -f json
```

### Multiple Signature Files

To use multiple signature files, merge them into a single YAML file:

```yaml
version: "1.0"

signatures:
  - name: "Cloudflare"
    enabled: true
    # ... Cloudflare indicators
  
  - name: "My Custom WAF"
    enabled: true
    # ... Custom indicators
```

## Best Practices

### 1. Confidence Scoring
- Use **0.3-0.5** for strong, unique indicators (specific headers)
- Use **0.2-0.3** for medium strength indicators (common patterns)
- Use **0.1-0.2** for weak indicators (generic patterns)
- Total confidence should reach ~1.0 with 2-3 strong indicators

### 2. Minimum Indicators
- Set `minimum_indicators: 2` for reliable detection
- Use `minimum_indicators: 1` only for WAFs with very unique signatures
- Adjust `confidence_multiplier` (0.3-0.7) for penalty when below minimum

### 3. Case Sensitivity
- Always use `case_insensitive: true` for text matching
- Only use case-sensitive matching for exact header names

### 4. Status Code Filtering
- Use status codes to reduce false positives
- Common blocked status codes: `[403, 406, 503]`
- Combine with body content for stronger signals

### 5. Multiple Values
- Use `values` array for variations (e.g., "cloudflare", "cf-ray")
- Set `require_all_values: true` only when all patterns must be present
- Keep value lists concise (3-5 items max)

## Testing Custom Signatures

### 1. Verify YAML Syntax
```bash
# Test with yamllint
yamllint my-signatures.yml

# Or use online validator
# https://www.yamllint.com/
```

### 2. Test Against Known Target
```bash
# Test with debug mode
waf-detector -u https://target.com -s my-signatures.yml --debug

# Check detection confidence
waf-detector -u https://target.com -s my-signatures.yml -f json | jq '.confidence'
```

### 3. Compare with Default Signatures
```bash
# Without custom signatures
waf-detector -u https://target.com -f json > default.json

# With custom signatures
waf-detector -u https://target.com -s my-signatures.yml -f json > custom.json

# Compare results
diff default.json custom.json
```

## Example Signatures

### Minimal Detection
```yaml
- name: "Simple WAF"
  enabled: true
  minimum_indicators: 1
  indicators:
    - type: header
      key: "X-WAF-Protection"
      condition: exists
      confidence: 0.8
```

### Comprehensive Detection
```yaml
- name: "Advanced WAF"
  enabled: true
  minimum_indicators: 3
  confidence_multiplier: 0.4
  indicators:
    - type: header
      key: "X-WAF-ID"
      condition: exists
      confidence: 0.35
    - type: header
      key: "Server"
      condition: contains
      value: "WAF"
      case_insensitive: true
      confidence: 0.25
    - type: cookie
      key: "waf_token"
      condition: contains
      confidence: 0.2
    - type: body
      condition: contains
      values: ["blocked", "firewall", "security"]
      case_insensitive: true
      status_codes: [403]
      confidence: 0.3
    - type: body
      condition: contains
      value: "incident id"
      case_insensitive: true
      confidence: 0.2
```

## Signature Library

The project includes a default signature library at:
```
signatures/waf-signatures.yml
```

Supported WAFs:
- Cloudflare
- AWS WAF
- Akamai
- Imperva Incapsula
- F5 BIG-IP
- ModSecurity
- Sucuri CloudProxy
- Wordfence
- Azure WAF
- Fastly
- Wallarm
- And more...

## Contributing Signatures

To contribute new signatures:

1. Create your custom signature file
2. Test against real targets
3. Document the WAF vendor and version
4. Submit a pull request with:
   - Signature YAML file
   - Test results
   - Documentation

## Troubleshooting

### Signature Not Loading
```bash
# Check for YAML syntax errors
waf-detector -s my-signatures.yml --debug
```

### Low Confidence Scores
- Increase confidence values for strong indicators
- Reduce `minimum_indicators`
- Adjust `confidence_multiplier`

### False Positives
- Increase `minimum_indicators`
- Make indicator patterns more specific
- Add status code filters
- Use `require_all_values: true`

### False Negatives
- Add more indicator variations
- Reduce `minimum_indicators`
- Increase confidence values
- Check with `--debug` to see probe results

## Advanced Topics

### Regular Expressions (Future)
```yaml
- type: body
  condition: regex
  value: "Incident ID: [A-F0-9]{16}"
  confidence: 0.4
```

### Custom Probe Types (Future)
```yaml
- type: custom_probe
  probe_name: "graphql_attack"
  indicators: [...]
```

### Signature Versioning (Future)
```yaml
version: "2.0"
schema_version: "2.0"
signatures: [...]
```
