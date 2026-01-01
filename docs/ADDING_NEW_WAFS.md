# Adding New WAF Signatures

This guide explains how to add new WAF signatures to the detector **without writing any Go code**. You simply need to edit the YAML configuration file.

## Quick Start

1. Open `signatures/waf-signatures.yml`
2. Add your new WAF signature following the template below
3. Save the file
4. Rebuild the application: `go build` or `make build`
5. Your new WAF is now detected automatically!

## Signature Template

```yaml
  - name: "Your WAF Name"
    enabled: true
    description: "Description of the WAF"
    vendor: "Vendor/Manufacturer Name"
    category: "cloud|cdn|appliance|opensource|plugin"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        key: "X-Custom-Header"
        condition: exists
        confidence: 0.35
      
      - type: header
        key: "Server"
        condition: contains
        value: "waf-name"
        case_insensitive: true
        confidence: 0.3
      
      - type: cookie
        key: "session_cookie"
        condition: contains
        confidence: 0.25
      
      - type: body
        condition: contains
        values: ["blocked", "firewall", "access denied"]
        case_insensitive: true
        status_codes: [403, 503]
        confidence: 0.3
```

## Field Explanations

### Top-Level Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | The display name of the WAF |
| `enabled` | Yes | Set to `true` to enable detection, `false` to disable |
| `description` | No | Human-readable description |
| `vendor` | No | Manufacturer/company name |
| `category` | No | Type: `cloud`, `cdn`, `appliance`, `opensource`, `plugin` |
| `minimum_indicators` | Yes | Minimum number of indicators required for detection |
| `confidence_multiplier` | No | Multiplier applied if minimum isn't met (default: 0.5) |

### Indicator Types

#### 1. Header Indicators

Check HTTP response headers:

```yaml
- type: header
  key: "X-WAF-Header"        # Header name to check
  condition: exists          # or "contains", "equals"
  confidence: 0.35          # Confidence score (0.0-1.0)
```

**With value matching:**

```yaml
- type: header
  key: "Server"
  condition: contains        # Check if value contains string
  value: "wafname"          # String to search for
  case_insensitive: true    # Ignore case (optional)
  confidence: 0.3
```

**Multiple values (any match):**

```yaml
- type: header
  key: "Server"
  condition: contains
  values: ["waf1", "waf2", "waf3"]  # Match any of these
  case_insensitive: true
  confidence: 0.3
```

#### 2. Cookie Indicators

Check Set-Cookie headers:

```yaml
- type: cookie
  key: "waf_session"        # Cookie name
  condition: contains       # or "exists"
  confidence: 0.25
```

#### 3. Body Indicators

Check response body content:

```yaml
- type: body
  condition: contains
  value: "access denied"     # Single string to search
  case_insensitive: true
  confidence: 0.3
```

**Multiple values:**

```yaml
- type: body
  condition: contains
  values: ["blocked", "firewall", "denied"]  # Any match
  case_insensitive: true
  confidence: 0.3
```

**With status code filter:**

```yaml
- type: body
  condition: contains
  values: ["waf blocked"]
  status_codes: [403, 503]   # Only check these status codes
  case_insensitive: true
  confidence: 0.35
```

**Require all values:**

```yaml
- type: body
  condition: contains
  values: ["error", "reference", "id"]
  require_all_values: true   # ALL values must be present
  case_insensitive: true
  confidence: 0.4
```

## Conditions

| Condition | Description | Applicable To |
|-----------|-------------|---------------|
| `exists` | Check if header/cookie exists | headers, cookies |
| `contains` | Check if value contains substring | headers, cookies, body |
| `equals` | Exact match (case-sensitive by default) | headers |

## Confidence Scores

- Total confidence is the **sum** of all matched indicators
- Each indicator contributes its `confidence` value when matched
- Final score is capped at **1.0** (100%)
- Use `minimum_indicators` to require multiple matches
- `confidence_multiplier` is applied if minimum isn't met

### Confidence Guidelines

| Score | Recommendation | Use Case |
|-------|----------------|----------|
| 0.40-0.50 | Unique/strong indicator | Proprietary headers, unique cookies |
| 0.30-0.40 | Strong indicator | Distinctive headers, specific error messages |
| 0.20-0.30 | Moderate indicator | Common headers, general patterns |
| 0.10-0.20 | Weak indicator | Very common patterns |

### Example Calculation

```yaml
minimum_indicators: 2
confidence_multiplier: 0.5
indicators:
  - confidence: 0.35  # ← Matches
  - confidence: 0.30  # ← Matches
  - confidence: 0.25  # ← No match
```

**Result:** 
- 2 indicators matched (meets minimum)
- Confidence = 0.35 + 0.30 = **0.65**

**If only 1 matched:**
- Confidence = 0.35 × 0.5 = **0.175** (multiplier applied)

## Real-World Examples

### Example 1: CloudFront WAF

```yaml
  - name: "Amazon CloudFront"
    enabled: true
    description: "Amazon CloudFront CDN with WAF"
    vendor: "Amazon"
    category: "cdn"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        key: "X-AMZ-CF-ID"
        condition: exists
        confidence: 0.35
      
      - type: header
        key: "Via"
        condition: contains
        value: "CloudFront"
        case_insensitive: true
        confidence: 0.3
      
      - type: header
        key: "Server"
        condition: contains
        value: "cloudfront"
        case_insensitive: true
        confidence: 0.25
```

### Example 2: Custom WAF with Body Detection

```yaml
  - name: "Custom Enterprise WAF"
    enabled: true
    description: "Custom in-house WAF solution"
    vendor: "Your Company"
    category: "appliance"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        key: "X-Custom-WAF"
        condition: exists
        confidence: 0.45
      
      - type: body
        condition: contains
        values: ["request blocked", "security policy", "reference id"]
        status_codes: [403]
        case_insensitive: true
        confidence: 0.35
      
      - type: cookie
        key: "custom_waf_session"
        condition: contains
        confidence: 0.3
```

### Example 3: Multiple Server Values

```yaml
  - name: "F5 BIG-IP"
    enabled: true
    description: "F5 BIG-IP Application Security Manager"
    vendor: "F5 Networks"
    category: "appliance"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header
        key: "Server"
        condition: contains
        values: ["bigip", "f5", "big-ip"]
        case_insensitive: true
        confidence: 0.4
      
      - type: cookie
        key: "TS"
        condition: contains
        confidence: 0.35
```

## Testing Your Signature

After adding a signature:

1. **Rebuild:**
   ```bash
   go build
   ```

2. **Test against a target:**
   ```bash
   ./waf-detector -u https://target.com
   ```

3. **Enable verbose mode for debugging:**
   ```bash
   ./waf-detector -u https://target.com -v
   ```

4. **Test with custom YAML file:**
   ```bash
   ./waf-detector -u https://target.com -s signatures/waf-signatures.yml
   ```

## Best Practices

### 1. **Use Unique Indicators**
- Prefer proprietary headers (e.g., `X-Vendor-WAF-ID`)
- Look for unique cookie names
- Search for specific error message patterns

### 2. **Combine Multiple Indicator Types**
```yaml
indicators:
  - type: header      # Proprietary header
  - type: cookie      # Session cookie
  - type: body        # Error message
```

### 3. **Set Appropriate Minimums**
- `minimum_indicators: 2` is recommended for most WAFs
- Use `3` for very high confidence requirements
- Use `1` only if you have a highly unique indicator

### 4. **Calibrate Confidence Scores**
Start conservative and adjust based on testing:
- High confidence (0.4+): Unique identifiers
- Medium (0.3): Distinctive patterns
- Low (0.2): Common patterns

### 5. **Use Case-Insensitive Matching**
Most web headers and error messages vary in case:
```yaml
case_insensitive: true
```

### 6. **Filter by Status Codes**
For body indicators, limit to relevant HTTP codes:
```yaml
status_codes: [403, 503, 406]
```

## Common Patterns

### Pattern: Vendor Header Detection
```yaml
- type: header
  key: "X-Vendor-ID"
  condition: exists
  confidence: 0.45
```

### Pattern: Server Header Variations
```yaml
- type: header
  key: "Server"
  condition: contains
  values: ["vendor", "vendorwaf", "vendor-waf"]
  case_insensitive: true
  confidence: 0.35
```

### Pattern: Blocked Request Body
```yaml
- type: body
  condition: contains
  values: ["blocked", "denied", "firewall"]
  status_codes: [403]
  case_insensitive: true
  confidence: 0.3
```

### Pattern: Challenge Page
```yaml
- type: body
  condition: contains
  values: ["checking your browser", "please wait"]
  status_codes: [503]
  case_insensitive: true
  confidence: 0.35
```

## Troubleshooting

### Signature Not Detecting

1. **Check `enabled: true`**
   ```yaml
   enabled: true
   ```

2. **Verify indicator accuracy**
   - Test manually: `curl -v https://target.com`
   - Check actual header names (case-sensitive for keys)
   - Verify body content exists

3. **Lower minimum_indicators**
   ```yaml
   minimum_indicators: 1  # For testing
   ```

4. **Increase confidence scores**
   ```yaml
   confidence: 0.5  # Make single indicator sufficient
   ```

5. **Enable verbose logging**
   ```bash
   ./waf-detector -u https://target.com -v
   ```

### False Positives

1. **Increase minimum_indicators**
   ```yaml
   minimum_indicators: 3
   ```

2. **Use more specific patterns**
   ```yaml
   values: ["very-specific-error-message"]
   ```

3. **Add status code filters**
   ```yaml
   status_codes: [403]  # Only check 403 responses
   ```

## Complete Example

Here's a complete, well-designed signature:

```yaml
  - name: "Acme WAF Pro"
    enabled: true
    description: "Acme Corporation Web Application Firewall"
    vendor: "Acme Corp"
    category: "appliance"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      # Unique header - highest confidence
      - type: header
        key: "X-Acme-WAF-ID"
        condition: exists
        confidence: 0.45
      
      # Server header - medium confidence
      - type: header
        key: "Server"
        condition: contains
        values: ["acmewaf", "acme-firewall"]
        case_insensitive: true
        confidence: 0.30
      
      # Session cookie - medium confidence
      - type: cookie
        key: "acme_waf_session"
        condition: contains
        confidence: 0.30
      
      # Blocked request body - lower confidence
      - type: body
        condition: contains
        values: ["acme waf", "request blocked by acme", "reference #"]
        status_codes: [403, 503]
        case_insensitive: true
        confidence: 0.25
      
      # Challenge page - lower confidence
      - type: body
        condition: contains
        values: ["verifying your request", "acme security"]
        status_codes: [503]
        case_insensitive: true
        confidence: 0.20
```

## Summary

✅ **No Go code required** - Just edit YAML  
✅ **Hot reload** - Rebuild and changes take effect  
✅ **Flexible matching** - Headers, cookies, body content  
✅ **Confidence scoring** - Calibrate accuracy  
✅ **Easy testing** - Verbose mode shows what matched  

Now you can add any WAF signature without touching the Go codebase!
