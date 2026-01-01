# YAML Signature System Migration

## Overview

WAF Detector has been upgraded from hardcoded Go signatures to a flexible YAML-based signature system. This enhancement allows users to customize WAF detection without recompiling the tool.

## What Changed

### New Features

1. **YAML Signature Files**: Define WAF signatures in human-readable YAML format
2. **Custom Signature Support**: Use custom signature files via `-s/--signatures` flag
3. **Runtime Configuration**: Add, modify, or disable signatures without recompilation
4. **Fallback Mechanism**: Automatically uses hardcoded signatures if YAML fails to load
5. **Enhanced Matching**: Multiple indicator types and conditions for flexible detection

### New Files

#### `signatures/loader.go`
- **Purpose**: YAML signature loading and parsing
- **Key Components**:
  - `YAMLSignature`: YAML-compatible signature structure
  - `LoadSignaturesFromYAML()`: Parses YAML files
  - `GetSignatures()`: Returns YAML or default signatures
  - Indicator matching functions for headers, cookies, body, status codes

#### `signatures/waf-signatures.yml`
- **Purpose**: Default signature library
- **Contains**: 11 pre-configured WAF signatures
  - Cloudflare
  - AWS WAF
  - Akamai Kona
  - Imperva Incapsula
  - F5 BIG-IP
  - ModSecurity
  - Sucuri
  - Wordfence
  - Azure Front Door WAF
  - Fastly
  - Wallarm

### Modified Files

#### `cli/cli.go`
- Added `SignaturesFile` field to `Config` struct
- Added `-s/--signatures` command-line flag

#### `detector/detector.go`
- Added `NewDetectorWithSignatures()` constructor
- Allows injection of custom signatures

#### `main.go`
- Added signature loading logic
- Uses YAML signatures if `-s` flag provided
- Falls back to hardcoded signatures otherwise
- Logs signature count in non-silent mode

#### `README.md`
- Added YAML Signatures to features list
- Added custom signatures usage example
- Added `-s/--signatures` to command-line options
- Expanded "How It Works" section

#### `docs/ARCHITECTURE.md`
- Updated with YAML signature system architecture
- Added signature matching flow diagram
- Documented indicator types and conditions

#### `docs/EXAMPLES.md`
- Added custom YAML signature examples
- Demonstrated signature file creation
- Showed how to enable/disable signatures

### New Dependencies

- `gopkg.in/yaml.v3`: YAML parsing library

## YAML Signature Structure

```yaml
signatures:
  - name: "WAF Name"
    enabled: true
    description: "WAF description"
    vendor: "Vendor name"
    category: "WAF category"
    minimum_indicators: 2
    confidence_multiplier: 0.5
    indicators:
      - type: header|cookie|body|status_code
        name: "header/cookie name (optional)"
        condition: exists|contains|equals
        value: "match value (optional)"
        confidence: 0.0-1.0
```

## Indicator Types

### 1. Header
Matches HTTP response headers.

**Example**:
```yaml
- type: header
  name: "Server"
  condition: contains
  value: "cloudflare"
  confidence: 0.5
```

### 2. Cookie
Matches Set-Cookie headers.

**Example**:
```yaml
- type: cookie
  name: "__cfduid"
  condition: exists
  confidence: 0.6
```

### 3. Body
Matches response body content.

**Example**:
```yaml
- type: body
  condition: contains
  value: "Access Denied"
  confidence: 0.7
```

### 4. Status Code
Matches HTTP status codes.

**Example**:
```yaml
- type: status_code
  value: "403"
  condition: equals
  confidence: 0.3
```

## Indicator Conditions

- **exists**: Checks if header/cookie exists (ignores value)
- **contains**: Checks if value contains substring (case-insensitive)
- **equals**: Checks for exact match (case-insensitive)
- **regex**: Regular expression matching (future enhancement)

## Confidence Scoring

Each signature calculates confidence based on:

1. **Individual Indicators**: Each indicator has a confidence value (0.0-1.0)
2. **Accumulation**: Matched indicators add their confidence to total
3. **Minimum Requirement**: `minimum_indicators` defines required matches
4. **Penalty Factor**: `confidence_multiplier` applied if below minimum
5. **Capping**: Final confidence capped at 1.0 (100%)

**Example**:
```yaml
minimum_indicators: 2
confidence_multiplier: 0.5

# If only 1 indicator matches with confidence 0.8:
# final_confidence = 0.8 * 0.5 = 0.4 (40%)

# If 2 indicators match with confidences 0.6 and 0.7:
# final_confidence = 0.6 + 0.7 = 1.0 (capped at 100%)
```

## Usage Examples

### Use Default YAML Signatures

```bash
waf-detector -u https://example.com -s signatures/waf-signatures.yml
```

Output:
```
INFO Loaded 11 signatures from signatures/waf-signatures.yml
✓ https://example.com - WAF Detected: Cloudflare
  Confidence: 95.0%
```

### Use Custom Signatures

Create `my-signatures.yml`:
```yaml
signatures:
  - name: "MyWAF"
    enabled: true
    description: "My custom WAF"
    minimum_indicators: 1
    confidence_multiplier: 0.7
    indicators:
      - type: header
        name: "X-MyWAF"
        condition: exists
        confidence: 1.0
```

Run:
```bash
waf-detector -u https://mysite.com -s my-signatures.yml
```

### Use Hardcoded Signatures (Default)

```bash
waf-detector -u https://example.com
```

No YAML file needed - uses built-in signatures automatically.

## Migration Benefits

### For Users

1. **No Recompilation**: Update signatures without rebuilding
2. **Easy Customization**: Add company-specific WAFs
3. **Version Control**: Track signature changes in Git
4. **Sharing**: Share signature files across teams
5. **Testing**: Experiment with different detection strategies

### For Developers

1. **Separation of Concerns**: Code separate from detection data
2. **Maintainability**: Easier to update signature library
3. **Extensibility**: Community contributions via YAML files
4. **Testing**: Test signatures without code changes
5. **Documentation**: Self-documenting signature format

## Backward Compatibility

The tool remains **100% backward compatible**:

- Default behavior unchanged (uses hardcoded signatures)
- All existing command-line flags work as before
- YAML signatures are **opt-in** via `-s` flag
- Graceful fallback to hardcoded signatures on YAML errors

## Future Enhancements

1. **Regex Conditions**: Regular expression matching for complex patterns
2. **Signature Repository**: Online repository of community signatures
3. **Signature Validation**: CLI command to validate YAML syntax
4. **Signature Updates**: Automatic signature file updates
5. **Multiple Files**: Load signatures from multiple YAML files
6. **Signature Scoring**: Advanced confidence calculation algorithms
7. **Custom Probes**: Define custom probe types in YAML

## Documentation

Full documentation available at:

- **Signature Guide**: [docs/SIGNATURES.md](SIGNATURES.md)
- **Architecture**: [docs/ARCHITECTURE.md](ARCHITECTURE.md)
- **Examples**: [docs/EXAMPLES.md](EXAMPLES.md)
- **Main README**: [README.md](../README.md)

## Contributing Signatures

We welcome community contributions! To submit new signatures:

1. Fork the repository
2. Add your signature to `signatures/waf-signatures.yml`
3. Test against target WAF: `waf-detector -u <target> -s signatures/waf-signatures.yml`
4. Submit pull request with:
   - Signature definition
   - Test results
   - WAF documentation link

See [docs/SIGNATURES.md](SIGNATURES.md) for detailed guidelines.

## Troubleshooting

### Signatures Not Loading

**Problem**: "Failed to load signatures from file"

**Solutions**:
- Check YAML syntax with validator: `yamllint my-signatures.yml`
- Verify file path is correct
- Check file permissions
- Review error message for specific issue

### Low Confidence Scores

**Problem**: WAF detected with low confidence

**Solutions**:
- Add more indicators to signature
- Increase individual indicator confidence values
- Lower `minimum_indicators` requirement
- Adjust `confidence_multiplier`

### No WAF Detected

**Problem**: Expected WAF not detected

**Solutions**:
- Enable debug mode: `--debug`
- Verify signature is enabled: `enabled: true`
- Check indicator conditions match actual responses
- Test with known WAF-protected site
- Compare with hardcoded signatures

### YAML Parse Errors

**Problem**: "yaml: unmarshal errors"

**Solutions**:
- Validate YAML indentation (use spaces, not tabs)
- Check for special characters requiring quotes
- Verify all required fields present
- Use online YAML validator

## Version History

- **v1.0.0**: Initial release with hardcoded signatures
- **v1.1.0**: YAML signature system introduced
  - Added YAML loading capability
  - Created default signature library
  - Added custom signature support
  - Updated documentation
