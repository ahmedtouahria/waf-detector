package signatures

import (
	"fmt"
	"os"
	"strings"

	"github.com/ahmedtouahria/waf-detector/scanner"
	"gopkg.in/yaml.v3"
)

// IndicatorType defines the type of indicator to check
type IndicatorType string

const (
	IndicatorHeader     IndicatorType = "header"
	IndicatorCookie     IndicatorType = "cookie"
	IndicatorBody       IndicatorType = "body"
	IndicatorStatusCode IndicatorType = "status_code"
)

// IndicatorCondition defines how to match the indicator
type IndicatorCondition string

const (
	ConditionExists   IndicatorCondition = "exists"
	ConditionContains IndicatorCondition = "contains"
	ConditionEquals   IndicatorCondition = "equals"
	ConditionRegex    IndicatorCondition = "regex"
)

// Indicator represents a single detection pattern
type Indicator struct {
	Type             IndicatorType      `yaml:"type"`
	Key              string             `yaml:"key,omitempty"`
	Condition        IndicatorCondition `yaml:"condition"`
	Value            string             `yaml:"value,omitempty"`
	Values           []string           `yaml:"values,omitempty"`
	StatusCodes      []int              `yaml:"status_codes,omitempty"`
	CaseInsensitive  bool               `yaml:"case_insensitive,omitempty"`
	Confidence       float64            `yaml:"confidence"`
	RequireAllValues bool               `yaml:"require_all_values,omitempty"`
}

// YAMLSignature represents a WAF signature loaded from YAML
type YAMLSignature struct {
	WAFName              string      `yaml:"name"`
	Enabled              bool        `yaml:"enabled"`
	Indicators           []Indicator `yaml:"indicators"`
	MinimumIndicators    int         `yaml:"minimum_indicators"`
	ConfidenceMultiplier float64     `yaml:"confidence_multiplier,omitempty"`
	Description          string      `yaml:"description,omitempty"`
	Vendor               string      `yaml:"vendor,omitempty"`
	Category             string      `yaml:"category,omitempty"`
}

// SignaturesConfig represents the full YAML configuration
type SignaturesConfig struct {
	Version    string          `yaml:"version"`
	Signatures []YAMLSignature `yaml:"signatures"`
}

// Name returns the signature name
func (y *YAMLSignature) Name() string {
	return y.WAFName
}

// Match implements the Signature interface
func (y *YAMLSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	if !y.Enabled {
		return 0.0
	}

	confidence := 0.0
	matchedIndicators := 0

	for _, indicator := range y.Indicators {
		if y.matchIndicator(indicator, probes) {
			confidence += indicator.Confidence
			matchedIndicators++
		}
	}

	// Apply minimum indicators requirement
	if y.MinimumIndicators > 0 && matchedIndicators < y.MinimumIndicators {
		multiplier := y.ConfidenceMultiplier
		if multiplier == 0 {
			multiplier = 0.5 // default
		}
		confidence *= multiplier
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// matchIndicator checks if a single indicator matches
func (y *YAMLSignature) matchIndicator(indicator Indicator, probes map[scanner.ProbeType]*scanner.ProbeResult) bool {
	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		switch indicator.Type {
		case IndicatorHeader:
			if y.matchHeader(indicator, probe) {
				return true
			}
		case IndicatorCookie:
			if y.matchCookie(indicator, probe) {
				return true
			}
		case IndicatorBody:
			if y.matchBody(indicator, probe) {
				return true
			}
		case IndicatorStatusCode:
			if y.matchStatusCode(indicator, probe) {
				return true
			}
		}
	}
	return false
}

// matchHeader checks header indicators
func (y *YAMLSignature) matchHeader(indicator Indicator, probe *scanner.ProbeResult) bool {
	headerValue := probe.Headers.Get(indicator.Key)

	switch indicator.Condition {
	case ConditionExists:
		return headerValue != ""
	case ConditionContains:
		return y.matchString(headerValue, indicator)
	case ConditionEquals:
		if indicator.CaseInsensitive {
			return strings.EqualFold(headerValue, indicator.Value)
		}
		return headerValue == indicator.Value
	}
	return false
}

// matchCookie checks cookie indicators
func (y *YAMLSignature) matchCookie(indicator Indicator, probe *scanner.ProbeResult) bool {
	cookieHeader := probe.Headers.Get("Set-Cookie")
	if cookieHeader == "" {
		return false
	}

	switch indicator.Condition {
	case ConditionExists:
		return strings.Contains(cookieHeader, indicator.Key)
	case ConditionContains:
		return y.matchString(cookieHeader, indicator)
	}
	return false
}

// matchBody checks body content indicators
func (y *YAMLSignature) matchBody(indicator Indicator, probe *scanner.ProbeResult) bool {
	// Check status code filter if specified
	if len(indicator.StatusCodes) > 0 {
		matched := false
		for _, code := range indicator.StatusCodes {
			if probe.StatusCode == code {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	body := probe.Body
	if indicator.CaseInsensitive {
		body = strings.ToLower(body)
	}

	switch indicator.Condition {
	case ConditionContains:
		if len(indicator.Values) > 0 {
			if indicator.RequireAllValues {
				// All values must be present
				for _, val := range indicator.Values {
					searchVal := val
					if indicator.CaseInsensitive {
						searchVal = strings.ToLower(val)
					}
					if !strings.Contains(body, searchVal) {
						return false
					}
				}
				return true
			} else {
				// Any value can match
				for _, val := range indicator.Values {
					searchVal := val
					if indicator.CaseInsensitive {
						searchVal = strings.ToLower(val)
					}
					if strings.Contains(body, searchVal) {
						return true
					}
				}
			}
		} else if indicator.Value != "" {
			searchVal := indicator.Value
			if indicator.CaseInsensitive {
				searchVal = strings.ToLower(indicator.Value)
			}
			return strings.Contains(body, searchVal)
		}
	}
	return false
}

// matchStatusCode checks status code indicators
func (y *YAMLSignature) matchStatusCode(indicator Indicator, probe *scanner.ProbeResult) bool {
	for _, code := range indicator.StatusCodes {
		if probe.StatusCode == code {
			return true
		}
	}
	return false
}

// matchString is a helper for string matching
func (y *YAMLSignature) matchString(value string, indicator Indicator) bool {
	if indicator.CaseInsensitive {
		value = strings.ToLower(value)
	}

	if len(indicator.Values) > 0 {
		for _, val := range indicator.Values {
			searchVal := val
			if indicator.CaseInsensitive {
				searchVal = strings.ToLower(val)
			}
			if strings.Contains(value, searchVal) {
				return true
			}
		}
		return false
	}

	searchVal := indicator.Value
	if indicator.CaseInsensitive {
		searchVal = strings.ToLower(indicator.Value)
	}
	return strings.Contains(value, searchVal)
}

// LoadSignaturesFromYAML loads signatures from a YAML file
func LoadSignaturesFromYAML(filename string) ([]Signature, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read signatures file: %w", err)
	}

	return parseSignaturesFromBytes(data)
}

// parseSignaturesFromBytes parses YAML signature data from bytes
func parseSignaturesFromBytes(data []byte) ([]Signature, error) {
	var config SignaturesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse signatures YAML: %w", err)
	}

	signatures := make([]Signature, 0, len(config.Signatures))
	for i := range config.Signatures {
		if config.Signatures[i].Enabled {
			signatures = append(signatures, &config.Signatures[i])
		}
	}

	return signatures, nil
}

// GetSignatures returns either YAML-loaded signatures or default hardcoded ones
func GetSignatures(yamlPath string) []Signature {
	if yamlPath != "" {
		signatures, err := LoadSignaturesFromYAML(yamlPath)
		if err == nil && len(signatures) > 0 {
			return signatures
		}
		// Fall back to default if YAML loading fails
		fmt.Fprintf(os.Stderr, "Warning: Failed to load YAML signatures (%v), using defaults\n", err)
	}

	// Return hardcoded defaults
	return GetAllSignatures()
}
