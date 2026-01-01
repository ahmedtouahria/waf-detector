package signatures

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ahmedtouahria/waf-detector/scanner"
)

//go:embed waf-signatures.yml
var embeddedSignatures embed.FS

type Signature interface {
	Name() string
	Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64
}

// GetAllSignatures loads signatures from YAML (embedded or file), falls back to hardcoded
func GetAllSignatures() []Signature {
	// Try to load from embedded YAML first
	data, err := embeddedSignatures.ReadFile("waf-signatures.yml")
	if err == nil {
		if sigs, err := parseSignaturesFromBytes(data); err == nil && len(sigs) > 0 {
			return sigs
		}
	}

	// Try to load from file system (for development)
	execPath, _ := os.Executable()
	execDir := filepath.Dir(execPath)
	possiblePaths := []string{
		"signatures/waf-signatures.yml",
		filepath.Join(execDir, "signatures/waf-signatures.yml"),
		filepath.Join(execDir, "waf-signatures.yml"),
		"waf-signatures.yml",
	}

	for _, path := range possiblePaths {
		if sigs, err := LoadSignaturesFromYAML(path); err == nil && len(sigs) > 0 {
			return sigs
		}
	}

	// Fall back to hardcoded signatures
	fmt.Fprintln(os.Stderr, "Warning: Could not load YAML signatures, using hardcoded defaults")
	return getHardcodedSignatures()
}

// getHardcodedSignatures returns the original hardcoded signatures as fallback
func getHardcodedSignatures() []Signature {
	return []Signature{
		&CloudflareSignature{},
		&AWSWAFSignature{},
		&AkamaiSignature{},
		&ImpervaSignature{},
		&F5BigIPSignature{},
		&FortiWebSignature{},
		&BarracudaSignature{},
		&CitrixNetScalerSignature{},
		&CloudfrontSignature{},
		&ModSecuritySignature{},
		&SucuriSignature{},
		&WordfenceSignature{},
		&StackPathSignature{},
		&ReblazeSignature{},
		&AzureWAFSignature{},
		&FastlySignature{},
		&EdgeCastSignature{},
		&WallarmSignature{},
		&SiteGroundSignature{},
		&PentaSecuritySignature{},
	}
}

type CloudflareSignature struct{}

func (s *CloudflareSignature) Name() string {
	return "Cloudflare"
}

func (s *CloudflareSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		// Strong indicators
		if cfRay := probe.Headers.Get("CF-Ray"); cfRay != "" {
			confidence += 0.35
			indicators++
		}

		if cfCache := probe.Headers.Get("CF-Cache-Status"); cfCache != "" {
			confidence += 0.25
			indicators++
		}

		if probe.Headers.Get("CF-Request-ID") != "" {
			confidence += 0.2
			indicators++
		}

		// Server header check
		if server := probe.Headers.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
			confidence += 0.3
			indicators++
		}

		// Set-Cookie checks
		if cookies := probe.Headers.Get("Set-Cookie"); cookies != "" {
			if strings.Contains(cookies, "__cfduid") || strings.Contains(cookies, "cf_clearance") {
				confidence += 0.25
				indicators++
			}
		}

		// Body content analysis for blocked requests
		bodyLower := strings.ToLower(probe.Body)
		if probe.StatusCode == 403 || probe.StatusCode == 503 {
			if strings.Contains(bodyLower, "attention required") ||
				strings.Contains(bodyLower, "cloudflare") ||
				strings.Contains(bodyLower, "ray id:") ||
				strings.Contains(bodyLower, "cf-ray") {
				confidence += 0.3
				indicators++
			}
		}

		// Challenge page detection
		if strings.Contains(bodyLower, "checking your browser") ||
			strings.Contains(bodyLower, "ddos protection by cloudflare") {
			confidence += 0.25
			indicators++
		}

		// Additional headers
		if probe.Headers.Get("CF-Team") != "" ||
			probe.Headers.Get("Cf-Railgun") != "" ||
			probe.Headers.Get("Expect-CT") != "" {
			confidence += 0.15
			indicators++
		}
	}

	// Require at least 2 indicators
	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type AWSWAFSignature struct{}

func (s *AWSWAFSignature) Name() string {
	return "AWS WAF"
}

func (s *AWSWAFSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		// AWS-specific headers
		if probe.Headers.Get("X-AMZ-ID") != "" ||
			probe.Headers.Get("X-AMZ-Request-ID") != "" ||
			probe.Headers.Get("X-AMZN-RequestID") != "" ||
			probe.Headers.Get("X-AMZN-Trace-ID") != "" {
			confidence += 0.35
			indicators++
		}

		if probe.Headers.Get("X-AMZ-CF-ID") != "" || probe.Headers.Get("X-AMZ-CF-POP") != "" {
			confidence += 0.3
			indicators++
		}

		// Server headers
		server := strings.ToLower(probe.Headers.Get("Server"))
		if strings.Contains(server, "awselb") ||
			strings.Contains(server, "aws") ||
			strings.Contains(server, "amazon") {
			confidence += 0.25
			indicators++
		}

		// Status code specific checks
		if probe.StatusCode == 403 {
			bodyLower := strings.ToLower(probe.Body)
			if strings.Contains(bodyLower, "request blocked") ||
				strings.Contains(bodyLower, "aws waf") ||
				strings.Contains(bodyLower, "requestid") {
				confidence += 0.3
				indicators++
			}

			if strings.Contains(bodyLower, "<title>403 forbidden</title>") &&
				strings.Contains(bodyLower, "aws") {
				confidence += 0.25
				indicators++
			}
		}

		// WAF-specific patterns
		if strings.Contains(strings.ToLower(probe.Body), "aws waf") {
			confidence += 0.35
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type AkamaiSignature struct{}

func (s *AkamaiSignature) Name() string {
	return "Akamai"
}

func (s *AkamaiSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "akamaighost") {
			confidence += 0.4
			indicators++
		}

		if probe.Headers.Get("X-Akamai-Session-Info") != "" {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "akamai") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type ImpervaSignature struct{}

func (s *ImpervaSignature) Name() string {
	return "Imperva Incapsula"
}

func (s *ImpervaSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("X-CDN")), "incapsula") {
			confidence += 0.4
			indicators++
		}

		if probe.Headers.Get("X-Iinfo") != "" {
			confidence += 0.35
			indicators++
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "incapsula") || strings.Contains(bodyLower, "imperva") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type F5BigIPSignature struct{}

func (s *F5BigIPSignature) Name() string {
	return "F5 BIG-IP"
}

func (s *F5BigIPSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "bigip") ||
			strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "f5") {
			confidence += 0.4
			indicators++
		}

		for key := range probe.Headers {
			if strings.HasPrefix(strings.ToLower(key), "x-wa-info") ||
				strings.HasPrefix(strings.ToLower(key), "x-cnection") {
				confidence += 0.3
				indicators++
				break
			}
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "TS") && probe.StatusCode == 403 {
			confidence += 0.3
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type FortiWebSignature struct{}

func (s *FortiWebSignature) Name() string {
	return "FortiWeb"
}

func (s *FortiWebSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "fortiweb") || strings.Contains(bodyLower, "fortigate") {
			confidence += 0.4
			indicators++
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "FORTIWAFSID") {
			confidence += 0.45
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type BarracudaSignature struct{}

func (s *BarracudaSignature) Name() string {
	return "Barracuda WAF"
}

func (s *BarracudaSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Body), "barracuda") {
			confidence += 0.4
			indicators++
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "barra_counter_session") {
			confidence += 0.45
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type CitrixNetScalerSignature struct{}

func (s *CitrixNetScalerSignature) Name() string {
	return "Citrix NetScaler"
}

func (s *CitrixNetScalerSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "ns_af") ||
			strings.Contains(probe.Headers.Get("Set-Cookie"), "citrix_ns_id") {
			confidence += 0.4
			indicators++
		}

		if strings.Contains(probe.Headers.Get("Via"), "NS-CACHE") {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "netscaler") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type CloudfrontSignature struct{}

func (s *CloudfrontSignature) Name() string {
	return "Amazon CloudFront"
}

func (s *CloudfrontSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "cloudfront") {
			confidence += 0.35
			indicators++
		}

		if probe.Headers.Get("X-Cache") != "" && strings.Contains(probe.Headers.Get("Via"), "CloudFront") {
			confidence += 0.35
			indicators++
		}

		if probe.Headers.Get("X-AMZ-CF-ID") != "" {
			confidence += 0.3
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

type ModSecuritySignature struct{}

func (s *ModSecuritySignature) Name() string {
	return "ModSecurity"
}

func (s *ModSecuritySignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		server := strings.ToLower(probe.Headers.Get("Server"))
		if strings.Contains(server, "mod_security") || strings.Contains(server, "modsecurity") {
			confidence += 0.4
			indicators++
		}

		bodyLower := strings.ToLower(probe.Body)
		if probe.StatusCode == 406 || probe.StatusCode == 403 || probe.StatusCode == 501 {
			if strings.Contains(bodyLower, "mod_security") ||
				strings.Contains(bodyLower, "modsecurity") ||
				strings.Contains(bodyLower, "not acceptable") && probe.StatusCode == 406 {
				confidence += 0.35
				indicators++
			}
		}

		// Common ModSecurity error patterns
		if strings.Contains(bodyLower, "reference id") ||
			strings.Contains(bodyLower, "your access has been blocked") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Sucuri
type SucuriSignature struct{}

func (s *SucuriSignature) Name() string {
	return "Sucuri CloudProxy WAF"
}

func (s *SucuriSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "sucuri") {
			confidence += 0.4
			indicators++
		}

		if probe.Headers.Get("X-Sucuri-ID") != "" || probe.Headers.Get("X-Sucuri-Cache") != "" {
			confidence += 0.35
			indicators++
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "sucuri") ||
			strings.Contains(bodyLower, "cloudproxy") ||
			strings.Contains(bodyLower, "access denied - sucuri website firewall") {
			confidence += 0.3
			indicators++
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "sucuri") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Wordfence
type WordfenceSignature struct{}

func (s *WordfenceSignature) Name() string {
	return "Wordfence"
}

func (s *WordfenceSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "wordfence") ||
			strings.Contains(bodyLower, "generated by wordfence") ||
			strings.Contains(bodyLower, "a potentially unsafe operation has been detected") {
			confidence += 0.4
			indicators++
		}

		if probe.StatusCode == 503 && strings.Contains(bodyLower, "this site is currently unavailable") {
			confidence += 0.25
			indicators++
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "wfvt_") {
			confidence += 0.35
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: StackPath
type StackPathSignature struct{}

func (s *StackPathSignature) Name() string {
	return "StackPath WAF"
}

func (s *StackPathSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "stackpath") {
			confidence += 0.4
			indicators++
		}

		if probe.Headers.Get("X-SP-Shield") != "" || probe.Headers.Get("X-StackPath-Shield") != "" {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "stackpath") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Reblaze
type ReblazeSignature struct{}

func (s *ReblazeSignature) Name() string {
	return "Reblaze"
}

func (s *ReblazeSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if probe.Headers.Get("X-Reblaze-Request-ID") != "" {
			confidence += 0.45
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "reblaze") {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "reblaze") ||
			strings.Contains(strings.ToLower(probe.Body), "rbzid") {
			confidence += 0.3
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Azure WAF
type AzureWAFSignature struct{}

func (s *AzureWAFSignature) Name() string {
	return "Azure WAF"
}

func (s *AzureWAFSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if probe.Headers.Get("X-Azure-Ref") != "" || probe.Headers.Get("X-Azure-SocketIP") != "" {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "azure") {
			confidence += 0.25
			indicators++
		}

		bodyLower := strings.ToLower(probe.Body)
		if probe.StatusCode == 403 && (strings.Contains(bodyLower, "azure") ||
			strings.Contains(bodyLower, "microsoft azure")) {
			confidence += 0.3
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Fastly
type FastlySignature struct{}

func (s *FastlySignature) Name() string {
	return "Fastly WAF"
}

func (s *FastlySignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if probe.Headers.Get("X-Fastly-Request-ID") != "" || probe.Headers.Get("Fastly-Debug-Digest") != "" {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Via")), "fastly") {
			confidence += 0.3
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "fastly") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: EdgeCast (Verizon)
type EdgeCastSignature struct{}

func (s *EdgeCastSignature) Name() string {
	return "EdgeCast WAF"
}

func (s *EdgeCastSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "edgecast") ||
			strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "ecd") {
			confidence += 0.4
			indicators++
		}

		if probe.Headers.Get("X-EC-Debug") != "" {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "reference #18") ||
			strings.Contains(strings.ToLower(probe.Body), "edgecast") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Wallarm
type WallarmSignature struct{}

func (s *WallarmSignature) Name() string {
	return "Wallarm"
}

func (s *WallarmSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "wallarm") {
			confidence += 0.4
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Via")), "wallarm") {
			confidence += 0.35
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Body), "wallarm") {
			confidence += 0.3
			indicators++
		}

		if probe.StatusCode == 403 && strings.Contains(strings.ToLower(probe.Body), "request blocked") {
			confidence += 0.2
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: SiteGround
type SiteGroundSignature struct{}

func (s *SiteGroundSignature) Name() string {
	return "SiteGround WAF"
}

func (s *SiteGroundSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "siteground") {
			confidence += 0.35
			indicators++
		}

		if probe.StatusCode == 403 && strings.Contains(bodyLower, "request was blocked by our security") {
			confidence += 0.4
			indicators++
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "siteground") {
			confidence += 0.25
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}

// New Signature: Penta Security
type PentaSecuritySignature struct{}

func (s *PentaSecuritySignature) Name() string {
	return "Penta Security WAPPLES"
}

func (s *PentaSecuritySignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0
	indicators := 0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "wapples") {
			confidence += 0.45
			indicators++
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "wapples") ||
			strings.Contains(bodyLower, "penta security") {
			confidence += 0.35
			indicators++
		}

		if probe.StatusCode == 403 && strings.Contains(bodyLower, "request blocked") {
			confidence += 0.2
			indicators++
		}
	}

	if indicators >= 2 && confidence > 1.0 {
		confidence = 1.0
	} else if indicators < 2 {
		confidence *= 0.5
	}

	return confidence
}
