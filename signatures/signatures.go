package signatures

import (
	"strings"

	"github.com/wafw00f/wafw00f-go/scanner"
)

type Signature interface {
	Name() string
	Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64
}

func GetAllSignatures() []Signature {
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
	}
}

type CloudflareSignature struct{}

func (s *CloudflareSignature) Name() string {
	return "Cloudflare"
}

func (s *CloudflareSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if server := probe.Headers.Get("Server"); strings.Contains(strings.ToLower(server), "cloudflare") {
			confidence += 0.4
		}

		if cfRay := probe.Headers.Get("CF-Ray"); cfRay != "" {
			confidence += 0.3
		}

		if cfCache := probe.Headers.Get("CF-Cache-Status"); cfCache != "" {
			confidence += 0.2
		}

		if strings.Contains(strings.ToLower(probe.Body), "cloudflare") {
			confidence += 0.1
		}

		if probe.StatusCode == 403 {
			bodyLower := strings.ToLower(probe.Body)
			if strings.Contains(bodyLower, "attention required") || strings.Contains(bodyLower, "ray id") {
				confidence += 0.3
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type AWSWAFSignature struct{}

func (s *AWSWAFSignature) Name() string {
	return "AWS WAF"
}

func (s *AWSWAFSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "awselb") {
			confidence += 0.3
		}

		if probe.StatusCode == 403 {
			bodyLower := strings.ToLower(probe.Body)
			if strings.Contains(bodyLower, "request blocked") || strings.Contains(bodyLower, "aws") {
				confidence += 0.4
			}

			if strings.Contains(bodyLower, "<title>403 forbidden</title>") {
				confidence += 0.2
			}

			if probe.Headers.Get("X-AMZ-ID") != "" || probe.Headers.Get("X-AMZ-Request-ID") != "" {
				confidence += 0.3
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type AkamaiSignature struct{}

func (s *AkamaiSignature) Name() string {
	return "Akamai"
}

func (s *AkamaiSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "akamaighost") {
			confidence += 0.5
		}

		if probe.Headers.Get("X-Akamai-Session-Info") != "" {
			confidence += 0.3
		}

		if strings.Contains(strings.ToLower(probe.Body), "akamai") {
			confidence += 0.2
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type ImpervaSignature struct{}

func (s *ImpervaSignature) Name() string {
	return "Imperva Incapsula"
}

func (s *ImpervaSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("X-CDN")), "incapsula") {
			confidence += 0.5
		}

		if probe.Headers.Get("X-Iinfo") != "" {
			confidence += 0.4
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "incapsula") || strings.Contains(bodyLower, "imperva") {
			confidence += 0.3
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type F5BigIPSignature struct{}

func (s *F5BigIPSignature) Name() string {
	return "F5 BIG-IP"
}

func (s *F5BigIPSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "bigip") ||
			strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "f5") {
			confidence += 0.5
		}

		for key := range probe.Headers {
			if strings.HasPrefix(strings.ToLower(key), "x-wa-info") ||
				strings.HasPrefix(strings.ToLower(key), "x-cnection") {
				confidence += 0.3
				break
			}
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "TS") && probe.StatusCode == 403 {
			confidence += 0.2
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type FortiWebSignature struct{}

func (s *FortiWebSignature) Name() string {
	return "FortiWeb"
}

func (s *FortiWebSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		bodyLower := strings.ToLower(probe.Body)
		if strings.Contains(bodyLower, "fortiweb") || strings.Contains(bodyLower, "fortigate") {
			confidence += 0.5
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "FORTIWAFSID") {
			confidence += 0.4
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type BarracudaSignature struct{}

func (s *BarracudaSignature) Name() string {
	return "Barracuda WAF"
}

func (s *BarracudaSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Body), "barracuda") {
			confidence += 0.5
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "barra_counter_session") {
			confidence += 0.4
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type CitrixNetScalerSignature struct{}

func (s *CitrixNetScalerSignature) Name() string {
	return "Citrix NetScaler"
}

func (s *CitrixNetScalerSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(probe.Headers.Get("Set-Cookie"), "ns_af") ||
			strings.Contains(probe.Headers.Get("Set-Cookie"), "citrix_ns_id") {
			confidence += 0.5
		}

		if strings.Contains(probe.Headers.Get("Via"), "NS-CACHE") {
			confidence += 0.3
		}

		if strings.Contains(strings.ToLower(probe.Body), "netscaler") {
			confidence += 0.2
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type CloudfrontSignature struct{}

func (s *CloudfrontSignature) Name() string {
	return "Amazon CloudFront"
}

func (s *CloudfrontSignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "cloudfront") {
			confidence += 0.4
		}

		if probe.Headers.Get("X-Cache") != "" && strings.Contains(probe.Headers.Get("Via"), "CloudFront") {
			confidence += 0.4
		}

		if probe.Headers.Get("X-AMZ-CF-ID") != "" {
			confidence += 0.3
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

type ModSecuritySignature struct{}

func (s *ModSecuritySignature) Name() string {
	return "ModSecurity"
}

func (s *ModSecuritySignature) Match(probes map[scanner.ProbeType]*scanner.ProbeResult) float64 {
	confidence := 0.0

	for _, probe := range probes {
		if probe == nil || probe.Error != nil {
			continue
		}

		if strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "mod_security") ||
			strings.Contains(strings.ToLower(probe.Headers.Get("Server")), "modsecurity") {
			confidence += 0.5
		}

		if probe.StatusCode == 406 || probe.StatusCode == 501 {
			bodyLower := strings.ToLower(probe.Body)
			if strings.Contains(bodyLower, "mod_security") || strings.Contains(bodyLower, "modsecurity") {
				confidence += 0.4
			}
		}
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}
