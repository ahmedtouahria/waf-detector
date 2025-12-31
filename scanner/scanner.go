package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wafw00f/waf-detector/cli"
)

type ProbeType string

const (
	ProbeNormal    ProbeType = "normal"
	ProbeSQLi      ProbeType = "sqli"
	ProbeXSS       ProbeType = "xss"
	ProbeMalformed ProbeType = "malformed"
)

type ProbeResult struct {
	Type       ProbeType
	StatusCode int
	Headers    http.Header
	Body       string
	BodyLength int
	Duration   time.Duration
	Error      error
}

type Scanner struct {
	client *http.Client
	config *cli.Config
}

func NewScanner(config *cli.Config) *Scanner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Scanner{
		client: client,
		config: config,
	}
}

func (s *Scanner) Scan(ctx context.Context, target string) (map[ProbeType]*ProbeResult, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	results := make(map[ProbeType]*ProbeResult)

	probes := []struct {
		probeType ProbeType
		fn        func(context.Context, string) *ProbeResult
	}{
		{ProbeNormal, s.probeNormal},
		{ProbeSQLi, s.probeSQLi},
		{ProbeXSS, s.probeXSS},
		{ProbeMalformed, s.probeMalformed},
	}

	for _, probe := range probes {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			result := probe.fn(ctx, target)
			results[probe.probeType] = result

			if s.config.Debug {
				fmt.Printf("[DEBUG] %s probe for %s: status=%d, length=%d, duration=%v\n",
					probe.probeType, target, result.StatusCode, result.BodyLength, result.Duration)
			}
		}
	}

	return results, nil
}

func (s *Scanner) probeNormal(ctx context.Context, target string) *ProbeResult {
	return s.doRequest(ctx, ProbeNormal, target, "", nil)
}

func (s *Scanner) probeSQLi(ctx context.Context, target string) *ProbeResult {
	u, err := url.Parse(target)
	if err != nil {
		return &ProbeResult{Type: ProbeSQLi, Error: err}
	}

	q := u.Query()
	q.Set("id", "1' OR '1'='1")
	q.Set("test", "' UNION SELECT NULL--")
	u.RawQuery = q.Encode()

	return s.doRequest(ctx, ProbeSQLi, u.String(), "", nil)
}

func (s *Scanner) probeXSS(ctx context.Context, target string) *ProbeResult {
	u, err := url.Parse(target)
	if err != nil {
		return &ProbeResult{Type: ProbeXSS, Error: err}
	}

	q := u.Query()
	q.Set("q", "<script>alert(1)</script>")
	q.Set("search", "<img src=x onerror=alert(1)>")
	u.RawQuery = q.Encode()

	return s.doRequest(ctx, ProbeXSS, u.String(), "", nil)
}

func (s *Scanner) probeMalformed(ctx context.Context, target string) *ProbeResult {
	headers := map[string]string{
		"X-Forwarded-For": "127.0.0.1' OR '1'='1",
		"User-Agent":      "../../../etc/passwd",
		"Referer":         "javascript:alert(1)",
		"Cookie":          "session=<script>alert(1)</script>",
	}

	return s.doRequest(ctx, ProbeMalformed, target, "", headers)
}

func (s *Scanner) doRequest(ctx context.Context, probeType ProbeType, target string, body string, headers map[string]string) *ProbeResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return &ProbeResult{
			Type:  probeType,
			Error: err,
		}
	}

	req.Header.Set("User-Agent", s.config.UserAgent)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return &ProbeResult{
			Type:     probeType,
			Duration: duration,
			Error:    err,
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return &ProbeResult{
			Type:       probeType,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Duration:   duration,
			Error:      err,
		}
	}

	return &ProbeResult{
		Type:       probeType,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       string(bodyBytes),
		BodyLength: len(bodyBytes),
		Duration:   duration,
	}
}
