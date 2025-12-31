package output

import (
	"os"
	"testing"
	"time"

	"github.com/wafw00f/waf-detector/cli"
)

func TestResult(t *testing.T) {
	result := Result{
		URL:        "https://example.com",
		WAFFound:   true,
		WAFName:    "Cloudflare",
		Confidence: 95.0,
		Details:    "Detected via headers",
		ScanTime:   100 * time.Millisecond,
		Timestamp:  time.Now(),
	}

	if result.URL != "https://example.com" {
		t.Errorf("URL = %s, want https://example.com", result.URL)
	}
	if !result.WAFFound {
		t.Error("WAFFound should be true")
	}
	if result.WAFName != "Cloudflare" {
		t.Errorf("WAFName = %s, want Cloudflare", result.WAFName)
	}
}

func TestWriteResultsJSON(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-output-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	config := &cli.Config{
		OutputFile: tmpfile.Name(),
		Format:     "json",
		NoColor:    true,
	}

	results := []Result{
		{
			URL:      "https://example.com",
			WAFFound: true,
			WAFName:  "TestWAF",
		},
	}

	err = WriteResults(results, config)
	if err != nil {
		t.Errorf("WriteResults failed: %v", err)
	}

	// Verify file was written
	info, err := os.Stat(tmpfile.Name())
	if err != nil {
		t.Errorf("Output file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("Output file is empty")
	}
}

func TestWriteResultsText(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-output-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	config := &cli.Config{
		OutputFile: tmpfile.Name(),
		Format:     "txt",
		NoColor:    true,
	}

	results := []Result{
		{
			URL:      "https://example.com",
			WAFFound: false,
		},
	}

	err = WriteResults(results, config)
	if err != nil {
		t.Errorf("WriteResults failed: %v", err)
	}
}
