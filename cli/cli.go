package cli

import (
	"flag"
	"fmt"
	"os"
	"time"
)

type Config struct {
	URL        string
	ListFile   string
	Threads    int
	OutputFile string
	Format     string
	Timeout    time.Duration
	Proxy      string
	UserAgent  string
	Silent     bool
	NoColor    bool
	Debug      bool
}

func ParseFlags() *Config {
	config := &Config{}

	flag.StringVar(&config.URL, "u", "", "Single target URL")
	flag.StringVar(&config.URL, "url", "", "Single target URL")
	flag.StringVar(&config.ListFile, "l", "", "File with list of URLs")
	flag.StringVar(&config.ListFile, "list", "", "File with list of URLs")
	flag.IntVar(&config.Threads, "t", 10, "Number of concurrent workers")
	flag.IntVar(&config.Threads, "threads", 10, "Number of concurrent workers")
	flag.StringVar(&config.OutputFile, "o", "", "Output file path")
	flag.StringVar(&config.OutputFile, "output", "", "Output file path")
	flag.StringVar(&config.Format, "f", "txt", "Output format: txt | json")
	flag.StringVar(&config.Format, "format", "txt", "Output format: txt | json")

	var timeoutSecs int
	flag.IntVar(&timeoutSecs, "timeout", 10, "HTTP timeout per request (seconds)")

	flag.StringVar(&config.Proxy, "proxy", "", "HTTP proxy URL")
	flag.StringVar(&config.UserAgent, "user-agent", "waf-detector/1.0", "Custom User-Agent")
	flag.BoolVar(&config.Silent, "silent", false, "Only print results")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colored output")
	flag.BoolVar(&config.Debug, "debug", false, "Verbose debug mode")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "waf-detector - Web Application Firewall Detection Tool\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  waf-detector [options]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  waf-detector -u https://example.com\n")
		fmt.Fprintf(os.Stderr, "  waf-detector -l targets.txt -t 20 -o results.json -f json\n")
		fmt.Fprintf(os.Stderr, "  waf-detector -u https://example.com --debug\n")
	}

	flag.Parse()

	config.Timeout = time.Duration(timeoutSecs) * time.Second

	if config.Format != "txt" && config.Format != "json" {
		fmt.Fprintf(os.Stderr, "Error: Invalid format '%s'. Use 'txt' or 'json'\n", config.Format)
		os.Exit(1)
	}

	return config
}
