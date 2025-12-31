package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig represents the YAML configuration file structure
type FileConfig struct {
	Targets    []string      `yaml:"targets"`
	Threads    int           `yaml:"threads"`
	Timeout    time.Duration `yaml:"timeout"`
	Proxy      string        `yaml:"proxy"`
	UserAgent  string        `yaml:"user_agent"`
	OutputFile string        `yaml:"output_file"`
	Format     string        `yaml:"format"`
	Silent     bool          `yaml:"silent"`
	NoColor    bool          `yaml:"no_color"`
	Debug      bool          `yaml:"debug"`
}

// LoadConfig loads configuration from a YAML file
func LoadConfig(path string) (*FileConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg FileConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// Set defaults
	if cfg.Threads == 0 {
		cfg.Threads = 10
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "waf-detector/1.0"
	}
	if cfg.Format == "" {
		cfg.Format = "txt"
	}

	return &cfg, nil
}

// LoadFromEnv loads configuration values from environment variables
func LoadFromEnv() *FileConfig {
	cfg := &FileConfig{}

	if val := os.Getenv("WAF_DETECTOR_THREADS"); val != "" {
		fmt.Sscanf(val, "%d", &cfg.Threads)
	}
	if val := os.Getenv("WAF_DETECTOR_TIMEOUT"); val != "" {
		var secs int
		fmt.Sscanf(val, "%d", &secs)
		cfg.Timeout = time.Duration(secs) * time.Second
	}
	if val := os.Getenv("WAF_DETECTOR_PROXY"); val != "" {
		cfg.Proxy = val
	}
	if val := os.Getenv("WAF_DETECTOR_USER_AGENT"); val != "" {
		cfg.UserAgent = val
	}
	if val := os.Getenv("WAF_DETECTOR_OUTPUT"); val != "" {
		cfg.OutputFile = val
	}
	if val := os.Getenv("WAF_DETECTOR_FORMAT"); val != "" {
		cfg.Format = val
	}
	if val := os.Getenv("WAF_DETECTOR_SILENT"); val == "true" || val == "1" {
		cfg.Silent = true
	}
	if val := os.Getenv("WAF_DETECTOR_NO_COLOR"); val == "true" || val == "1" {
		cfg.NoColor = true
	}
	if val := os.Getenv("WAF_DETECTOR_DEBUG"); val == "true" || val == "1" {
		cfg.Debug = true
	}

	return cfg
}
