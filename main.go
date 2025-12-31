package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/wafw00f/waf-detector/cli"
	"github.com/wafw00f/waf-detector/detector"
	"github.com/wafw00f/waf-detector/logger"
	"github.com/wafw00f/waf-detector/output"
	"github.com/wafw00f/waf-detector/scanner"
)

func main() {
	config := cli.ParseFlags()

	if config.ShowVersion {
		fmt.Printf("waf-detector version %s\n", Version)
		fmt.Printf("Commit: %s\n", Commit)
		fmt.Printf("Build Date: %s\n", BuildDate)
		os.Exit(0)
	}

	// Initialize logger
	logger.Init(config.Debug, config.Silent)

	if config.Debug {
		logger.Debugf("Starting waf-detector version %s (commit: %s)", Version, Commit)
		logger.Debugf("Config: %+v", config)
	}

	targets := collectTargets(config)
	if len(targets) == 0 {
		logger.Fatal("No targets specified. Use -u or -l")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !config.Silent {
			logger.Warn("\nInterrupt received, shutting down...")
		}
		cancel()
	}()

	results := processTargets(ctx, targets, config)

	if err := output.WriteResults(results, config); err != nil {
		logger.Fatalf("Error writing output: %v", err)
	}
}

func collectTargets(config *cli.Config) []string {
	var targets []string

	if config.URL != "" {
		targets = append(targets, config.URL)
	}

	if config.ListFile != "" {
		file, err := os.Open(config.ListFile)
		if err != nil {
			logger.Fatalf("Error opening list file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				targets = append(targets, line)
			}
		}

		if err := scanner.Err(); err != nil {
			logger.Fatalf("Error reading list file: %v", err)
		}

		logger.Infof("Loaded %d targets from file", len(targets))
	}

	return targets
}

func processTargets(ctx context.Context, targets []string, config *cli.Config) []output.Result {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []output.Result
	)

	targetChan := make(chan string, len(targets))
	for _, target := range targets {
		targetChan <- target
	}
	close(targetChan)

	s := scanner.NewScanner(config)
	d := detector.NewDetector()

	// Create progress bar for multiple targets
	var bar *progressbar.ProgressBar
	if len(targets) > 1 && !config.Silent {
		bar = progressbar.NewOptions(len(targets),
			progressbar.OptionSetDescription("Scanning"),
			progressbar.OptionSetWidth(40),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionClearOnFinish(),
		)
	}

	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for target := range targetChan {
				select {
				case <-ctx.Done():
					return
				default:
					if config.Debug {
						logger.Debugf("Worker %d processing: %s", workerID, target)
					}
					result := processTarget(ctx, target, s, d, config)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if !config.Silent {
						if bar != nil {
							bar.Add(1)
						} else {
							output.PrintResult(result, config)
						}
					}
				}
			}
		}(i)
	}

	wg.Wait()

	// Print results after progress bar completes
	if bar != nil && !config.Silent {
		for _, result := range results {
			output.PrintResult(result, config)
		}
		output.PrintSummary(results, config)
	}

	return results
}

func processTarget(ctx context.Context, target string, s *scanner.Scanner, d *detector.Detector, config *cli.Config) output.Result {
	start := time.Now()

	probes, err := s.Scan(ctx, target)
	if err != nil {
		return output.Result{
			URL:       target,
			WAFFound:  false,
			Error:     err.Error(),
			ScanTime:  time.Since(start),
			Timestamp: time.Now(),
		}
	}

	detection := d.Detect(probes)

	return output.Result{
		URL:        target,
		WAFFound:   detection.WAFDetected,
		WAFName:    detection.WAFName,
		Confidence: detection.Confidence,
		Details:    detection.Details,
		ScanTime:   time.Since(start),
		Timestamp:  time.Now(),
	}
}
