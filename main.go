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

	"github.com/wafw00f/waf-detector/cli"
	"github.com/wafw00f/waf-detector/detector"
	"github.com/wafw00f/waf-detector/output"
	"github.com/wafw00f/waf-detector/scanner"
)

func main() {
	config := cli.ParseFlags()

	if config.Debug {
		fmt.Println("[DEBUG] Starting waf-detector")
		fmt.Printf("[DEBUG] Config: %+v\n", config)
	}

	targets := collectTargets(config)
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No targets specified. Use -u or -l")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if !config.Silent {
			fmt.Println("\n[!] Interrupt received, shutting down...")
		}
		cancel()
	}()

	results := processTargets(ctx, targets, config)

	if err := output.WriteResults(results, config); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error opening list file: %v\n", err)
			os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error reading list file: %v\n", err)
			os.Exit(1)
		}
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
						fmt.Printf("[DEBUG] Worker %d processing: %s\n", workerID, target)
					}
					result := processTarget(ctx, target, s, d, config)
					mu.Lock()
					results = append(results, result)
					mu.Unlock()

					if !config.Silent {
						output.PrintResult(result, config)
					}
				}
			}
		}(i)
	}

	wg.Wait()
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
