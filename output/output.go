package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/ahmedtouahria/waf-detector/cli"
)

type Result struct {
	URL        string        `json:"url"`
	WAFFound   bool          `json:"waf_found"`
	WAFName    string        `json:"waf_name,omitempty"`
	Confidence float64       `json:"confidence,omitempty"`
	Details    string        `json:"details,omitempty"`
	Error      string        `json:"error,omitempty"`
	ScanTime   time.Duration `json:"scan_time"`
	Timestamp  time.Time     `json:"timestamp"`
}

type JSONOutput struct {
	Results []Result  `json:"results"`
	Summary Summary   `json:"summary"`
	Time    time.Time `json:"scan_time"`
}

type Summary struct {
	TotalScanned int `json:"total_scanned"`
	WAFsDetected int `json:"wafs_detected"`
	Errors       int `json:"errors"`
}

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

func WriteResults(results []Result, config *cli.Config) error {
	if config.OutputFile == "" {
		return nil
	}

	file, err := os.Create(config.OutputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	switch config.Format {
	case "json":
		return writeJSON(file, results)
	case "csv":
		return writeCSV(file, results)
	case "html":
		return writeHTML(file, results)
	default: // txt
		return writeText(file, results, config)
	}
}

func writeJSON(file *os.File, results []Result) error {
	summary := calculateSummary(results)
	output := JSONOutput{
		Results: results,
		Summary: summary,
		Time:    time.Now(),
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return fmt.Errorf("failed to encode JSON: %w", err)
	}
	return nil
}

func writeCSV(file *os.File, results []Result) error {
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"URL", "WAF Detected", "WAF Name", "Confidence", "Details", "Error", "Scan Time", "Timestamp"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write rows
	for _, result := range results {
		row := []string{
			result.URL,
			fmt.Sprintf("%t", result.WAFFound),
			result.WAFName,
			fmt.Sprintf("%.2f", result.Confidence),
			result.Details,
			result.Error,
			result.ScanTime.String(),
			result.Timestamp.Format(time.RFC3339),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}

func writeHTML(file *os.File, results []Result) error {
	summary := calculateSummary(results)

	data := struct {
		Results []Result
		Summary Summary
		Time    string
	}{
		Results: results,
		Summary: summary,
		Time:    time.Now().Format(time.RFC3339),
	}

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse HTML template: %w", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return nil
}

func writeText(file *os.File, results []Result, config *cli.Config) error {
	for _, result := range results {
		line := formatTextResult(result, config)
		if _, err := file.WriteString(line + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}
	return nil
}

func PrintResult(result Result, config *cli.Config) {
	if config.Silent {
		return
	}

	if config.Format == "json" {
		data, _ := json.Marshal(result)
		fmt.Println(string(data))
	} else {
		fmt.Println(formatTextResult(result, config))
	}
}

func formatTextResult(result Result, config *cli.Config) string {
	useColor := !config.NoColor

	if result.Error != "" {
		if useColor {
			return fmt.Sprintf("[%s--%s] %s - %sERROR%s: %s",
				ColorRed, ColorReset, result.URL, ColorRed, ColorReset, result.Error)
		}
		return fmt.Sprintf("[--] %s - ERROR: %s", result.URL, result.Error)
	}

	if !result.WAFFound {
		if useColor {
			return fmt.Sprintf("[%s--%s] %s - %sNo WAF detected%s",
				ColorYellow, ColorReset, result.URL, ColorYellow, ColorReset)
		}
		return fmt.Sprintf("[--] %s - No WAF detected", result.URL)
	}

	wafInfo := "WAF detected"
	if result.WAFName != "" {
		if result.Confidence > 0 {
			wafInfo = fmt.Sprintf("%s (%.0f%% confidence)", result.WAFName, result.Confidence*100)
		} else {
			wafInfo = result.WAFName
		}
	}

	if useColor {
		return fmt.Sprintf("[%s++%s] %s - %s%s%s [%s%.2fs%s]",
			ColorGreen, ColorReset, result.URL, ColorCyan, wafInfo, ColorReset,
			ColorBlue, result.ScanTime.Seconds(), ColorReset)
	}

	return fmt.Sprintf("[++] %s - %s [%.2fs]", result.URL, wafInfo, result.ScanTime.Seconds())
}

func calculateSummary(results []Result) Summary {
	summary := Summary{
		TotalScanned: len(results),
	}

	for _, result := range results {
		if result.Error != "" {
			summary.Errors++
		} else if result.WAFFound {
			summary.WAFsDetected++
		}
	}

	return summary
}

func PrintSummary(results []Result, config *cli.Config) {
	if config.Silent {
		return
	}

	summary := calculateSummary(results)

	fmt.Println()
	fmt.Println("=== Scan Summary ===")
	fmt.Printf("Total scanned:  %d\n", summary.TotalScanned)
	fmt.Printf("WAFs detected:  %d\n", summary.WAFsDetected)
	fmt.Printf("Errors:         %d\n", summary.Errors)
}
