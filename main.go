package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cokovali10-sketch/GoPortScan/scanner"
)

func main() {
	host := flag.String("host", "127.0.0.1", "Target host")
	portsFlag := flag.String("ports", "common", "Port range: common, full, or comma-separated (e.g. 80,443,8080)")
	workers := flag.Int("workers", 100, "Number of concurrent workers")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "Connection timeout")
	noBanner := flag.Bool("no-banner", false, "Disable banner grabbing")
	jsonOutput := flag.Bool("json", false, "Output results as JSON to stdout")
	outputFile := flag.String("output", "", "Write results to file (JSON or CSV based on extension)")
	checkAlive := flag.Bool("ping", false, "Check if host is alive before scanning")
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "Error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	ports := scanner.ParsePorts(*portsFlag)
	if len(ports) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no valid ports specified")
		os.Exit(1)
	}

	fmt.Printf("Scanning %s (%d ports) with %d workers...\n\n", *host, len(ports), *workers)

	s := scanner.NewScanner(*host, ports, *workers, *timeout).
		WithBannerGrabbing(!*noBanner).
		WithHostCheck(*checkAlive)

	stdoutMode := !*jsonOutput && *outputFile == ""
	var allResults []scanner.ScanResult

	if stdoutMode {
		s.OnResult = func(r scanner.ScanResult) {
			if r.Open {
				banner := ""
				if r.Banner != "" {
					banner = fmt.Sprintf(" [%s]", r.Banner[:min(len(r.Banner), 40)])
				}
				version := ""
				if r.Version != "" {
					version = fmt.Sprintf(" v%s", r.Version)
				}
				fmt.Printf("  %-20s  %-6d  OPEN   %-15s  %v%s%s\n",
					r.Host, r.Port, r.Service, r.Latency.Round(time.Microsecond), version, banner)
			}
		}
	} else {
		s.OnResult = func(r scanner.ScanResult) {
			allResults = append(allResults, r)
		}
	}

	stats := s.Scan()

	if !stdoutMode {
		sort.Slice(allResults, func(i, j int) bool {
			return allResults[i].Port < allResults[j].Port
		})
	}

	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Printf("Scan complete: %d/%d ports open\n", stats.OpenPorts, stats.TotalPorts)
	fmt.Printf("Duration: %s | Rate: %.1f ports/sec\n", stats.Duration.Round(time.Millisecond), stats.PortsPerSec)
	if stats.OSGuess != "" && stats.OSGuess != "unknown" {
		fmt.Printf("OS guess: %s (TTL-based)\n", stats.OSGuess)
	}
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	if stdoutMode {
		var open []scanner.ScanResult
		for _, r := range allResults {
			if r.Open {
				open = append(open, r)
			}
		}
		if len(open) > 0 {
			fmt.Println("\nOpen ports:")
			for _, r := range open {
				banner := ""
				if r.Banner != "" {
					banner = fmt.Sprintf("  banner: %s", r.Banner[:min(len(r.Banner), 60)])
				}
				version := ""
				if r.Version != "" {
					version = fmt.Sprintf("  version: %s", r.Version)
				}
				fmt.Printf("  %5d/%-12s  latency: %v%s%s\n", r.Port, r.Service, r.Latency.Round(time.Microsecond), version, banner)
			}
		} else {
			fmt.Println("\nNo open ports found.")
		}
	}

	if *outputFile != "" {
		ext := strings.ToLower(filepath.Ext(*outputFile))
		var content string
		var err error

		switch ext {
		case ".csv":
			content, err = scanner.ToCSV(allResults)
		default:
			content = s.ToJSON(allResults)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting output: %v\n", err)
			os.Exit(1)
		}

		if err := scanner.WriteToFile(content, *outputFile); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\nResults written to %s\n", *outputFile)
	}

	if *jsonOutput {
		fmt.Println(s.ToJSON(allResults))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
