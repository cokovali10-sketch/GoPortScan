package main

import (
	"flag"
	"fmt"
	"os"
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
	jsonOutput := flag.Bool("json", false, "Output results as JSON")
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

	s := scanner.NewScanner(*host, ports, *workers, *timeout).WithBannerGrabbing(!*noBanner)

	var results []scanner.ScanResult
	if *jsonOutput {
		s.OnResult = nil
		results = s.Scan()
		fmt.Println(s.ToJSON(results))
		return
	}

	s.OnResult = func(r scanner.ScanResult) {
		if r.Open {
			banner := ""
			if r.Banner != "" {
				banner = fmt.Sprintf(" [%s]", r.Banner[:min(len(r.Banner), 40)])
			}
			fmt.Printf("  %-20s  %-6d  OPEN   %-15s  %v%s\n",
				r.Host, r.Port, r.Service, r.Latency.Round(time.Microsecond), banner)
		}
	}

	results = s.Scan()

	var open []scanner.ScanResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}

	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})

	fmt.Printf("\n%s", strings.Repeat("=", 70))
	fmt.Printf("\nScan complete: %d/%d ports open\n", len(open), len(ports))
	fmt.Printf("%s\n", strings.Repeat("=", 70))

	if len(open) > 0 {
		fmt.Println("\nOpen ports:")
		for _, r := range open {
			banner := ""
			if r.Banner != "" {
				banner = fmt.Sprintf("  banner: %s", r.Banner[:min(len(r.Banner), 60)])
			}
			fmt.Printf("  %5d/%-12s  latency: %v%s\n", r.Port, r.Service, r.Latency.Round(time.Microsecond), banner)
		}
	} else {
		fmt.Println("\nNo open ports found.")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
