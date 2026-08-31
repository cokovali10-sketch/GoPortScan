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
	flag.Parse()

	if *host == "" {
		fmt.Fprintln(os.Stderr, "Error: host is required")
		flag.Usage()
		os.Exit(1)
	}

	var ports []int
	switch *portsFlag {
	case "common":
		ports = scanner.DefaultPorts()
	case "full":
		ports = scanner.FullPortRange()
	default:
		for _, p := range strings.Split(*portsFlag, ",") {
			var port int
			if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port <= 65535 {
				ports = append(ports, port)
			}
		}
	}

	fmt.Printf("Scanning %s (%d ports) with %d workers...\n\n", *host, len(ports), *workers)

	s := scanner.NewScanner(*host, ports, *workers, *timeout)
	s.OnResult = func(r scanner.ScanResult) {
		if r.Open {
			fmt.Printf("  %-20s  %-6d  OPEN   %-15s  %v\n", r.Host, r.Port, r.State, r.Latency.Round(time.Microsecond))
		}
	}

	results := s.Scan()

	var open []scanner.ScanResult
	for _, r := range results {
		if r.Open {
			open = append(open, r)
		}
	}

	sort.Slice(open, func(i, j int) bool {
		return open[i].Port < open[j].Port
	})

	fmt.Printf("\n%s", strings.Repeat("=", 60))
	fmt.Printf("\nScan complete: %d/%d ports open\n", len(open), len(ports))
	fmt.Printf("%s\n", strings.Repeat("=", 60))

	if len(open) > 0 {
		fmt.Println("\nOpen ports:")
		for _, r := range open {
			fmt.Printf("  %5d/%-12s  latency: %v\n", r.Port, r.State, r.Latency.Round(time.Microsecond))
		}
	} else {
		fmt.Println("\nNo open ports found.")
	}
}
