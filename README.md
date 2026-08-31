# GoPortScan

Fast concurrent TCP port scanner with banner grabbing and JSON output.

**Version:** 1.0.0 | **Language:** Go | **License:** MIT

## Features

### Core Capabilities
- **Concurrent scanning** — configurable worker pool (default 100 goroutines)
- **Banner grabbing** — read service banners from open ports
- **Service detection** — identify 30+ common services by port number
- **Latency measurement** — per-port response time tracking

### Port Ranges
- **Common ports** — 32 most frequently used ports (default)
- **Full range** — scan ports 1-1024
- **Custom** — comma-separated port list (e.g., `80,443,8080,3306`)

### Output
- **Text output** — color-coded terminal display with real-time results
- **JSON output** — structured output for programmatic consumption
- **Real-time callback** — process results as they arrive

## Build & Run

```bash
go build -o goportscan .

# Scan common ports on localhost
./goportscan -host 127.0.0.1

# Scan specific ports
./goportscan -host 192.168.1.1 -ports 80,443,8080,3306

# Scan full range with more workers
./goportscan -host 10.0.0.1 -ports full -workers 500

# JSON output
./goportscan -host 127.0.0.1 -json

# Disable banner grabbing
./goportscan -host 127.0.0.1 --no-banner

# Custom timeout
./goportscan -host 127.0.0.1 -timeout 1s
```

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-host` | `127.0.0.1` | Target host |
| `-ports` | `common` | Port range: `common`, `full`, or comma-separated |
| `-workers` | `100` | Number of concurrent workers |
| `-timeout` | `500ms` | Connection timeout |
| `-no-banner` | `false` | Disable banner grabbing |
| `-json` | `false` | Output as JSON |

## Programmatic API

```go
package main

import (
    "fmt"
    "github.com/cokovali10-sketch/GoPortScan/scanner"
)

func main() {
    s := scanner.NewScanner("127.0.0.1", scanner.DefaultPorts(), 100, 500*time.Millisecond)
    s.OnResult = func(r scanner.ScanResult) {
        if r.Open {
            fmt.Printf("Port %d: %s (banner: %s)\n", r.Port, r.Service, r.Banner)
        }
    }
    results := s.Scan()
    fmt.Println(s.ToJSON(results))
}
```

## Test

```bash
go test -v ./scanner/
```

## Project Structure

```
GoPortScan/
├── main.go                # CLI entry point
├── scanner/
│   ├── scanner.go         # Scanner core with banner grabbing
│   └── scanner_test.go    # 8 unit tests
├── go.mod                 # Go module definition
├── .gitignore
└── README.md
```

## License

MIT
