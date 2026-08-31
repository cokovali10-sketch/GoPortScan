# GoPortScan

Fast concurrent TCP port scanner written in Go.

## Features

- Concurrent scanning with configurable workers
- Common port presets and full range mode
- Service detection for 30+ known ports
- Latency measurement per port
- Real-time callback for results
- Simple CLI interface

## Build & Run

```bash
go build -o goportscan .

# Scan common ports on localhost
./goportscan -host 127.0.0.1

# Scan specific ports
./goportscan -host 192.168.1.1 -ports 80,443,8080,3306

# Scan full range with more workers
./goportscan -host 10.0.0.1 -ports full -workers 500

# Custom timeout
./goportscan -host 127.0.0.1 -timeout 1s
```

## Test

```bash
go test -v
```

## License

MIT
