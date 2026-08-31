package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"
)

type ScanResult struct {
	Host  string
	Port  int
	Open  bool
	State string
	Latency time.Duration
}

type Scanner struct {
	Host       string
	Ports      []int
	Workers    int
	Timeout    time.Duration
	OnResult   func(ScanResult)
}

func NewScanner(host string, ports []int, workers int, timeout time.Duration) *Scanner {
	if workers <= 0 {
		workers = 100
	}
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	if len(ports) == 0 {
		ports = DefaultPorts()
	}
	return &Scanner{
		Host:    host,
		Ports:   ports,
		Workers: workers,
		Timeout: timeout,
	}
}

func DefaultPorts() []int {
	common := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
		9090, 9200, 9300, 11211, 27017, 50000,
	}
	return common
}

func FullPortRange() []int {
	ports := make([]int, 1024)
	for i := 0; i < 1024; i++ {
		ports[i] = i + 1
	}
	return ports
}

func (s *Scanner) Scan() []ScanResult {
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	portCh := make(chan int, s.Workers*2)

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				result := s.scanPort(port)
				mu.Lock()
				results = append(results, result)
				mu.Unlock()
				if s.OnResult != nil {
					s.OnResult(result)
				}
			}
		}()
	}

	for _, port := range s.Ports {
		portCh <- port
	}
	close(portCh)
	wg.Wait()

	return results
}

func (s *Scanner) scanPort(port int) ScanResult {
	addr := fmt.Sprintf("%s:%d", s.Host, port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", addr, s.Timeout)
	latency := time.Since(start)

	if err != nil {
		return ScanResult{
			Host:    s.Host,
			Port:    port,
			Open:    false,
			State:   "closed",
			Latency: latency,
		}
	}
	conn.Close()

	service := GuessService(port)
	return ScanResult{
		Host:    s.Host,
		Port:    port,
		Open:    true,
		State:   service,
		Latency: latency,
	}
}

func GuessService(port int) string {
	services := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 111: "rpcbind",
		135: "msrpc", 139: "netbios", 143: "imap",
		443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
		1433: "mssql", 1521: "oracle", 2049: "nfs",
		3306: "mysql", 3389: "rdp", 5432: "postgresql",
		5900: "vnc", 6379: "redis", 8080: "http-alt",
		8443: "https-alt", 8888: "http-alt2", 9090: "prometheus",
		9200: "elasticsearch", 9300: "es-transport",
		11211: "memcached", 27017: "mongodb",
	}
	if svc, ok := services[port]; ok {
		return svc
	}
	return "unknown"
}
