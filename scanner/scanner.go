package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	Open     bool          `json:"open"`
	Service  string        `json:"service"`
	Banner   string        `json:"banner,omitempty"`
	Latency  time.Duration `json:"latency"`
}

func (r ScanResult) MarshalJSON() ([]byte, error) {
	type Alias struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service"`
		Banner  string `json:"banner,omitempty"`
		Latency string `json:"latency"`
	}
	return json.Marshal(Alias{
		Host:    r.Host,
		Port:    r.Port,
		Open:    r.Open,
		Service: r.Service,
		Banner:  r.Banner,
		Latency: r.Latency.String(),
	})
}

type ScanOptions struct {
	GrabBanner bool
	JSONOutput bool
}

type Scanner struct {
	Host       string
	Ports      []int
	Workers    int
	Timeout    time.Duration
	Options    ScanOptions
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
		Options: ScanOptions{GrabBanner: true},
	}
}

func (s *Scanner) WithBannerGrabbing(enabled bool) *Scanner {
	s.Options.GrabBanner = enabled
	return s
}

func DefaultPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888,
		9090, 9200, 9300, 11211, 27017, 50000,
	}
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
			Service: "closed",
			Latency: latency,
		}
	}
	defer conn.Close()

	service := GuessService(port)
	banner := ""

	if s.Options.GrabBanner {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			banner = strings.TrimSpace(string(buf[:n]))
			if len(banner) > 200 {
				banner = banner[:200] + "..."
			}
		}
	}

	return ScanResult{
		Host:    s.Host,
		Port:    port,
		Open:    true,
		Service: service,
		Banner:  banner,
		Latency: latency,
	}
}

func (s *Scanner) ToJSON(results []ScanResult) string {
	data, _ := json.MarshalIndent(results, "", "  ")
	return string(data)
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

func ParsePorts(spec string) []int {
	if spec == "common" {
		return DefaultPorts()
	}
	if spec == "full" {
		return FullPortRange()
	}
	var ports []int
	for _, p := range strings.Split(spec, ",") {
		var port int
		if _, err := fmt.Sscanf(strings.TrimSpace(p), "%d", &port); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}
