package scanner

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	Host    string        `json:"host"`
	Port    int           `json:"port"`
	Open    bool          `json:"open"`
	Service string        `json:"service"`
	Banner  string        `json:"banner,omitempty"`
	Version string        `json:"version,omitempty"`
	Latency time.Duration `json:"latency"`
}

func (r ScanResult) MarshalJSON() ([]byte, error) {
	type Alias struct {
		Host    string `json:"host"`
		Port    int    `json:"port"`
		Open    bool   `json:"open"`
		Service string `json:"service"`
		Banner  string `json:"banner,omitempty"`
		Version string `json:"version,omitempty"`
		Latency string `json:"latency"`
	}
	return json.Marshal(Alias{
		Host:    r.Host,
		Port:    r.Port,
		Open:    r.Open,
		Service: r.Service,
		Banner:  r.Banner,
		Version: r.Version,
		Latency: r.Latency.String(),
	})
}

type ScanStats struct {
	StartTime   time.Time     `json:"start_time"`
	EndTime     time.Time     `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	TotalPorts  int           `json:"total_ports"`
	OpenPorts   int           `json:"open_ports"`
	ClosedPorts int           `json:"closed_ports"`
	PortsPerSec float64       `json:"ports_per_sec"`
	HostAlive   bool          `json:"host_alive"`
	OSGuess     string        `json:"os_guess"`
}

type ScanOptions struct {
	GrabBanner  bool
	JSONOutput  bool
	CheckAlive  bool
	OutputFile  string
	OutputFormat string
}

type Scanner struct {
	Host    string
	Ports   []int
	Workers int
	Timeout time.Duration
	Options ScanOptions
	OnResult func(ScanResult)
	Stats    ScanStats
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

func (s *Scanner) WithHostCheck(enabled bool) *Scanner {
	s.Options.CheckAlive = enabled
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

func CheckHostAlive(host string, timeout time.Duration) bool {
	var out bytes.Buffer
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), host)
	}
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return false
	}
	output := out.String()
	return strings.Contains(output, "TTL=") || strings.Contains(output, "ttl=") ||
		strings.Contains(output, "time=") || strings.Contains(output, "Time=")
}

func DetectOSFromPing(host string, timeout time.Duration) string {
	var out bytes.Buffer
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("ping", "-n", "1", "-w", fmt.Sprintf("%d", int(timeout.Milliseconds())), host)
	} else {
		cmd = exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", int(timeout.Seconds())), host)
	}
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "unknown"
	}
	return DetectOSFromBanner(out.String())
}

func DetectOSFromBanner(banner string) string {
	lower := strings.ToLower(banner)
	ttlMatch := regexp.MustCompile(`(?:ttl=|TTL=)(\d+)`)
	matches := ttlMatch.FindStringSubmatch(banner)
	if len(matches) < 2 {
		return guessOSFromBannerContent(lower)
	}
	ttl, err := strconv.Atoi(matches[1])
	if err != nil {
		return guessOSFromBannerContent(lower)
	}
	return OSFromTTL(ttl)
}

func OSFromTTL(ttl int) string {
	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 254:
		return "Cisco/Network Device"
	default:
		return "unknown"
	}
}

func guessOSFromBannerContent(banner string) string {
	if strings.Contains(banner, "openssh") || strings.Contains(banner, "linux") {
		return "Linux/Unix"
	}
	if strings.Contains(banner, "microsoft") || strings.Contains(banner, "iis") {
		return "Windows"
	}
	if strings.Contains(banner, "cisco") {
		return "Cisco"
	}
	return "unknown"
}

var versionPatterns = map[string]*regexp.Regexp{
	"ssh":          regexp.MustCompile(`(?i)SSH-[\d.]+-(\S+)`),
	"http":         regexp.MustCompile(`(?i)Server:\s*(\S+)`),
	"ftp":          regexp.MustCompile(`(?i)^220\s+(\S+)`),
	"smtp":         regexp.MustCompile(`(?i)220\s+(.+?)(?:\s+ESMTP|\s*[\r\n])`),
	"mysql":        regexp.MustCompile(`(?i)(?:mysql|mariadb)[\s/]*([\d.]+)`),
	"redis":        regexp.MustCompile(`(?i)redis_version:([\d.]+)`),
	"postgresql":   regexp.MustCompile(`(?i)PostgreSQL\s+([\d.]+)`),
	"elasticsearch": regexp.MustCompile(`(?i)"version"\s*:\s*\{\s*"number"\s*:\s*"([\d.]+)"`),
	"smb":          regexp.MustCompile(`(?i)(?:Samba|Windows)\s+[\d.]+`),
	"mssql":        regexp.MustCompile(`(?i)mssql[\s/]*([\d.]+)`),
	"mongodb":      regexp.MustCompile(`(?i)MongoDB\s+([\d.]+)`),
	"memcached":    regexp.MustCompile(`(?i)VERSION\s+([\d.]+)`),
}

func ParseBannerForVersion(service, banner string) string {
	if banner == "" {
		return ""
	}
	if re, ok := versionPatterns[service]; ok {
		matches := re.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	for _, re := range versionPatterns {
		matches := re.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			return matches[1]
		}
	}
	return ""
}

func (s *Scanner) Scan() ScanStats {
	s.Stats = ScanStats{
		StartTime: time.Now(),
		TotalPorts: len(s.Ports),
	}

	if s.Options.CheckAlive {
		s.Stats.HostAlive = CheckHostAlive(s.Host, s.Timeout*4)
		if !s.Stats.HostAlive {
			s.Stats.EndTime = time.Now()
			s.Stats.Duration = s.Stats.EndTime.Sub(s.Stats.StartTime)
			return s.Stats
		}
		s.Stats.OSGuess = DetectOSFromPing(s.Host, s.Timeout*4)
	} else {
		s.Stats.HostAlive = true
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	portCh := make(chan int, s.Workers*2)
	var osDetected sync.Once

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portCh {
				result := s.scanPort(port)
				mu.Lock()
				if result.Open {
					s.Stats.OpenPorts++
					if s.Stats.OSGuess == "" || s.Stats.OSGuess == "unknown" {
						osDetected.Do(func() {
							s.Stats.OSGuess = DetectOSFromBanner(result.Banner)
						})
					}
				} else {
					s.Stats.ClosedPorts++
				}
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

	s.Stats.EndTime = time.Now()
	s.Stats.Duration = s.Stats.EndTime.Sub(s.Stats.StartTime)
	if s.Stats.Duration.Seconds() > 0 {
		s.Stats.PortsPerSec = float64(s.Stats.TotalPorts) / s.Stats.Duration.Seconds()
	}

	return s.Stats
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

	version := ParseBannerForVersion(service, banner)

	return ScanResult{
		Host:    s.Host,
		Port:    port,
		Open:    true,
		Service: service,
		Banner:  banner,
		Version: version,
		Latency: latency,
	}
}

func (s *Scanner) ToJSON(results []ScanResult) string {
	data, _ := json.MarshalIndent(results, "", "  ")
	return string(data)
}

func ToCSV(results []ScanResult) (string, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{"host", "port", "open", "service", "version", "banner", "latency"}
	if err := w.Write(header); err != nil {
		return "", err
	}

	for _, r := range results {
		latency := r.Latency.String()
		banner := strings.ReplaceAll(r.Banner, ",", ";")
		banner = strings.ReplaceAll(banner, "\n", " ")
		row := []string{
			r.Host,
			strconv.Itoa(r.Port),
			strconv.FormatBool(r.Open),
			r.Service,
			r.Version,
			banner,
			latency,
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}
	w.Flush()
	return buf.String(), w.Error()
}

func WriteToFile(content, path string) error {
	return os.WriteFile(path, []byte(content), 0644)
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
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var port int
		if _, err := fmt.Sscanf(p, "%d", &port); err == nil && port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	return ports
}
