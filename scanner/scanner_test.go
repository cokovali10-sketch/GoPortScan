package scanner

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultPorts(t *testing.T) {
	ports := DefaultPorts()
	if len(ports) == 0 {
		t.Fatal("DefaultPorts returned empty")
	}
	if len(ports) < 20 {
		t.Fatalf("Expected at least 20 default ports, got %d", len(ports))
	}
}

func TestFullPortRange(t *testing.T) {
	ports := FullPortRange()
	if len(ports) != 1024 {
		t.Fatalf("Expected 1024 ports, got %d", len(ports))
	}
	if ports[0] != 1 || ports[1023] != 1024 {
		t.Fatal("Port range incorrect")
	}
}

func TestGuessService(t *testing.T) {
	tests := map[int]string{
		22:   "ssh",
		80:   "http",
		443:  "https",
		3306: "mysql",
		6379: "redis",
		9999: "unknown",
	}
	for port, expected := range tests {
		got := GuessService(port)
		if got != expected {
			t.Errorf("GuessService(%d) = %s, want %s", port, got, expected)
		}
	}
}

func TestScanLocalhost(t *testing.T) {
	s := NewScanner("127.0.0.1", []int{1, 2, 3}, 10, 200*time.Millisecond)
	stats := s.Scan()
	if stats.TotalPorts != 3 {
		t.Fatalf("Expected 3 total ports, got %d", stats.TotalPorts)
	}
	if !stats.HostAlive {
		t.Error("Expected host to be alive")
	}
}

func TestScanCallback(t *testing.T) {
	var count int
	s := NewScanner("127.0.0.1", []int{1}, 1, 100*time.Millisecond)
	s.OnResult = func(r ScanResult) {
		count++
	}
	s.Scan()
	if count != 1 {
		t.Fatalf("Expected callback to fire once, fired %d times", count)
	}
}

func TestNewScannerDefaults(t *testing.T) {
	s := NewScanner("10.0.0.1", nil, 0, 0)
	if s.Workers != 100 {
		t.Errorf("Expected 100 workers, got %d", s.Workers)
	}
	if len(s.Ports) == 0 {
		t.Error("Expected default ports")
	}
}

func TestParsePortsInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"empty string", "", 0},
		{"non-numeric", "abc", 0},
		{"negative port", "-1", 0},
		{"zero port", "0", 0},
		{"port too large", "70000", 0},
		{"mixed valid invalid", "80,abc,443", 2},
		{"trailing comma", "80,443,", 2},
		{"spaces only", "   ", 0},
		{"single valid", "22", 1},
		{"out of range", "99999", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ports := ParsePorts(tt.input)
			if len(ports) != tt.want {
				t.Errorf("ParsePorts(%q) returned %d ports, want %d", tt.input, len(ports), tt.want)
			}
		})
	}
}

func TestParsePortsSpecialKeywords(t *testing.T) {
	common := ParsePorts("common")
	if len(common) != len(DefaultPorts()) {
		t.Errorf("ParsePorts('common') returned %d ports, want %d", len(common), len(DefaultPorts()))
	}

	full := ParsePorts("full")
	if len(full) != 1024 {
		t.Errorf("ParsePorts('full') returned %d ports, want 1024", len(full))
	}
}

func TestParsePortsDuplicates(t *testing.T) {
	ports := ParsePorts("80,80,80")
	if len(ports) != 3 {
		t.Errorf("ParsePorts('80,80,80') returned %d ports, want 3 (duplicates allowed)", len(ports))
	}
}

func TestBannerSSH(t *testing.T) {
	banner := "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
	version := ParseBannerForVersion("ssh", banner)
	if version != "OpenSSH_8.9p1" {
		t.Errorf("ParseBannerForVersion(ssh, %q) = %q, want %q", banner, version, "OpenSSH_8.9p1")
	}
}

func TestBannerHTTP(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\n"
	version := ParseBannerForVersion("http", banner)
	if version != "Apache/2.4.52" {
		t.Errorf("ParseBannerForVersion(http, %q) = %q, want %q", banner, version, "Apache/2.4.52")
	}
}

func TestBannerFTP(t *testing.T) {
	banner := "220 ProFTPD 1.3.7e Server ready."
	version := ParseBannerForVersion("ftp", banner)
	if version != "ProFTPD" {
		t.Errorf("ParseBannerForVersion(ftp, %q) = %q, want %q", banner, version, "ProFTPD")
	}
}

func TestBannerRedis(t *testing.T) {
	banner := "$-1\r\nredis_version:7.0.11\r\nredis_mode:standalone"
	version := ParseBannerForVersion("redis", banner)
	if version != "7.0.11" {
		t.Errorf("ParseBannerForVersion(redis, %q) = %q, want %q", banner, version, "7.0.11")
	}
}

func TestBannerMySQL(t *testing.T) {
	banner := "mysql_native_password\x00\x00mysql 5.7.42-0ubuntu0.18.04.1-log"
	version := ParseBannerForVersion("mysql", banner)
	if version != "5.7.42" {
		t.Errorf("ParseBannerForVersion(mysql, %q) = %q, want %q", banner, version, "5.7.42")
	}
}

func TestBannerEmpty(t *testing.T) {
	version := ParseBannerForVersion("ssh", "")
	if version != "" {
		t.Errorf("ParseBannerForVersion(ssh, empty) = %q, want empty", version)
	}
}

func TestBannerNoMatch(t *testing.T) {
	banner := "random garbage data with no version info"
	version := ParseBannerForVersion("unknown", banner)
	if version != "" {
		t.Errorf("ParseBannerForVersion(unknown, %q) = %q, want empty", banner, version)
	}
}

func TestOSFromTTL(t *testing.T) {
	tests := []struct {
		ttl  int
		want string
	}{
		{64, "Linux/Unix"},
		{32, "Linux/Unix"},
		{128, "Windows"},
		{65, "Windows"},
		{127, "Windows"},
		{254, "Cisco/Network Device"},
		{129, "Cisco/Network Device"},
		{255, "unknown"},
		{1, "Linux/Unix"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := OSFromTTL(tt.ttl)
			if got != tt.want {
				t.Errorf("OSFromTTL(%d) = %q, want %q", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestDetectOSFromBanner(t *testing.T) {
	tests := []struct {
		name   string
		banner string
		want   string
	}{
		{"linux ttl", "PING 127.0.0.1: 64 bytes, ttl=64 time=0.01 ms", "Linux/Unix"},
		{"windows ttl", "Reply from 192.168.1.1: bytes=32 time<1ms TTL=128", "Windows"},
		{"cisco ttl", "Reply from 10.0.0.1: bytes=32 time=1ms TTL=254", "Cisco/Network Device"},
		{"openssh banner", "SSH-2.0-OpenSSH_8.9p1", "Linux/Unix"},
		{"microsoft banner", "Microsoft IIS/10.0", "Windows"},
		{"empty", "", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectOSFromBanner(tt.banner)
			if got != tt.want {
				t.Errorf("DetectOSFromBanner(%q) = %q, want %q", tt.banner, got, tt.want)
			}
		})
	}
}

func TestToCSV(t *testing.T) {
	results := []ScanResult{
		{Host: "127.0.0.1", Port: 80, Open: true, Service: "http", Banner: "Apache", Version: "2.4.52", Latency: 1 * time.Millisecond},
		{Host: "127.0.0.1", Port: 22, Open: false, Service: "closed", Latency: 500 * time.Microsecond},
	}

	csv, err := ToCSV(results)
	if err != nil {
		t.Fatalf("ToCSV returned error: %v", err)
	}
	if csv == "" {
		t.Fatal("ToCSV returned empty string")
	}
	lines := splitLines(csv)
	if len(lines) != 3 {
		t.Errorf("ToCSV returned %d lines, want 3 (header + 2 rows)", len(lines))
	}
	header := "host,port,open,service,version,banner,latency"
	if lines[0] != header {
		t.Errorf("CSV header = %q, want %q", lines[0], header)
	}
	if !strings.Contains(lines[1], "80") {
		t.Errorf("First data row missing port 80: %q", lines[1])
	}
	if !strings.Contains(lines[1], "Apache") {
		t.Errorf("First data row missing banner: %q", lines[1])
	}
}

func splitLines(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		result = append(result, s[start:])
	}
	return result
}

func TestScanStats(t *testing.T) {
	s := NewScanner("127.0.0.1", []int{1, 2, 3}, 10, 200*time.Millisecond)
	stats := s.Scan()
	if stats.Duration <= 0 {
		t.Error("Expected positive scan duration")
	}
	if stats.TotalPorts != 3 {
		t.Errorf("Expected 3 total ports, got %d", stats.TotalPorts)
	}
	if stats.OpenPorts+stats.ClosedPorts != stats.TotalPorts {
		t.Errorf("Open(%d) + Closed(%d) != Total(%d)", stats.OpenPorts, stats.ClosedPorts, stats.TotalPorts)
	}
	if stats.PortsPerSec <= 0 {
		t.Error("Expected positive ports/sec")
	}
	if stats.EndTime.Before(stats.StartTime) {
		t.Error("EndTime before StartTime")
	}
}

func TestScanWithHostCheck(t *testing.T) {
	s := NewScanner("127.0.0.1", []int{1}, 1, 200*time.Millisecond).
		WithHostCheck(true)
	stats := s.Scan()
	if !stats.HostAlive {
		t.Error("Expected localhost to be alive")
	}
}

func TestScanResultJSON(t *testing.T) {
	r := ScanResult{
		Host:    "127.0.0.1",
		Port:    80,
		Open:    true,
		Service: "http",
		Banner:  "Apache",
		Version: "2.4.52",
		Latency: 1 * time.Millisecond,
	}
	data, err := r.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	json := string(data)
	if json == "" {
		t.Fatal("MarshalJSON returned empty")
	}
}
