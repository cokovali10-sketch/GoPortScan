package scanner

import (
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
	results := s.Scan()
	if len(results) != 3 {
		t.Fatalf("Expected 3 results, got %d", len(results))
	}
	for _, r := range results {
		if r.Host != "127.0.0.1" {
			t.Errorf("Expected host 127.0.0.1, got %s", r.Host)
		}
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
