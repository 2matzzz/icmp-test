package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestICMPTypeToString verifies that icmpTypeToString returns the expected strings.
func TestICMPTypeToString(t *testing.T) {
	tests := []struct {
		in       ipv4.ICMPType
		expected string
	}{
		{ipv4.ICMPTypeEcho, "echo request"},
		{ipv4.ICMPTypeEchoReply, "echo reply"},
		{ipv4.ICMPTypeTimestamp, "timestamp"},
		{ipv4.ICMPTypeTimestampReply, "timestamp reply"},
	}
	for _, tc := range tests {
		got := icmpTypeToString(tc.in)
		if got != tc.expected {
			t.Errorf("icmpTypeToString(%v) = %q; want %q", tc.in, got, tc.expected)
		}
	}
}

// TestCreateICMPMessageEcho verifies that an echo message is created with the correct ID and sequence.
func TestCreateICMPMessageEcho(t *testing.T) {
	id := os.Getpid() & 0xffff
	seq := 42
	msg, err := createICMPMessage(ipv4.ICMPTypeEcho, id, seq)
	if err != nil {
		t.Fatalf("createICMPMessage(echo, %d, %d) error: %v", id, seq, err)
	}
	if msg.Type != ipv4.ICMPTypeEcho {
		t.Errorf("expected type %v; got %v", ipv4.ICMPTypeEcho, msg.Type)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("expected body type *icmp.Echo; got %T", msg.Body)
	}
	if echo.ID != id {
		t.Errorf("expected id %d; got %d", id, echo.ID)
	}
	if echo.Seq != seq {
		t.Errorf("expected seq %d; got %d", seq, echo.Seq)
	}
	if string(echo.Data) != "PING" {
		t.Errorf("expected data %q; got %q", "PING", echo.Data)
	}
}

// TestCreateICMPMessageTimestamp verifies that a timestamp message is created with the correct ID and sequence.
func TestCreateICMPMessageTimestamp(t *testing.T) {
	id := os.Getpid() & 0xffff
	seq := 17
	msg, err := createICMPMessage(ipv4.ICMPTypeTimestamp, id, seq)
	if err != nil {
		t.Fatalf("createICMPMessage(timestamp, %d, %d) error: %v", id, seq, err)
	}
	if msg.Type != ipv4.ICMPTypeTimestamp {
		t.Errorf("expected type %v; got %v", ipv4.ICMPTypeTimestamp, msg.Type)
	}
	ts, ok := msg.Body.(*icmpTimestamp)
	if !ok {
		t.Fatalf("expected body type *icmpTimestamp; got %T", msg.Body)
	}
	if ts.ID != id {
		t.Errorf("expected id %d; got %d", id, ts.ID)
	}
	if ts.Seq != seq {
		t.Errorf("expected seq %d; got %d", seq, ts.Seq)
	}
}

// TestParseExpectedResult verifies that parseExpectedResult returns the correct boolean.
func TestParseExpectedResult(t *testing.T) {
	r, err := parseExpectedResult("response")
	if err != nil {
		t.Fatalf("parseExpectedResult(\"response\") error: %v", err)
	}
	if r != true {
		t.Error("expected true for response")
	}

	r, err = parseExpectedResult("timeout")
	if err != nil {
		t.Fatalf("parseExpectedResult(\"timeout\") error: %v", err)
	}
	if r != false {
		t.Error("expected false for timeout")
	}
}

// TestGetICMPResponseType verifies that getICMPResponseType returns the correct ICMP response type.
func TestGetICMPResponseType(t *testing.T) {
	tests := []struct {
		test     Test
		expected ipv4.ICMPType
		err      bool
	}{
		{
			test: Test{
				RequestType: ipv4.ICMPTypeEcho,
			},
			expected: ipv4.ICMPTypeEchoReply,
			err:      false,
		},
		{
			test: Test{
				RequestType: ipv4.ICMPTypeTimestamp,
				Destination: "127.0.0.1",
			},
			expected: ipv4.ICMPTypeTimestamp,
			err:      false,
		},
		{
			test: Test{
				RequestType: ipv4.ICMPTypeTimestamp,
				Destination: "8.8.8.8",
			},
			expected: ipv4.ICMPTypeTimestampReply,
			err:      false,
		},
		{
			test: Test{
				RequestType: ipv4.ICMPType(99),
			},
			expected: 99,
			err:      true,
		},
	}

	for _, tc := range tests {
		got, err := getICMPResponseType(tc.test)
		if (err != nil) != tc.err {
			t.Errorf("getICMPResponseType(%v) error = %v, wantErr %v", tc.test, err, tc.err)
			continue
		}
		if got != tc.expected {
			t.Errorf("getICMPResponseType(%v) = %v, want %v", tc.test, got, tc.expected)
		}
	}
}

func getValidInterfaceAndIP(t *testing.T) (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Unable to get network interfaces: ", err)
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.To4() == nil {
				continue
			}
			return iface.Name, ip.String()
		}
	}
	t.Skip("No valid network interface with IPv4 found")
	return "", ""
}

// TestLoadConfigValid verifies that a valid YAML configuration file is loaded correctly.
func TestLoadConfigValid(t *testing.T) {
	ifaceName, ipStr := getValidInterfaceAndIP(t)

	// Prepare a YAML configuration content with valid values.
	yamlContent := fmt.Sprintf(`
general:
  output: "json"
  parallelism: 4
  tos: 100
  interfaceName: "%s"
  sourceIPAddress: "%s"
tests:
  - name: "scenario1"
`, ifaceName, ipStr)

	// Write the YAML content to a temporary file.
	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	cfg, err := loadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("Expected no error, but got: %v", err)
	}

	// Validate each configuration field.
	if cfg.General.Output == nil || *cfg.General.Output != "json" {
		t.Errorf("Expected output to be 'json', got: %v", cfg.General.Output)
	}
	if cfg.General.Parallelism == nil || *cfg.General.Parallelism != 4 {
		t.Errorf("Expected parallelism to be 4, got: %v", cfg.General.Parallelism)
	}
	if cfg.General.TOS == nil || *cfg.General.TOS != 100 {
		t.Errorf("Expected TOS to be 100, got: %v", cfg.General.TOS)
	}
	if len(cfg.Tests) != 1 || cfg.Tests[0].Name != "scenario1" {
		t.Errorf("Expected tests to be ['scenario1'], got: %v", cfg.Tests)
	}

	// Verify that the network interface and source IP are set correctly.
	if cfg.General.Interface.Name != ifaceName {
		t.Errorf("Expected interface to be %s, got: %s", ifaceName, cfg.General.Interface.Name)
	}
	if cfg.General.SourceIPAddress == nil || cfg.General.SourceIPAddress.String() != ipStr {
		t.Errorf("Expected source IP to be %s, got: %v", ipStr, cfg.General.SourceIPAddress)
	}
}

// TestLoadConfigInvalidOutput checks that an invalid output value results in an error.
func TestLoadConfigInvalidOutput(t *testing.T) {
	ifaceName, ipStr := getValidInterfaceAndIP(t)

	yamlContent := fmt.Sprintf(`
general:
  output: "xml"
  parallelism: 4
  tos: 100
  interfaceName: "%s"
  sourceIPAddress: "%s"
tests:
  - name: "scenario1"
`, ifaceName, ipStr)

	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = loadConfig(tmpfile.Name())
	if err == nil {
		t.Fatal("Expected an error for invalid output value, but got nil")
	}
	if !strings.Contains(err.Error(), "invalid output value") {
		t.Errorf("Expected error message to contain 'invalid output value', got: %v", err)
	}
}

// TestLoadConfigInvalidTOS checks that an out-of-range TOS value results in an error.
func TestLoadConfigInvalidTOS(t *testing.T) {
	ifaceName, ipStr := getValidInterfaceAndIP(t)

	yamlContent := fmt.Sprintf(`
general:
  output: "json"
  parallelism: 4
  tos: 300
  interfaceName: "%s"
  sourceIPAddress: "%s"
tests:
  - name: "scenario1"
`, ifaceName, ipStr)

	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = loadConfig(tmpfile.Name())
	if err == nil {
		t.Fatal("Expected an error for invalid TOS value, but got nil")
	}
	if !strings.Contains(err.Error(), "invalid TOS value") {
		t.Errorf("Expected error message to contain 'invalid TOS value', got: %v", err)
	}
}

// TestLoadConfigNoTests checks that an empty tests section results in an error.
func TestLoadConfigNoTests(t *testing.T) {
	ifaceName, ipStr := getValidInterfaceAndIP(t)

	yamlContent := fmt.Sprintf(`
general:
  output: "json"
  parallelism: 4
  tos: 100
  interfaceName: "%s"
  sourceIPAddress: "%s"
tests: []
`, ifaceName, ipStr)

	tmpfile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatal(err)
	}
	tmpfile.Close()

	_, err = loadConfig(tmpfile.Name())
	if err == nil {
		t.Fatal("Expected an error for empty tests section, but got nil")
	}
	if !strings.Contains(err.Error(), "no test scenarios found") {
		t.Errorf("Expected error message to contain 'no test scenarios found', got: %v", err)
	}
}

// TestGetIfaceFromInterfaceName verifies the behavior of getIfaceFromInterfaceName for valid and invalid interface names.
func TestGetIfaceFromInterfaceName(t *testing.T) {
	ifaceName, _ := getValidInterfaceAndIP(t)
	// Test with a valid interface name.
	iface, err := getIfaceFromInterfaceName(ifaceName)
	if err != nil {
		t.Fatalf("Expected no error for a valid interface name, but got: %v", err)
	}
	if iface.Name != ifaceName {
		t.Errorf("Expected interface name %s, got %s", ifaceName, iface.Name)
	}

	// Test with an empty string.
	_, err = getIfaceFromInterfaceName("")
	if err == nil {
		t.Fatal("Expected an error for empty interface name, but got nil")
	}

	// Test with a non-existent interface name.
	_, err = getIfaceFromInterfaceName("nonexistent_interface_12345")
	if err == nil {
		t.Fatal("Expected an error for a non-existent interface name, but got nil")
	}
}

// TestDetermineNetworkInterfaceAndIPAddress_BothSpecified verifies the behavior when both interfaceName and sourceIPAddress are specified.
func TestDetermineNetworkInterfaceAndIPAddress_BothSpecified(t *testing.T) {
	ifaceName, ipStr := getValidInterfaceAndIP(t)
	cfg := Config{
		General: generalConfig{
			InterfaceName:         &ifaceName,
			SourceIPAddressString: &ipStr,
		},
	}

	iface, ip := determineNetworkInterfaceAndIPAddress(cfg)
	if iface.Name != ifaceName {
		t.Errorf("Expected interface name %s, got %s", ifaceName, iface.Name)
	}
	if ip == nil || ip.String() != ipStr {
		t.Errorf("Expected IP %s, got %v", ipStr, ip)
	}
}

// TestDetermineNetworkInterfaceAndIPAddress_InterfaceOnly verifies the behavior when only interfaceName is specified.
func TestDetermineNetworkInterfaceAndIPAddress_InterfaceOnly(t *testing.T) {
	ifaceName, _ := getValidInterfaceAndIP(t)
	cfg := Config{
		General: generalConfig{
			InterfaceName: &ifaceName,
		},
	}
	iface, ip := determineNetworkInterfaceAndIPAddress(cfg)
	if iface.Name != ifaceName {
		t.Errorf("Expected interface name %s, got %s", ifaceName, iface.Name)
	}
	if ip == nil || ip.To4() == nil {
		t.Errorf("Expected a valid IPv4 address for interface %s, got: %v", ifaceName, ip)
	}
}

// TestDetermineNetworkInterfaceAndIPAddress_NeitherSpecified verifies the behavior when neither interfaceName nor sourceIPAddress is specified.
// Note: This branch returns the first valid interface found on the system.
func TestDetermineNetworkInterfaceAndIPAddress_NeitherSpecified(t *testing.T) {
	cfg := Config{
		General: generalConfig{},
	}
	iface, ip := determineNetworkInterfaceAndIPAddress(cfg)
	if ip == nil || ip.To4() == nil {
		t.Errorf("Expected a valid IPv4 address, got: %v", ip)
	}
	if iface.Name == "" {
		t.Errorf("Expected a valid interface, got: %v", iface)
	}
}
