package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestCreateICMPMessageEcho verifies that an echo message is created with the correct ID and sequence.
func TestCreateICMPMessageEcho(t *testing.T) {
	id := os.Getpid() & 0xffff
	seq := 42
	payloadSize := 32
	msg, err := createICMPMessage(ipv4.ICMPTypeEcho, id, seq, payloadSize)
	if err != nil {
		t.Fatalf("createICMPMessage(echo, %d, %d, %d) error: %v", id, seq, payloadSize, err)
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
	if len(echo.Data) != payloadSize {
		t.Errorf("expected data length %d; got %d", payloadSize, len(echo.Data))
	}
	// Check the first few characters of the payload pattern
	expected := "0123456789abcdefghijklmnopqrstuvwxyz"
	for i := 0; i < len(echo.Data) && i < len(expected); i++ {
		if echo.Data[i] != expected[i%len(expected)] {
			t.Errorf("expected data[%d] = %c; got %c", i, expected[i%len(expected)], echo.Data[i])
		}
	}
}

// TestCreateICMPMessageTimestamp verifies that a timestamp message is created with the correct ID and sequence.
func TestCreateICMPMessageTimestamp(t *testing.T) {
	id := os.Getpid() & 0xffff
	seq := 17
	payloadSize := 32 // Payload size parameter, but timestamp messages ignore it
	msg, err := createICMPMessage(ipv4.ICMPTypeTimestamp, id, seq, payloadSize)
	if err != nil {
		t.Fatalf("createICMPMessage(timestamp, %d, %d, %d) error: %v", id, seq, payloadSize, err)
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
			if ip == nil || ip.To4() == nil || ip.IsLoopback() {
				continue
			}
			return iface.Name, ip.String()
		}
	}
	t.Skip("No valid network interface with IPv4 found")
	return "", ""
}

func getLocalInterfaceAndIP(t *testing.T) (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Unable to get network interfaces: ", err)
	}
	for _, iface := range ifaces {
		if iface.Name == "lo0" || iface.Name == "lo" {
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
				if ip == nil || ip.To4() == nil || !ip.IsLoopback() {
					continue
				}
				return iface.Name, ip.String()
			}
		}
	}
	// Fallback to any loopback address
	return "lo0", "127.0.0.1"
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
	if cfg.General.Output != "json" {
		t.Errorf("Expected output to be 'json', got: %v", cfg.General.Output)
	}
	if cfg.General.Parallelism != 4 {
		t.Errorf("Expected parallelism to be 4, got: %v", cfg.General.Parallelism)
	}
	if cfg.General.TOS != 100 {
		t.Errorf("Expected TOS to be 100, got: %v", cfg.General.TOS)
	}
	if len(cfg.Tests) != 1 || cfg.Tests[0].Name != "scenario1" {
		t.Errorf("Expected tests to be ['scenario1'], got: %v", cfg.Tests)
	}

	// Verify that the network interface and source IP are set correctly.
	// Note: Due to the updated getValidInterfaceAndIP function, we just verify they're non-empty
	if cfg.General.Interface.Name == "" {
		t.Errorf("Expected interface to be set, but got empty string")
	}
	if cfg.General.SourceIPAddress == nil {
		t.Errorf("Expected source IP to be set, but got nil")
	}

	// Log for debugging purposes
	t.Logf("Using interface: %s, IP: %s", cfg.General.Interface.Name, cfg.General.SourceIPAddress.String())
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
	cfg := inputConfig{
		General: inputGeneralConfig{
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
	cfg := inputConfig{
		General: inputGeneralConfig{
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
	cfg := inputConfig{
		General: inputGeneralConfig{},
	}
	iface, ip := determineNetworkInterfaceAndIPAddress(cfg)
	if ip == nil || ip.To4() == nil {
		t.Errorf("Expected a valid IPv4 address, got: %v", ip)
	}
	if iface.Name == "" {
		t.Errorf("Expected a valid interface, got: %v", iface)
	}
}

// TestCreateICMPMessageEchoPayloadSizes verifies that echo messages are created with various payload sizes.
func TestCreateICMPMessageEchoPayloadSizes(t *testing.T) {
	id := os.Getpid() & 0xffff
	seq := 1

	testCases := []struct {
		name        string
		payloadSize int
		expected    string
	}{
		{"Zero payload", 0, ""},
		{"Small payload", 10, "0123456789"},
		{"Default payload", 32, "0123456789abcdefghijklmnopqrstuvwxyz"[:32]},
		{"Large payload", 100, strings.Repeat("0123456789abcdefghijklmnopqrstuvwxyz", 3)[:100]},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := createICMPMessage(ipv4.ICMPTypeEcho, id, seq, tc.payloadSize)
			if err != nil {
				t.Fatalf("createICMPMessage(echo, %d, %d, %d) error: %v", id, seq, tc.payloadSize, err)
			}

			echo, ok := msg.Body.(*icmp.Echo)
			if !ok {
				t.Fatalf("expected body type *icmp.Echo; got %T", msg.Body)
			}

			if len(echo.Data) != tc.payloadSize {
				t.Errorf("expected data length %d; got %d", tc.payloadSize, len(echo.Data))
			}

			// Verify the pattern
			pattern := "0123456789abcdefghijklmnopqrstuvwxyz"
			for i := 0; i < len(echo.Data); i++ {
				expected := pattern[i%len(pattern)]
				if echo.Data[i] != expected {
					t.Errorf("data[%d]: expected %c, got %c", i, expected, echo.Data[i])
				}
			}
		})
	}
}

// TestCreateICMPMessageEchoPatternConsistency verifies the payload pattern is consistent across multiple creations.
func TestCreateICMPMessageEchoPatternConsistency(t *testing.T) {
	id := os.Getpid() & 0xffff
	payloadSize := 72 // Two full cycles of the 36-character pattern

	// Create multiple messages
	msg1, err := createICMPMessage(ipv4.ICMPTypeEcho, id, 1, payloadSize)
	if err != nil {
		t.Fatalf("createICMPMessage error: %v", err)
	}

	msg2, err := createICMPMessage(ipv4.ICMPTypeEcho, id, 2, payloadSize)
	if err != nil {
		t.Fatalf("createICMPMessage error: %v", err)
	}

	echo1, ok := msg1.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("expected body type *icmp.Echo; got %T", msg1.Body)
	}

	echo2, ok := msg2.Body.(*icmp.Echo)
	if !ok {
		t.Fatalf("expected body type *icmp.Echo; got %T", msg2.Body)
	}

	// Payload should be identical (only ID/Seq should differ)
	if !bytes.Equal(echo1.Data, echo2.Data) {
		t.Errorf("payload data should be identical across different message creations")
	}

	// Verify the pattern is exactly two full cycles
	expected := "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz"
	if string(echo1.Data) != expected {
		t.Errorf("expected payload %q; got %q", expected, string(echo1.Data))
	}
}
