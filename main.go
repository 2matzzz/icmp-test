package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v2"
)

// GeneralConfig holds general configuration options.
type GeneralConfig struct {
	Output string `yaml:"output"` // "text" or "json"
}

// Test defines the structure for a single test scenario.
type Test struct {
	Name     string `yaml:"name"`     // Test name
	Dest     string `yaml:"dest"`     // Destination IP address
	Req      string `yaml:"req"`      // Request type ("echo" or "timestamp")
	Timeout  string `yaml:"timeout"`  // Timeout duration (e.g., "2s")
	Expected string `yaml:"expected"` // Expected outcome ("response" or "timeout")
}

// Config defines the YAML configuration structure.
type Config struct {
	General GeneralConfig `yaml:"general"`
	Tests   []Test        `yaml:"tests"`
}

// icmpTimestamp represents the ICMP Timestamp message body.
// It consists of: ID (2 bytes) + Seq (2 bytes) + OriginateTime (4 bytes)
// + ReceiveTime (4 bytes) + TransmitTime (4 bytes) = 16 bytes total.
type icmpTimestamp struct {
	ID            int
	Seq           int
	OriginateTime uint32
	ReceiveTime   uint32
	TransmitTime  uint32
}

// Len returns the length of the ICMP Timestamp message body.
func (t *icmpTimestamp) Len(_ int) int {
	return 16
}

// Marshal converts the icmpTimestamp structure to network byte order (big endian).
func (t *icmpTimestamp) Marshal(_ int) ([]byte, error) {
	b := make([]byte, 16)
	b[0] = byte(t.ID >> 8)
	b[1] = byte(t.ID & 0xff)
	b[2] = byte(t.Seq >> 8)
	b[3] = byte(t.Seq & 0xff)
	b[4] = byte(t.OriginateTime >> 24)
	b[5] = byte(t.OriginateTime >> 16)
	b[6] = byte(t.OriginateTime >> 8)
	b[7] = byte(t.OriginateTime)
	b[8] = byte(t.ReceiveTime >> 24)
	b[9] = byte(t.ReceiveTime >> 16)
	b[10] = byte(t.ReceiveTime >> 8)
	b[11] = byte(t.ReceiveTime)
	b[12] = byte(t.TransmitTime >> 24)
	b[13] = byte(t.TransmitTime >> 16)
	b[14] = byte(t.TransmitTime >> 8)
	b[15] = byte(t.TransmitTime)
	return b, nil
}

// icmpTypeToString converts an ICMP type to a descriptive string.
// It uses a type switch to check if the underlying concrete type is ipv4.ICMPType.
func icmpTypeToString(t icmp.Type) string {
	switch v := t.(type) {
	case ipv4.ICMPType:
		switch v {
		case ipv4.ICMPTypeEcho:
			return ipv4.ICMPTypeEcho.String()
		case ipv4.ICMPTypeEchoReply:
			return ipv4.ICMPTypeEchoReply.String()
		case ipv4.ICMPTypeTimestamp:
			return ipv4.ICMPTypeTimestamp.String()
		case ipv4.ICMPTypeTimestampReply:
			return ipv4.ICMPTypeTimestampReply.String()
		default:
			return fmt.Sprintf("type %d", int(v))
		}
	default:
		return fmt.Sprintf("%v", t)
	}
}

// createICMPMessage builds an ICMP message based on the provided request type.
func createICMPMessage(reqType icmp.Type) (*icmp.Message, error) {
	if reqType == ipv4.ICMPTypeEcho {
		echo := &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("PING"),
		}
		return &icmp.Message{
			Type: reqType,
			Code: 0,
			Body: echo,
		}, nil
	} else if reqType == ipv4.ICMPTypeTimestamp {
		ts := &icmpTimestamp{
			ID:            os.Getpid() & 0xffff,
			Seq:           1,
			OriginateTime: 0,
			ReceiveTime:   0,
			TransmitTime:  0,
		}
		return &icmp.Message{
			Type: reqType,
			Code: 0,
			Body: ts,
		}, nil
	}
	return nil, fmt.Errorf("unsupported request type: %v", reqType)
}

// TestResult holds the result of a test scenario.
type TestResult struct {
	Name        string        `json:"name"`
	Destination string        `json:"destination"`
	RequestType string        `json:"request_type"`
	Expected    string        `json:"expected"`
	Actual      string        `json:"actual"`
	DurationNs  time.Duration `json:"duration_ns"`
	Status      string        `json:"status"` // "PASSED" or "FAILED"
	Details     string        `json:"details,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
}

// runICMPTest sends an ICMP request and returns the result.
func runICMPTest(name, dest string, reqType, expectedType icmp.Type, timeout time.Duration, expectResponse bool) TestResult {
	result := TestResult{
		Name:        name,
		Destination: dest,
		RequestType: icmpTypeToString(reqType),
		Expected:    icmpTypeToString(expectedType),
		Timestamp:   time.Now(),
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("ListenPacket error: %v", err)
		return result
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", dest)
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("ResolveIPAddr error: %v", err)
		return result
	}

	msg, err := createICMPMessage(reqType)
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("createICMPMessage error: %v", err)
		return result
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("message marshal error: %v", err)
		return result
	}

	start := time.Now()
	n, err := conn.WriteTo(b, dst)
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("WriteTo error: %v", err)
		return result
	}
	if n != len(b) {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("sent %d bytes, expected %d", n, len(b))
		return result
	}

	if err = conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("SetReadDeadline error: %v", err)
		return result
	}

	resp := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(resp)
	elapsed := time.Since(start)
	result.DurationNs = elapsed

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if expectResponse {
				result.Status = "FAILED"
				result.Details = fmt.Sprintf("expected response, but timed out after %v", timeout)
				result.Actual = "timeout"
			} else {
				result.Status = "PASSED"
				result.Details = fmt.Sprintf("expected timeout occurred (after %v)", timeout)
				result.Actual = "timeout"
			}
			return result
		}
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("ReadFrom error: %v", err)
		return result
	}

	if !expectResponse {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("expected timeout, but received response from %v in %v", peer, elapsed)
		parsedMsg, err := icmp.ParseMessage(1, resp[:n])
		if err == nil {
			result.Actual = icmpTypeToString(parsedMsg.Type)
		} else {
			result.Actual = "unknown"
		}
		return result
	}

	parsedMsg, err := icmp.ParseMessage(1, resp[:n])
	if err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("icmp.ParseMessage error: %v", err)
		return result
	}

	actualType := parsedMsg.Type
	result.Actual = icmpTypeToString(actualType)

	if actualType != expectedType {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("unexpected ICMP type: got %v from %v, expected %v",
			icmpTypeToString(actualType), peer, icmpTypeToString(expectedType))
	} else {
		result.Status = "PASSED"
		result.Details = fmt.Sprintf("received expected response %v from %v", icmpTypeToString(actualType), peer)
	}

	return result
}

// determineICMPTypes returns the request and expected response types.
func determineICMPTypes(test Test) (icmp.Type, icmp.Type, error) {
	switch test.Req {
	case "echo":
		return ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply, nil
	case "timestamp":
		reqType := ipv4.ICMPTypeTimestamp
		ip := net.ParseIP(test.Dest)
		if ip != nil && ip.IsLoopback() {
			return reqType, ipv4.ICMPTypeTimestamp, nil
		}
		return reqType, ipv4.ICMPTypeTimestampReply, nil
	default:
		return nil, nil, fmt.Errorf("unsupported request type: %s", test.Req)
	}
}

// parseExpectedResult returns whether a response is expected.
func parseExpectedResult(expected string) (bool, error) {
	switch expected {
	case "response":
		return true, nil
	case "timeout":
		return false, nil
	default:
		return false, fmt.Errorf("unsupported expected outcome: %s", expected)
	}
}

func main() {
	configFile := flag.String("config", "config.yaml", "Path to YAML test configuration file")
	flag.Parse()

	data, err := os.ReadFile(*configFile)
	if err != nil {
		log.Fatalf("config file read error: %v", err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		log.Fatalf("YAML unmarshal error: %v", err)
	}

	outputMode := config.General.Output
	if outputMode == "" {
		outputMode = "text"
	}

	var results []TestResult
	allPassed := true
	// Run each test scenario.
	for _, test := range config.Tests {
		duration, err := time.ParseDuration(test.Timeout)
		if err != nil {
			res := TestResult{
				Name:        test.Name,
				Destination: test.Dest,
				RequestType: test.Req,
				Expected:    "N/A",
				Actual:      "N/A",
				DurationNs:  0,
				Status:      "FAILED",
				Details:     fmt.Sprintf("invalid timeout %q: %v", test.Timeout, err),
				Timestamp:   time.Now(),
			}
			results = append(results, res)
			allPassed = false
			continue
		}

		reqType, expectedType, err := determineICMPTypes(test)
		if err != nil {
			res := TestResult{
				Name:        test.Name,
				Destination: test.Dest,
				RequestType: test.Req,
				Expected:    "N/A",
				Actual:      "N/A",
				DurationNs:  0,
				Status:      "FAILED",
				Details:     err.Error(),
				Timestamp:   time.Now(),
			}
			results = append(results, res)
			allPassed = false
			continue
		}

		expectResponse, err := parseExpectedResult(test.Expected)
		if err != nil {
			res := TestResult{
				Name:        test.Name,
				Destination: test.Dest,
				RequestType: test.Req,
				Expected:    "N/A",
				Actual:      "N/A",
				DurationNs:  0,
				Status:      "FAILED",
				Details:     err.Error(),
				Timestamp:   time.Now(),
			}
			results = append(results, res)
			allPassed = false
			continue
		}

		res := runICMPTest(test.Name, test.Dest, reqType, expectedType, duration, expectResponse)
		results = append(results, res)
		if res.Status == "FAILED" {
			allPassed = false
		}
	}

	// Output the results in the requested format.
	if outputMode == "text" {
		for _, res := range results {
			fmt.Printf("Running test: %s\n", res.Name)
			fmt.Printf("Destination: %s\n", res.Destination)
			fmt.Printf("Request Type: %s\n", res.RequestType)
			fmt.Printf("Expected Result: %s\n", res.Expected)
			fmt.Printf("Actual Result: %s\n", res.Actual)
			fmt.Printf("Status: %s\n", res.Status)
			fmt.Printf("Details: %s\n", res.Details)
			fmt.Printf("Timestamp: %s\n", res.Timestamp.Format(time.RFC3339Nano))
			fmt.Println()
		}
	} else if outputMode == "json" {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			log.Fatalf("JSON marshal error: %v", err)
		}
		fmt.Println(string(b))
	}

	// If any test has FAILED, exit with a nonzero exit code.
	if !allPassed {
		os.Exit(1)
	}
}
