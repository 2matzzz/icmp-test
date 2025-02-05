package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v2"
)

// GeneralConfig holds general configuration options.
type GeneralConfig struct {
	Output      string `yaml:"output"`      // "text" or "json"
	Parallelism int    `yaml:"parallelism"` // Number of tests to run concurrently
}

// Test defines the structure for a single test scenario.
type Test struct {
	Name     string `yaml:"name"`     // Test name
	Dest     string `yaml:"dest"`     // Destination IP address
	Req      string `yaml:"req"`      // Request type ("echo" or "timestamp")
	Timeout  string `yaml:"timeout"`  // Timeout duration (e.g., "2s")
	Expected string `yaml:"expected"` // Expected result ("response" or "timeout")
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
func icmpTypeToString(t icmp.Type) string {
	switch v := t.(type) {
	case ipv4.ICMPType:
		switch v {
		case ipv4.ICMPTypeEcho:
			return "echo request"
		case ipv4.ICMPTypeEchoReply:
			return "echo reply"
		case ipv4.ICMPTypeTimestamp:
			return "timestamp"
		case ipv4.ICMPTypeTimestampReply:
			return "timestamp reply"
		default:
			return fmt.Sprintf("type %d", int(v))
		}
	default:
		return fmt.Sprintf("%v", t)
	}
}

// createICMPMessage builds an ICMP message based on the provided request type,
// using the given id and sequence number.
func createICMPMessage(reqType icmp.Type, id, seq int) (*icmp.Message, error) {
	if reqType == ipv4.ICMPTypeEcho {
		echo := &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("PING"),
		}
		return &icmp.Message{
			Type: reqType,
			Code: 0,
			Body: echo,
		}, nil
	} else if reqType == ipv4.ICMPTypeTimestamp {
		ts := &icmpTimestamp{
			ID:            id,
			Seq:           seq,
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
	Duration    time.Duration `json:"duration"`
	Status      string        `json:"status"` // "PASSED" or "FAILED"
	Details     string        `json:"details,omitempty"`
	Timestamp   time.Time     `json:"timestamp"`
}

// runICMPTest sends an ICMP request and waits until a reply with the matching sequence is received.
// It ignores any replies whose sequence number does not match until the deadline (timeout) is reached.
func runICMPTest(name, dest string, reqType, expectedType icmp.Type, timeout time.Duration, expectResponse bool, seq int) TestResult {
	result := TestResult{
		Name:        name,
		Destination: dest,
		RequestType: icmpTypeToString(reqType),
		Expected:    icmpTypeToString(expectedType),
		Timestamp:   time.Now(),
	}
	// Use the process ID as the ID.
	id := os.Getpid() & 0xffff

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

	msg, err := createICMPMessage(reqType, id, seq)
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

	// Set the read deadline.
	deadline := time.Now().Add(timeout)
	if err = conn.SetReadDeadline(deadline); err != nil {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf("SetReadDeadline error: %v", err)
		return result
	}

	resp := make([]byte, 1500)
	// Loop until we get a matching response or timeout.
	for {
		n, peer, err := conn.ReadFrom(resp)
		elapsed := time.Since(start)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// No matching message received before timeout.
				if expectResponse {
					result.Status = "FAILED"
					result.Details = fmt.Sprintf("expected response, but timed out after %v waiting for matching message", timeout)
					result.Actual = "timeout"
				} else {
					result.Status = "PASSED"
					result.Details = fmt.Sprintf("expected timeout occurred (after %v)", timeout)
					result.Actual = "timeout"
				}
				result.Duration = elapsed
				return result
			}
			result.Status = "FAILED"
			result.Details = fmt.Sprintf("ReadFrom error: %v", err)
			result.Duration = elapsed
			return result
		}

		parsedMsg, err := icmp.ParseMessage(1, resp[:n])
		if err != nil {
			// Ignore malformed messages.
			continue
		}

		// Check if the message body is of type *icmp.Echo or *icmpTimestamp
		// and if its ID and Seq match the ones we sent.
		matched := false
		switch body := parsedMsg.Body.(type) {
		case *icmp.Echo:
			if body.ID == id && body.Seq == seq {
				matched = true
			}
		case *icmpTimestamp:
			if body.ID == id && body.Seq == seq {
				matched = true
			}
		}
		if !matched {
			// Not the reply for our message; ignore it.
			continue
		}

		// Matching message found.
		result.Duration = elapsed
		result.Actual = icmpTypeToString(parsedMsg.Type)
		if parsedMsg.Type != expectedType {
			result.Status = "FAILED"
			result.Details = fmt.Sprintf("unexpected ICMP type: got %v from %v, expected %v",
				icmpTypeToString(parsedMsg.Type), peer, icmpTypeToString(expectedType))
		} else {
			result.Status = "PASSED"
			result.Details = fmt.Sprintf("received expected response %v from %v", icmpTypeToString(parsedMsg.Type), peer)
		}
		return result
	}
}

// determineICMPTypes returns the request and expected response types based on the test.
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
		return false, fmt.Errorf("unsupported expected result: %s", expected)
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

	// Determine the maximum number of concurrent jobs.
	maxConcurrent := config.General.Parallelism
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	var (
		results   = make([]TestResult, len(config.Tests))
		allPassed = true
		wg        sync.WaitGroup
		sem       = make(chan struct{}, maxConcurrent) // semaphore to limit concurrency
	)

	// Launch tests concurrently.
	for i, test := range config.Tests {
		wg.Add(1)
		sem <- struct{}{} // acquire semaphore
		go func(i int, test Test) {
			defer wg.Done()
			duration, err := time.ParseDuration(test.Timeout)
			if err != nil {
				results[i] = TestResult{
					Name:        test.Name,
					Destination: test.Dest,
					RequestType: test.Req,
					Expected:    "N/A",
					Actual:      "N/A",
					Duration:    0,
					Status:      "FAILED",
					Details:     fmt.Sprintf("invalid timeout %q: %v", test.Timeout, err),
					Timestamp:   time.Now(),
				}
				<-sem // release semaphore
				return
			}

			reqType, expectedType, err := determineICMPTypes(test)
			if err != nil {
				results[i] = TestResult{
					Name:        test.Name,
					Destination: test.Dest,
					RequestType: test.Req,
					Expected:    "N/A",
					Actual:      "N/A",
					Duration:    0,
					Status:      "FAILED",
					Details:     err.Error(),
					Timestamp:   time.Now(),
				}
				<-sem
				return
			}

			expectResponse, err := parseExpectedResult(test.Expected)
			if err != nil {
				results[i] = TestResult{
					Name:        test.Name,
					Destination: test.Dest,
					RequestType: test.Req,
					Expected:    "N/A",
					Actual:      "N/A",
					Duration:    0,
					Status:      "FAILED",
					Details:     err.Error(),
					Timestamp:   time.Now(),
				}
				<-sem
				return
			}

			// Use (i+1) as the sequence number (unique per test).
			seq := i + 1

			res := runICMPTest(test.Name, test.Dest, reqType, expectedType, duration, expectResponse, seq)
			results[i] = res
			<-sem // release semaphore
		}(i, test)
	}
	wg.Wait()

	// Check if any test failed.
	for _, res := range results {
		if res.Status != "PASSED" {
			allPassed = false
			break
		}
	}

	// Output the results.
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
