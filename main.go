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

// TestInput defines the structure for a single test scenario.
type TestInput struct {
	Name           string `yaml:"name"`            // Test name
	Destination    string `yaml:"dest"`            // Destination IP address
	RequestType    string `yaml:"request_type"`    // Request type ("echo" or "timestamp")
	ExpectedResult string `yaml:"expected_result"` // Expected result ("response" or "timeout")
	Timeout        string `yaml:"timeout"`         // Timeout duration (e.g., "2s")
}

type Test struct {
	Name           string
	Destination    string
	ID             int
	Seq            int
	RequestType    ipv4.ICMPType
	Timeout        time.Duration
	ExpectedResult string
}

// Config defines the YAML configuration structure.
type Config struct {
	General GeneralConfig `yaml:"general"`
	Tests   []TestInput   `yaml:"tests"`
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

var pid = os.Getpid() & 0xffff

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
func icmpTypeToString(t ipv4.ICMPType) string {
	switch t {
	case ipv4.ICMPTypeEcho:
		return "echo request"
	case ipv4.ICMPTypeEchoReply:
		return "echo reply"
	case ipv4.ICMPTypeTimestamp:
		return "timestamp"
	case ipv4.ICMPTypeTimestampReply:
		return "timestamp reply"
	default:
		return fmt.Sprintf("type %d", t.Protocol())
	}
}

// createICMPMessage builds an ICMP message based on the provided request type,
// using the given id and sequence number.
func createICMPMessage(reqType ipv4.ICMPType, id, seq int) (*icmp.Message, error) {
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
	Name           string        `json:"name"`
	Destination    string        `json:"destination"`
	RequestType    string        `json:"request_type"`
	ExpectedResult string        `json:"expected_result"`
	ActualResult   string        `json:"actual_result"`
	Duration       time.Duration `json:"duration"`
	Status         string        `json:"status"` // "PASSED" or "FAILED"
	Details        string        `json:"details,omitempty"`
	Timestamp      time.Time     `json:"timestamp"`
}

// runICMPTest sends an ICMP request and waits until a reply with a matching (ID, Seq) is received.
// It ignores any replies whose (ID, Seq) pair does not match the one sent. The overall timeout is applied.
func runICMPTest(test Test) TestResult {
	result := TestResult{
		Name:           test.Name,
		Destination:    test.Destination,
		RequestType:    test.RequestType.String(),
		ExpectedResult: test.ExpectedResult,
		Timestamp:      time.Now(),
	}

	fail := func(format string, args ...interface{}) TestResult {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf(format, args...)
		return result
	}

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fail("[error] test name: %s, ListenPacket error: %v", test.Name, err)
	}
	defer conn.Close()

	dst, err := net.ResolveIPAddr("ip4", test.Destination)
	if err != nil {
		return fail("[error] test name: %s, ResolveIPAddr error: %v", test.Name, err)
	}

	msg, err := createICMPMessage(test.RequestType, test.ID, test.Seq)
	if err != nil {
		return fail("[error] test name: %s, createICMPMessage error: %v", test.Name, err)
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return fail("[error] test name: %s, message marshal error: %v", test.Name, err)
	}

	start := time.Now()
	n, err := conn.WriteTo(b, dst)
	if err != nil {
		return fail("WriteTo error: %v", err)
	}
	if n != len(b) {
		return fail("sent %d bytes, expected %d", n, len(b))
	}

	deadline := time.Now().Add(test.Timeout)
	if err = conn.SetReadDeadline(deadline); err != nil {
		return fail("SetReadDeadline error: %v", err)
	}

	resp := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(resp)
		elapsed := time.Since(start)
		if err != nil {
			// timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				result.Duration = elapsed
				result.ActualResult = "timeout"
				if test.ExpectedResult != "timeout" {
					return fail("expected response, but timed out after %v waiting for matching message", test.Timeout)
				}
				result.Status = "PASSED"
				result.Details = fmt.Sprintf("expected timeout occurred (after %v)", test.Timeout)
				return result
			}
			result.Duration = elapsed
			return fail("ReadFrom error: %v", err)
		}

		parsedMsg, err := icmp.ParseMessage(1, resp[:n])
		if err != nil {
			// if the message is not ICMP, ignore it
			continue
		}

		var matched bool
		switch body := parsedMsg.Body.(type) {
		case *icmp.Echo:
			matched = (body.ID == test.ID && body.Seq == test.Seq)
		case *icmpTimestamp:
			matched = (body.ID == test.ID && body.Seq == test.Seq)
		case *icmp.RawBody:
			if len(body.Data) >= 4 {
				replyID := int(body.Data[0])<<8 | int(body.Data[1])
				replySeq := int(body.Data[2])<<8 | int(body.Data[3])
				matched = (replyID == test.ID && replySeq == test.Seq)
			}
		}
		if !matched {
			// ignore non-matching messages
			continue
		}

		result.Duration = elapsed
		result.ActualResult = fmt.Sprintf("%s", parsedMsg.Type)

		expectedICMPResponseType, err := getICMPResponseType(test)
		if err != nil || parsedMsg.Type != expectedICMPResponseType {
			return fail("received unexpected response %s from %v", parsedMsg.Type, peer)
		}

		result.Status = "PASSED"
		result.Details = fmt.Sprintf("received expected response %s from %v", parsedMsg.Type, peer)
		return result
	}
}

// getICMPResponseType returns expected response types based on the test.
func getICMPResponseType(test Test) (ipv4.ICMPType, error) {
	switch test.RequestType.String() {
	case "echo":
		return ipv4.ICMPTypeEchoReply, nil
	case "timestamp":
		ip := net.ParseIP(test.Destination)
		if ip != nil && ip.IsLoopback() {
			return ipv4.ICMPTypeTimestamp, nil
		}
		return ipv4.ICMPTypeTimestampReply, nil
	default:
		return 99, fmt.Errorf("unsupported ICMP type: %s", test.RequestType) // 99 is an invalid ICMP type
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
func parseICMPRequestType(reqType string) (ipv4.ICMPType, error) {
	switch reqType {
	case "echo":
		return ipv4.ICMPTypeEcho, nil
	case "timestamp":
		return ipv4.ICMPTypeTimestamp, nil
	default:
		return 99, fmt.Errorf("unsupported request type: %s", reqType) // 99 is an invalid ICMP type
	}
}

func buildFailedTestResult(testInput TestInput, details string) TestResult {
	return TestResult{
		Name:           testInput.Name,
		Destination:    testInput.Destination,
		RequestType:    testInput.RequestType,
		ExpectedResult: testInput.ExpectedResult,
		ActualResult:   "N/A",
		Duration:       0,
		Status:         "FAILED",
		Details:        details,
		Timestamp:      time.Now(),
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
		sem <- struct{}{}
		go func(i int, testInput TestInput) {
			defer func() {
				wg.Done()
				<-sem
			}()

			if testInput.ExpectedResult != "response" && testInput.ExpectedResult != "timeout" {
				results[i] = buildFailedTestResult(testInput,
					fmt.Sprintf("invalid expected_result: %q", testInput.ExpectedResult))
				return
			}

			duration, err := time.ParseDuration(testInput.Timeout)
			if err != nil {
				results[i] = buildFailedTestResult(testInput,
					fmt.Sprintf("invalid timeout %q: %v", testInput.Timeout, err))
				return
			}

			reqType, err := parseICMPRequestType(testInput.RequestType)
			if err != nil {
				results[i] = buildFailedTestResult(testInput, err.Error())
				return
			}

			test := Test{
				Name:           testInput.Name,
				Destination:    testInput.Destination,
				ID:             pid,
				Seq:            i + 1,
				RequestType:    reqType,
				Timeout:        duration,
				ExpectedResult: testInput.ExpectedResult,
			}

			results[i] = runICMPTest(test)
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
			fmt.Printf("Expected Result: %s\n", res.ExpectedResult)
			fmt.Printf("Actual Result: %s\n", res.ActualResult)
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
