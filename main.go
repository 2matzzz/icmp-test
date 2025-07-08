package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"gopkg.in/yaml.v2"
)

type generalConfig struct {
	Output                string `yaml:"output"`      // "text" or "json"
	Parallelism           int    `yaml:"parallelism"` // Number of tests to run concurrently
	TOS                   int    `yaml:"tos"`
	InterfaceName         string `yaml:"interface_name"` // Network interface name
	Interface             net.Interface
	SourceIPAddressString string `yaml:"source_ip"` // Source IP address
	SourceIPAddress       net.IP
	ResultFilter          []string `yaml:"result_filter"`
	SetDFBit              bool     `yaml:"set_df_bit"` // Set Don't Fragment bit in IP header
}

// Config defines the YAML configuration structure.
type Config struct {
	General generalConfig `yaml:"general"`
	Tests   []testInput   `yaml:"tests"`
}

type inputGeneralConfig struct {
	Output                *string `yaml:"output"`      // "text" or "json"
	Parallelism           *int    `yaml:"parallelism"` // Number of tests to run concurrently
	TOS                   *string `yaml:"tos"`
	InterfaceName         *string `yaml:"interface_name"` // Network interface name
	Interface             net.Interface
	SourceIPAddressString *string `yaml:"source_ip"` // Source IP address
	SourceIPAddress       net.IP
	ResultFilter          *[]string `yaml:"result_filter"`
	SetDFBit              *bool     `yaml:"set_df_bit"` // Set Don't Fragment bit in IP header
}

type inputConfig struct {
	General inputGeneralConfig `yaml:"general"`
	Tests   []testInput        `yaml:"tests"`
}

// testInput defines the structure for a single test scenario.
type testInput struct {
	Name           string  `yaml:"name"`            // Test name
	Destination    string  `yaml:"dest"`            // Destination IP address
	RequestType    string  `yaml:"request_type"`    // Request type ("echo" or "timestamp")
	ExpectedResult string  `yaml:"expected_result"` // Expected result ("response" or "timeout")
	Timeout        *string `yaml:"timeout"`         // Timeout duration (e.g., "2s")
	PayloadSize    *int    `yaml:"payload_size"`    // ICMP echo payload size in bytes
}

type Test struct {
	Name           string
	Destination    string
	ID             int
	Seq            int
	RequestType    ipv4.ICMPType
	Timeout        time.Duration
	ExpectedResult string
	PayloadSize    int
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

const (
	defaultOutput      = "text"
	defaultParallelism = 1
	defaultTOS         = 0
	defaultTimeout     = "1s"
	defaultPayloadSize = 32
	defaultSetDFBit    = false

	// Socket options for DF bit setting
	IP_DONTFRAG     = 28 // macOS: Don't fragment flag
	IP_MTU_DISCOVER = 10 // Linux: Path MTU discovery option
	IP_PMTUDISC_DO  = 2  // Linux: Always send DF bit
)

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

// createICMPMessage builds an ICMP message based on the provided request type,
// using the given id, sequence number, and payload size.
func createICMPMessage(reqType ipv4.ICMPType, id, seq, payloadSize int) (*icmp.Message, error) {
	if reqType == ipv4.ICMPTypeEcho {
		// Create payload data with specified size
		data := make([]byte, payloadSize)
		// Fill with [0-9a-z] pattern (36 characters total)
		pattern := "0123456789abcdefghijklmnopqrstuvwxyz"
		for i := 0; i < payloadSize; i++ {
			data[i] = pattern[i%len(pattern)]
		}

		echo := &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: data,
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
	Name            string        `json:"name"`
	SourceInterface string        `json:"source_interface"`
	SourceIPAddress string        `json:"source_ip_address"`
	Destination     string        `json:"destination"`
	RequestType     string        `json:"request_type"`
	ExpectedResult  string        `json:"expected_result"`
	ActualResult    string        `json:"actual_result"`
	Duration        time.Duration `json:"duration"`
	Status          string        `json:"status"` // "PASSED" or "FAILED"
	Details         string        `json:"details,omitempty"`
	Timestamp       time.Time     `json:"timestamp"`
}

// runICMPTest sends an ICMP request and waits until a reply with a matching (ID, Seq) is received.
// It ignores any replies whose (ID, Seq) pair does not match the one sent. The overall timeout is applied.
func runICMPTest(config *Config, test Test) TestResult {
	result := TestResult{
		Name:            test.Name,
		Destination:     test.Destination,
		RequestType:     test.RequestType.String(),
		ExpectedResult:  test.ExpectedResult,
		Timestamp:       time.Now(),
		SourceInterface: config.General.Interface.Name,
		SourceIPAddress: config.General.SourceIPAddress.String(),
	}

	fail := func(format string, args ...interface{}) TestResult {
		result.Status = "FAILED"
		result.Details = fmt.Sprintf(format, args...)
		return result
	}

	localAddr := &net.IPAddr{IP: config.General.SourceIPAddress}

	ipconn, err := net.ListenIP("ip4:icmp", localAddr)
	if err != nil {
		log.Fatalf("ListenIP failed: %v\n", err)
	}
	defer ipconn.Close()

	// Set DF bit at socket level if requested
	if config.General.SetDFBit {
		if rawConn, err := ipconn.SyscallConn(); err == nil {
			rawConn.Control(func(fd uintptr) {
				// Try to set IP_DONTFRAG (macOS) or IP_MTU_DISCOVER (Linux)
				if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_DONTFRAG, 1); err != nil {
					// On Linux, try IP_MTU_DISCOVER with IP_PMTUDISC_DO
					if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DO); err != nil {
						log.Printf("Warning: Failed to set DF bit: %v", err)
					}
				}
			})
		}
	}

	pconn := ipv4.NewPacketConn(ipconn)
	if err := pconn.SetTOS(config.General.TOS); err != nil {
		log.Fatalf("SetTOS failed: %v\n", err)
	}

	if err := pconn.SetControlMessage(ipv4.FlagInterface, true); err != nil {
		log.Fatalf("SetControlMessage failed: %v\n", err)
	}

	dst, err := net.ResolveIPAddr("ip4", test.Destination)
	if err != nil {
		return fail("[error] test name: %s, ResolveIPAddr error: %v", test.Name, err)
	}

	cm := &ipv4.ControlMessage{
		IfIndex: config.General.Interface.Index,
		Src:     config.General.SourceIPAddress,
	}

	// Check if fragmentation is needed based on interface MTU
	mtu := config.General.Interface.MTU
	maxPayloadSize := mtu - 28 // 20 bytes IP header + 8 bytes ICMP header

	start := time.Now()

	if config.General.SetDFBit && test.PayloadSize > maxPayloadSize {
		// DF bit is set and payload exceeds MTU - this will likely result in ICMP error
		// Still attempt to send, but expect potential failure
		fmt.Printf("Warning: DF bit set with payload size %d exceeding MTU %d. May receive ICMP error.\n",
			test.PayloadSize, maxPayloadSize)
	}

	// Create and send ICMP message (kernel handles fragmentation automatically if needed)
	msg, err := createICMPMessage(test.RequestType, test.ID, test.Seq, test.PayloadSize)
	if err != nil {
		return fail("[error] test name: %s, createICMPMessage error: %v", test.Name, err)
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return fail("[error] test name: %s, message marshal error: %v", test.Name, err)
	}

	// Send ICMP packet - kernel will fragment automatically if needed and DF bit is not set
	n, err := pconn.WriteTo(b, cm, dst)
	if err != nil {
		return fail("WriteTo error: %v", err)
	}
	if n != len(b) {
		return fail("sent %d bytes, expected %d", n, len(b))
	}

	deadline := time.Now().Add(test.Timeout)
	if err = pconn.SetReadDeadline(deadline); err != nil {
		return fail("SetReadDeadline error: %v", err)
	}

	resp := make([]byte, 1500)
	for {
		// ignore control message for now
		n, _, peer, err := pconn.ReadFrom(resp)
		elapsed := time.Since(start)
		if err != nil {
			// timeout occurred
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

		// At this point, we have received a matching reply.
		result.Duration = elapsed
		result.ActualResult = fmt.Sprintf("%s", parsedMsg.Type)

		// Check if a response was not expected.
		if test.ExpectedResult == "timeout" {
			return fail("received response %s from %v, but expected timeout", parsedMsg.Type, peer)
		}

		expectedICMPResponseType, err := getICMPResponseType(test)
		if err != nil {
			continue
		}
		if parsedMsg.Type != expectedICMPResponseType {
			isSelf := false
			ip := net.ParseIP(test.Destination)
			if ip != nil && (ip.IsLoopback() || ip.Equal(config.General.SourceIPAddress)) {
				isSelf = true
			}
			if isSelf && (parsedMsg.Type == ipv4.ICMPTypeEcho || parsedMsg.Type == ipv4.ICMPTypeTimestamp) {
				continue
			}
			return fail("received unexpected ICMP type %s from %v (expected %s)", parsedMsg.Type, peer, expectedICMPResponseType)
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

func buildFailedTestResult(testInput testInput, details string) TestResult {
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

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config file read error: %w", err)
	}

	var input inputConfig
	if err := yaml.Unmarshal(data, &input); err != nil {
		return nil, fmt.Errorf("YAML unmarshal error: %w", err)
	}

	var cfg Config

	if input.General.InterfaceName != nil {
		iface, err := getIfaceFromInterfaceName(*input.General.InterfaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get interface %s: %v", *input.General.InterfaceName, err)
		}
		input.General.Interface = *iface
	} else {
		ifaces, err := net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("failed to get interfaces: %v", err)
		}
		if len(ifaces) == 0 {
			return nil, fmt.Errorf("no network interfaces found")
		}
		input.General.Interface = ifaces[0]
	}
	if input.General.SourceIPAddressString != nil {
		sourceIP := net.ParseIP(*input.General.SourceIPAddressString)
		if sourceIP == nil {
			return nil, fmt.Errorf("invalid source IP address: %s", *input.General.SourceIPAddressString)
		}
		input.General.SourceIPAddress = sourceIP
	} else {
		addrs, err := input.General.Interface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get addresses for interface %s: %v", input.General.Interface.Name, err)
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
			input.General.SourceIPAddress = ip
			break
		}
	}

	if input.General.Output == nil {
		// Allocate memory for the pointer and set the default value.
		cfg.General.Output = defaultOutput
	} else {
		// Check for valid values.
		if *input.General.Output != "text" && *input.General.Output != "json" {
			return nil, fmt.Errorf("invalid output value: %s. It must be 'text' or 'json'", *input.General.Output)
		}
		// Use the provided output.
		cfg.General.Output = *input.General.Output
	}

	if input.General.Parallelism == nil || *input.General.Parallelism <= 0 {
		cfg.General.Parallelism = defaultParallelism
	} else {
		cfg.General.Parallelism = *input.General.Parallelism
	}

	if input.General.TOS == nil {
		cfg.General.TOS = defaultTOS
	} else {
		tosValue, err := strconv.ParseInt(*input.General.TOS, 0, 8)
		if err != nil || tosValue < 0 || tosValue > 255 {
			return nil, fmt.Errorf("invalid TOS value in general configuration: %s. It must be a number or hex string (like '0x00') between 0 and 255", *input.General.TOS)
		}
		cfg.General.TOS = int(tosValue)
	}

	cfg.General.Interface, cfg.General.SourceIPAddress = determineNetworkInterfaceAndIPAddress(input)

	if input.General.ResultFilter != nil {
		cfg.General.ResultFilter = *input.General.ResultFilter
	}

	if input.General.SetDFBit == nil {
		cfg.General.SetDFBit = defaultSetDFBit
	} else {
		cfg.General.SetDFBit = *input.General.SetDFBit
	}

	if len(input.Tests) == 0 {
		return nil, fmt.Errorf("no test scenarios found")
	}
	cfg.Tests = input.Tests
	return &cfg, nil
}

func getIfaceFromInterfaceName(interfaceName string) (*net.Interface, error) {
	if interfaceName == "" {
		return nil, fmt.Errorf("interface name is empty")
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("InterfaceByName(%s) failed: %v", interfaceName, err)
	}
	return iface, nil
}

func determineNetworkInterfaceAndIPAddress(input inputConfig) (net.Interface, net.IP) {
	// interface name and source IP address not specified
	if input.General.InterfaceName == nil && input.General.SourceIPAddressString == nil {
		// lookup default interface
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Interfaces() failed: %v\n", err)
		}
		if len(ifaces) == 0 {
			log.Fatalf("No network interfaces found\n")
		}
		iface := ifaces[0]
		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatalf("Failed to get addresses for interface %s: %v\n", iface.Name, err)
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
			return iface, ip
		}
	}

	// interface name specified, but source IP address not specified
	if input.General.InterfaceName != nil && input.General.SourceIPAddressString == nil {
		iface, err := getIfaceFromInterfaceName(*input.General.InterfaceName)
		if err != nil {
			log.Fatalf("%s", err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatalf("Failed to get addresses for interface %s: %v\n", *input.General.InterfaceName, err)
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
			return *iface, ip
		}
	}

	// source IP address specified, but interface name not specified
	if input.General.InterfaceName == nil && input.General.SourceIPAddressString != nil {
		sourceIP := net.ParseIP(*input.General.SourceIPAddressString)
		if sourceIP == nil {
			log.Fatalf("Invalid source IP address: %s\n", *input.General.SourceIPAddressString)
		}
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("Interfaces() failed: %v\n", err)
		}
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				log.Fatalf("Failed to get addresses for interface %s: %v\n", iface.Name, err)
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
				if ip.Equal(sourceIP) {
					return iface, sourceIP
				}
			}
			log.Fatalf("No network interface found with IP address %s\n", sourceIP)
		}
	}

	// both interface name and source IP address specified
	if input.General.InterfaceName != nil && input.General.SourceIPAddressString != nil {
		iface, err := getIfaceFromInterfaceName(*input.General.InterfaceName)
		if err != nil {
			log.Fatalf("%s", err)
		}
		sourceIP := net.ParseIP(*input.General.SourceIPAddressString)
		if sourceIP == nil {
			log.Fatalf("Invalid source IP address: %s\n", *input.General.SourceIPAddressString)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			log.Fatalf("Failed to get addresses for interface %s: %v\n", *input.General.InterfaceName, err)
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
			if ip.Equal(sourceIP) {
				return *iface, sourceIP
			}
		}
		log.Fatalf("No network interface found with IP address %s\n", sourceIP)
	}
	log.Fatalf("Failed to determine network interface and source IP address\n")
	return net.Interface{}, nil // unreachable
}

func main() {
	configFilePath := flag.String("config", "config.yaml", "Path to YAML test configuration file")
	flag.Parse()
	config, err := loadConfig(*configFilePath)
	if err != nil {
		log.Fatalf("config load error: %v", err)
	}

	var (
		results   = make([]TestResult, len(config.Tests))
		allPassed = true
		wg        sync.WaitGroup
		sem       = make(chan struct{}, config.General.Parallelism) // semaphore to limit concurrency
	)

	// Launch tests concurrently.
	for i, test := range config.Tests {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, testInput testInput) {
			defer func() {
				wg.Done()
				<-sem
			}()

			if testInput.ExpectedResult != "response" && testInput.ExpectedResult != "timeout" {
				results[i] = buildFailedTestResult(testInput,
					fmt.Sprintf("invalid expected_result: %q", testInput.ExpectedResult))
				return
			}

			var timeout string
			if testInput.Timeout == nil {
				timeout = defaultTimeout
			} else {
				timeout = *testInput.Timeout
			}

			duration, err := time.ParseDuration(timeout)
			// Check if the timeout is valid.
			if err != nil {
				results[i] = buildFailedTestResult(testInput,
					fmt.Sprintf("invalid timeout %q: %v", timeout, err))
				return
			}
			if duration <= 0 || duration > 10*time.Second {
				results[i] = buildFailedTestResult(testInput,
					fmt.Sprintf("invalid timeout %q: must be between 1ms and 10s", timeout))
				return
			}

			reqType, err := parseICMPRequestType(testInput.RequestType)
			if err != nil {
				results[i] = buildFailedTestResult(testInput, err.Error())
				return
			}

			// Set payload size (default to 32 bytes if not specified)
			payloadSize := defaultPayloadSize
			if testInput.PayloadSize != nil {
				payloadSize = *testInput.PayloadSize
				// Validate payload size (must be positive and reasonable)
				if payloadSize < 0 || payloadSize > 65507 { // 65507 = 65535 - 20 (IP header) - 8 (ICMP header)
					results[i] = buildFailedTestResult(testInput,
						fmt.Sprintf("invalid payload_size %d: must be between 0 and 65507", payloadSize))
					return
				}
			}

			test := Test{
				Name:           testInput.Name,
				Destination:    testInput.Destination,
				ID:             pid,
				Seq:            i + 1,
				RequestType:    reqType,
				Timeout:        duration,
				ExpectedResult: testInput.ExpectedResult,
				PayloadSize:    payloadSize,
			}

			results[i] = runICMPTest(config, test)
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

	// フィルタリング処理
	filteredResults := results
	if len(config.General.ResultFilter) > 0 {
		tmp := []TestResult{}
		for _, res := range results {
			for _, status := range config.General.ResultFilter {
				if res.Status == status {
					tmp = append(tmp, res)
					break
				}
			}
		}
		filteredResults = tmp
	}

	// Output the results.
	if config.General.Output == "text" {
		for _, res := range filteredResults {
			fmt.Printf("Running test: %s\n", res.Name)
			fmt.Printf("Destination: %s\n", res.Destination)
			fmt.Printf("Source IP: %s\n", res.SourceIPAddress)
			fmt.Printf("Source Interface: %s\n", res.SourceInterface)
			fmt.Printf("Request Type: %s\n", res.RequestType)
			fmt.Printf("Expected Result: %s\n", res.ExpectedResult)
			fmt.Printf("Actual Result: %s\n", res.ActualResult)
			fmt.Printf("Status: %s\n", res.Status)
			fmt.Printf("Details: %s\n", res.Details)
			fmt.Printf("Timestamp: %s\n", res.Timestamp.Format(time.RFC3339Nano))
			fmt.Println()
		}
	} else if config.General.Output == "json" {
		b, err := json.MarshalIndent(filteredResults, "", "  ")
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
