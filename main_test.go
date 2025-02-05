package main

import (
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestDetermineICMPTypesEcho verifies the behavior for an "echo" request.
func TestDetermineICMPTypesEcho(t *testing.T) {
	testCase := Test{
		Name:     "Test Echo",
		Dest:     "8.8.8.8", // Example IP address
		Req:      "echo",
		Timeout:  "1s",
		Expected: "response",
	}
	reqType, expectedType, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes returned error: %v", err)
	}
	if reqType != ipv4.ICMPTypeEcho {
		t.Errorf("Expected reqType %v, got %v", ipv4.ICMPTypeEcho, reqType)
	}
	if expectedType != ipv4.ICMPTypeEchoReply {
		t.Errorf("Expected expectedType %v, got %v", ipv4.ICMPTypeEchoReply, expectedType)
	}
}

// TestDetermineICMPTypesTimestampLoopback verifies the behavior for a "timestamp" request when using a loopback address.
func TestDetermineICMPTypesTimestampLoopback(t *testing.T) {
	testCase := Test{
		Name:     "Test Timestamp Loopback",
		Dest:     "127.0.0.1",
		Req:      "timestamp",
		Timeout:  "1s",
		Expected: "response",
	}
	reqType, expectedType, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes returned error: %v", err)
	}
	if reqType != ipv4.ICMPTypeTimestamp {
		t.Errorf("Expected reqType %v, got %v", ipv4.ICMPTypeTimestamp, reqType)
	}
	// For loopback, the expected type is also ICMPTypeTimestamp.
	if expectedType != ipv4.ICMPTypeTimestamp {
		t.Errorf("Expected expectedType %v, got %v", ipv4.ICMPTypeTimestamp, expectedType)
	}
}

// TestDetermineICMPTypesTimestampNonLoopback verifies the behavior for a "timestamp" request when not using a loopback address.
func TestDetermineICMPTypesTimestampNonLoopback(t *testing.T) {
	testCase := Test{
		Name:     "Test Timestamp NonLoopback",
		Dest:     "8.8.8.8",
		Req:      "timestamp",
		Timeout:  "1s",
		Expected: "response",
	}
	reqType, expectedType, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes returned error: %v", err)
	}
	if reqType != ipv4.ICMPTypeTimestamp {
		t.Errorf("Expected reqType %v, got %v", ipv4.ICMPTypeTimestamp, reqType)
	}
	// For non-loopback, the expected type should be ICMPTypeTimestampReply.
	if expectedType != ipv4.ICMPTypeTimestampReply {
		t.Errorf("Expected expectedType %v, got %v", ipv4.ICMPTypeTimestampReply, expectedType)
	}
}

// TestParseExpectedResult verifies the behavior of the parseExpectedResult function.
func TestParseExpectedResult(t *testing.T) {
	// Test valid input "response"
	expect, err := parseExpectedResult("response")
	if err != nil {
		t.Errorf("parseExpectedResult returned error for valid input 'response': %v", err)
	}
	if expect != true {
		t.Errorf("Expected true for 'response', got %v", expect)
	}

	// Test valid input "timeout"
	expect, err = parseExpectedResult("timeout")
	if err != nil {
		t.Errorf("parseExpectedResult returned error for valid input 'timeout': %v", err)
	}
	if expect != false {
		t.Errorf("Expected false for 'timeout', got %v", expect)
	}

	// Test invalid input
	_, err = parseExpectedResult("invalid")
	if err == nil {
		t.Errorf("Expected error for invalid input, got nil")
	}
}

// TestICMPTypeToString verifies the conversion of ICMP types to descriptive strings.
func TestICMPTypeToString(t *testing.T) {
	// Test echo type.
	s := icmpTypeToString(ipv4.ICMPTypeEcho)
	if s != "echo" {
		t.Errorf("Expected 'echo' for ipv4.ICMPTypeEcho, got %q", s)
	}
	// Test echo reply type.
	s = icmpTypeToString(ipv4.ICMPTypeEchoReply)
	if s != "echo reply" {
		t.Errorf("Expected 'echo reply' for ipv4.ICMPTypeEchoReply, got %q", s)
	}
	// Test timestamp type.
	s = icmpTypeToString(ipv4.ICMPTypeTimestamp)
	if s != "timestamp" {
		t.Errorf("Expected 'timestamp' for ipv4.ICMPTypeTimestamp, got %q", s)
	}
	// Test timestamp reply type.
	s = icmpTypeToString(ipv4.ICMPTypeTimestampReply)
	if s != "timestamp reply" {
		t.Errorf("Expected 'timestamp reply' for ipv4.ICMPTypeTimestampReply, got %q", s)
	}
	// Test an unknown type using ipv4.ICMPType.
	unknownType := ipv4.ICMPType(99)
	s = icmpTypeToString(unknownType)
	expected := "type 99"
	if s != expected {
		t.Errorf("Expected %q for unknown type, got %q", expected, s)
	}
}

// TestCreateICMPMessageEcho verifies that createICMPMessage works correctly for an echo request.
func TestCreateICMPMessageEcho(t *testing.T) {
	msg, err := createICMPMessage(ipv4.ICMPTypeEcho)
	if err != nil {
		t.Fatalf("createICMPMessage returned error: %v", err)
	}
	if msg.Type != ipv4.ICMPTypeEcho {
		t.Errorf("Expected message type %v, got %v", ipv4.ICMPTypeEcho, msg.Type)
	}
	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		t.Errorf("Expected message body to be of type *icmp.Echo, got %T", msg.Body)
	}
	if echo.Data == nil || string(echo.Data) != "PING" {
		t.Errorf("Expected echo data to be 'PING', got %q", echo.Data)
	}
}

// TestCreateICMPMessageTimestamp verifies that createICMPMessage works correctly for a timestamp request.
func TestCreateICMPMessageTimestamp(t *testing.T) {
	msg, err := createICMPMessage(ipv4.ICMPTypeTimestamp)
	if err != nil {
		t.Fatalf("createICMPMessage returned error: %v", err)
	}
	if msg.Type != ipv4.ICMPTypeTimestamp {
		t.Errorf("Expected message type %v, got %v", ipv4.ICMPTypeTimestamp, msg.Type)
	}
	ts, ok := msg.Body.(*icmpTimestamp)
	if !ok {
		t.Errorf("Expected message body to be of type *icmpTimestamp, got %T", msg.Body)
	}
	// Check default values.
	if ts.Seq != 1 {
		t.Errorf("Expected sequence number 1, got %d", ts.Seq)
	}
	if ts.OriginateTime != 0 || ts.ReceiveTime != 0 || ts.TransmitTime != 0 {
		t.Errorf("Expected times to be 0, got OriginateTime=%d, ReceiveTime=%d, TransmitTime=%d",
			ts.OriginateTime, ts.ReceiveTime, ts.TransmitTime)
	}
}
