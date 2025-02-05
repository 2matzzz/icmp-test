package main

import (
	"os"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// TestICMPTypeToString verifies that icmpTypeToString returns the expected strings.
func TestICMPTypeToString(t *testing.T) {
	tests := []struct {
		in       icmp.Type
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

// TestDetermineICMPTypes_Echo verifies determineICMPTypes for an echo test.
func TestDetermineICMPTypes_Echo(t *testing.T) {
	testCase := Test{
		Name:     "Test Echo",
		Dest:     "8.8.8.8",
		Req:      "echo",
		Timeout:  "2s",
		Expected: "response",
	}
	req, resp, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes error: %v", err)
	}
	if req != ipv4.ICMPTypeEcho {
		t.Errorf("expected request type %v; got %v", ipv4.ICMPTypeEcho, req)
	}
	if resp != ipv4.ICMPTypeEchoReply {
		t.Errorf("expected response type %v; got %v", ipv4.ICMPTypeEchoReply, resp)
	}
}

// TestDetermineICMPTypes_TimestampLoopback verifies determineICMPTypes for a timestamp test using a loopback address.
func TestDetermineICMPTypes_TimestampLoopback(t *testing.T) {
	testCase := Test{
		Name:     "Test Timestamp Loopback",
		Dest:     "127.0.0.1",
		Req:      "timestamp",
		Timeout:  "2s",
		Expected: "response",
	}
	req, resp, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes error: %v", err)
	}
	if req != ipv4.ICMPTypeTimestamp {
		t.Errorf("expected request type %v; got %v", ipv4.ICMPTypeTimestamp, req)
	}
	if resp != ipv4.ICMPTypeTimestamp {
		t.Errorf("expected response type %v; got %v", ipv4.ICMPTypeTimestamp, resp)
	}
}

// TestDetermineICMPTypes_TimestampNonLoopback verifies determineICMPTypes for a timestamp test using a non-loopback address.
func TestDetermineICMPTypes_TimestampNonLoopback(t *testing.T) {
	testCase := Test{
		Name:     "Test Timestamp NonLoopback",
		Dest:     "8.8.8.8",
		Req:      "timestamp",
		Timeout:  "2s",
		Expected: "response",
	}
	req, resp, err := determineICMPTypes(testCase)
	if err != nil {
		t.Fatalf("determineICMPTypes error: %v", err)
	}
	if req != ipv4.ICMPTypeTimestamp {
		t.Errorf("expected request type %v; got %v", ipv4.ICMPTypeTimestamp, req)
	}
	if resp != ipv4.ICMPTypeTimestampReply {
		t.Errorf("expected response type %v; got %v", ipv4.ICMPTypeTimestampReply, resp)
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
