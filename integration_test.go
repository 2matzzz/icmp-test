package main

import (
	"net"
	"testing"
	"time"
)

// TestICMPIntegration runs various ICMP tests that were previously defined in YAML files
func TestICMPIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Note: These tests require root privileges to run
	testCases := []struct {
		name       string
		config     Config
		shouldPass bool
	}{
		{
			name: "Basic Echo Test",
			config: Config{
				General: generalConfig{
					Output:      "text",
					Parallelism: 1,
					TOS:         0,
					SetDFBit:    false,
				},
				Tests: []testInput{
					{
						Name:           "Basic Echo to Google DNS",
						Destination:    "8.8.8.8",
						RequestType:    "echo",
						ExpectedResult: "response",
						Timeout:        stringPtr("3s"),
						PayloadSize:    intPtr(32),
					},
				},
			},
			shouldPass: true,
		},
		{
			name: "Large Payload Test",
			config: Config{
				General: generalConfig{
					Output:      "text",
					Parallelism: 1,
					TOS:         0,
					SetDFBit:    false,
				},
				Tests: []testInput{
					{
						Name:           "Large payload - 1000 bytes",
						Destination:    "8.8.8.8",
						RequestType:    "echo",
						ExpectedResult: "response",
						Timeout:        stringPtr("5s"),
						PayloadSize:    intPtr(1000),
					},
					{
						Name:           "Large payload - 1400 bytes",
						Destination:    "8.8.8.8",
						RequestType:    "echo",
						ExpectedResult: "response",
						Timeout:        stringPtr("5s"),
						PayloadSize:    intPtr(1400),
					},
				},
			},
			shouldPass: true,
		},
		{
			name: "DF Bit Test",
			config: Config{
				General: generalConfig{
					Output:      "text",
					Parallelism: 1,
					TOS:         0,
					SetDFBit:    true, // DF bit enabled
				},
				Tests: []testInput{
					{
						Name:           "DF bit with large payload (should timeout)",
						Destination:    "8.8.8.8",
						RequestType:    "echo",
						ExpectedResult: "timeout",
						Timeout:        stringPtr("3s"),
						PayloadSize:    intPtr(2000),
					},
				},
			},
			shouldPass: true,
		},
		{
			name: "Localhost Test",
			config: Config{
				General: generalConfig{
					Output:      "text",
					Parallelism: 1,
					TOS:         0,
					SetDFBit:    false,
				},
				Tests: []testInput{
					{
						Name:           "Localhost echo",
						Destination:    "127.0.0.1",
						RequestType:    "echo",
						ExpectedResult: "response",
						Timeout:        stringPtr("2s"),
						PayloadSize:    intPtr(32),
					},
					{
						Name:           "Localhost large payload",
						Destination:    "127.0.0.1",
						RequestType:    "echo",
						ExpectedResult: "response",
						Timeout:        stringPtr("2s"),
						PayloadSize:    intPtr(2000),
					},
				},
			},
			shouldPass: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set up network interface and source IP
			config := setupTestConfig(t, &tc.config)

			// Run all tests in this configuration
			allPassed := true
			for i, testInput := range config.Tests {
				// Parse timeout
				var timeout time.Duration = 2 * time.Second
				if testInput.Timeout != nil {
					if d, err := time.ParseDuration(*testInput.Timeout); err == nil {
						timeout = d
					}
				}

				// Parse request type
				reqType, err := parseICMPRequestType(testInput.RequestType)
				if err != nil {
					t.Errorf("Invalid request type %s: %v", testInput.RequestType, err)
					continue
				}

				// Set payload size
				payloadSize := defaultPayloadSize
				if testInput.PayloadSize != nil {
					payloadSize = *testInput.PayloadSize
				}

				test := Test{
					Name:           testInput.Name,
					Destination:    testInput.Destination,
					ID:             pid,
					Seq:            i + 1,
					RequestType:    reqType,
					Timeout:        timeout,
					ExpectedResult: testInput.ExpectedResult,
					PayloadSize:    payloadSize,
				}

				result := runICMPTest(config, test)

				if result.Status != "PASSED" {
					if tc.shouldPass {
						t.Errorf("Test %s failed: %s", result.Name, result.Details)
					}
					allPassed = false
				} else {
					t.Logf("Test %s passed: %s", result.Name, result.Details)
				}
			}

			if tc.shouldPass && !allPassed {
				t.Errorf("Expected all tests to pass, but some failed")
			}
		})
	}
}

// Helper functions
func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func setupTestConfig(t *testing.T, config *Config) *Config {
	// Determine if this config uses localhost destinations
	usesLocalhost := false
	for _, test := range config.Tests {
		if test.Destination == "127.0.0.1" || test.Destination == "::1" || test.Destination == "localhost" {
			usesLocalhost = true
			break
		}
	}

	var ifaceName, ipStr string
	if usesLocalhost {
		// Use loopback interface for localhost tests
		ifaceName, ipStr = getLocalInterfaceAndIP(t)
	} else {
		// Use external interface for external destinations
		ifaceName, ipStr = getValidInterfaceAndIP(t)
	}

	iface, err := getIfaceFromInterfaceName(ifaceName)
	if err != nil {
		t.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	config.General.Interface = *iface
	config.General.SourceIPAddress = parseIP(ipStr)
	config.General.InterfaceName = ifaceName
	config.General.SourceIPAddressString = ipStr

	return config
}

func parseIP(ipStr string) net.IP {
	return net.ParseIP(ipStr)
}
