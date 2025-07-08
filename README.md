# ICMP Test Tool

A Go-based tool for testing ICMP packet transmission and reception. Supports payload size, DF bit configuration, and fragmentation behavior verification.

## Build
```bash
make build
```

## Running Tests

### Using YAML Configuration Files

#### Available Configuration Files
```bash
make list-configs
```

#### Individual Test Execution
```bash
# Comprehensive tests (basic functionality + payload sizes)
make test-comprehensive

# DF bit tests
make test-df

# Localhost tests
make test-localhost

# Specify a specific configuration file
make test-config CONFIG=tests/configs/comprehensive.yaml
```

#### Run All YAML Tests
```bash
# Run all configuration files
make test-all-yaml

# With detailed output
make test-yaml
```

### Go Integration Tests

```bash
# Programmatic tests in Go
sudo make test-integration

# Regular unit tests (no root privileges required)
make test
```

### Manual Execution
```bash
sudo ./icmp-test -config tests/configs/comprehensive.yaml
```

## Test Configuration

### tests/configs/

- `comprehensive.yaml`: Comprehensive configuration for basic functionality and payload size tests
- `df_bit.yaml`: DF bit behavior tests
- `localhost.yaml`: Localhost environment tests

### Configuration Example

```yaml
general:
  output: "text"
  parallelism: 1
  tos: 0x00
  interface_name: "en0"
  set_df_bit: false

tests:
  - name: "Basic Echo Test"
    dest: "8.8.8.8"
    request_type: "echo"
    expected_result: "response"
    timeout: "3s"
    payload_size: 32
```

## For Developers

### Choosing Test Execution Methods

1. **YAML Configuration Files**: Visual and easy to understand, suitable for CI/CD pipelines
2. **Go Integration Tests**: Programmatic control, suitable for complex test logic

### Makefile Targets

```bash
make help  # Display available commands
```