# Tracee Tests

This directory contains various test suites for Tracee.

## Test Types

- **Unit tests**: `make test-unit` - Test individual components
- **Integration tests**: `make test-integration` - Test system integration (requires root)
- **E2E tests**: End-to-end testing with real scenarios

## Running Tests in a VM

For safe, isolated testing that won't affect your host system, see:

**[VM Testing Guide](../docs/contributing/vm-testing.md)**

Quick start:
```bash
./run-vm-tests.sh
```

This will run all tests in an isolated VM environment with automatic cleanup.

