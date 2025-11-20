# Code Coverage in Tracee

This document explains how code coverage is configured and used in Tracee.

## Overview

Tracee uses Go's built-in coverage tools combined with Codecov for comprehensive test coverage reporting. Coverage is tracked for multiple test types to ensure quality across all components.

## Coverage Types

### 1. Unit Tests Coverage

- **Target**: Maintain current baseline, 60% for new code
- **Scope**: Core Go logic, utilities, and non-eBPF components
- **Files**: `cmd/`, `pkg/`, `signatures/`
- **Command**: `make test-unit`

### 2. Integration Tests Coverage

- **Scope**: eBPF + Go integration, full system testing
- **Command**: `make test-integration`

## Local Development

### View Coverage Summary
```bash
make coverage
```

### Generate HTML Coverage Reports
```bash
make coverage-html
# Opens coverage.html and types/coverage.html
```

### Run Individual Coverage Commands
```bash
# Unit tests only
go test ./... -coverprofile=coverage.txt -covermode=atomic

# View coverage percentage
go tool cover -func=coverage.txt

# Generate HTML report
go tool cover -html=coverage.txt -o coverage.html
```

## CI/CD Integration

Coverage is automatically collected and reported on:
- Every Pull Request
- Every push to main branch
- Integration tests (when run)

### Codecov Integration

Coverage reports are uploaded to [Codecov](https://codecov.io) with the following flags:

- `unit`: Unit test coverage
- `integration`: Integration test coverage

### Coverage Configuration

Coverage behavior is configured in `codecov.yml`:

- Project coverage target: Auto (maintains current baseline)
- Patch coverage target: 60% for new code
- Automatic PR comments with coverage diff
- Excludes test files, generated code, and vendor dependencies

## Coverage Files

The following coverage files are generated (and gitignored):

- `coverage.txt`: Main unit test coverage
- `integration-coverage.txt`: Integration test coverage
- `coverage.html`: HTML report for local viewing

## Best Practices

1. **Focus on Critical Paths**: Prioritize coverage for core event processing, filtering, and detection logic
2. **Test Edge Cases**: Include error handling and boundary conditions
3. **Integration Coverage**: Ensure eBPF + Go interactions are tested
4. **Meaningful Tests**: Aim for tests that verify behavior, not just coverage numbers

## Excluded from Coverage

- Generated files (`*.pb.go`)
- Test files (`*_test.go`)
- Mock files (`mock_*.go`, `*_mock.go`)
- Vendor dependencies (`vendor/`, `3rdparty/`)
- Documentation and build scripts
- Test utilities and test data

## Troubleshooting

### Coverage Not Generated

- Ensure you're running tests with `-coverprofile` flag
- Check that `-covermode=atomic` is set (required for concurrent programs)

### Low Coverage Warnings

- Review which functions/lines are not covered
- Consider if uncovered code represents important paths
- Add tests for critical uncovered functionality

### Codecov Upload Failures

- Verify `CODECOV_TOKEN` is set in repository secrets
- Check that coverage files exist before upload
- Review GitHub Actions logs for specific error messages
