# Unit Test Checklist

Use this checklist when creating or revising unit tests in Tracee.

## Design

- test behavior contracts, not implementation internals
- include at least one failure-path assertion for new logic
- cover boundary values and empty-input scenarios

## Structure

- keep tests close to source in `*_test.go`
- prefer table-driven tests for repeated input/output patterns
- keep test setup minimal and explicit

## Assertions

- use `require` for prerequisites and `assert` for follow-up checks
- make assertion messages explain the expected behavior
- avoid brittle assertions based on unrelated formatting or ordering

## Reliability

- clean up resources with `defer`
- avoid shared mutable state across test cases
- remove sleeps when deterministic synchronization is possible

## Execution

- iterate quickly:
  - `make test-unit PKG=<pkg> TEST=<TestName>`
- verify package:
  - `make test-unit PKG=<pkg>`
- verify full suite before finalizing:
  - `make test-unit`

## Optional Coverage Review

- generate coverage summary:
  - `make coverage`
- generate coverage html report:
  - `make coverage-html`
