---
name: tracee-testing-guide
description: Run Tracee tests correctly, especially BPF unit tests via make targets. Use when writing tests, debugging test failures, or validating changes before commit.
---

# Tracee Testing Guide

## Critical Rule

For BPF-related unit tests, do not run `go test` directly.
Use `make test-unit` so the required BPF environment is configured.

## When To Use This Skill

Use this skill when:
- creating new unit tests for changed behavior
- revising existing `*_test.go` files after refactors
- fixing flaky tests or false assumptions in assertions
- tightening coverage for bug fixes

## Fast Development Commands

- All unit tests: `make test-unit`
- Package-only: `make test-unit PKG=pkg/detectors`
- Function-only: `make test-unit TEST=TestKernelVersionRequirement_Basic`
- Function in package: `make test-unit PKG=pkg/ebpf/probes TEST=TestProbeCompatibility_Basic`

## Other Test Suites

- Integration tests: `make test-integration` (root required)
- E2E tests: `make test-e2e`, `make test-e2e-net`, `make test-e2e-kernel` (root required)
- Coverage: `make coverage`, `make coverage-html`

## Troubleshooting

- `fatal error: bpf/bpf.h: No such file or directory`
  - Use `make test-unit` instead of direct `go test`.
- Slow runs
  - Use `PKG=` and `TEST=` during iteration.
- Integration or E2E failures
  - Verify root privileges and kernel eBPF support.

## Test Authoring Notes

- Use `testify/assert` and `testify/require`.
- Keep test files near source (`*_test.go`).
- Prefer explicit cleanup with `defer`.
- Maintain or improve coverage for changed code.

## Unit Test Creation Workflow

1. Identify the behavior contract and edge cases from changed code.
2. Add focused test cases first for success path, then error path.
3. Use table-driven tests when only inputs/expected outputs vary.
4. Keep each test name descriptive and behavior-based.
5. Run targeted command first:
   - `make test-unit PKG=<pkg> TEST=<TestName>`
6. Run package-wide tests:
   - `make test-unit PKG=<pkg>`
7. Before finishing, run broader validation:
   - `make test-unit`

## Unit Test Revision Workflow

When updating existing tests:
- prefer fixing test intent instead of copying implementation details
- remove stale assertions tied to old behavior
- keep failure messages explicit so regressions are easy to diagnose
- check cleanup paths and goroutine/resource lifecycle assumptions

## Flaky Test Triage Checklist

- verify timing assumptions (timeouts, retries, async ordering)
- avoid shared mutable global state across tests
- isolate test inputs from environment-dependent behavior
- run the test repeatedly with:
  - `make test-unit PKG=<pkg> TEST=<TestName>`

## Additional Reference

For a concise checklist to apply during unit test creation and review, see
[unit-test-checklist.md](unit-test-checklist.md).
