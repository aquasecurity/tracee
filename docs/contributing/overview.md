# Contributing

Thank you for taking interest in contributing to Tracee! This document covers our working practices and conventions.

## Issues and Discussions

We encourage open discussion and collaboration using both GitHub Issues and Discussions.  

- [Discussions](https://github.com/aquasecurity/tracee/discussions) are a free-style conversational tool.
- [Issues](https://github.com/aquasecurity/tracee/issues) are a project management tool, we use them to keep track of who's working on what and plan ahead.

If you have a suggestion, question, or a general comment - please use Discussions. If there's a clear work item (including bugs) - you can open an Issue.

## Discussions

- We have the following discussion topics:
    1. [Announcements](https://github.com/aquasecurity/tracee/discussions/categories/announcements): One way communication from the team to the community. Consider this like our mini blog.
    1. [Questions and Help](https://github.com/aquasecurity/tracee/discussions/categories/questions-and-help): For help and support. Consider this similar to StackOverflow.
    1. [Development](https://github.com/aquasecurity/tracee/discussions/categories/development): For discussing potential features, and collaborating on their design.

## Issues

1. **Actionable and Assignable:** Every issue must be clear, actionable, and assignable to a specific person.  Break down large issues into smaller, more manageable tasks.
2. **Clear and Definitive Descriptions:** Be precise in your issue descriptions:
    - **Bug Reports:** Include the following:
        - Detailed steps to reproduce the bug.
        - The complete error message.
        - Your operating system, Tracee version, and any other relevant environment details.
    - **Feature Requests:** Define:
        - A clear scope for the feature.
        - Specific acceptance criteria that will be used to determine if the feature is complete.
3. **Issue Labels:** We use these labels to categorize and track issues:
    - `area/...` (e.g., `ebpf`, `events`): Specifies the area of Tracee affected by the issue.
    - `kind/...` (e.g., `bug`, `chore`, `enhancement`, `documentation`): Indicates the type of issue.
    - `milestone/...`: Specifies the target release for the issue.
    - `priority/...`:  Indicates the urgency of the issue.
    - `good-first-issue`:  Marks issues suitable for first-time contributors.
    - `backport`: Applies to PRs targeting release branches for integrating changes from `main`. The original `main` PR gets labeled `backported/vX.X.X` after merge.
    - `cherry-pick`: Similar to `backport`, but for specific commits. The original `main` PR gets labeled `cherry-picked/vX.X.X` after merge.
    - `candidate/...`: (e.g., `candidate/v0.1.2`)  Identifies PRs in the `main` branch as candidates for backporting or cherry-picking to a release branch (e.g., `v0.1.2`). The specific method will be determined during the porting process.
    - `backported/...` (e.g., `backported/v0.1.2`): Marks PRs in the `main` branch as the basis for backporting changes to a release branch (e.g., `v0.1.2`) after the porting process.
    - `cherry-picked/...` (e.g., `cherry-picked/v0.1.2`): Marks PRs in the `main` branch as the basis for cherry-picking commits to a release branch (e.g., `v0.1.2`) after the porting process.
4. **Issue Assignment:** Self-assign issues or request assignment. Don't work on an issue assigned to someone else without their consent.

**Backporting and Cherry-Picking Workflow:**

To backport or cherry-pick a change:

1. Create a new PR targeting the appropriate release branch.
2. Label the new PR with `backport` or `cherry-pick`, depending on the method used.
3. Once the new PR is merged, remove the `candidate/vX.X.X` label from the original PR in `main`.
4. Finally, add the `backported/vX.X.X` or `cherry-picked/vX.X.X` label to the original PR in `main`, as appropriate.

## Pull Requests

1. Every Pull Request should have an associated Issue unless it is a trivial fix.
2. When adding a flag option or other UX related change, make sure the design is explicitly described in the associated issue, and a maintainer approved it.
3. Commit subject should succinctly describe the change:
    1. Max 50 chars.
    2. Written in imperative mood: begin with a verb like "fix", "add", "improve", or "refactor"; Think "once applied, this commit will...".
    3. If ambiguous, mention the area that this commit affects (see area labels above).
4. Optional commit body (separated by empty line from subject) may explain why the change was made and not how. Wrap at 72 chars.
5. Code related information should be in commit message, review related information should be in PR description.
6. For changes that span different areas please try to make each change self contained and independent.

## Development and Testing

### Development Images

For testing the latest changes without building from source, Tracee provides daily development images:

```bash
# Get the latest development build
docker pull aquasec/tracee:dev

# Test your changes quickly
docker run --rm -it --pid=host --privileged aquasec/tracee:dev --version
```

Development images are built daily from the `main` branch and include the latest features and fixes. See [Building Documentation](building/building.md#development-images) for complete details.

### Development Workflows

Tracee provides several `make` targets to streamline development:

```bash
# Quick development checks before committing
make check-pr              # Run all code quality checks for PR submission
make format-pr             # Show what formatting changes are needed
make fix-fmt               # Automatically fix code formatting

# Testing workflows
make test-unit             # Run unit tests with coverage
make test-types            # Run tests for the types module
make test-common           # Run tests for the common module
make test-integration      # Run integration tests

# Development builds
make all                   # Build all components (tracee-ebpf, tracee-rules, signatures)
make tracee                # Build the main tracee binary
make bpf                   # Build just the eBPF object

# Code analysis and debugging
make bear                  # Generate compile_commands.json for IDE integration
DEBUG=1 make              # Build with debug symbols
METRICS=1 make            # Build with BPF metrics enabled
```

**Quick Start for Development:**
```bash
# 1. Check your environment
make env

# 2. Build everything
make all

# 3. Run tests
make test-unit

# 4. Check code quality before submitting PR
make check-pr
```

For a complete list of available targets, run `make help`.

## Code

1. Follow Golang's code review standards: [https://github.com/golang/go/wiki/CodeReviewComments](https://github.com/golang/go/wiki/CodeReviewComments)
2. Follow `gofmt` + `govet` + `goimports` formatting.
3. Tests should be included alongside code changes wherever applicable, except for parts that are harder to test and are not currently tested (e.g. eBPF). When modifying already tested code, your changes must be represented in the existing tests.

## Contributing Code

### Adding New Event Tracing

If you're looking to add new event tracing capabilities to Tracee, see our comprehensive guide: [Adding New Event Tracing](adding-events.md).

This guide covers:
- Event definition in Go code
- eBPF probe configuration
- Implementation patterns and best practices
- Testing and troubleshooting
