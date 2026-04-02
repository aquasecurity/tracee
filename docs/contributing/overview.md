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
3. **Issue Labels:**

    - `area/...` (e.g., `ebpf`, `events`): Area of Tracee affected.
    - `kind/...` (e.g., `bug`, `feature`, `documentation`): Type of issue or pull request.
    - `priority/...`: Urgency of the issue.
    - `milestone/...` (e.g., `milestone/v0.x.y`): Target release; add when you want the item considered for a specific version (issues and pull requests).
    - `good-first-issue`: Suitable for first-time contributors.

4. **Issue Assignment:** Self-assign issues or request assignment. Don't work on an issue assigned to someone else without their consent.

## Submitting Changes

External contributors must fork the repository and submit changes as pull
requests from their fork. Branch creation in this repository is restricted.

## Pull Requests

1. Every Pull Request should have an associated Issue unless it is a trivial fix.
2. When adding a flag option or other UX related change, make sure the design is explicitly described in the associated issue, and a maintainer approved it.
3. Pull requests require all review threads resolved and at least one approving
   review. When the change touches code-owner areas, at least two approving
   reviews are required.
4. Code related information should be in the commit message, review related information should be in the PR description.
5. For changes that span different areas please try to make each change self contained and independent.

## Commits

All commits must be **signed** (GPG, SSH, or S/MIME). See
[GitHub's signing guide](https://docs.github.com/en/authentication/managing-commit-signature-verification)
to set up commit signing.

Commit messages must follow the
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
specification:

```
type(optional scope): description

optional body
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `revert`.

The commit subject should be max 50 characters, written in imperative mood.
The optional body (separated by an empty line) may explain **why** the change
was made. Wrap at 72 characters.

### Breaking Changes

Breaking changes must include `!` after the type/scope and a `BREAKING CHANGE`
footer in the commit body explaining what changed:

```
feat(ebpf)!: remove deprecated event field

BREAKING CHANGE: The `oldField` field has been removed from the
`anti_debugging` event. Use `newField` instead.
```

The `BREAKING CHANGE` footer is required so that the change is clearly
documented for downstream users and automated tooling.

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

**Common Development Tasks:**
```bash
# Development builds
make tracee                # Build the main tracee binary
make bpf                   # Build just the eBPF object
make all                   # Build all components

# Testing
make test-unit             # Run unit tests with coverage
make test-integration      # Run integration tests

# Performance and stress testing
make evt                   # Build the event generator tool
make evt-trigger-runner    # Build stress testing container
```

For detailed information about code quality checks, dependencies, and troubleshooting, see our [Code Quality Guide](checkpatch.md).

For performance testing and stress testing with the `evt` tool, see [evt - Event Generator and Stress Testing Tool](evt-tool.md).

For complete build options and development environment setup, run `make help` or see [Building Documentation](building/building.md).

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
