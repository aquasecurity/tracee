## Contributing

Thank you for taking interest in contributing to Tracee! This document covers our working practices and conventions.

## Issues and Discussions

We encourage open discussion and collaboration using both GitHub Issues and Discussions.  

- [Discussions](https://github.com/aquasecurity/tracee/discussions) are free-style conversational tool, we use them for conversations.
- [Issues](https://github.com/aquasecurity/tracee/issues) are project management tool, we use them to keep track on who's working on what and plan ahead.

If you have a suggestion, question, or a general comment - please use Discussions. If there's a clear work item (including bugs) - you can open an Issue.

### Discussions:

- We have the following discussion topics: 
    1. [Announcements](https://github.com/aquasecurity/tracee/discussions/categories/announcements): One way communication from the team to the community. Consider this like our mini blog
    1. [Questions and Help](https://github.com/aquasecurity/tracee/discussions/categories/questions-and-help): For help and support. Consider this similar to StackOverflow.
    1. [Development](https://github.com/aquasecurity/tracee/discussions/categories/development): For discussing potential features, and collaborating on their design.

### Issues:

1. Every issue needs to be actionable and assignable. Consider the scope of the issue if assigned to one person, and break down if necessary.
1. Be clear and definitive when composing issues. For bug reports, include detailed error messages and environment description. For features, include a clear scope and acceptance criteria.
1. Since we have different projects under the same monorepo, use labels to denote areas that the issue relates to:
    1. `tracee`
    1. `tracee-ebpf`
    1. `tracee-rules`
    1. `signatures`
    1.  If non of the labels is relevant don't add any (usually for top-level issues)
1. We use the following labels to describe the type of issue:
    1. `bug`
    1. `good-first-issue`
1. Self-assign or request assignment for issues you intend to work on. Don't work on an issue assigned to someone else without checking with them first and reassigning.

## Pull Requests

1. Every Pull Request should have an associated Issue unless it is a trivial fix.
1. When adding a flag option or other UX related change, make sure the design is explicitly described in the associated issue, and a maintainer approved it.
1. Commit subject should succinctly describe the change:
    1. Max 50 chars.
    1. Written in imperative mood: begin with a verb like "fix", "add", "improve", or "refactor"; Think "once applied, this commit will...".
    1. If ambiguous, mention the area that this commit affects (see area labels above).
1. Optional commit body (separated by empty line from subject) may explain why the change was made and not how. Wrap at 72 chars.
1. Code related information should be in commit message, review related information should be in PR description.
1. For changes that span different areas please try to make each change self contained and independent.


## Code

1. Follow Golang's code review standards: https://github.com/golang/go/wiki/CodeReviewComments.
1. Follow `gofmt` + `govet` + `goimports` formatting.
1. Tests should be included alongside code changes wherever applicable, except for parts that are harder to test and are not currently tested (e.g. eBPF). When modifying already tested code, your changes must be represented in the existing tests.
