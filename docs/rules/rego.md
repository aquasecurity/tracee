Create a `.rego` file in the rules directory that has the following Rego Rules (in this context rules are Rego's language constructs):

1. `__rego_metadoc__`: A *document* rule that defines the rule's metadata (based on [WIP Rego convention](https://hackmd.io/@ZtQnh19kS26YiNlJLqKJnw/H1gAv5nB) for describing policy metadata).
2. `tracee_selected_events`: A *set* rule that defines the event selectors.
3. `tracee_match`: A *boolean* or a *document* rule that defines the logic of the signature. If bool is "returned", a true evaluation will generate a Finding with no data if document is "returned", any non-empty evaluation will generate a Finding with the returned document as the Finding's "Data".

See [example2.rego](https://github.com/aquasecurity/tracee/blob/main/tracee-rules/signatures/rego/examples/example2.rego) and [example1.rego](https://github.com/aquasecurity/tracee/blob/main/tracee-rules/signatures/rego/examples/example1.rego) for example Rego signatures.
