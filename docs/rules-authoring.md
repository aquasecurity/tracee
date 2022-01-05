# Authoring Rules
Tracee supports authoring rules in Golang) or in Rego (the language of [Open Policy Agent]).

## Rego Rules

Create a `.rego` file in the rules directory that has the following Rego Rules (in this context rules are Rego's language constructs):

1. `__rego_metadoc__`: A *document* rule that defines the rule's metadata.
2. `tracee_selected_events`: A *set* rule that defines the event selectors.
3. `tracee_match`: A *boolean* or a *document* rule that defines the logic of the signature. If bool is "returned", a true evaluation will generate a Finding with no data. If a document is "returned", any non-empty evaluation will generate a Finding with the returned document as the Finding's "Data".

See [tracee/signatures/rego] for example Rego signatures.

## Golang Rules

Tracee exports a `Signature` interface that you can implement. We use [Go Plugins] to load Go signatures.

1. Create a new Go project with a package `main`.
2. Import `github.com/aquasecurity/tracee/tracee-rules/types` and implement the `types.Signature` interface.
3. Export a package level variable called `ExportedSignatures` of type `[]types.Signature` that declares the implemented signature (or more) that your package exports.
4. Compile using goplugins `go build -buildmode=plugin -o yourplugin.so yoursource.go`.
5. Place the resulting compiled file in the rules directory, and it will be automatically discovered by Tracee.

See [tracee/signatures/golang/examples] for example Go signatures.

[Open Policy Agent]: https://github.com/open-policy-agent/opa/
[Go Plugins]: https://golang.org/pkg/plugin/
[tracee/signatures/rego]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/signatures/rego
[tracee/signatures/golang/examples]: https://github.com/aquasecurity/tracee/tree/{{ git.tag }}/signatures/golang/examples
