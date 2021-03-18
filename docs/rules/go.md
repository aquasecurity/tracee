Tracee-Rules exports a `Signature` interface that you can implement. We use [Go Plugins](https://golang.org/pkg/plugin/) to load Go signatures.  

1. Create a new Go project with a package `main`
2. Import `github.com/aquasecurity/tracee/tracee-rules/types` and implement the `types.Signature` interface.
3. Export a package level variable called `ExportedSignatures` of type `[]types.Signature` that declares the implemented signature (or more) that your package exports.
4. Compile using goplugins `go build -buildmode=plugin -o yourplugin.so yoursource.go`.
5. Place the resulting compiled file in the rules directory and it will be automatically discovered by Tracee-Rules.

See [example.go](https://github.com/aquasecurity/tracee/blob/main/tracee-rules/signatures/golang/examples/example.go) for example Go signatures.
