module github.com/aquasecurity/tracee/environment

go 1.22.0

require (
	github.com/aquasecurity/tracee/errfmt v0.0.0-00010101000000-000000000000
	github.com/aquasecurity/tracee/logger v0.0.0-00010101000000-000000000000
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20240604190554-fc45aab8b7f8 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// To be removed in a sequential PR
replace (
	github.com/aquasecurity/tracee/errfmt => ../errfmt
	github.com/aquasecurity/tracee/logger => ../logger
)
