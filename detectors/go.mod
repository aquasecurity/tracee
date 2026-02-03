module github.com/aquasecurity/tracee/detectors

go 1.24.0

require (
	github.com/aquasecurity/tracee/api v0.0.0
	github.com/aquasecurity/tracee/common v0.0.0
	github.com/hashicorp/golang-lru/v2 v2.0.7
	github.com/stretchr/testify v1.11.1
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/arch v0.19.0 // indirect
	golang.org/x/exp v0.0.0-20250718183923-645b1fa84792 // indirect
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250218202821-56aae31c358a // indirect
	google.golang.org/grpc v1.72.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/aquasecurity/tracee/api => ../api

replace github.com/aquasecurity/tracee/common => ../common
