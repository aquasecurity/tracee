module github.com/aquasecurity/tracee/detectors

go 1.24

require github.com/aquasecurity/tracee/api v0.0.0

require (
	golang.org/x/net v0.38.0 // indirect
	golang.org/x/sys v0.31.0 // indirect
	golang.org/x/text v0.23.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250218202821-56aae31c358a // indirect
	google.golang.org/grpc v1.72.0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

replace github.com/aquasecurity/tracee/api => ../api
