package main

import "github.com/aquasecurity/tracee/types/detect"

var ExportedSignatures = []detect.Signature{
	// Instrumentation e2e signatures
	&e2eFileModification{},
}
