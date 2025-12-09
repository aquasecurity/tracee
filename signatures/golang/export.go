package main

import "github.com/aquasecurity/tracee/types/detect"

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures = []detect.Signature{
	&SystemRequestKeyConfigModification{},
	&SyscallTableHooking{},
}

// ExportedDataSources fulfills the goplugins contract required by the rule-engine
// this is a list of data-sources that this plugin exports
var ExportedDataSources = []detect.DataSource{
	// add data-sources here
}
