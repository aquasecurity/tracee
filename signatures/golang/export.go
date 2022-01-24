package main

import "github.com/aquasecurity/tracee/types"

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures = []types.Signature{
	&stdioOverSocket{},
	&K8sApiConnection{},
}
