package main

import "github.com/aquasecurity/tracee/types/detect"

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures = []detect.Signature{
	// XPAV-derived Cryptominer Detection
	&CryptominerProcess{},
	&MiningPoolArguments{},
	&MiningStratumConnection{},

	// XPAV-derived Container Escape Detection
	&ContainerNamespaceEscape{},
	&CgroupReleaseAgentEscape{},
	&ContainerHostAccess{},
	&PrivilegedDeviceAccess{},
	&ContainerSetns{},
	&ContainerUnshare{},

	// XPAV-derived Web Server Abuse Detection
	&WebServerShellSpawn{},
	&WebServerSuspiciousChild{},
	&WebServerReverseShell{},

	// XPAV-derived Persistence & Fileless Detection
	&CronJobModification{},
	&SSHAuthorizedKeysModification{},
	&LDPreloadHijacking{},
	&FilelessMemfdExecution{},
	&SuspiciousMemoryExecution{},
	&UnusualKernelModule{},
}

// ExportedDataSources fulfills the goplugins contract required by the rule-engine
// this is a list of data-sources that this plugin exports
var ExportedDataSources = []detect.DataSource{
	// add data-sources here
}
