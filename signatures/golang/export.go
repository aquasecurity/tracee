package main

import "github.com/aquasecurity/tracee/types/detect"

// ExportedSignatures fulfills the goplugins contract required by the rule-engine
// this is a list of signatures that this plugin exports
var ExportedSignatures = []detect.Signature{
	&StdioOverSocket{},
	&K8sApiConnection{},
	&ProcMemCodeInjection{},
	&DockerAbuse{},
	&ScheduledTaskModification{},
	&LdPreload{},
	&SudoersModification{},
	&SchedDebugRecon{},
	&SystemRequestKeyConfigModification{},
	&RcdModification{},
	&ProcMemAccess{},
	&PtraceCodeInjection{},
	&ProcessVmWriteCodeInjection{},
	&DiskMount{},
	&DynamicCodeLoading{},
	&FilelessExecution{},
	&IllegitimateShell{},
	&KernelModuleLoading{},
	&KubernetesCertificateTheftAttempt{},
	&ProcFopsHooking{},
	&SyscallTableHooking{},
	&DroppedExecutable{},
}

// ExportedDataSources fulfills the goplugins contract required by the rule-engine
// this is a list of data-sources that this plugin exports
var ExportedDataSources = []detect.DataSource{
	// add data-sources here
}
