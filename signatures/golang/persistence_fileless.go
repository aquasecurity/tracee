// SPDX-License-Identifier: MIT
//
// Persistence & Fileless Malware Detection Signatures for Tracee
// Derived from XPAV (https://github.com/JNC4/xpav)
//
// These signatures detect:
// - Persistence mechanisms (cron, SSH keys, systemd, LD_PRELOAD)
// - Fileless malware execution (memfd_create, /dev/shm)
// - Rootkit indicators

package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// Package manager binaries to exclude from persistence alerts
var packageManagerBinaries = []string{
	"dpkg", "apt", "apt-get", "yum", "dnf", "rpm", "pacman",
	"zypper", "emerge", "pkg", "apk",
}

// =============================================================================
// Signature: Cron Job Modification
// =============================================================================

type CronJobModification struct {
	cb detect.SignatureHandler
}

func (sig *CronJobModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *CronJobModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-PERSIST-001",
		Version:     "1.0.0",
		Name:        "Cron Job Modification",
		EventName:   "cron_job_modification",
		Description: "Detects creation or modification of cron jobs, a common persistence mechanism. Attackers use cron jobs to maintain access and re-establish connections.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "persistence",
			"Technique":    "Scheduled Task/Job: Cron",
			"Technique ID": "T1053.003",
			"external_id":  "XPAV-PERSIST-001",
		},
	}, nil
}

func (sig *CronJobModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open"},
		{Source: "tracee", Name: "openat"},
	}, nil
}

func (sig *CronJobModification) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip package managers
	for _, pm := range packageManagerBinaries {
		if strings.EqualFold(ee.ProcessName, pm) {
			return nil
		}
	}

	// Get pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check if it's a cron-related path
	isCronPath := strings.HasPrefix(pathname, "/etc/cron") ||
		strings.HasPrefix(pathname, "/var/spool/cron") ||
		pathname == "/etc/crontab"

	if !isCronPath {
		return nil
	}

	// Check if it's a write operation
	flagsArg, _ := ee.GetArgumentByName("flags", trace.GetArgOps{DefaultArgs: false})
	flags, ok := flagsArg.Value.(string)
	if !ok {
		return nil
	}

	if !strings.Contains(flags, "O_WRONLY") && !strings.Contains(flags, "O_RDWR") &&
		!strings.Contains(flags, "O_CREAT") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"file_path":    pathname,
			"process_name": ee.ProcessName,
			"container_id": ee.Container.ID,
			"severity":     "warning",
		},
	})

	return nil
}

func (sig *CronJobModification) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *CronJobModification) Close() {}

// =============================================================================
// Signature: SSH Authorized Keys Modification
// =============================================================================

type SSHAuthorizedKeysModification struct {
	cb detect.SignatureHandler
}

func (sig *SSHAuthorizedKeysModification) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *SSHAuthorizedKeysModification) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-PERSIST-002",
		Version:     "1.0.0",
		Name:        "SSH Authorized Keys Modification",
		EventName:   "ssh_authorized_keys_modification",
		Description: "Detects modifications to SSH authorized_keys files, which could indicate an attacker establishing persistent SSH access.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "persistence",
			"Technique":    "Account Manipulation: SSH Authorized Keys",
			"Technique ID": "T1098.004",
			"external_id":  "XPAV-PERSIST-002",
		},
	}, nil
}

func (sig *SSHAuthorizedKeysModification) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open"},
		{Source: "tracee", Name: "openat"},
	}, nil
}

func (sig *SSHAuthorizedKeysModification) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip SSH-related processes
	if strings.Contains(ee.ProcessName, "ssh") {
		return nil
	}

	// Get pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check if it's an authorized_keys file
	if !strings.Contains(pathname, "authorized_keys") {
		return nil
	}

	// Check if it's a write operation
	flagsArg, _ := ee.GetArgumentByName("flags", trace.GetArgOps{DefaultArgs: false})
	flags, ok := flagsArg.Value.(string)
	if !ok {
		return nil
	}

	if !strings.Contains(flags, "O_WRONLY") && !strings.Contains(flags, "O_RDWR") &&
		!strings.Contains(flags, "O_CREAT") && !strings.Contains(flags, "O_APPEND") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"file_path":    pathname,
			"process_name": ee.ProcessName,
			"container_id": ee.Container.ID,
			"severity":     "warning",
		},
	})

	return nil
}

func (sig *SSHAuthorizedKeysModification) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *SSHAuthorizedKeysModification) Close() {}

// =============================================================================
// Signature: LD Preload Hijacking
// =============================================================================

type LDPreloadHijacking struct {
	cb detect.SignatureHandler
}

func (sig *LDPreloadHijacking) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *LDPreloadHijacking) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-PERSIST-003",
		Version:     "1.0.0",
		Name:        "LD Preload Hijacking",
		EventName:   "ld_preload_hijacking",
		Description: "Detects modifications to /etc/ld.so.preload, which forces libraries to be loaded into all processes. Commonly used by rootkits and for privilege escalation.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "persistence",
			"Technique":    "Hijack Execution Flow: LD_PRELOAD",
			"Technique ID": "T1574.006",
			"external_id":  "XPAV-PERSIST-003",
		},
	}, nil
}

func (sig *LDPreloadHijacking) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open"},
		{Source: "tracee", Name: "openat"},
	}, nil
}

func (sig *LDPreloadHijacking) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip package managers
	for _, pm := range packageManagerBinaries {
		if strings.EqualFold(ee.ProcessName, pm) {
			return nil
		}
	}

	// Get pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check if it's ld.so.preload or ld.so.conf
	isLdPath := pathname == "/etc/ld.so.preload" ||
		strings.HasPrefix(pathname, "/etc/ld.so.conf")

	if !isLdPath {
		return nil
	}

	// Check if it's a write operation
	flagsArg, _ := ee.GetArgumentByName("flags", trace.GetArgOps{DefaultArgs: false})
	flags, ok := flagsArg.Value.(string)
	if !ok {
		return nil
	}

	if !strings.Contains(flags, "O_WRONLY") && !strings.Contains(flags, "O_RDWR") &&
		!strings.Contains(flags, "O_CREAT") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"file_path":    pathname,
			"process_name": ee.ProcessName,
			"container_id": ee.Container.ID,
			"severity":     "critical",
		},
	})

	return nil
}

func (sig *LDPreloadHijacking) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *LDPreloadHijacking) Close() {}

// =============================================================================
// Signature: Fileless Execution via memfd_create
// =============================================================================

type FilelessMemfdExecution struct {
	cb detect.SignatureHandler
}

func (sig *FilelessMemfdExecution) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *FilelessMemfdExecution) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-FILELESS-001",
		Version:     "1.0.0",
		Name:        "Fileless Execution via memfd_create",
		EventName:   "fileless_memfd_execution",
		Description: "Detects execution of files created via memfd_create, which allows creating anonymous files in memory that can be executed without touching disk. Common technique for fileless malware.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "fileless",
			"Technique":    "Reflective Code Loading",
			"Technique ID": "T1620",
			"external_id":  "XPAV-FILELESS-001",
		},
	}, nil
}

func (sig *FilelessMemfdExecution) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *FilelessMemfdExecution) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check for memfd execution
	if !strings.Contains(pathname, "memfd:") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"exe_path":     pathname,
			"process_name": ee.ProcessName,
			"container_id": ee.Container.ID,
			"severity":     "critical",
		},
	})

	return nil
}

func (sig *FilelessMemfdExecution) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *FilelessMemfdExecution) Close() {}

// =============================================================================
// Signature: Execution from Suspicious Memory Location
// =============================================================================

type SuspiciousMemoryExecution struct {
	cb detect.SignatureHandler
}

func (sig *SuspiciousMemoryExecution) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *SuspiciousMemoryExecution) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-FILELESS-002",
		Version:     "1.0.0",
		Name:        "Execution from Suspicious Memory Location",
		EventName:   "suspicious_memory_execution",
		Description: "Detects process execution from paths typically used for fileless malware such as /dev/shm, /run/shm, or /proc/self/fd.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "fileless",
			"Technique":    "Reflective Code Loading",
			"Technique ID": "T1620",
			"external_id":  "XPAV-FILELESS-002",
		},
	}, nil
}

func (sig *SuspiciousMemoryExecution) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *SuspiciousMemoryExecution) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check for suspicious execution paths
	suspiciousPaths := []string{
		"/dev/shm",
		"/run/shm",
		"/tmp/.X",
		"/proc/self/fd",
	}

	matchedPath := ""
	for _, suspicious := range suspiciousPaths {
		if strings.HasPrefix(pathname, suspicious) {
			matchedPath = suspicious
			break
		}
	}

	if matchedPath == "" {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"exe_path":      pathname,
			"matched_path":  matchedPath,
			"process_name":  ee.ProcessName,
			"container_id":  ee.Container.ID,
			"severity":      "critical",
		},
	})

	return nil
}

func (sig *SuspiciousMemoryExecution) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *SuspiciousMemoryExecution) Close() {}

// =============================================================================
// Signature: Kernel Module from Unusual Location
// =============================================================================

type UnusualKernelModule struct {
	cb detect.SignatureHandler
}

func (sig *UnusualKernelModule) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *UnusualKernelModule) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ROOTKIT-001",
		Version:     "1.0.0",
		Name:        "Kernel Module from Unusual Location",
		EventName:   "unusual_kernel_module",
		Description: "Detects kernel module loading from paths outside the standard module directories. Rootkits often load malicious kernel modules from /tmp or other writable locations.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "rootkit",
			"Technique":    "Boot or Logon Autostart Execution: Kernel Modules",
			"Technique ID": "T1547.006",
			"external_id":  "XPAV-ROOTKIT-001",
		},
	}, nil
}

func (sig *UnusualKernelModule) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "init_module"},
		{Source: "tracee", Name: "finit_module"},
	}, nil
}

func (sig *UnusualKernelModule) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get pathname if available
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		// For init_module, there might not be a pathname
		// Still alert on any kernel module loading by non-standard processes
		if !strings.Contains(ee.ProcessName, "mod") && ee.ProcessName != "kmod" {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"process_name": ee.ProcessName,
					"container_id": ee.Container.ID,
					"severity":     "critical",
				},
			})
		}
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check if module is from standard location
	if strings.HasPrefix(pathname, "/lib/modules") ||
		strings.HasPrefix(pathname, "/usr/lib/modules") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"module_path":  pathname,
			"process_name": ee.ProcessName,
			"container_id": ee.Container.ID,
			"severity":     "critical",
		},
	})

	return nil
}

func (sig *UnusualKernelModule) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *UnusualKernelModule) Close() {}
