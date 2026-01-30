// SPDX-License-Identifier: MIT
//
// Container Escape Detection Signatures for Tracee
// Derived from XPAV (https://github.com/JNC4/xpav)
//
// These signatures detect container escape attempts through:
// - Namespace manipulation tools (nsenter, unshare)
// - Cgroup release_agent abuse
// - Host filesystem access
// - Privileged device access
// - setns syscall monitoring

package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// Container escape tools
var containerEscapeBinaries = []string{
	"nsenter", "unshare", "chroot", "pivot_root",
}

// Known container runtime processes to exclude
var containerRuntimes = []string{
	"containerd", "containerd-shim", "dockerd", "docker",
	"runc", "crio", "cri-o", "conmon", "podman",
}

// Suspicious host paths when accessed from containers
var hostPaths = []string{
	"/host", "/rootfs", "/hostfs",
}

// Raw block devices
var blockDevices = []string{
	"/dev/sda", "/dev/sdb", "/dev/sdc",
	"/dev/nvme", "/dev/vda", "/dev/vdb",
	"/dev/xvda", "/dev/xvdb",
	"/dev/mem", "/dev/kmem",
}

// =============================================================================
// Signature: Container Escape via Namespace Tools
// =============================================================================

type ContainerNamespaceEscape struct {
	cb detect.SignatureHandler
}

func (sig *ContainerNamespaceEscape) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *ContainerNamespaceEscape) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-001",
		Version:     "1.0.0",
		Name:        "Container Escape via Namespace Tools",
		EventName:   "container_namespace_escape",
		Description: "Detects usage of namespace manipulation tools (nsenter, unshare) within containers, which can be used to escape container isolation by joining host namespaces.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-001",
		},
	}, nil
}

func (sig *ContainerNamespaceEscape) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *ContainerNamespaceEscape) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip if not in a container
	if ee.Container.ID == "" {
		return nil
	}

	processName := ee.ProcessName

	// Skip container runtimes
	for _, runtime := range containerRuntimes {
		if strings.EqualFold(processName, runtime) {
			return nil
		}
	}

	// Check for escape tools
	for _, escapeTool := range containerEscapeBinaries {
		if strings.EqualFold(processName, escapeTool) {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"process_name":   processName,
					"container_id":   ee.Container.ID,
					"container_name": ee.Container.Name,
					"escape_tool":    escapeTool,
					"severity":       "critical",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *ContainerNamespaceEscape) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *ContainerNamespaceEscape) Close() {}

// =============================================================================
// Signature: Cgroup Release Agent Escape
// =============================================================================

type CgroupReleaseAgentEscape struct {
	cb detect.SignatureHandler
}

func (sig *CgroupReleaseAgentEscape) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *CgroupReleaseAgentEscape) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-002",
		Version:     "1.0.0",
		Name:        "Cgroup Release Agent Escape Attempt",
		EventName:   "cgroup_release_agent_escape",
		Description: "Detects writes to cgroup release_agent files from within containers. This technique abuses the cgroup notify_on_release mechanism to execute arbitrary commands on the host.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-002",
		},
	}, nil
}

func (sig *CgroupReleaseAgentEscape) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_file_open"},
		{Source: "tracee", Name: "openat"},
	}, nil
}

func (sig *CgroupReleaseAgentEscape) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip if not in a container
	if ee.Container.ID == "" {
		return nil
	}

	// Get the pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check for release_agent or notify_on_release access
	if strings.Contains(pathname, "release_agent") ||
		strings.Contains(pathname, "notify_on_release") {

		// Check if it's a write operation
		flagsArg, _ := ee.GetArgumentByName("flags", trace.GetArgOps{DefaultArgs: false})
		flags, ok := flagsArg.Value.(string)
		if ok && (strings.Contains(flags, "O_WRONLY") || strings.Contains(flags, "O_RDWR")) {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"file_path":      pathname,
					"container_id":   ee.Container.ID,
					"container_name": ee.Container.Name,
					"process_name":   ee.ProcessName,
					"severity":       "critical",
				},
			})
		}
	}

	return nil
}

func (sig *CgroupReleaseAgentEscape) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *CgroupReleaseAgentEscape) Close() {}

// =============================================================================
// Signature: Container Host Filesystem Access
// =============================================================================

type ContainerHostAccess struct {
	cb detect.SignatureHandler
}

func (sig *ContainerHostAccess) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *ContainerHostAccess) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-003",
		Version:     "1.0.0",
		Name:        "Container Accessing Host Filesystem",
		EventName:   "container_host_access",
		Description: "Detects container processes accessing paths that typically indicate host filesystem access. This may indicate a container escape in progress or a misconfigured volume mount.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-003",
		},
	}, nil
}

func (sig *ContainerHostAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "security_file_open"},
	}, nil
}

func (sig *ContainerHostAccess) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Skip if not in a container
	if ee.Container.ID == "" {
		return nil
	}

	// Skip container runtimes
	for _, runtime := range containerRuntimes {
		if strings.EqualFold(ee.ProcessName, runtime) {
			return nil
		}
	}

	// Get the pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check for host path access
	for _, hostPath := range hostPaths {
		if strings.HasPrefix(pathname, hostPath) {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"file_path":      pathname,
					"container_id":   ee.Container.ID,
					"container_name": ee.Container.Name,
					"process_name":   ee.ProcessName,
					"host_path":      hostPath,
					"severity":       "warning",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *ContainerHostAccess) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *ContainerHostAccess) Close() {}

// =============================================================================
// Signature: Privileged Container Device Access
// =============================================================================

type PrivilegedDeviceAccess struct {
	cb detect.SignatureHandler
}

func (sig *PrivilegedDeviceAccess) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *PrivilegedDeviceAccess) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-004",
		Version:     "1.0.0",
		Name:        "Privileged Container Device Access",
		EventName:   "privileged_device_access",
		Description: "Detects container processes accessing raw block devices, which could be used to escape container isolation by directly accessing host storage.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-004",
		},
	}, nil
}

func (sig *PrivilegedDeviceAccess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "openat"},
		{Source: "tracee", Name: "security_file_open"},
	}, nil
}

func (sig *PrivilegedDeviceAccess) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Only check containers
	if ee.Container.ID == "" {
		return nil
	}

	// Get the pathname
	pathnameArg, err := ee.GetArgumentByName("pathname", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	pathname, ok := pathnameArg.Value.(string)
	if !ok {
		return nil
	}

	// Check for block device access
	for _, device := range blockDevices {
		if strings.HasPrefix(pathname, device) {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"device_path":    pathname,
					"container_id":   ee.Container.ID,
					"container_name": ee.Container.Name,
					"process_name":   ee.ProcessName,
					"severity":       "critical",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *PrivilegedDeviceAccess) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *PrivilegedDeviceAccess) Close() {}

// =============================================================================
// Signature: setns Syscall from Container
// =============================================================================

type ContainerSetns struct {
	cb detect.SignatureHandler
}

func (sig *ContainerSetns) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *ContainerSetns) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-005",
		Version:     "1.0.0",
		Name:        "setns Syscall from Container",
		EventName:   "container_setns",
		Description: "Detects setns syscall usage from within containers. setns allows a process to join an existing namespace and is a key primitive for container escapes.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-005",
		},
	}, nil
}

func (sig *ContainerSetns) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "setns"},
	}, nil
}

func (sig *ContainerSetns) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Only check containers
	if ee.Container.ID == "" {
		return nil
	}

	// Skip container runtimes
	for _, runtime := range containerRuntimes {
		if strings.EqualFold(ee.ProcessName, runtime) {
			return nil
		}
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"container_id":   ee.Container.ID,
			"container_name": ee.Container.Name,
			"process_name":   ee.ProcessName,
			"severity":       "warning",
		},
	})

	return nil
}

func (sig *ContainerSetns) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *ContainerSetns) Close() {}

// =============================================================================
// Signature: unshare Syscall from Container
// =============================================================================

type ContainerUnshare struct {
	cb detect.SignatureHandler
}

func (sig *ContainerUnshare) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *ContainerUnshare) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-ESCAPE-006",
		Version:     "1.0.0",
		Name:        "unshare Syscall from Container",
		EventName:   "container_unshare",
		Description: "Detects unshare syscall from within containers. unshare creates new namespaces and can be used as part of container escape techniques.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "container_escape",
			"Technique":    "Escape to Host",
			"Technique ID": "T1611",
			"external_id":  "XPAV-ESCAPE-006",
		},
	}, nil
}

func (sig *ContainerUnshare) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "unshare"},
	}, nil
}

func (sig *ContainerUnshare) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Only check containers
	if ee.Container.ID == "" {
		return nil
	}

	// Skip container runtimes
	for _, runtime := range containerRuntimes {
		if strings.EqualFold(ee.ProcessName, runtime) {
			return nil
		}
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"container_id":   ee.Container.ID,
			"container_name": ee.Container.Name,
			"process_name":   ee.ProcessName,
			"severity":       "warning",
		},
	})

	return nil
}

func (sig *ContainerUnshare) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *ContainerUnshare) Close() {}
