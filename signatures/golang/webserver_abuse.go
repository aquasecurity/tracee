// SPDX-License-Identifier: MIT
//
// Web Server Abuse Detection Signatures for Tracee
// Derived from XPAV (https://github.com/JNC4/xpav)
//
// These signatures detect webshell and web server exploitation through:
// - Web server spawning shells
// - Suspicious child processes from web servers
// - Reverse shell patterns

package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// Web server process names
var webServerBinaries = []string{
	"nginx", "httpd", "apache", "apache2", "lighttpd",
	"php-fpm", "php", "php-cgi", "php7", "php8",
	"gunicorn", "uwsgi", "tomcat", "java",
}

// Shell binaries
var shellBinaries = []string{
	"sh", "bash", "dash", "zsh", "ash", "ksh", "csh", "tcsh",
}

// Suspicious child processes for web servers
var suspiciousWebChildren = []string{
	"curl", "wget", "nc", "ncat", "netcat", "socat",
	"python", "python3", "perl", "ruby", "php",
	"nmap", "id", "whoami", "uname", "cat", "base64",
	"chmod", "chown", "useradd", "passwd",
}

// Reverse shell patterns in command lines
var reverseShellPatterns = []string{
	"/dev/tcp/",
	"nc -e",
	"ncat -e",
	"bash -i",
	"python -c 'import socket",
	"python3 -c 'import socket",
	"perl -e 'use Socket",
	"ruby -rsocket",
	"mkfifo",
	"exec 5<>/dev/tcp",
	"0<&196",
	"/bin/sh -i",
}

// =============================================================================
// Helper function to check if process is descendant of web server
// =============================================================================

func isDescendantOfWebServer(event trace.Event) bool {
	// Check parent process name
	parentName := event.Ancestor.ProcessName
	if parentName == "" {
		return false
	}

	for _, webServer := range webServerBinaries {
		if strings.EqualFold(parentName, webServer) ||
			strings.Contains(strings.ToLower(parentName), webServer) {
			return true
		}
	}

	return false
}

// =============================================================================
// Signature: Web Server Spawned Shell
// =============================================================================

type WebServerShellSpawn struct {
	cb detect.SignatureHandler
}

func (sig *WebServerShellSpawn) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *WebServerShellSpawn) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-WEB-001",
		Version:     "1.0.0",
		Name:        "Web Server Spawned Shell",
		EventName:   "webserver_shell_spawn",
		Description: "Detects a web server process spawning an interactive shell. This is a strong indicator of webshell exploitation or remote code execution vulnerability.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "webshell",
			"Technique":    "Server Software Component: Web Shell",
			"Technique ID": "T1505.003",
			"external_id":  "XPAV-WEB-001",
		},
	}, nil
}

func (sig *WebServerShellSpawn) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *WebServerShellSpawn) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	processName := ee.ProcessName

	// Check if this is a shell
	isShell := false
	for _, shell := range shellBinaries {
		if strings.EqualFold(processName, shell) {
			isShell = true
			break
		}
	}

	if !isShell {
		return nil
	}

	// Check if parent is a web server
	if !isDescendantOfWebServer(ee) {
		return nil
	}

	// Get command line for context
	cmdline := ""
	argvArg, err := ee.GetArgumentByName("argv", trace.GetArgOps{DefaultArgs: false})
	if err == nil {
		if argv, ok := argvArg.Value.([]string); ok {
			cmdline = strings.Join(argv, " ")
		}
	}

	// Skip simple shell wrappers (health checks, etc.)
	if strings.Contains(cmdline, "healthcheck") ||
		strings.Contains(cmdline, "/usr/bin/env") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"shell":          processName,
			"parent_process": ee.Ancestor.ProcessName,
			"cmdline":        cmdline,
			"container_id":   ee.Container.ID,
			"severity":       "critical",
		},
	})

	return nil
}

func (sig *WebServerShellSpawn) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *WebServerShellSpawn) Close() {}

// =============================================================================
// Signature: Web Server Suspicious Child
// =============================================================================

type WebServerSuspiciousChild struct {
	cb detect.SignatureHandler
}

func (sig *WebServerSuspiciousChild) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *WebServerSuspiciousChild) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-WEB-002",
		Version:     "1.0.0",
		Name:        "Web Server Spawned Suspicious Child",
		EventName:   "webserver_suspicious_child",
		Description: "Detects web server processes spawning suspicious child processes like curl, wget, netcat, or scripting interpreters. These often indicate exploitation of web application vulnerabilities.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "webshell",
			"Technique":    "Command and Scripting Interpreter",
			"Technique ID": "T1059",
			"external_id":  "XPAV-WEB-002",
		},
	}, nil
}

func (sig *WebServerSuspiciousChild) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *WebServerSuspiciousChild) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	processName := ee.ProcessName

	// Skip if it's a shell (handled by WebServerShellSpawn)
	for _, shell := range shellBinaries {
		if strings.EqualFold(processName, shell) {
			return nil
		}
	}

	// Check if this is a suspicious child process
	isSuspicious := false
	for _, suspicious := range suspiciousWebChildren {
		if strings.EqualFold(processName, suspicious) {
			isSuspicious = true
			break
		}
	}

	if !isSuspicious {
		return nil
	}

	// Check if parent is a web server
	if !isDescendantOfWebServer(ee) {
		return nil
	}

	// Get command line for context
	cmdline := ""
	argvArg, err := ee.GetArgumentByName("argv", trace.GetArgOps{DefaultArgs: false})
	if err == nil {
		if argv, ok := argvArg.Value.([]string); ok {
			cmdline = strings.Join(argv, " ")
		}
	}

	// Skip health checks
	if strings.Contains(cmdline, "healthcheck") ||
		strings.Contains(cmdline, "status") {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"process_name":   processName,
			"parent_process": ee.Ancestor.ProcessName,
			"cmdline":        cmdline,
			"container_id":   ee.Container.ID,
			"severity":       "warning",
		},
	})

	return nil
}

func (sig *WebServerSuspiciousChild) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *WebServerSuspiciousChild) Close() {}

// =============================================================================
// Signature: Reverse Shell from Web Server
// =============================================================================

type WebServerReverseShell struct {
	cb detect.SignatureHandler
}

func (sig *WebServerReverseShell) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *WebServerReverseShell) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-WEB-003",
		Version:     "1.0.0",
		Name:        "Reverse Shell from Web Server",
		EventName:   "webserver_reverse_shell",
		Description: "Detects common reverse shell patterns spawned from web server processes. Attackers frequently establish reverse shells after exploiting web vulnerabilities to maintain interactive access.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "webshell",
			"Technique":    "Command and Scripting Interpreter",
			"Technique ID": "T1059",
			"external_id":  "XPAV-WEB-003",
		},
	}, nil
}

func (sig *WebServerReverseShell) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *WebServerReverseShell) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Check if parent is a web server
	if !isDescendantOfWebServer(ee) {
		return nil
	}

	// Get command line
	argvArg, err := ee.GetArgumentByName("argv", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	argv, ok := argvArg.Value.([]string)
	if !ok {
		return nil
	}

	cmdline := strings.Join(argv, " ")
	cmdlineLower := strings.ToLower(cmdline)

	// Check for reverse shell patterns
	matchedPattern := ""
	for _, pattern := range reverseShellPatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			matchedPattern = pattern
			break
		}
	}

	if matchedPattern == "" {
		return nil
	}

	metadata, _ := sig.GetMetadata()
	sig.cb(&detect.Finding{
		Event:       event,
		SigMetadata: metadata,
		Data: map[string]interface{}{
			"process_name":    ee.ProcessName,
			"parent_process":  ee.Ancestor.ProcessName,
			"cmdline":         cmdline,
			"matched_pattern": matchedPattern,
			"container_id":    ee.Container.ID,
			"severity":        "critical",
		},
	})

	return nil
}

func (sig *WebServerReverseShell) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *WebServerReverseShell) Close() {}
