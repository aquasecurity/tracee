// SPDX-License-Identifier: MIT
//
// Cryptominer Detection Signatures for Tracee
// Derived from XPAV (https://github.com/JNC4/xpav)
//
// These signatures detect cryptocurrency mining activity through:
// - Known miner binary execution
// - Stratum protocol arguments
// - Mining pool connections

package main

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// Known cryptominer binary names
var minerBinaries = []string{
	"xmrig", "xmr-stak", "minerd", "minergate", "cpuminer", "ccminer",
	"ethminer", "cgminer", "bfgminer", "sgminer", "claymore", "nbminer",
	"t-rex", "gminer", "lolminer", "phoenixminer", "teamredminer",
	"nanominer", "bminer", "wildrig", "srbminer",
}

// Mining stratum ports
var stratumPorts = []string{
	"3333", "4444", "5555", "7777", "8888", "9999",
	"14433", "14444", "45560", "45700",
}

// Mining-related argument patterns
var miningArgPatterns = []string{
	"stratum+tcp://",
	"stratum+ssl://",
	"stratum://",
	"--donate-level",
	"--cpu-priority",
	"-o pool.",
	"-o stratum",
	"--algo=",
	"--coin=",
	"-a randomx",
	"-a cryptonight",
}

// =============================================================================
// Signature: Known Cryptominer Process
// =============================================================================

type CryptominerProcess struct {
	cb detect.SignatureHandler
}

func (sig *CryptominerProcess) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *CryptominerProcess) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-MINER-001",
		Version:     "1.0.0",
		Name:        "Cryptominer Process Detected",
		EventName:   "cryptominer_process",
		Description: "Detects execution of known cryptocurrency mining software. Cryptominers are commonly deployed by attackers after gaining initial access to monetize compromised systems.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "cryptominer",
			"Technique":    "Resource Hijacking",
			"Technique ID": "T1496",
			"external_id":  "XPAV-MINER-001",
		},
	}, nil
}

func (sig *CryptominerProcess) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *CryptominerProcess) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get the process name from comm or extract from pathname
	processName := ee.ProcessName

	// Check if process name matches known miners
	for _, miner := range minerBinaries {
		if strings.EqualFold(processName, miner) ||
			strings.Contains(strings.ToLower(processName), miner) {

			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"process_name": processName,
					"miner_match":  miner,
					"severity":     "critical",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *CryptominerProcess) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *CryptominerProcess) Close() {}

// =============================================================================
// Signature: Mining Pool Arguments
// =============================================================================

type MiningPoolArguments struct {
	cb detect.SignatureHandler
}

func (sig *MiningPoolArguments) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *MiningPoolArguments) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-MINER-002",
		Version:     "1.0.0",
		Name:        "Mining Pool Arguments Detected",
		EventName:   "mining_pool_arguments",
		Description: "Detects processes with command line arguments containing stratum protocol URLs or mining pool configuration patterns. Attackers often hide miners by renaming binaries, but the stratum:// protocol in arguments reveals mining activity.",
		Properties: map[string]interface{}{
			"Severity":     "critical",
			"Category":     "cryptominer",
			"Technique":    "Resource Hijacking",
			"Technique ID": "T1496",
			"external_id":  "XPAV-MINER-002",
		},
	}, nil
}

func (sig *MiningPoolArguments) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "execve"},
		{Source: "tracee", Name: "execveat"},
	}, nil
}

func (sig *MiningPoolArguments) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get argv arguments
	argvArg, err := ee.GetArgumentByName("argv", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil // No argv, skip
	}

	argv, ok := argvArg.Value.([]string)
	if !ok {
		return nil
	}

	cmdline := strings.Join(argv, " ")
	cmdlineLower := strings.ToLower(cmdline)

	// Check for mining argument patterns
	for _, pattern := range miningArgPatterns {
		if strings.Contains(cmdlineLower, strings.ToLower(pattern)) {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"cmdline":         cmdline,
					"matched_pattern": pattern,
					"process_name":    ee.ProcessName,
					"severity":        "critical",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *MiningPoolArguments) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *MiningPoolArguments) Close() {}

// =============================================================================
// Signature: Mining Stratum Port Connection
// =============================================================================

type MiningStratumConnection struct {
	cb detect.SignatureHandler
}

func (sig *MiningStratumConnection) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback
	return nil
}

func (sig *MiningStratumConnection) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
		ID:          "XPAV-MINER-003",
		Version:     "1.0.0",
		Name:        "Mining Stratum Port Connection",
		EventName:   "mining_stratum_connection",
		Description: "Detects outbound network connections to common cryptocurrency mining stratum ports. Mining pools use specific ports for the stratum protocol.",
		Properties: map[string]interface{}{
			"Severity":     "warning",
			"Category":     "cryptominer",
			"Technique":    "Resource Hijacking",
			"Technique ID": "T1496",
			"external_id":  "XPAV-MINER-003",
		},
	}, nil
}

func (sig *MiningStratumConnection) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "security_socket_connect"},
	}, nil
}

func (sig *MiningStratumConnection) OnEvent(event protocol.Event) error {
	ee, ok := event.Payload.(trace.Event)
	if !ok {
		return fmt.Errorf("failed to cast event payload")
	}

	// Get remote address info
	remoteAddrArg, err := ee.GetArgumentByName("remote_addr", trace.GetArgOps{DefaultArgs: false})
	if err != nil {
		return nil
	}

	remoteAddr, ok := remoteAddrArg.Value.(map[string]string)
	if !ok {
		return nil
	}

	port := remoteAddr["port"]

	// Check if connecting to stratum port
	for _, stratumPort := range stratumPorts {
		if port == stratumPort {
			metadata, _ := sig.GetMetadata()
			sig.cb(&detect.Finding{
				Event:       event,
				SigMetadata: metadata,
				Data: map[string]interface{}{
					"dest_ip":      remoteAddr["ip"],
					"dest_port":    port,
					"process_name": ee.ProcessName,
					"severity":     "warning",
				},
			})
			return nil
		}
	}

	return nil
}

func (sig *MiningStratumConnection) OnSignal(s detect.Signal) error {
	return nil
}

func (sig *MiningStratumConnection) Close() {}
