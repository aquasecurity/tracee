// Package e2e contains end-to-end test detectors for validating Tracee functionality.
//
// The e2e detectors are organized into two categories with separate build tags:
//
//   - Network detectors (build tag: e2e_net): Test network packet events
//     like IPv4, IPv6, TCP, UDP, ICMP, DNS, HTTP.
//     Build with: go build -tags e2e_net
//     Registry: registerE2eNet() -> GetE2eNetDetectors()
//
//   - Non-network detectors (build tag: e2e): Test other event types
//     like LSM hooks, BPF attach, VFS operations, file modifications, etc.
//     Build with: go build -tags e2e
//     Registry: registerE2e() -> GetE2eDetectors()
//
// Each detector registers itself via init() using the appropriate register function.
// The registry files (registry_e2e.go and registry_e2e_net.go) maintain separate
// slices for each build tag. The parent detectors package imports these functions
// to register them with the main registry.
package e2e
