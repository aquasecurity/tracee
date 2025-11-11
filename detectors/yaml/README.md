# YAML Detectors

This directory contains example YAML-based detectors that demonstrate the declarative detector specification format.

## Example

**`suspicious_binary_execution.yaml`** - Threat detector that identifies execution of networking tools commonly used in attacks (nc, ncat, netcat, socat, nmap)

## Usage

These examples serve as:
- **Reference documentation** for YAML detector syntax
- **Starting templates** for creating custom detectors
- **Integration test fixtures** for validating YAML detector functionality

## Creating Custom Detectors

To create your own YAML detectors:

1. Copy an example file as a template
2. Modify the `id`, `produced_event`, and `requirements` sections
3. Place your detector in:
   - `./detectors/` (local development)
   - `/etc/tracee/detectors/` (system-wide)
   - Or use `--detectors yaml-dir=/custom/path`

## Schema Reference

See the main Tracee documentation for complete YAML detector schema reference and field extraction syntax.
