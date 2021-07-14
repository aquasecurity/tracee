// +build core

package main

import "embed"

//go:embed "dist/tracee.bpf.core.o"
var coreObject embed.FS

var bpf_core bool = true
