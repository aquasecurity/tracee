//go:build core
// +build core

package main

import (
	"embed"
)

var coreEmbedded bool = true

//go:embed "dist/tracee.bpf.core.o"

var embeddedCORE embed.FS
