//go:build !core
// +build !core

package main

import (
	"embed"
)

var coreEmbedded bool = false

// needed by linters as this is the default source
var embeddedCORE embed.FS
