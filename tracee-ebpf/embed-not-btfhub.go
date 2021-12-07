//go:build !btfhub
// +build !btfhub

package main

import (
	"embed"
)

var btfEmbedded bool = false

// needed by linters as this is the default source
var embeddedBTF embed.FS
