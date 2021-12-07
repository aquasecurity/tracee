//go:build btfhub
// +build btfhub

package main

import (
	"embed"
)

var btfEmbedded bool = true

//go:embed "dist/btfhub/*"

var embeddedBTF embed.FS
