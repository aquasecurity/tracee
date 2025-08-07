package tracee

import (
	"embed"
)

//go:embed "docs/man/*.1"
var ManPagesBundle embed.FS
