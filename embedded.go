package tracee

import (
	_ "embed"
)

//go:embed signatures/rego/helpers.rego
var RegoHelpersCode string
