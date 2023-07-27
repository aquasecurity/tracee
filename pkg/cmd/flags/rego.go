package flags

import (
	"strings"

	"github.com/open-policy-agent/opa/compile"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/signatures/rego"
)

func regoHelp() string {
	return `Rego configurations.
possible options:
partial-eval            enable partial evaluation of rego signatures.
aio                     compile rego signatures altogether as an aggregate policy. By default each signature is compiled separately.
Examples:
  --rego partial-eval                               | enable partial evaluation
  --rego partial-eval --rego aio                    | enable partial evaluation, and aggregate policy compilation.
Use this flag multiple times to choose multiple output options
`
}

func PrepareRego(regoSlice []string) (rego.Config, error) {
	c := rego.Config{
		RuntimeTarget: compile.TargetRego,
		PartialEval:   false,
		AIO:           false,
	}

	if len(regoSlice) == 0 {
		return c, nil
	}

	for _, s := range regoSlice {
		optValue := strings.TrimSpace(s)
		switch optValue {
		case "partial-eval":
			c.PartialEval = true
		case "aio":
			c.AIO = true
		default:
			// TODO: build man page
			// return rego.Config{}, errfmt.Errorf("invalid rego option specified, see 'tracee-rego' man page for more info")
			return rego.Config{}, errfmt.Errorf("invalid rego option specified, use '--help' for more info")
		}
	}

	return c, nil
}
