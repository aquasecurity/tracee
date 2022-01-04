package pipeline

import (
	"github.com/aquasecurity/tracee/tracee-rules/process_tree"
	"github.com/aquasecurity/tracee/tracee-rules/types"
)

func CreateTraceeInputPipeline(traceeInput chan types.Event, config types.TraceePipelineConfig) chan types.Event {
	if config.EnableProcessTree {
		return process_tree.CreateProcessTreeInputPipeline(traceeInput)
	} else {
		return traceeInput
	}
}

func CreateTraceeOutputPipeline(traceeOutput chan types.Finding, config types.TraceePipelineConfig) chan types.Finding {
	if config.EnableProcessTree {
		return process_tree.CreateProcessTreeOutputEnrichmentPipeline(traceeOutput)
	} else {
		return traceeOutput
	}
}
