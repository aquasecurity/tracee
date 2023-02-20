package rego

// Config represents configurations to the rego engine
type Config struct {
	// RuntimeTarget, currently only supports rego
	RuntimeTarget string
	// Rego Partial Evaluation of signatures
	PartialEval bool
	// Aggregation Policy complication
	AIO bool
}
