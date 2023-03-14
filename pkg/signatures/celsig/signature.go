package celsig

import (
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/aquasecurity/tracee/pkg/signatures/celsig/wrapper"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
)

type signature struct {
	metadata       detect.SignatureMetadata
	selectedEvents []detect.SignatureEventSelector
	program        cel.Program
	cb             detect.SignatureHandler
}

// NewSignature constructs a Common Expression Language (CEL) signature based on
// the specified SignatureConfig.
func NewSignature(config SignatureConfig) (detect.Signature, error) {
	env, err := cel.NewEnv(cel.Lib(&customLib{}))
	if err != nil {
		return nil, fmt.Errorf("failed constructing program environment: %w", err)
	}

	ast, issues := env.Compile(config.Expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed compiling signature expression: %w", issues.Err())
	}
	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed constructing program: %w", err)
	}

	return &signature{
		program:        program,
		selectedEvents: config.EventSelectors,
		metadata:       config.Metadata,
	}, nil
}

func (s *signature) GetMetadata() (detect.SignatureMetadata, error) {
	return s.metadata, nil
}

func (s *signature) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return s.selectedEvents, nil
}

func (s *signature) Init(ctx detect.SignatureContext) error {
	s.cb = ctx.Callback
	return nil
}

func (s *signature) OnEvent(event protocol.Event) error {
	input, err := wrapper.Wrap(event)
	if err != nil {
		return err
	}
	out, _, err := s.program.Eval(map[string]interface{}{
		"input": input,
	})
	if err != nil {
		return fmt.Errorf("failed evaluating expression: %w", err)
	}
	if out.Type() != types.BoolType {
		return fmt.Errorf("expected boolean value, got: %v", out.Type())
	}
	matches := out.Value().(bool)
	if matches {
		s.cb(detect.Finding{
			Event:       event,
			SigMetadata: s.metadata,
		})
	}
	return nil
}

func (s *signature) Close() {
	// Do nothing
}

func (s *signature) OnSignal(_ detect.Signal) error {
	// Do nothing
	return nil
}

// NewSignaturesFromDir loads CEL signatures from *.cel, *.yaml, and *.yml
// configuration files in the given configuration directory.
func NewSignaturesFromDir(dirPath string) ([]detect.Signature, error) {
	configs, err := NewConfigsFromDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed loading configs: %w", err)
	}
	var signatures []detect.Signature
	for _, config := range configs {
		for _, signatureConfig := range config.Signatures {
			signature, err := NewSignature(signatureConfig)
			if err != nil {
				return nil, fmt.Errorf("failed constructing CEL signature: %w", err)
			}
			signatures = append(signatures, signature)
		}
	}
	return signatures, nil
}
