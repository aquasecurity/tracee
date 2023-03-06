package celsig

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/aquasecurity/tracee/pkg/signatures/celsig/wrapper"
)

var (
	wrapperEvent  = decls.NewObjectType("wrapper.Event")
	sockaddrEvent = decls.NewObjectType("wrapper.sockaddr")
)

type customLib struct{}

func (c *customLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&wrapper.Event{}),
		cel.Declarations(
			decls.NewVar("input", wrapperEvent),
			decls.NewFunction("stringArg",
				decls.NewInstanceOverload("wrapper.Event_stringArg_string",
					[]*exprpb.Type{
						wrapperEvent,
						decls.String,
					},
					decls.String,
				),
			),
			decls.NewFunction("sockaddrArg",
				decls.NewInstanceOverload("wrapper.Event_sockaddrArg_string",
					[]*exprpb.Type{
						wrapperEvent,
						decls.String,
					},
					sockaddrEvent,
				),
			),
		),
	}
}

func (c *customLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "wrapper.Event_stringArg_string",
				Binary:   stringArg,
			},
			&functions.Overload{
				Operator: "wrapper.Event_sockaddrArg_string",
				Binary:   c.sockaddrArg,
			},
		),
	}
}

func (c *customLib) sockaddrArg(lhs ref.Val, rhs ref.Val) ref.Val {
	event := lhs.Value().(*wrapper.Event)
	argName := rhs.Value().(string)
	arg := argByName(event, argName)
	if arg == nil || arg.Value.SockaddrValue == nil {
		return types.NewObject(nil, nil, nil, &wrapper.Sockaddr{})
	}
	return types.NewObject(nil, nil, nil, arg.Value.SockaddrValue)
}

func stringArg(lhs ref.Val, rhs ref.Val) ref.Val {
	event := lhs.Value().(*wrapper.Event)
	argName := rhs.Value().(string)
	arg := argByName(event, argName)
	if arg == nil || arg.Value.StringValue == nil {
		return types.String("")
	}
	return types.String(*arg.Value.StringValue)
}

// argByName is the same code as helpers.GetTraceeArgumentByName but for *wrapper.Event.
func argByName(event *wrapper.Event, argName string) *wrapper.Argument {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg
		}
	}
	return nil
}
