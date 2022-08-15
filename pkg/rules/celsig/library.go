package celsig

import (
	"github.com/aquasecurity/tracee/pkg/proto"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

var (
	wrapperEvent  = decls.NewObjectType("proto.Event")
	sockaddrEvent = decls.NewObjectType("proto.sockaddr")
)

type customLib struct{}

func (c *customLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Types(&proto.Event{}),
		cel.Declarations(
			decls.NewVar("input", wrapperEvent),
			decls.NewFunction("stringArg",
				decls.NewInstanceOverload("proto.Event_stringArg_string",
					[]*exprpb.Type{
						wrapperEvent,
						decls.String,
					},
					decls.String,
				),
			),
			decls.NewFunction("sockaddrArg",
				decls.NewInstanceOverload("proto.Event_sockaddrArg_string",
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
				Operator: "proto.Event_stringArg_string",
				Binary:   stringArg,
			},
			&functions.Overload{
				Operator: "proto.Event_sockaddrArg_string",
				Binary:   c.sockaddrArg,
			},
		),
	}
}

func (c *customLib) sockaddrArg(lhs ref.Val, rhs ref.Val) ref.Val {
	event := lhs.Value().(*proto.Event)
	argName := rhs.Value().(string)
	arg := argByName(event, argName)
	if arg == nil || arg.Value.SockaddrValue == nil {
		return types.NewObject(nil, nil, nil, &proto.Sockaddr{})
	}
	return types.NewObject(nil, nil, nil, arg.Value.SockaddrValue)
}

func stringArg(lhs ref.Val, rhs ref.Val) ref.Val {
	event := lhs.Value().(*proto.Event)
	argName := rhs.Value().(string)
	arg := argByName(event, argName)
	if arg == nil || arg.Value.StringValue == nil {
		return types.String("")
	}
	return types.String(*arg.Value.StringValue)
}

// argByName is the same code as helpers.GetTraceeArgumentByName but for *proto.Event.
func argByName(event *proto.Event, argName string) *proto.Argument {
	for _, arg := range event.Args {
		if arg.Name == argName {
			return arg
		}
	}
	return nil
}
