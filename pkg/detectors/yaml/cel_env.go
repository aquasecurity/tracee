package yaml

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/ast"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/parser"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

const (
	// MaxCELCost is the maximum cost units allowed for a CEL expression evaluation
	// Cost is roughly proportional to the number of operations performed
	// This prevents expensive operations like creating huge lists or deeply nested iterations
	// Typical production value is 1,000,000 which allows complex expressions while preventing DoS
	MaxCELCost = 1000000 // 1 million operations
)

// createCELEnvironment creates a CEL environment with event context and helper functions
// lists: optional map of list name -> list values to expose as global variables
// registry: optional registry for datastore access (nil during validation)
func createCELEnvironment(lists map[string][]string, registry datastores.Registry) (*cel.Env, error) {
	envOptions := []cel.EnvOption{
		// Register protobuf types so CEL can access nested fields
		cel.Types(&v1beta1.Event{}, &v1beta1.Workload{}, &v1beta1.Policies{}, &wrapperspb.UInt32Value{}),

		// Declare 'event' variable with its protobuf type
		cel.Variable("event", cel.ObjectType("tracee.v1beta1.Event")),

		// Top-level convenience variables (no "event." prefix needed)
		// Note: Only event properties are exposed, not configuration (like policies)
		cel.Variable("workload", cel.ObjectType("tracee.v1beta1.Workload")),
		cel.Variable("timestamp", cel.ObjectType("google.protobuf.Timestamp")),

		// Macros for simplified syntax (compile-time rewrites)
		cel.Macros(
			// Macro 1: getEventData("field") → getEventData(event, "field")
			cel.GlobalMacro("getEventData", 1, getEventDataMacroExpander),
			// Macro 2: hasData("field") → hasData(event, "field")
			cel.GlobalMacro("hasData", 1, hasDataMacroExpander),
		),

		// Helper function: getEventData - extract data field from event (returns native type)
		// Usage: getEventData(event, "pathname") or getEventData("pathname") via macro
		// Returns: string, int32, uint32, etc. - whatever type the field actually is
		cel.Function("getEventData",
			cel.Overload("getEventData_event_string",
				[]*cel.Type{cel.AnyType, cel.StringType},
				cel.DynType, // Returns dynamic type - CEL handles it automatically!
				cel.BinaryBinding(getEventDataBinding),
			),
		),

		// Helper function: hasData - check if data field exists
		// Usage: hasData(event, "pathname") or hasData("pathname") via macro
		cel.Function("hasData",
			cel.Overload("hasData_event_string",
				[]*cel.Type{cel.AnyType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(hasDataBinding),
			),
		),
	}

	// Add shared list variables
	for name := range lists {
		envOptions = append(envOptions, cel.Variable(name, cel.ListType(cel.StringType)))
	}

	// Always register datastore functions (for validation and runtime)
	// During validation (registry == nil), functions return null
	// During runtime (registry != nil), functions access actual data
	datastoreOptions := registerDatastoreFunctions(registry)
	envOptions = append(envOptions, datastoreOptions...)

	return cel.NewEnv(envOptions...)
}

// getEventDataBinding extracts a data field from event.Data and returns its native type
func getEventDataBinding(lhs, rhs ref.Val) ref.Val {
	// lhs is the event (protobuf)
	event, ok := lhs.Value().(*v1beta1.Event)
	if !ok {
		return types.NewErr("getEventData: first argument must be an Event")
	}

	fieldName, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("getEventData: second argument must be a string")
	}

	// Find the field in event data
	for _, dataValue := range event.Data {
		if dataValue.Name == fieldName {
			// Return the value in its native type
			return convertEventValueToCEL(dataValue)
		}
	}

	// Return nil/null if field not found (CEL-safe)
	return types.NullValue
}

// convertEventValueToCEL converts an EventValue to a CEL ref.Val with the appropriate type
func convertEventValueToCEL(ev *v1beta1.EventValue) ref.Val {
	if ev.GetValue() == nil {
		return types.NullValue
	}

	// Extract the actual value from the oneof and convert to CEL type
	switch v := ev.Value.(type) {
	case *v1beta1.EventValue_Str:
		return types.String(v.Str)
	case *v1beta1.EventValue_Int32:
		return types.Int(v.Int32)
	case *v1beta1.EventValue_Int64:
		return types.Int(v.Int64)
	case *v1beta1.EventValue_UInt32:
		return types.Uint(v.UInt32)
	case *v1beta1.EventValue_UInt64:
		return types.Uint(v.UInt64)
	case *v1beta1.EventValue_Bool:
		return types.Bool(v.Bool)
	case *v1beta1.EventValue_Bytes:
		return types.Bytes(v.Bytes)
	// For complex types, return as dynamic value
	// CEL will handle them appropriately
	default:
		return types.DefaultTypeAdapter.NativeToValue(v)
	}
}

// hasDataBinding checks if a data field exists in the event
func hasDataBinding(lhs, rhs ref.Val) ref.Val {
	event, ok := lhs.Value().(*v1beta1.Event)
	if !ok {
		return types.NewErr("hasData: first argument must be an Event")
	}

	fieldName, ok := rhs.Value().(string)
	if !ok {
		return types.NewErr("hasData: second argument must be a string")
	}

	// Check if field exists
	for _, dataValue := range event.Data {
		if dataValue.Name == fieldName {
			return types.Bool(true)
		}
	}
	return types.Bool(false)
}

// CompileCondition compiles a single CEL condition expression
// Conditions must return boolean values
func CompileCondition(env *cel.Env, expression string) (cel.Program, error) {
	compiled, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compilation failed: %w", issues.Err())
	}

	// Check return type is boolean
	if compiled.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("condition must return boolean, got %v", compiled.OutputType())
	}

	// Enable interruptible evaluation for timeout support and cost tracking
	return env.Program(compiled,
		cel.EvalOptions(cel.OptExhaustiveEval, cel.OptTrackCost),
		cel.InterruptCheckFrequency(100), // Check for interruption every 100 operations
		cel.CostLimit(MaxCELCost),        // Limit computation cost
	)
}

// CompileExpression compiles a CEL expression for field extraction
// Expressions can return any type
func CompileExpression(env *cel.Env, expression string) (cel.Program, error) {
	compiled, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("compilation failed: %w", issues.Err())
	}

	// Enable interruptible evaluation for timeout support and cost tracking
	return env.Program(compiled,
		cel.EvalOptions(cel.OptExhaustiveEval, cel.OptTrackCost),
		cel.InterruptCheckFrequency(100), // Check for interruption every 100 operations
		cel.CostLimit(MaxCELCost),        // Limit computation cost
	)
}

// EvaluateCondition evaluates a compiled CEL condition with timeout enforcement
func EvaluateCondition(prog cel.Program, event *v1beta1.Event, lists map[string][]string, timeout time.Duration) (bool, error) {
	// Validate event is not nil
	if event == nil {
		return false, errors.New("event cannot be nil")
	}

	// Create context with timeout for evaluation
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Build evaluation variables with nil-safe access
	vars := map[string]any{
		"event": event,
	}

	// Add workload if available (nil is valid - CEL will handle it)
	if event.Workload != nil {
		vars["workload"] = event.Workload
	}

	// Add timestamp if available (nil is valid - CEL will handle it)
	if event.Timestamp != nil {
		vars["timestamp"] = event.Timestamp
	}

	// Add list variables
	for name, values := range lists {
		vars[name] = values
	}

	// Evaluate with context - will be interrupted if timeout is exceeded
	result, details, err := prog.ContextEval(ctx, vars)

	if err != nil {
		// Check if timeout was exceeded
		if ctx.Err() == context.DeadlineExceeded {
			return false, fmt.Errorf("evaluation timeout exceeded (%v)", timeout)
		}
		// Check if cost limit was exceeded
		if details != nil {
			if cost := details.ActualCost(); cost != nil && *cost > MaxCELCost {
				return false, fmt.Errorf("evaluation cost limit exceeded: %d (max: %d)", *cost, MaxCELCost)
			}
		}
		return false, fmt.Errorf("evaluation error: %w", err)
	}

	// Convert result to boolean
	boolVal, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("condition did not return boolean: %T", result.Value())
	}

	return boolVal, nil
}

// EvaluateExpression evaluates a compiled CEL expression with timeout enforcement
func EvaluateExpression(prog cel.Program, event *v1beta1.Event, lists map[string][]string, timeout time.Duration) (interface{}, error) {
	// Validate event is not nil
	if event == nil {
		return nil, errors.New("event cannot be nil")
	}

	// Create context with timeout for evaluation
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Build evaluation variables with nil-safe access
	vars := map[string]any{
		"event": event,
	}

	// Add workload if available (nil is valid - CEL will handle it)
	if event.Workload != nil {
		vars["workload"] = event.Workload
	}

	// Add timestamp if available (nil is valid - CEL will handle it)
	if event.Timestamp != nil {
		vars["timestamp"] = event.Timestamp
	}

	// Add list variables
	for name, values := range lists {
		vars[name] = values
	}

	// Evaluate with context - will be interrupted if timeout is exceeded
	result, details, err := prog.ContextEval(ctx, vars)

	if err != nil {
		// Check if timeout was exceeded
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("evaluation timeout exceeded (%v)", timeout)
		}
		// Check if cost limit was exceeded
		if details != nil {
			if cost := details.ActualCost(); cost != nil && *cost > MaxCELCost {
				return nil, fmt.Errorf("evaluation cost limit exceeded: %d (max: %d)", *cost, MaxCELCost)
			}
		}
		return nil, fmt.Errorf("evaluation error: %w", err)
	}

	return result.Value(), nil
}

// Macro expanders - these rewrite CEL AST at compile time

// getEventDataMacroExpander rewrites getEventData("field") → getEventData(event, "field")
func getEventDataMacroExpander(eh parser.ExprHelper, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) != 1 {
		return nil, eh.NewError(target.ID(), "getEventData macro requires exactly 1 argument")
	}

	// Create: getEventData(event, args[0])
	eventIdent := eh.NewIdent("event")
	return eh.NewCall("getEventData", eventIdent, args[0]), nil
}

// hasDataMacroExpander rewrites hasData("field") → hasData(event, "field")
func hasDataMacroExpander(eh parser.ExprHelper, target ast.Expr, args []ast.Expr) (ast.Expr, *common.Error) {
	if len(args) != 1 {
		return nil, eh.NewError(target.ID(), "hasData macro requires exactly 1 argument")
	}

	// Create: hasData(event, args[0])
	eventIdent := eh.NewIdent("event")
	return eh.NewCall("hasData", eventIdent, args[0]), nil
}
