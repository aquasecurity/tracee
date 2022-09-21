package derive

import (
	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/events/parse"
	"github.com/aquasecurity/tracee/types/trace"
)

func ProcessExecution() deriveFunction {
	return deriveSingleEvent(events.ProcessExecution, deriveProcessExecution())
}

func deriveProcessExecution() func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		cmdpath, err := parse.ArgStringVal(&event, "cmdpath")
		if err != nil {
			return nil, err
		}
		pathname, err := parse.ArgStringVal(&event, "pathname")
		if err != nil {
			return nil, err
		}
		argv, err := parse.ArgStringArrVal(&event, "argv")
		if err != nil {
			return nil, err
		}
		invokedFromKernel, err := parse.ArgInt32Val(&event, "invoked_from_kernel")
		if err != nil {
			return nil, err
		}
		ctime, err := parse.ArgUint64Val(&event, "ctime")
		if err != nil {
			return nil, err
		}
		// If exec-hash option wasn't turned on this function will return an empty string and an error
		// Therefore the error is not checked.
		sha256, _ := parse.ArgStringVal(&event, "sha256")
		return []interface{}{
			cmdpath,
			pathname,
			argv,
			invokedFromKernel,
			ctime,
			sha256,
		}, nil
	}
}

func ProcessTermination() deriveFunction {
	return deriveSingleEvent(events.ProcessTermination, deriveProcessTermination())
}

func deriveProcessTermination() func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		groupExit, err := parse.ArgBoolVal(&event, "process_group_exit")
		if err != nil {
			return nil, err
		}
		if groupExit {
			returnCode, err := parse.ArgInt64Val(&event, "exit_code")
			if err != nil {
				return nil, err
			}

			return []interface{}{
				returnCode,
			}, nil
		}
		return nil, nil
	}
}

func FileDeletion() deriveFunction {
	return deriveSingleEvent(events.FileDeletion, deriveFileDeletion())
}

func deriveFileDeletion() func(event trace.Event) ([]interface{}, error) {
	return func(event trace.Event) ([]interface{}, error) {
		pathname, err := parse.ArgStringVal(&event, "pathname")
		if err != nil {
			return nil, err
		}
		ctime, err := parse.ArgUint64Val(&event, "ctime")
		if err != nil {
			return nil, err
		}
		return []interface{}{
			pathname,
			ctime,
		}, nil
	}
}
