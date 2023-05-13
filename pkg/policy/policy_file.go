package policy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
)

// PolicyFile is the structure of the policy file
type PolicyFile struct {
	Name          string   `yaml:"name"`
	Description   string   `yaml:"description"`
	Scope         []string `yaml:"scope"`
	DefaultAction string   `yaml:"defaultAction"`
	Rules         []Rule   `yaml:"rules"`
}

// Rule is the structure of the rule in the policy file
type Rule struct {
	Event  string   `yaml:"event"`
	Filter []string `yaml:"filter"`
	Action []string `yaml:"action"`
}

func (p PolicyFile) Validate() error {
	if p.Name == "" {
		return errfmt.Errorf("policy name cannot be empty")
	}

	if p.Description == "" {
		return errfmt.Errorf("policy %s, description cannot be empty", p.Name)
	}

	if p.Scope == nil || len(p.Scope) == 0 {
		return errfmt.Errorf("policy %s, scope cannot be empty", p.Name)
	}

	if p.Rules == nil || len(p.Rules) == 0 {
		return errfmt.Errorf("policy %s, rules cannot be empty", p.Name)
	}

	if p.DefaultAction == "" {
		return errfmt.Errorf("policy %s, default action cannot be empty", p.Name)
	}

	if err := p.validateDefaultAction(); err != nil {
		return err
	}

	if err := p.validateScope(); err != nil {
		return err
	}

	return p.validateRules()
}

func (p PolicyFile) validateDefaultAction() error {
	return validateAction(p.Name, p.DefaultAction)
}

func validateAction(policyName, a string) error {
	actions := []string{
		"log",
		"webhook",
		"forward",
	}

	for _, action := range actions {
		if action == a {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, action %s is not valid", policyName, a)
}

func (p PolicyFile) validateScope() error {
	scopes := []string{
		"uid",
		"pid",
		"mntns",
		"pidns",
		"uts",
		"comm",
		"container",
		"!container",
		"tree",
		"binary",
		"bin",
		"follow",
	}

	for _, scope := range p.Scope {
		scope = strings.ReplaceAll(scope, " ", "")

		if scope == "global" && len(p.Scope) > 1 {
			return errfmt.Errorf("policy %s, global scope must be unique", p.Name)
		}

		if scope == "global" {
			return nil
		}

		scope, err := parseScope(p.Name, scope)
		if err != nil {
			return err
		}

		var found bool
		for _, s := range scopes {
			if scope == s {
				found = true
			}
		}

		if !found {
			return errfmt.Errorf("policy %s, scope %s is not valid", p.Name, scope)
		}
	}
	return nil
}

func parseScope(policyName, scope string) (string, error) {
	switch scope {
	case "follow", "!container", "container":
		return scope, nil
	default:
		operatorIdx := strings.IndexAny(scope, "=!<>")

		if operatorIdx == -1 {
			return "", errfmt.Errorf("policy %s, scope %s is not valid", policyName, scope)
		}

		return scope[:operatorIdx], nil
	}
}

func (p PolicyFile) validateRules() error {
	evts := make(map[string]bool)

	for _, r := range p.Rules {
		// Currently, an event can only be used once in the policy. Support for using the same
		// event, multiple times, with different filters, shall be implemented in the future.
		if _, ok := evts[r.Event]; ok {
			return errfmt.Errorf("policy %s, event %s is duplicated", p.Name, r.Event)
		}

		evts[r.Event] = true

		err := validateEvent(p.Name, r.Event)
		if err != nil {
			return err
		}

		for _, a := range r.Action {
			if a != "" {
				err = validateAction(p.Name, a)
				if err != nil {
					return err
				}
			}
		}

		for _, f := range r.Filter {
			operatorIdx := strings.IndexAny(f, "=!<>")

			if operatorIdx == -1 {
				return errfmt.Errorf("policy %s, invalid filter operator: %s", p.Name, f)
			}

			filterName := f[:operatorIdx]

			// args
			if strings.HasPrefix(f, "args") {
				s := strings.Split(f, ".")
				if len(s) == 1 {
					return errfmt.Errorf("policy %s, arg name can't be empty", p.Name)
				}

				err := validateEventArg(p.Name, r.Event, s[1])
				if err != nil {
					return err
				}

				continue
			}

			// retval
			if strings.HasPrefix(f, "retval") {
				s := strings.Split(f, "=")
				if len(s) == 1 {
					return errfmt.Errorf("policy %s, retval must have value: %s", p.Name, f)
				}

				if s[1] == "" {
					return errfmt.Errorf("policy %s, retval cannot be empty", p.Name)
				}

				_, err := strconv.Atoi(s[1])
				if err != nil {
					return errfmt.Errorf("policy %s, retval must be an integer: %s", p.Name, s[1])
				}

				continue
			}

			// context
			err = validateContext(p.Name, filterName)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func validateEvent(policyName, eventName string) error {
	if eventName == "" {
		return errfmt.Errorf("policy %s, event cannot be empty", policyName)
	}

	_, ok := events.Definitions.GetID(eventName)
	if !ok {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}
	return nil
}

func validateEventArg(policyName, eventName, argName string) error {
	s := strings.Split(argName, "!=")

	if len(s) == 1 {
		s = strings.Split(argName, "=")
	}

	if len(s) == 1 {
		return errfmt.Errorf("policy %s, arg %s value can't be empty", policyName, s[0])
	}

	if s[1] == "" {
		return errfmt.Errorf("policy %s, arg %s value can't be empty", policyName, s[0])
	}

	argName = s[0]

	eventID, ok := events.Definitions.GetID(eventName)
	if !ok {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}
	event := events.Definitions.Get(eventID)
	for _, s := range event.Sets {
		// we don't validate signature events because the arguments are dynamic
		if s == "signatures" {
			return nil
		}
	}

	for _, p := range event.Params {
		if p.Name == argName {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, event %s does not have argument %s", policyName, eventName, argName)
}

// todo: check if we really need this here? it will be tested later when creating policies anyway
// also - we don't check for validity of args and retval - so why should we check this?
// also - having this here is a duplication of checking the event flag - so let's do it in one place
func validateContext(policyName, c string) error {
	contexts := []string{
		"timestamp",
		"processorId",
		"p",
		"pid",
		"processId",
		"tid",
		"threadId",
		"ppid",
		"parentProcessId",
		"hostTid",
		"hostThreadId",
		"hostPid",
		"hostParentProcessId",
		"uid",
		"userId",
		"mntns",
		"mountNamespace",
		"pidns",
		"pidNamespace",
		"processName",
		"comm",
		"hostName",
		"cgroupId",
		"host",
		"container",
		"containerId",
		"containerImage",
		"containerName",
		"podName",
		"podNamespace",
		"podUid",
		"syscall",
	}

	for _, context := range contexts {
		if c == context {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, filter %s is not valid", policyName, c)
}

// PoliciesFromPaths returns a slice of policies from the given paths
func PoliciesFromPaths(paths []string) ([]PolicyFile, error) {
	policies := make([]PolicyFile, 0)

	for _, path := range paths {
		if path == "" {
			return nil, errfmt.Errorf("policy path cannot be empty")
		}

		path, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return nil, err
		}

		if !fileInfo.IsDir() {
			p, err := getPoliciesFromFile(path)
			if err != nil {
				return nil, err
			}
			policies = append(policies, p)

			continue
		}

		files, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}

		policyNames := make(map[string]bool)

		for _, file := range files {
			if file.IsDir() {
				continue
			}

			// TODO: support json
			if strings.HasSuffix(file.Name(), ".yaml") ||
				strings.HasSuffix(file.Name(), ".yml") {
				policy, err := getPoliciesFromFile(filepath.Join(path, file.Name()))
				if err != nil {
					return nil, err
				}

				// validate policy name is unique
				if _, ok := policyNames[policy.Name]; ok {
					return nil, errfmt.Errorf("policy %s already exist", policy.Name)
				}

				policyNames[policy.Name] = true

				policies = append(policies, policy)
			}
		}
	}

	return policies, nil
}

func getPoliciesFromFile(filePath string) (PolicyFile, error) {
	var p PolicyFile

	data, err := os.ReadFile(filePath)
	if err != nil {
		return p, err
	}

	err = yaml.Unmarshal(data, &p)
	if err != nil {
		return p, err
	}

	err = p.Validate()
	if err != nil {
		return p, err
	}

	return p, nil
}
