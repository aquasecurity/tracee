package v1beta1

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/aquasecurity/tracee/pkg/errfmt"
	"github.com/aquasecurity/tracee/pkg/events"
	k8s "github.com/aquasecurity/tracee/pkg/k8s/apis/tracee.aquasec.com/v1beta1"
)

// PolicyFile is the structure of the policy file
type PolicyFile struct {
	APIVersion string         `yaml:"apiVersion"`
	Kind       string         `yaml:"kind"`
	Metadata   Metadata       `yaml:"metadata"`
	Spec       k8s.PolicySpec `yaml:"spec"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Annotations map[string]string `yaml:"annotations"`
}

func (p PolicyFile) GetName() string {
	return p.Metadata.Name
}

func (p PolicyFile) GetDescription() string {
	if p.Metadata.Annotations == nil {
		return ""
	}

	d, ok := p.Metadata.Annotations["description"]
	if !ok {
		return ""
	}
	return d
}

func (p PolicyFile) GetScope() []string {
	return p.Spec.Scope
}

func (p PolicyFile) GetDefaultActions() []string {
	return p.Spec.DefaultActions
}

func (p PolicyFile) GetRules() []k8s.Rule {
	return p.Spec.Rules
}

func (p PolicyFile) Validate() error {
	if err := validation.IsDNS1123Subdomain(p.GetName()); err != nil {
		return errfmt.Errorf("policy name %s is invalid: %s", p.GetName(), err)
	}

	if p.APIVersion != "tracee.aquasec.com/v1beta1" {
		return errfmt.Errorf("policy %s, apiVersion not supported", p.GetName())
	}

	if p.Kind != "Policy" {
		return errfmt.Errorf("policy %s, kind not supported", p.GetName())
	}

	if p.GetScope() == nil || len(p.GetScope()) == 0 {
		return errfmt.Errorf("policy %s, scope cannot be empty", p.GetName())
	}

	if p.GetRules() == nil || len(p.GetRules()) == 0 {
		return errfmt.Errorf("policy %s, rules cannot be empty", p.GetName())
	}

	if err := p.validateDefaultActions(); err != nil {
		return err
	}

	if err := p.validateScope(); err != nil {
		return err
	}

	return p.validateRules()
}

func (p PolicyFile) validateDefaultActions() error {
	if p.GetDefaultActions() == nil || len(p.GetDefaultActions()) == 0 {
		return nil
	}

	return validateActions(p.GetName(), p.GetDefaultActions())
}

func validateActions(policyName string, actions []string) error {
	for _, action := range actions {
		switch action {
		case "log", "print": // supported actions
			continue
		default:
			return errfmt.Errorf("policy %s, action %s is not valid", policyName, action)
		}
	}

	return nil
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
		"not-container",
		"tree",
		"exec", "executable", "bin", "binary",
		"follow",
	}

	for _, scope := range p.GetScope() {
		scope = strings.ReplaceAll(scope, " ", "")

		if scope == "global" && len(p.GetScope()) > 1 {
			return errfmt.Errorf("policy %s, global scope must be unique", p.GetName())
		}

		if scope == "global" {
			return nil
		}

		scope, err := parseScope(p.GetName(), scope)
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
			return errfmt.Errorf("policy %s, scope %s is not valid", p.GetName(), scope)
		}
	}
	return nil
}

func parseScope(policyName, scope string) (string, error) {
	switch scope {
	case "follow", "not-container", "container":
		return scope, nil
	default:
		operatorIdx := strings.IndexAny(scope, "=!<>")

		if operatorIdx == -1 {
			return "", errfmt.Errorf("policy %s, scope %s is not valid", policyName, scope)
		}
		if operatorIdx == 0 {
			return scope, nil
		}

		return scope[:operatorIdx], nil
	}
}

func (p PolicyFile) validateRules() error {
	evts := make(map[string]bool)

	for _, r := range p.GetRules() {
		// Currently, an event can only be used once in the policy. Support for using the same
		// event, multiple times, with different filters, shall be implemented in the future.
		if _, ok := evts[r.Event]; ok {
			return errfmt.Errorf("policy %s, event %s is duplicated", p.GetName(), r.Event)
		}

		evts[r.Event] = true

		err := validateEvent(p.GetName(), r.Event)
		if err != nil {
			return err
		}

		err = validateActions(p.GetName(), r.Actions)
		if err != nil {
			return err
		}

		for _, f := range r.Filters {
			operatorIdx := strings.IndexAny(f, "=!<>")

			if operatorIdx == -1 {
				return errfmt.Errorf("policy %s, invalid filter operator: %s", p.GetName(), f)
			}

			// data
			// option "args" will be deprecate in future
			if strings.HasPrefix(f, "data") || strings.HasPrefix(f, "args") {
				s := strings.Split(f, ".")
				if len(s) == 1 {
					return errfmt.Errorf("policy %s, data name can't be empty", p.GetName())
				}

				err := validateEventData(p.GetName(), r.Event, s[1])
				if err != nil {
					return err
				}

				continue
			}

			// retval
			if strings.HasPrefix(f, "retval") {
				s := strings.Split(f, "=")
				if len(s) == 1 {
					return errfmt.Errorf("policy %s, retval must have value: %s", p.GetName(), f)
				}

				if s[1] == "" {
					return errfmt.Errorf("policy %s, retval cannot be empty", p.GetName())
				}

				_, err := strconv.Atoi(s[1])
				if err != nil {
					return errfmt.Errorf("policy %s, retval must be an integer: %s", p.GetName(), s[1])
				}

				continue
			}
		}
	}

	return nil
}

func validateEvent(policyName, eventName string) error {
	if eventName == "" {
		return errfmt.Errorf("policy %s, event cannot be empty", policyName)
	}

	_, ok := events.Core.GetDefinitionIDByName(eventName)
	if !ok {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}
	return nil
}

func validateEventData(policyName, eventName, dataName string) error {
	s := strings.Split(dataName, "!=")

	if len(s) == 1 {
		s = strings.Split(dataName, "=")
	}

	if len(s) == 1 {
		return errfmt.Errorf("policy %s, data %s value can't be empty", policyName, s[0])
	}

	if s[1] == "" {
		return errfmt.Errorf("policy %s, data %s value can't be empty", policyName, s[0])
	}

	dataName = s[0]

	eventDefinition := events.Core.GetDefinitionByName(eventName)
	if eventDefinition.NotValid() {
		return errfmt.Errorf("policy %s, event %s is not valid", policyName, eventName)
	}

	for _, set := range eventDefinition.GetSets() {
		if set == "signatures" { // no sig event validation (arguments are dynamic)
			return nil
		}
	}
	for _, p := range eventDefinition.GetFields() {
		if p.Name == dataName {
			return nil
		}
	}

	return errfmt.Errorf("policy %s, event %s does not have data %s", policyName, eventName, dataName)
}

// PoliciesFromPaths returns a slice of policies from the given paths
func PoliciesFromPaths(paths []string) ([]k8s.PolicyInterface, error) {
	policies := make([]k8s.PolicyInterface, 0)

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
				if _, ok := policyNames[policy.GetName()]; ok {
					return nil, errfmt.Errorf("policy %s already exist", policy.GetName())
				}

				policyNames[policy.GetName()] = true

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
