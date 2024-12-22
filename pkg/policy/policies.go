package policy

import (
	bpf "github.com/aquasecurity/libbpfgo"

	"github.com/aquasecurity/tracee/pkg/events"
	"github.com/aquasecurity/tracee/pkg/logger"
	"github.com/aquasecurity/tracee/pkg/utils"
)

// TODO: move all of this file and structs to be under policy_manager.go
type policies struct {
	bpfInnerMaps map[string]*bpf.BPFMapLow
	policies     map[string]*Policy

	// computed values
	rules         map[events.ID][]*Rule // The slice of rules should be up to 64, which is the max rule count per event
	userlandRules map[events.ID][]*Rule // Rules that have usersland filters enabled (read in a hot path)
}

type Rule struct {
	ruleData *RuleData // taken from Policy struct
	policy   *Policy
	submit   bool
	emit     bool
}

func NewPolicies() *policies {
	return &policies{
		bpfInnerMaps:  map[string]*bpf.BPFMapLow{},
		policies:      map[string]*Policy{},
		rules:         map[events.ID][]*Rule{},
		userlandRules: map[events.ID][]*Rule{},
	}
}

// Compile-time check to ensure that Policies implements the Cloner interface
var _ utils.Cloner[*policies] = &policies{}

func (ps *policies) count() int {
	return len(ps.policies)
}

// Deprecated: version returns the version of the Policies.
// Will be removed soon.
func (ps *policies) version() uint16 {
	return 1 // version will be removed soon
}

// add adds a policy.
func (ps *policies) add(p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}
	if _, ok := ps.policies[p.Name]; ok {
		return PolicyAlreadyExistsError(p.Name)
	}

	ps.policies[p.Name] = p

	ps.compute()

	return nil
}

// set sets a policy.
func (ps *policies) set(p *Policy) error {
	if p == nil {
		return PolicyNilError()
	}

	// TODO: we can merge set and add together to avoid code duplication
	ps.policies[p.Name] = p

	ps.compute()

	return nil
}

// remove removes a policy by name.
func (ps *policies) remove(name string) error {
	p, ok := ps.policies[name]
	if !ok {
		return PolicyNotFoundByNameError(name)
	}

	delete(ps.policies, p.Name)

	ps.compute()

	return nil
}

// lookupByName returns a policy by name.
func (ps *policies) lookupByName(name string) (*Policy, error) {
	if p, ok := ps.policies[name]; ok {
		return p, nil
	}

	return nil, PolicyNotFoundByNameError(name)
}

// matchedNames returns a list of matched policies names based on
// the given matched bitmap.
func (ps *policies) matchedNames(matched uint64) []string {
	names := []string{}

	// TODO: this will take event id and matched rules bitmap, and map to policies in userspace
	// for _, p := range ps.allFromMap() {
	// 	if utils.HasBit(matched, uint(p.ID)) {
	// 		names = append(names, p.Name)
	// 	}
	// }

	return names
}

// allFromMap returns a map of allFromMap policies by ID.
// When iterating, the order is not guaranteed.
func (ps *policies) allFromMap() map[string]*Policy {
	return ps.policies
}

// Clone returns a deep copy of Policies.
func (ps *policies) Clone() *policies {
	if ps == nil {
		return nil
	}

	nPols := NewPolicies()

	// Deep copy of all policies
	for _, p := range ps.policies {
		if p == nil {
			continue
		}
		if err := nPols.set(p.Clone()); err != nil {
			logger.Errorw("Cloning policy %s: %v", p.Name, err)
			return nil
		}
	}

	return nPols
}
