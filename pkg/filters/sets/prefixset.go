package sets

import (
	"math"
	"sort"

	"golang.org/x/exp/maps"
)

type PrefixSet struct {
	Set       map[string]struct{}
	lengthSet map[int]struct{}
	lengths   []int
	minLen    int
}

func NewPrefixSet() PrefixSet {
	return PrefixSet{
		Set:       map[string]struct{}{},
		lengthSet: map[int]struct{}{},
		lengths:   []int{},
		minLen:    math.MaxInt,
	}
}

func (set *PrefixSet) Put(prefix string) {
	if prefix == "" {
		return
	}

	set.Set[prefix] = struct{}{}
	prefixLen := len(prefix)
	if _, ok := set.lengthSet[prefixLen]; !ok {
		set.lengthSet[prefixLen] = struct{}{}
		set.lengths = append(set.lengths, prefixLen)
		sort.Ints(set.lengths)
	}
	if prefixLen < set.minLen {
		set.minLen = prefixLen
	}
}

func (set *PrefixSet) Exists(prefix string) bool {
	_, found := set.Set[prefix]
	return found
}

func (set *PrefixSet) Filter(val string) bool {
	valLen := len(val)
	if set.minLen == math.MaxInt || valLen < set.minLen {
		return false
	}

	for _, prefixLen := range set.lengths {
		if valLen < prefixLen {
			return false
		}

		check := val[0:prefixLen]
		if _, found := set.Set[check]; found {
			return true
		}
	}
	return false
}

func (set *PrefixSet) Length() int {
	return len(set.Set)
}

func (set *PrefixSet) Clone() *PrefixSet {
	if set == nil {
		return nil
	}

	n := NewPrefixSet()

	maps.Copy(n.Set, set.Set)
	maps.Copy(n.lengthSet, set.lengthSet)
	n.lengths = append(n.lengths, set.lengths...)
	n.minLen = set.minLen

	return &n
}
