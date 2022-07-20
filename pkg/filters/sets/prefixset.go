package sets

import (
	"math"
	"sort"
)

type PrefixSet struct {
	Set       map[string]bool
	lengthSet map[int]struct{}
	lengths   []int
	minLen    int
}

func NewPrefixSet() PrefixSet {
	return PrefixSet{
		Set:       map[string]bool{},
		lengthSet: map[int]struct{}{},
		lengths:   []int{},
		minLen:    math.MaxInt,
	}
}

func (set *PrefixSet) Put(prefix string) {
	if prefix == "" {
		return
	}

	set.Set[prefix] = true
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
	return set.Set[prefix]
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
		if set.Set[check] {
			return true
		}
	}
	return false
}

func (set *PrefixSet) Length() int {
	return len(set.Set)
}
