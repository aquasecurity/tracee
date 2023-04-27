package sets

import (
	"math"
	"sort"
)

type SuffixSet struct {
	Set       map[string]bool
	lengthSet map[int]struct{}
	lengths   []int
	minLen    int
}

func NewSuffixSet() SuffixSet {
	return SuffixSet{
		Set:       map[string]bool{},
		lengthSet: map[int]struct{}{},
		lengths:   []int{},
		minLen:    math.MaxInt,
	}
}

func (set *SuffixSet) Put(suffix string) {
	if suffix == "" {
		return
	}
	suffixLength := len(suffix)
	set.Set[suffix] = true
	if _, ok := set.lengthSet[suffixLength]; !ok {
		set.lengthSet[suffixLength] = struct{}{}
		set.lengths = append(set.lengths, suffixLength)
		sort.Ints(set.lengths)
	}
	if suffixLength < set.minLen {
		set.minLen = suffixLength
	}
}

func (set *SuffixSet) Exists(suffix string) bool {
	return set.Set[suffix]
}

func (set *SuffixSet) Filter(val string) bool {
	lenVal := len(val)
	if set.minLen == math.MaxInt || lenVal < set.minLen {
		return false
	}

	for _, suffixLen := range set.lengths {
		if lenVal < suffixLen {
			return false
		}

		check := val[lenVal-suffixLen : lenVal]
		if set.Set[check] {
			return true
		}
	}
	return false
}

func (set *SuffixSet) Length() int {
	return len(set.Set)
}
