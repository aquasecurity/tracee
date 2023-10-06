package sets

import (
	"math"
	"sort"

	"golang.org/x/exp/maps"
)

type SuffixSet struct {
	Set       map[string]struct{}
	lengthSet map[int]struct{}
	lengths   []int
	minLen    int
}

func NewSuffixSet() SuffixSet {
	return SuffixSet{
		Set:       map[string]struct{}{},
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
	set.Set[suffix] = struct{}{}
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
	_, found := set.Set[suffix]
	return found
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
		if _, found := set.Set[check]; found {
			return true
		}
	}
	return false
}

func (set *SuffixSet) Length() int {
	return len(set.Set)
}

func (set *SuffixSet) Clone() *SuffixSet {
	if set == nil {
		return nil
	}

	n := NewSuffixSet()

	maps.Copy(n.Set, set.Set)
	maps.Copy(n.lengthSet, set.lengthSet)
	n.lengths = append(n.lengths, set.lengths...)
	n.minLen = set.minLen

	return &n
}
