package sets

type SuffixSet struct {
	Set    map[string]bool
	minLen int
	maxLen int
}

func (set *SuffixSet) Put(suffix string) {
	if suffix == "" {
		return
	}
	initLenghts := false
	suffixLength := len(suffix)
	if len(set.Set) == 0 {
		set.minLen = suffixLength
		set.maxLen = suffixLength
		initLenghts = true
	}
	set.Set[suffix] = true

	if !initLenghts {
		if suffixLength < set.minLen {
			set.minLen = suffixLength
		}
		if suffixLength > set.maxLen {
			set.maxLen = suffixLength
		}
	}

}

func (set *SuffixSet) Exists(suffix string) bool {
	return set.Set[suffix]
}

func (set *SuffixSet) Filter(val string) bool {
	if set.minLen == 0 || set.maxLen == 0 {
		return false
	}

	lenVal := len(val)

	if lenVal < set.minLen {
		return false
	}

	for suffixLen := set.minLen; suffixLen <= set.maxLen; suffixLen++ {
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
