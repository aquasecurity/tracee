package sets

type PrefixSet struct {
	Set    map[string]bool
	minLen int
	maxLen int
}

func (set *PrefixSet) Put(prefix string) {
	if prefix == "" {
		return
	}
	initLenghts := false
	prefixLength := len(prefix)
	if len(set.Set) == 0 {
		set.minLen = prefixLength
		set.maxLen = prefixLength
		initLenghts = true
	}
	set.Set[prefix] = true

	if !initLenghts {
		if prefixLength < set.minLen {
			set.minLen = prefixLength
		}
		if prefixLength > set.maxLen {
			set.maxLen = prefixLength
		}
	}

}

func (set *PrefixSet) Exists(prefix string) bool {
	return set.Set[prefix]
}

func (set *PrefixSet) Filter(val string) bool {
	if set.minLen == 0 || set.maxLen == 0 {
		return false
	}
	if len(val) < set.minLen {
		return false
	}

	for prefixLen := set.minLen; prefixLen <= set.maxLen; prefixLen++ {
		if len(val) < prefixLen {
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
