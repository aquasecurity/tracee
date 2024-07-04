package time

// TimeNormalizer normalizes the time to be relative to tracee start time or current time in nanoseconds.
type TimeNormalizer interface {
	NormalizeTime(timeNs int) int
	GetOriginalTime(timeNs int) int
}

// CreateTimeNormalizerByConfig create a TimeNormalizer according to given configuration using
// runtime functions.
func CreateTimeNormalizerByConfig(relative bool, startTime uint64, bootTime uint64) TimeNormalizer {
	if relative {
		return NewRelativeTimeNormalizer(int(startTime))
	}
	return NewAbsoluteTimeNormalizer(int(bootTime))
}

// RelativeTimeNormalizer normalize the time to be relative to Tracee start time
type RelativeTimeNormalizer struct {
	startTime int
}

func NewRelativeTimeNormalizer(startTime int) *RelativeTimeNormalizer {
	return &RelativeTimeNormalizer{
		startTime: startTime,
	}
}

func (rn *RelativeTimeNormalizer) NormalizeTime(timeNs int) int {
	return timeNs - rn.startTime
}

func (rn *RelativeTimeNormalizer) GetOriginalTime(timeNs int) int {
	return timeNs + rn.startTime
}

// AbsoluteTimeNormalizer normalize the time to be absolute time since epoch
type AbsoluteTimeNormalizer struct {
	bootTime int
}

func NewAbsoluteTimeNormalizer(bootTime int) *AbsoluteTimeNormalizer {
	return &AbsoluteTimeNormalizer{
		bootTime: bootTime,
	}
}
func (rn *AbsoluteTimeNormalizer) NormalizeTime(timeNs int) int {
	return timeNs + rn.bootTime
}

func (rn *AbsoluteTimeNormalizer) GetOriginalTime(timeNs int) int {
	return timeNs - rn.bootTime
}
