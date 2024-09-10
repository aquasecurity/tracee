package time

// TimeNormalizer normalizes the time to be relative to tracee start time or current time in nanoseconds.
type TimeNormalizer interface {
	NormalizeTime(timeNs int) int
	GetOriginalTime(timeNs int) int
}

// CreateTimeNormalizerByConfig create a TimeNormalizer according to given configuration using
// runtime functions.
func CreateTimeNormalizerByConfig(bootTime uint64) TimeNormalizer {
	return NewAbsoluteTimeNormalizer(int(bootTime))
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
