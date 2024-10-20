package version

var (
	version string
	metrics string
)

func GetVersion() string {
	return version
}

func MetricsBuild() bool {
	return metrics == "1"
}
