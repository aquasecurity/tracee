package version

var (
	version string
	debug   string
)

func GetVersion() string {
	return version
}

func DebugBuild() bool {
	return debug == "1"
}
