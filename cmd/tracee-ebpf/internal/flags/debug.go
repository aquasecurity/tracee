package flags

var (
	debug bool
)

func init() {
	debug = false
}

// returns if the internal debug variable has been enabled
func DebugModeEnabled() bool {
	return debug
}

// enable debug mode
func EnableDebugMode() error {
	debug = true

	return nil
}

// disable debug mode
func DisableDebugMode() error {
	debug = false

	return nil
}
