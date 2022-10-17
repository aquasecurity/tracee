package debug

var (
	debug bool
)

func init() {
	debug = false
}

// returns if the internal debug variable has been enabled
func Enabled() bool {
	return debug
}

// enable debug mode
func Enable() error {
	debug = true

	return nil
}

// disable debug mode
func Disable() error {
	debug = false

	return nil
}
