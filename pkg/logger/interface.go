package logger

// ILogger is an interface for handling multiple types of messages that should pass to the user in some way.
// For best practice, most classes should have access to a logger class through this interface.
type ILogger interface {
	Error(string)   // Critical error has happened
	Warning(string) // A non-critical error has happened
	Info(string)    // A message worth recording has happened
	Debug(string)   // A message related to the workflow for debug purposes
}
