package helpers

// This file has been deprecated.
// All argument extraction functions have been moved to types/trace as Event methods:
//
// Old helpers.GetTraceeStringArgumentByName(event, name)
// -> New event.GetStringArgumentByName(name)
//
// Old helpers.GetTraceeArgumentByName(event, name, opts)
// -> New event.GetArgumentByName(name, opts)
//
// Similar pattern for all other argument extraction functions.
