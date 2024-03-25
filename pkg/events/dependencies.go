package events

// GetAllEventsDependencies returns a map of all the dependencies of a given event ID.
// It gathers all the dependencies recursively.
func GetAllEventsDependencies(givenEvtId ID) map[ID]struct{} {
	allDeps := make(map[ID]struct{})

	var gatherDeps func(evtId ID)
	gatherDeps = func(evtId ID) {
		eventDefinition := Core.GetDefinitionByID(evtId)
		for _, depEventId := range eventDefinition.GetDependencies().GetIDs() {
			if _, found := allDeps[depEventId]; !found {
				allDeps[depEventId] = struct{}{}
				gatherDeps(depEventId) // Recursively gather dependencies
			}
		}
	}

	gatherDeps(givenEvtId) // Start the recursion with the given event ID

	return allDeps
}
