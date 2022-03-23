package flags

func EventsPriorityHelp() string {
	return `Select the priority for every event via a JSON file. The priority will be used by the throttling engine, increasing/decreasing 
load according to the events priority. The json structure for the definition of the events priority should be as follow:

	{
		"prioPerEventId": [{
			"EventId": 1,
			"Prio": 2
		}, 
		{
			"EventId": 6,
			"Prio": 4
		},
		...
		]
	}
	
In the example above event 'write' (id 1) will get priority 2 and event 'lstat' (id 6) will get priority 4.
The Prio value should be between 0 and 4 (included). Any value strictly less than 0 will be considered as 0, and
any value strictly greater than 4 will be considered as 4. The smaller is the Priority number, the more critical the event is.`
}
