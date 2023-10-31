# Event Filtering

Tracee output might become too hard to consume when tracing all the events from
a system. Luckily, Tracee has a powerful mechanism to accurately filter just the
information that is relevant to the user using the `--scope` and `--events` flags.

With those command line flags you define expressions that tell **tracee**
what you are interested in based on event metadata filtering
capabilities. Only events that match given criteria will be traced.

!!! Tip
    You can filter events by most of the visible fields from Tracee events.
