# <event_name>

## Intro

<event_name> - one sentence description of the event

## Description

Detailed description of the event. Should include:

* What is the purpose of the event?
* Are there any edge-cases, drawbacks or advantages of using it?

## Arguments

* `<arg#1>`:`<type>`[<tags>] - short description of the argument value. If the type or value might change (like with the `parse-arguments` flag) it should be elaborated here.
* `<arg#2>`:`<type>`[<tags>] - ...

### Available Tags

* K - Originated from kernel-space.
* U - Originated from user space.
* TOCTOU - Vulnerable to TOCTOU (time of check, time of use).
* OPT - Optional argument - might not always be available (passed with null value).

## Hooks

### <hooked_func#1>

#### Type

Type of probes or hooks used to hook this function.
If include more than one, should be in the form of <type1> + <type2>.

#### Purpose

Why was this function hooked?

### <hooked_func#2>

...

## Example Use Case

Example of a case where this event could be used.

## Issues

If there is an issue with this event, this is the place to write it.

## Related Events

Events connected by logic or interesting to be used in the context of the event.
