# do_sigaction

## Intro
do_sigaction - register new signal handler or get information about current one

## Description
The event marks that an attempt to get current task signal handler or to change the signal handler of the current task
for a specific signal occurred. Signal handler change mark the change of the program behavior, and might indicate
an attempt to defy expected signal behavior.
This event is relevant for each syscall related to signal handling - `rt_sigaction`, `sigaction` and `signal`.

## Arguments
* `sig`:`int`[K] - the signal that its handler is inspected or changed.
* `is_sa_initialized`:`bool`[K] - is a new signal handler given. If not, this event marks only inspection of data. If given, this will be the new handler for the event.
* `sa_flags`:`unsigned long`[K,OPT] - the flags given for the new signal handler. Passed only if `is_sa_initialized`=`true`.
* `sa_mask`:`unsigned long` [K,OPT] - the mask given for the new signal handler. Passed only if `is_sa_initialized`=`true`.
* `sa_handle_method`:`u8`[K,OPT] - the handling method of the new signal handler. Passed only if `is_sa_initialized`=`true`.
* `sa_handler`:`void*`[K,OPT] - the address of the new signal handling function if method is SIG_HND. Passed only if `is_sa_initialized`=`true`.
* `is_old_sa_initialized`:`bool`[K] - is an old signal handler given. If given, the old signal handler will be copied back to the caller.
* `old_sa_flags`:`unsigned long`[K] - the flags of the old signal handler
* `old_sa_mask`:`unsigned long`[K] - the mask of the old signal handler
* `old_sa_handle_method`:`u8`[K] - the handling method of the old signal handler
* `old_sa_handler`:`void*`[K] - the address of the old signal handling function if method was SIG_HND

### Handle Method
In the kernel, the handle method and the handler are united to one field.
To make it more accessible to the user, Tracee split the two apart.
Normally, the value can be one of the following: `SIG_DFL`(0), `SIG_IGN`(1) or pointer to user-mode handler function.
To deal with the case of a user-mode handler, the value `SIG_HND`(2) is created to specify that the method is by handler.

## Hooks
### do_sigaction
#### Type
kprobe
#### Purpose
The function implementing the signal handler inspection/modification for syscalls

## Related Events
`rt_sigaction`,`sigaction`,`signal`