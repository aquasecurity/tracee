---
title: TRACEE-FTRACE-HOOK
section: 1
header: Tracee Event Manual
---

## NAME

**ftrace_hook** - ftrace function hook detected

## DESCRIPTION

Triggered when an ftrace function hook is detected on the system. Ftrace hooks are kernel tracing mechanisms that can be used for legitimate system monitoring or potentially malicious purposes such as rootkits hiding their presence or intercepting system calls.

This event monitors the function tracing infrastructure to detect when functions are hooked, providing visibility into both legitimate kernel tracing activities and potential security threats.

This event is useful for:

- **Rootkit detection**: Identify malicious function hooks used by rootkits
- **Security monitoring**: Detect unauthorized kernel function interception
- **System analysis**: Monitor legitimate kernel tracing activities

## EVENT SETS

**none**

## DATA FIELDS

**symbol** (*string*)
: The symbol (function name) that is being hooked

**trampoline** (*string*)
: The name or address of the ftrace trampoline

**callback** (*string*)
: The callback name or address that will be called when the symbol is executed

**callback_offset** (*integer*)
: The callback offset inside the function

**callback_owner** (*string*)
: The owner of the callback (kernel module name if applicable)

**flags** (*string*)
: Ftrace flags indicating hook behavior:
- **R**: Registers are passed to the callback
- **I**: Callback can change the RIP register value
- **D**: Direct call to the function
- **O**: Callsite-specific operations
- **M**: Function has I or D flags

**count** (*integer*)
: The number of callbacks registered with the symbol

## DEPENDENCIES

**Self-triggered:**

- Uses internal kernel tracing mechanisms for detection

## USE CASES

- **Rootkit detection**: Identify kernel-level hooks used by rootkits

- **Security incident response**: Investigate unauthorized kernel modifications

- **System integrity monitoring**: Verify expected vs. actual kernel hooks

- **Forensic analysis**: Understand kernel hooking patterns during incidents

- **Compliance verification**: Ensure no unauthorized kernel modifications

## FLAG DESCRIPTIONS

Ftrace flags provide important context about hook behavior:

- **R (Registers)**: Hook receives CPU register state
- **I (IP modification)**: Hook can modify instruction pointer
- **D (Direct)**: Direct function call bypass
- **O (Ops-specific)**: Custom operation handling
- **M (Modified)**: Function has been modified with I or D flags

## RELATED EVENTS

- **hidden_kernel_module**: Hidden kernel module detection
- **hooked_syscall**: System call hook detection
- **symbols_loaded**: Symbol loading detection
- **syscall_table_hooking**: System call table modification detection