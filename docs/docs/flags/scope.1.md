---
title: TRACEE-SCOPE
section: 1
header: Tracee Scope Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-scope** - Select the scope for tracing events

## SYNOPSIS

tracee **\-\-scope** [<[uid|pid][=|!=|<|\>|<=|\>=]value1(,value2...)\> | <[mntns|pidns|tree][=|!=]value1(,value2...)\> | <[uts|comm|container|[executable|exec|binary|bin]][=|!=]value1(,value2...)\>] | <not-container\> | <container[=|!=]value\> | <[container|pid]=new\> | <follow\>]  ...

## DESCRIPTION

The **\-\-scope** flag allows you to select the scope for tracing events by defining filters.

## FILTER EXPRESSION

Filter expressions can be defined to operate on scope options or process metadata. Only events that match all filter expressions will be traced.

Multiple flags are combined with AND logic, while multiple values within a single flag are combined with OR logic when using the equals operator '='. Multiple values can be specified using ','.

### NUMERICAL EXPRESSION OPERATORS

The following numerical fields support the operators '=', '!=', '<', '>', '<=', '>=':

- uid: Select events from specific user IDs.
- pid: Select events from specific process IDs.

The following numerical fields only support the operators '=' and '!=':

- mntns: Select events from specific mount namespace IDs.
- pidns: Select events from specific process namespace IDs.
- tree: Select events that descend from specific process IDs.

NOTE: Expressions containing '<' or '\>' tokens must be escaped!

### STRING EXPRESSION OPERATORS

'=', '!='

Available for the following string fields:

- uts: Select events based on UTS (Unix Timesharing System) names.
- comm: Select events based on process command names.
- container: Select events from specific container IDs.
- executable: Select events based on the executable path.

Strings can be compared as a prefix if ending with '\*', or as a suffix if starting with '\*'.

NOTE: Expressions containing '\*' token must be escaped!

### BOOLEAN OPERATOR (PREPENDED)

'!'

Available for the following boolean field:

- container: Select events based on whether they originate from a container or not.

## SPECIAL FILTERS

The following special filters can be used within the scope filter expressions:

- new: Select newly created containers or process IDs.
- follow: Select events from the processes that match the criteria and their descendants.

## EXAMPLES

- To trace only events from new processes, use the following flag:

  ```console
  --scope pid=new
  ```

- To trace only events from pid 510 or pid 1709, use the following flag:

  ```console
  --scope pid=510,1709
  ```

- To trace only events from pid 510 or pid 1709 (same as above), use the following flag:

  ```console
  --scope p=510 --scope p=1709
  ```

- To trace only events from newly created containers, use the following flag:

  ```console
  --scope container=new
  ```

- To trace only events from the container with ID 'ab356bc4dd554', use the following flag:

  ```console
  --scope container=ab356bc4dd554
  ```

- To trace only events from containers, use the following flag:

  ```console
  --scope container
  ```

- To only trace events from containers (same as above), use the following flag:

  ```console
  --scope c
  ```

- To trace only events from the host, use the following flag:

  ```console
  --scope not-container
  ```

- To trace only events from uid 0, use the following flag:

  ```console
  --scope uid=0
  ```

- To trace only events from mntns id 4026531840, use the following flag:

  ```console
  --scope mntns=4026531840
  ```

- To trace only events from pidns id not equal to 4026531836, use the following flag:

  ```console
  --scope pidns!=4026531836
  ```

- To trace only events that descend from the process with pid 476165, use the following flag:

  ```console
  --scope tree=476165
  ```

- To trace only events if they do not descend from the process with pid 5023, use the following flag:

  ```console
  --scope tree!=5023
  ```

- To trace only events if they descend from 3213 or 5200, but not 3215, use the following flag:

  ```console
  --scope tree=3213,5200 --scope tree!=3215
  ```

- To trace only events from uids greater than 0, use the following flag:

  ```console
  --scope 'uid>0'
  ```

- To trace only events from pids between 0 and 1000, use the following flag:

  ```console
  --scope 'pid>0' --scope 'pid<1000'
  ```

- To trace only events from uids greater than 0 but not 1000, use the following flag:

  ```console
  --scope 'u>0' --scope u!=1000
  ```

- To exclude events from uts name 'ab356bc4dd554', use the following flag:

  ```console
  --scope uts!=ab356bc4dd554
  ```

- To trace only events from the 'ls' command, use the following flag:

  ```console
  --scope comm=ls
  ```

- To trace only events from the '/usr/bin/ls' executable, use the executable flag (or the binary alias):

  ```console
  --scope executable=/usr/bin/ls
  ```

  ```console
  --scope binary=/usr/bin/ls
  ```

- To trace only events from the '/usr/bin/ls' executable in the host mount namespace, use the following flag:

  ```console
  --scope executable=host:/usr/bin/ls
  ```

- To trace only events from the '/usr/bin/ls' executable in the 4026532448 mount namespace, use the following flag:

  ```console
  --scope executable=4026532448:/usr/bin/ls
  ```

- To trace all events that originated from 'bash' or from one of the processes spawned by 'bash', use the following flag:

  ```console
  --scope comm=bash --scope follow
  ```
