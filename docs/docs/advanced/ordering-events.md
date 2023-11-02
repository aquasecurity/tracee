# Special: Ordering Events

Package sorting feature is responsible for sorting incoming events from the BPF
programs chronologically.

```console
sudo ./dist/tracee \
    -o json \
    -o option:parse-arguments \
    -o option:sort-events
```

!!! Information
    There are **3 known** sources to events **sorting issues**:
    
      1. In perf buffer, events are read in round robing order from CPUs buffers
         (and not according to invocation time).
    
      2. Syscall events are invoked after internal events of the syscall (though
         the syscall happened before the internal events).
    
      3. Virtual CPUs might enter sleep mode by host machine scheduler and send
         events after some delay.


## Deep Dive Into Sorting Feature

To address the events perf buffers issue, the events are **divided to queues
according to the source CPU**. This way the events are almost ordered (except
for syscalls). The syscall events are inserted to their right chronological
place manually.

This way, **all events which occurred before the last event** of the **most
delaying CPU** could be sent forward with guaranteed order.

To make sure **syscall events are not missed** when sending, a **small delay**
is needed. Lastly, to address the **vCPU sleep issue** (which might cause up to
2 events received in a delay), the events need to be sent **after a delay which
is bigger than max possible vCPU sleep time** (which is just an increase of the
syscall events delay sending).

## Algorithm for Nerds =D

To summarize the algorithm main logic, here is textual simulation of the
operation (assume that 2 scheduler ticks are larger than max possible vCPU
sleep time):  

Tn = Timestamp (n == TOD)  
\#m = Event's Source CPU  

1. Initial State

    ```text
           [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
      HEAD    T1           T2           T4
              T3           T5
              T6
      TAIL    T8
    ```

2. Scheduler Tick #1

    ```text
    Incoming events: T9#1, T11#2, T13#1, T10#2, T12#2
    
    Queues state after insert:
           [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
      HEAD    T1           T2           T4
              T3           T5           T10 +
              T6           T9  +        T11 +
      TAIL    T8           T13 +        T12 +
    
      - No event sent.
      - Oldest timestamp = T1.
      - T8 is oldest timestamp in most recent timestamps.
      - In 2 ticks from now: send all events up to T8.
      - Bigger timestamps than T8 (+) will be sent in future scheduling.
    ```

3. Scheduler Tick #2

    ```text
    Incoming events: T7#0, T22#1, T23#2, T20#0, T25#1, T24#2, T21#0
    
    Queues state after insert:
           [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
      HEAD    T1  ^        T2  ^        T4  ^
              T3  ^        T5  ^        T10
              T6  ^        T9           T11
              T7  +^       T13          T12
              T8  ^        T22 +        T23 +
              T20 +        T25 +        T24 +
      TAIL    T21 +
    
      - No event sent.
      - Oldest timestamp = T1.
      - T21 is oldest timestamp in most recent timestamps.
      - In 2 ticks from now: send all events up to T21.
      - T8 is previous oldest timestamp in most recent timestamps.
      - Next tick: send all events up to T8.
      - Bigger timestamps than T21 (+) will be sent in future scheduling.
    ```

4. Scheduler Tick #3

    ```text
    Incoming events: T30#0, T34#1, T35#2, T31#0, T36#2, T32#0, T37#2, T33#0, T38#2, T50#1, T51#1
    
    Queues state after insert:
           [ CPU 0 ]    [ CPU 1 ]    [ CPU 2 ]
      HEAD    T20 ^        T9  ^        T10 ^
              T21 ^        T13 ^        T11 ^
              T30 +        T22          T12 ^
              T31 +        T23          T24
              T32 +        T25          T35 +
              T33 +        T34 +        T36 +
                           T50 +        T37 +
       TAIL                T51 +        T38 +
    
      - Max sent timestamp = T8.
      - Oldest timestamp = T9.
      - T33 is oldest timestamp in most recent timestamps.
      - In 2 ticks from now: send all events up to T33.
      - T21 is previous oldest timestamp in most recent timestamps.
      - Next tick: send all events up to T21.
      - Bigger timestamps than T33 (+) will be sent in future scheduling.
    ```
