# Benchmark

The `tracee-rules` binary implements pluggable heuristics to detect suspicious behavioral patterns based on events
collected by the `tracee-ebpf` binary. By default, `tracee-ebpf` binary prints events to the standard output, which is
redirected to the standard input of the `tracee-rules` binary:

```console
tracee-ebpf --output=format:gob --filter event=mem_prot_alert | tracee-rules --input-tracee=file:stdin --input-tracee=format:gob
```

The heuristics implemented by `tracee-rules` are either Go or Rego signatures loaded on startup as Go plugins or Rego
scripts. Input events captured by `tracee-ebpf` are read from the standard input, decoded, and sent on the Go input
events channel. All signatures "subscribe" to Go input channel and consume events by processing **one event at
a time** (no batch). One can load tens or hundreds of different signatures of each type. Notice that Rego signatures
**do not share** the Rego object.

For example, the `signature.rego` is a typical rule that inspects the input `event.json` to detect anti debugging attempts:

```rego
# signature.rego
package tracee.TRC_2

__rego_metadoc__ := {
  "id": "TRC-2",
  "version": "0.1.0",
  "name": "Anti-Debugging",
  "description": "Process uses anti-debugging technique to block debugger",
  "tags": ["linux", "container"],
  "properties": {
    "Severity": 3,
    "MITRE ATT&CK": "Defense Evasion: Execution Guardrails",
  }
}

tracee_selected_events[eventSelector] {
  eventSelector := {
    "source": "tracee",
    "name": "ptrace"
  }
}

tracee_match {
  input.eventName == "ptrace"
  arg := input.args[_]
  arg.name == "request"
  arg.value == "PTRACE_TRACEME"
}
```

```json
{
   "timestamp":           5323.321532,
   "processID":           1,
   "threadID":            1,
   "parentProcessID":     3788,
   "hostProcessID":       3217,
   "hostThreadID":        3217,
   "hostParentProcessID": 3788,
   "userID":              0,
   "mountNS":             2983424533,
   "PIDNS":               2983424536,
   "processName":         "malware",
   "hostName":            "234134134ab",
   "eventID":             521,
   "eventName":           "ptrace",
   "argsNum":             2,
   "returnValue":         124,
   "args": [
     {
       "argMeta": {
         "name": "request"
       },
       "value": "PTRACE_TRACEME"
     }
  ]
}
```

The goal of this benchmark is to:

- [ ] Find out how `tracee-rules` scales with the number of signatures.
- [ ] Measure the overhead of Rego signatures (OPA embedded as a Go library) versus Go signatures (local method invocation).
- [ ] Compare OPA `rego` versus OPA `wasm` targets when evaluating signatures.

There are two types of benchmark tests:
- `BenchmarkOnEvent*` benchmark a signature in isolation by invoking its `OnEvent` method with a single input event
  passed as the argument
- `BenchmarkEngine*` benchmark a signature with rules engine started and the stream of 1000 input events

## Sample Results

### Hardware and Software

| Property      | Value                         |
|---------------|-------------------------------|
| Computer      | iMac Retina 5K, 27-inch, 2019 |
| Processor     | 3,6 GHz 8-Core Intel Core i9  |
| Memory        | 32 GB 2667 MHz DDR4           |
| OS            | macOS Big Sur<br>Version 11.4 |
| Go version    | 1.16.5 darwin/amd64           |

### Number of Signatures

#### Go Noop

```console
go test -bench=EngineWithNSignatures/noop -benchtime=100x -benchmem
```

```text
goos: darwin
goarch: amd64
pkg: github.com/aquasecurity/tracee/pkg/rules/benchmark
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngineWithNSignatures/noop/2Signatures-16         	     100	   1301712 ns/op	     529 B/op	       3 allocs/op
BenchmarkEngineWithNSignatures/noop/4Signatures-16         	     100	   1327458 ns/op	     637 B/op	       3 allocs/op
BenchmarkEngineWithNSignatures/noop/8Signatures-16         	     100	   1304873 ns/op	     502 B/op	       4 allocs/op
BenchmarkEngineWithNSignatures/noop/16Signatures-16        	     100	   1269636 ns/op	     878 B/op	       8 allocs/op
BenchmarkEngineWithNSignatures/noop/32Signatures-16        	     100	   1249964 ns/op	    1826 B/op	      16 allocs/op
BenchmarkEngineWithNSignatures/noop/64Signatures-16        	     100	   1257590 ns/op	    4048 B/op	      41 allocs/op
BenchmarkEngineWithNSignatures/noop/128Signatures-16       	     100	   1241413 ns/op	    9333 B/op	     100 allocs/op
PASS
ok  	github.com/aquasecurity/tracee/pkg/rules/benchmark	1.639s
```

#### Go

```console
go test -bench=EngineWithNSignatures/golang -benchtime=100x -benchmem
```

```text
goos: darwin
goarch: amd64
pkg: github.com/aquasecurity/tracee/pkg/rules/benchmark
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngineWithNSignatures/golang/2Signatures-16         	     100	   2163504 ns/op	  473897 B/op	    4030 allocs/op
BenchmarkEngineWithNSignatures/golang/4Signatures-16         	     100	   3153459 ns/op	  946281 B/op	    7998 allocs/op
BenchmarkEngineWithNSignatures/golang/8Signatures-16         	     100	   4161725 ns/op	 1782167 B/op	   16011 allocs/op
BenchmarkEngineWithNSignatures/golang/16Signatures-16        	     100	   5799148 ns/op	 3439889 B/op	   32126 allocs/op
BenchmarkEngineWithNSignatures/golang/32Signatures-16        	     100	   9474728 ns/op	 6706250 B/op	   64136 allocs/op
BenchmarkEngineWithNSignatures/golang/64Signatures-16        	     100	  17449105 ns/op	13234869 B/op	  128030 allocs/op
BenchmarkEngineWithNSignatures/golang/128Signatures-16       	     100	  33983570 ns/op	26490405 B/op	  255662 allocs/op
PASS
ok  	github.com/aquasecurity/tracee/pkg/rules/benchmark	8.415s
```

#### OPA `rego` Target

```console
go test -bench=EngineWithNSignatures/rego -benchtime=100x -benchmem
```

```text
goos: darwin
goarch: amd64
pkg: github.com/aquasecurity/tracee/pkg/rules/benchmark
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngineWithNSignatures/rego/2Signatures-16         	     100	  13850918 ns/op	11435425 B/op	  241931 allocs/op
BenchmarkEngineWithNSignatures/rego/4Signatures-16         	     100	  21849863 ns/op	23076399 B/op	  486469 allocs/op
BenchmarkEngineWithNSignatures/rego/8Signatures-16         	     100	  37441545 ns/op	45798750 B/op	  967174 allocs/op
BenchmarkEngineWithNSignatures/rego/16Signatures-16        	     100	  56402273 ns/op	91420207 B/op	 1938903 allocs/op
BenchmarkEngineWithNSignatures/rego/32Signatures-16        	     100	  84383169 ns/op	183565424 B/op	 3895568 allocs/op
BenchmarkEngineWithNSignatures/rego/64Signatures-16        	     100	 146659052 ns/op	360762744 B/op	 7659578 allocs/op
BenchmarkEngineWithNSignatures/rego/128Signatures-16       	     100	 285815478 ns/op	728968827 B/op	15477259 allocs/op
PASS
ok  	github.com/aquasecurity/tracee/pkg/rules/benchmark	66.856s
```

#### OPA `wasm` Target

```console
go test -tags=opa_wasm -bench=EngineWithNSignatures/wasm -benchmem
```

```text
goos: darwin
goarch: amd64
pkg: github.com/aquasecurity/tracee/pkg/rules/benchmark
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkEngineWithNSignatures/wasm/2Signatures-16         	       2	 514803519 ns/op	100335968 B/op	 3286271 allocs/op
BenchmarkEngineWithNSignatures/wasm/4Signatures-16         	       2	 795849985 ns/op	199761468 B/op	 6532683 allocs/op
BenchmarkEngineWithNSignatures/wasm/8Signatures-16         	       2	1079399668 ns/op	396760096 B/op	12990511 allocs/op
BenchmarkEngineWithNSignatures/wasm/16Signatures-16        	       1	1284956028 ns/op	791910312 B/op	25900972 allocs/op
BenchmarkEngineWithNSignatures/wasm/32Signatures-16        	       1	2447603349 ns/op	1580583920 B/op	51730795 allocs/op
BenchmarkEngineWithNSignatures/wasm/64Signatures-16        	       1	4953602994 ns/op	3174994912 B/op	103727996 allocs/op
BenchmarkEngineWithNSignatures/wasm/128Signatures-16       	       1	11184859051 ns/op	6314287224 B/op	206598951 allocs/op
PASS
ok  	github.com/aquasecurity/tracee/pkg/rules/benchmark	118.785s
```

### OPA Overhead

```console
go test -tags=opa_wasm -bench=OnEventWithCodeInjectionSignature -benchtime=1000x -benchmem
```

```text
goos: darwin
goarch: amd64
pkg: github.com/aquasecurity/tracee/pkg/rules/benchmark
cpu: Intel(R) Core(TM) i9-9900K CPU @ 3.60GHz
BenchmarkOnEventWithCodeInjectionSignature/rego-16         	    1000	     37893 ns/op	   18557 B/op	     381 allocs/op
BenchmarkOnEventWithCodeInjectionSignature/golang-16       	    1000	       643.0 ns/op	     784 B/op	       6 allocs/op
BenchmarkOnEventWithCodeInjectionSignature/wasm-16         	    1000	    386341 ns/op	   47215 B/op	    1564 allocs/op
PASS
ok  	github.com/aquasecurity/tracee/pkg/rules/benchmark	1.327s
```

## Summary

Apparently `tracee-rules` does not scale well with the number of signatures. With increasing number of signatures
(2, 4, 8, 16, 32, 64, 128) the performance overhead has a linear growth. With hundreds or thousands of signatures
the rules engine can become relatively slow.

### CPU and Memory Profiling

Some observations running the CPU and memory profiler on `BenchmarkOnEvent*` tests.

#### OPA `wasm` Target

```console
go test -tags=opa_wasm -bench=OnEventWithCodeInjectionSignature/wasm -benchtime=10000x \
  -cpuprofile wasm.cpu.prof -memprofile wasm.mem.prof
```

```console
go tool pprof wasm.cpu.prof
```

```text
Type: cpu
Time: Jul 5, 2021 at 11:51pm (CEST)
Duration: 5.11s, Total samples = 7.50s (146.91%)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 7.24s, 96.53% of 7.50s total
Dropped 114 nodes (cum <= 0.04s)
Showing top 10 nodes out of 117
      flat  flat%   sum%        cum   cum%
     3.77s 50.27% 50.27%      3.78s 50.40%  runtime.cgocall
     2.20s 29.33% 79.60%      2.20s 29.33%  runtime.pthread_cond_signal
     0.51s  6.80% 86.40%      0.52s  6.93%  runtime.pthread_cond_wait
     0.40s  5.33% 91.73%      0.40s  5.33%  runtime.nanotime1
     0.20s  2.67% 94.40%      0.20s  2.67%  runtime.pthread_kill
     0.06s   0.8% 95.20%      0.06s   0.8%  runtime.madvise
     0.05s  0.67% 95.87%      0.05s  0.67%  runtime.kevent
     0.03s   0.4% 96.27%      0.05s  0.67%  runtime.scanobject
     0.01s  0.13% 96.40%      0.28s  3.73%  github.com/bytecodealliance/wasmtime-go.mkInstanceType.func1.1
     0.01s  0.13% 96.53%      0.04s  0.53%  runtime.handoff
```

```console
go tool pprof wasm.mem.prof
```

```text
Type: alloc_space
Time: Jul 5, 2021 at 11:51pm (CEST)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 268.54MB, 57.61% of 466.13MB total
Dropped 103 nodes (cum <= 2.33MB)
Showing top 10 nodes out of 135
      flat  flat%   sum%        cum   cum%
   65.50MB 14.05% 14.05%    65.50MB 14.05%  github.com/bytecodealliance/wasmtime-go.mkExtern
   44.50MB  9.55% 23.60%    44.50MB  9.55%  github.com/bytecodealliance/wasmtime-go.mkExportType
   37.50MB  8.05% 31.64%    37.50MB  8.05%  github.com/bytecodealliance/wasmtime-go._Cfunc_GoStringN (inline)
   21.01MB  4.51% 36.15%    24.01MB  5.15%  github.com/open-policy-agent/opa/ast.valueToInterface
   19.50MB  4.18% 40.34%    19.50MB  4.18%  github.com/open-policy-agent/opa/ast.(*Parser).save
   19.50MB  4.18% 44.52%   248.51MB 53.31%  github.com/open-policy-agent/opa/internal/wasm/sdk/internal/wasm.callOrCancel
   16.51MB  3.54% 48.06%    24.01MB  5.15%  encoding/json.(*decodeState).objectInterface
      16MB  3.43% 51.50%       16MB  3.43%  github.com/bytecodealliance/wasmtime-go.(*ExportType).Name.func1
   14.50MB  3.11% 54.61%       59MB 12.66%  github.com/bytecodealliance/wasmtime-go.(*exportTypeList).mkGoList
      14MB  3.00% 57.61%       81MB 17.38%  github.com/bytecodealliance/wasmtime-go.(*Instance).Exports
```

#### OPA `rego` Target

```console
go test -bench=OnEventWithCodeInjectionSignature/rego -benchtime=10000x \
  -cpuprofile rego.cpu.prof -memprofile rego.mem.prof
```

```console
go tool pprof rego.cpu.prof
```

```text
Type: cpu
Time: Jul 5, 2021 at 11:59pm (CEST)
Duration: 500.28ms, Total samples = 610ms (121.93%)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 540ms, 88.52% of 610ms total
Showing top 10 nodes out of 103
      flat  flat%   sum%        cum   cum%
     300ms 49.18% 49.18%      300ms 49.18%  runtime.pthread_cond_signal
      60ms  9.84% 59.02%       60ms  9.84%  runtime.usleep
      50ms  8.20% 67.21%       50ms  8.20%  runtime.pthread_cond_wait
      50ms  8.20% 75.41%       50ms  8.20%  runtime.pthread_kill
      30ms  4.92% 80.33%       30ms  4.92%  runtime.nanotime1
      10ms  1.64% 81.97%       10ms  1.64%  github.com/open-policy-agent/opa/ast.(*object).insert
      10ms  1.64% 83.61%       10ms  1.64%  runtime.findObject
      10ms  1.64% 85.25%       10ms  1.64%  runtime.findnull
      10ms  1.64% 86.89%      120ms 19.67%  runtime.gcDrain
      10ms  1.64% 88.52%       10ms  1.64%  runtime.gentraceback
```

```console
go tool pprof rego.mem.prof
```

```text
Type: alloc_space
Time: Jul 5, 2021 at 11:59pm (CEST)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 96.03MB, 55.92% of 171.71MB total
Dropped 20 nodes (cum <= 0.86MB)
Showing top 10 nodes out of 110
      flat  flat%   sum%        cum   cum%
   19.01MB 11.07% 11.07%    24.01MB 13.98%  encoding/json.(*decodeState).objectInterface
   12.51MB  7.28% 18.36%    12.51MB  7.28%  github.com/open-policy-agent/opa/ast.newobject (inline)
   12.50MB  7.28% 25.64%    12.50MB  7.28%  github.com/open-policy-agent/opa/ast.NewTerm (inline)
      11MB  6.41% 32.04%       11MB  6.41%  github.com/open-policy-agent/opa/util.(*HashMap).Put
    8.50MB  4.95% 36.99%     8.50MB  4.95%  github.com/open-policy-agent/opa/topdown.(*bindingsArrayHashmap).Put
       7MB  4.08% 41.07%        9MB  5.24%  github.com/open-policy-agent/opa/topdown.(*eval).child (inline)
       7MB  4.08% 45.15%    38.01MB 22.13%  github.com/open-policy-agent/opa/ast.InterfaceToValue
    6.50MB  3.79% 48.93%     6.50MB  3.79%  github.com/open-policy-agent/opa/ast.(*object).insert
    6.50MB  3.79% 52.72%     6.50MB  3.79%  github.com/open-policy-agent/opa/util.NewHashMap (inline)
    5.50MB  3.20% 55.92%    20.50MB 11.94%  github.com/open-policy-agent/opa/topdown.(*Query).Iter
```

#### Go

```console
go test -bench=OnEventWithCodeInjectionSignature/golang -benchtime=1000000x \
  -cpuprofile golang.cpu.prof -memprofile golang.mem.prof
```

```console
go tool pprof golang.cpu.prof
```

```text
Type: cpu
Time: Jul 6, 2021 at 12:05am (CEST)
Duration: 801.38ms, Total samples = 790ms (98.58%)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 570ms, 72.15% of 790ms total
Showing top 10 nodes out of 95
      flat  flat%   sum%        cum   cum%
     280ms 35.44% 35.44%      280ms 35.44%  runtime.kevent
      70ms  8.86% 44.30%       70ms  8.86%  runtime.pthread_cond_wait
      60ms  7.59% 51.90%       60ms  7.59%  runtime.pthread_kill
      30ms  3.80% 55.70%      140ms 17.72%  runtime.mallocgc
      30ms  3.80% 59.49%       40ms  5.06%  runtime.scanobject
      20ms  2.53% 62.03%       20ms  2.53%  runtime.findfunc
      20ms  2.53% 64.56%       20ms  2.53%  runtime.heapBitsSetType
      20ms  2.53% 67.09%       20ms  2.53%  runtime.madvise
      20ms  2.53% 69.62%       20ms  2.53%  runtime.memclrNoHeapPointers
      20ms  2.53% 72.15%       20ms  2.53%  runtime.pthread_cond_signal
```

```console
go tool pprof golang.mem.prof
```

```text
Type: alloc_space
Time: Jul 6, 2021 at 12:05am (CEST)
Entering interactive mode (type "help" for commands, "o" for options)
(pprof) top 10
Showing nodes accounting for 757.66MB, 99.80% of 759.18MB total
Dropped 7 nodes (cum <= 3.80MB)
      flat  flat%   sum%        cum   cum%
  534.12MB 70.35% 70.35%   534.12MB 70.35%  github.com/aquasecurity/tracee/pkg/rules/benchmark/signature/golang.(*codeInjection).OnEvent
  223.54MB 29.45% 99.80%   757.66MB 99.80%  github.com/aquasecurity/tracee/pkg/rules/benchmark.BenchmarkOnEventWithCodeInjectionSignature.func1
         0     0% 99.80%   757.66MB 99.80%  testing.(*B).launch
         0     0% 99.80%   757.66MB 99.80%  testing.(*B).runN
```

## Running Tests

```console
git clone https://github.com/aquasecurity/tracee.git
cd tracee/tracee-rules/benchmark
```

```console
# Run all benchmark tests in the current directory
go test -tags=opa_wasm -bench=. -benchmem
# Run all benchmark tests in the current directory and specify b.N to equal 100
go test -tags=opa_wasm -bench=. -benchtime=100x -benchmem
# Run just BenchmarkEngineWithCodeInjecionSignature test with Rego signature and WASM target
go test -tags=opa_wasm -bench=EngineWithCodeInjectionSignature/wasm -benchmem
# Run benchmark with CPU and memory profiling
go test -tags=opa_wasm -bench=OnEventWithCodeInjectionSignature/wasm \
  -benchmem -benchtime=100x \
  -cpuprofile wasm.cpu.prof -memprofile wasm.mem.prof
```
