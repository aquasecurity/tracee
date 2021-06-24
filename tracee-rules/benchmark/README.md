# Benchmark

```
cd tracee-rules/benchmark
```

```
# Run all benchmark tests in the current directory
go test -bench=. -benchmem
# Run all benchmark tests in the current directory and spcify b.N to equal 100
go test -bench=. -benchtime=100x -benchmem
# Run just BenchmarkEngineWithCodeInjecionRuleGp test
go test -bench=EngineWithCodeInjectionRuleGo -benchmem
```
