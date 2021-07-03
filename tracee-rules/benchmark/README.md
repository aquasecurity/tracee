# Benchmark

```
git clone https://github.com/aquasecurity/tracee.git
cd tracee-rules/benchmark
```

```
# Run all benchmark tests in the current directory
go test -tags=opa_wasm -bench=. -benchmem
# Run all benchmark tests in the current directory and specify b.N to equal 100
go test -tags=opa_wasm -bench=. -benchtime=100x -benchmem
# Run just BenchmarkEngineWithCodeInjecion signature implemented in Go with data race detector enabled
go test -race -bench=EngineWithCodeInjection/golang -benchmem
```
