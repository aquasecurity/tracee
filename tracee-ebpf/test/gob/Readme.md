### Testing tracee-ebpf gob output

```
cd tracee-ebpf
make
sudo ./dist/tracee-ebpf -o gob | go run test/gob/gob.go
```	
