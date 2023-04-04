Configure log severity:

```console
sudo ./dist/tracee --log debug
```

Redirect logs to a file if needed:

```console
sudo ./dist/tracee --filter comm=bash --filter follow --filter event=openat --output json:/tmp/tracee.events --log file:/tmp/tracee.log
```

Logs can be aggregated for a given interval to delay its output:

```console
sudo ./dist/tracee --log debug --log aggregate:5s
```


