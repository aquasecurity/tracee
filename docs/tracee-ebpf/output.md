# Output Options

Control how and where output is printed.

## CLI Options

CLI Option | Description
--- | ---
`[format:]{table,table-verbose,json,gob,gotemplate=/path/to/template}` | output events in the specified format. for gotemplate, specify the mandatory template file
`out-file:/path/to/file` | write the output to a specified file. the path to the file will be created if not existing and the file will be deleted if existing (deafult: stdout)
`err-file:/path/to/file` | write the errors to a specified file. the path to the file will be created if not existing and the file will be deleted if existing (deafult: stderr)
`option:{stack-addresses,detect-syscall,exec-env}` | augment output according to given options (default: none)
  stack-addresses | include stack memory addresses for each event
  detect-syscall | when tracing kernel functions which are not syscalls, detect and show the original syscall that called that function
  exec-env | when tracing execve/execveat, show the environment variables that were used for execution

(Use this flag multiple times to choose multiple capture options)

## Examples

output as json

```
--output json
```

output as the provided go template

```
--output gotemplate=/path/to/my.tmpl
```

output to `/my/out` and errors to `/my/err`

```
--output out-file:/my/out err-file:/my/err
```
