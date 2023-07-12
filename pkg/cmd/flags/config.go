package flags

func configHelp() string {
	return `The --config flag allows you to define global configuration options (flags)
for tracee, by providing a file in YAML or JSON format between others (see documentation).

All flags can be set in the config file, except for the following, which are reserved only
for the CLI:
  --config (this flag)
  --capture
  --policy
  --scope
  --event
`
}
