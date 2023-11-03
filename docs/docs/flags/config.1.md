---
title: TRACEE-CONFIG
section: 1
header: Tracee Config Flag Manual
date: 2023/10
...

## NAME

tracee **\-\-config** - Define global configuration options for tracee

## SYNOPSIS

tracee **\-\-config** <file\>

## DESCRIPTION

The **\-\-config** flag allows you to define global configuration options (flags) for tracee. It expects a file in YAML or JSON format, among others (see [documentation](../install/config/kubernetes.md)).

All flags can be set in the config file, except for the following, which are reserved only for the CLI:

- **\-\-config**: This flag itself is reserved for the CLI and should not be set in the config file.
- **\-\-capture**
- **\-\-policy**
- **\-\-scope**
- **\-\-event**

Please refer to the [documentation](../install/config/kubernetes.md) for more information on the file format and available configuration options.
