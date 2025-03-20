#!/usr/bin/bash

# Execute ls to trigger shared_object_loaded, security_file_mprotect
# and security_bprm_check events.

# shared_object_loaded (libc.so.6) – The dynamic linker loads libc.so.6, as
# ls is dynamically linked and requires it for execution.
# security_file_mprotect (/usr/bin/bash) – Memory protections for bash are
# temporarily changed (PROT_READ).
# security_bprm_check (/usr/bin/ls) – Bash executes ls -l, triggering an
# execution check via security_bprm_check.

ls -l
