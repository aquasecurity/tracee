---
title: TRACEE-ILLEGITIMATE-SHELL
section: 1
header: Tracee Event Manual
---

## NAME

**illegitimate_shell** - detect web servers spawning shell processes

## DESCRIPTION

This event detects when a web server program spawns a shell process. Under normal circumstances, web servers serve content and handle web requests without needing shell access. The presence of a shell being spawned by a web server often indicates a compromise, such as a web application vulnerability being exploited for command execution.

This detection is particularly important as web shells and command injection attacks are common methods for attackers to gain unauthorized access to web servers and execute arbitrary commands.

## SIGNATURE METADATA

- **ID**: TRC-1016
- **Version**: 1
- **Severity**: 2
- **Category**: initial-access
- **Technique**: Exploit Public-Facing Application
- **MITRE ID**: attack-pattern--3f886f2a-874f-4333-b794-aa6075009b1c
- **MITRE External ID**: T1190

## EVENT SETS

**signatures**, **default**

## DATA FIELDS

This signature event uses fields from the underlying security_bprm_check event:

**pathname** (*string*)
: Path to the shell being executed

**comm** (*string*)
: Name of the web server process

**interpreter** (*string*)
: Path to the interpreter if script execution

**stdin_type** (*string*)
: Type of standard input

## DEPENDENCIES

- `security_bprm_check`: Monitor program execution attempts

## USE CASES

- **Web security**: Detect web shell installations

- **Command injection**: Identify successful exploits

- **Intrusion detection**: Spot initial access attempts

- **Incident response**: Track compromise indicators

## SHELL EXECUTION PATTERNS

Suspicious patterns to monitor:

- Direct shell execution (sh, bash)
- Command interpreters (python, perl)
- System utilities (awk, sed)
- Network tools (nc, curl)
- Custom interpreters

## ATTACK VECTORS

Common exploitation methods:

- **Web shells**: Malicious web scripts
- **Command injection**: User input exploitation
- **File upload**: Malicious file execution
- **CGI exploitation**: Script parameter abuse

## RISK ASSESSMENT

Risk factors to consider:

- **Remote Access**: Shell provides system access
- **Command Execution**: Full system commands
- **Persistence**: Web shell remains active
- **Privilege Level**: Runs as web server user

## LEGITIMATE USES

Rare but valid scenarios:

- Maintenance scripts
- System health checks
- Automated backups
- Development debugging

## MITIGATION

Recommended security controls:

- Web application firewalls
- Input validation
- File upload restrictions
- Process execution controls
- Regular security audits

## RELATED EVENTS

- **security_bprm_check**: Binary execution checks
- **process_execute**: Process execution tracking
- **dropped_executable**: New executable detection
- **dynamic_code_loading**: Runtime code execution
