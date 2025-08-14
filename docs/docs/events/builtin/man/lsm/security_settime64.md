---
title: TRACEE-SECURITY-SETTIME64
section: 1
header: Tracee Event Manual
---

## NAME

**security_settime64** - security check for system time modification

## DESCRIPTION

Triggered when a process attempts to modify the system time. This LSM (Linux Security Module) hook event captures the security check performed before the system time is changed, providing visibility into time-related system modifications.

The event provides detailed information about the requested time change, including both seconds and nanoseconds components, as well as timezone adjustments. This visibility is crucial for security monitoring as system time modifications can affect logging, authentication, and other time-dependent security mechanisms.

This event is useful for:

- **Time change monitoring**: Track system time modifications
- **Security auditing**: Detect unauthorized time changes
- **Compliance verification**: Monitor time synchronization
- **System integrity**: Track time-based security controls

## EVENT SETS

**none**

## DATA FIELDS

**tv_sec** (*uint64*)
: The time in seconds

**tv_nsec** (*uint64*)
: The time in nanoseconds

**tz_minuteswest** (*int32*)
: Minutes west of Greenwich

**tz_dsttime** (*int32*)
: Type of DST correction

## DEPENDENCIES

**LSM Hook:**

- security_settime64 (required): LSM hook for system time modification security checks

## USE CASES

- **Security monitoring**: Detect unauthorized time changes

- **Compliance auditing**: Track time synchronization events

- **System integrity**: Monitor time-based security controls

- **Forensic analysis**: Track time manipulation attempts

- **Configuration monitoring**: Verify time and timezone settings

## TIME COMPONENTS

The event captures multiple time aspects:

- **Seconds**: Unix timestamp in seconds
- **Nanoseconds**: Sub-second precision
- **Timezone offset**: Minutes west of GMT
- **DST settings**: Daylight saving time configuration

## SECURITY IMPLICATIONS

Critical security aspects to monitor:

- **Log manipulation**: Through time rollbacks
- **Certificate validation**: Through time advancement
- **Authentication bypass**: Through time-based token manipulation
- **Audit trail integrity**: Through time desynchronization
- **Service disruption**: Through time jumps

## TIMEZONE CONSIDERATIONS

Important timezone aspects:

- **UTC offset**: Minutes west of Greenwich
- **DST handling**: Daylight saving time transitions
- **Time zones**: Geographic time zone changes
- **Local time**: System local time settings

## RELATED EVENTS

- **settimeofday**: System call for setting time
- **clock_settime**: Clock setting system call
- **adjtimex**: Time adjustment system call
- **ntp_adjtime**: NTP time adjustment events
