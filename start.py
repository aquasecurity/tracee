#!/usr/bin/python

# Authors:
#       Yaniv Agman <yaniv@aquasec.com>

# arguments
import argparse
import sys
import re

from tracee.tracer import EventMonitor, syscalls, sysevents

examples = """examples:
    ./start.py -c
"""

class EventsToTraceAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        events = re.split('\W+', values)
        for e in events:
            if e not in syscalls and e not in sysevents and e != "all":
                parser.error("Invalid event {0}".format(e))

        if "all" in events:
            events = syscalls + sysevents

        setattr(namespace, self.dest, events)


def parse_args(input_args):
    parser = argparse.ArgumentParser(
        description="Trace container syscalls and events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-c", "--container", action="store_true",
                        help="only trace newly created containers")
    parser.add_argument("-r", "--raw-syscalls", action="store_true",
                        help="trace raw syscalls")
    parser.add_argument("-b", "--buf-pages", type=int, default=64,
                        choices=[1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024],
                        help="number of pages for perf buffer, defaults to %(default)s")
    parser.add_argument("--ebpf", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("-j", "--json", action="store_true",
                        help="save events in json format")
    parser.add_argument("-l", "--list", action="store_true",
                        help="list events")
    parser.add_argument("-e", "--events", default = syscalls + sysevents, action=EventsToTraceAction,
                        help="trace only the specified events and syscalls (default: trace all)")
    parser.add_argument("--show-syscall", action="store_true",
                        help="show syscall name in kprobes")
    parser.add_argument("--exec-env", action="store_true",
                        help="show execve(at) environment variables in output")
    return parser.parse_args(input_args)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])

    event_monitor = EventMonitor(args)
    event_monitor.init_bpf()
    event_monitor.monitor_events()
