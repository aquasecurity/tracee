#!/usr/bin/python

# Authors:
#       Yaniv Agman <yaniv@aquasec.com>

# arguments
import argparse
import sys

from tracee.container_tracer import EventMonitor

examples = """examples:
    ./start.py -v
"""


def parse_args(input_args):
    parser = argparse.ArgumentParser(
        description="Trace container syscalls and events",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("--max-args", default="20",
                        help="maximum number of arguments parsed and displayed, defaults to 20")
    parser.add_argument("--ebpf", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("-j", "--json", action="store_true",
                        help="save events in json format")
    # args = parser.parse_args()
    return parser.parse_args(input_args)


if __name__ == '__main__':
    args = parse_args(sys.argv[1:])

    event_monitor = EventMonitor(args)
    event_monitor.init_bpf()
    event_monitor.monitor_events()
