#!/usr/bin/python

# arguments
import argparse
from container_tracer import EventMonitor

examples = """examples:
    ./start.py -v
"""
parser = argparse.ArgumentParser(
    description="Trace container syscalls and events",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--max-args", default="20",
    help="maximum number of arguments parsed and displayed, defaults to 20")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-v", "--verbose", action="store_true",
    help="print events to stdout")
args = parser.parse_args()


event_monitor = EventMonitor(args)
event_monitor.init_bpf()
event_monitor.monitor_events()