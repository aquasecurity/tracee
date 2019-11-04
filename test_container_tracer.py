import unittest
import tracee

from tracee.container_tracer import EventMonitor


class TestEventMonitor(unittest.TestCase):
    def test_load_bpf_program(self):
        self.longMessage = True

        with open(tracee.container_tracer.BPF_PROGRAM, "r") as f:
            expectedbpf = f.read()

        actualbpf = tracee.container_tracer.load_bpf_program()
        self.assertEqual(expectedbpf, actualbpf, "should be a valid bpf program")


if __name__ == '__main__':
    unittest.main()
