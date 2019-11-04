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

    def test_execveat_flags_to_str(self):
        self.longMessage = True

        test_cases = [
            {
                "name": "invalid flags",
                "input": 0x666,
                "expected": "",
            },
            {
                "name": "empty path",
                "input": 0x1000,
                "expected": "AT_EMPTY_PATH",
            },
            {
                "name": "symlink no follow",
                "input": 0x100,
                "expected": "AT_SYMLINK_NOFOLLOW",
            },
            {
                "name": "symlink no follow with empty path",
                "input": 0x1100,
                "expected": "AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW",
            },
        ]
        for test_case in test_cases:
            self.assertEqual(test_case["expected"], tracee.container_tracer.execveat_flags_to_str(test_case["input"]),
                             test_case["name"])


if __name__ == '__main__':
    unittest.main()
