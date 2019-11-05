import ctypes
import unittest
import tracee
import start

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

    # TODO: Add additional test cases for file modes
    def test_open_flags_to_str(self):
        self.longMessage = True

        test_cases = [
            {
                "name": "open for write only",
                "input": 0o1,
                "expected": "O_WRONLY",
            },
            {
                "name": "open for read and write",
                "input": 0o2,
                "expected": "O_RDWR",
            },
            {
                "name": "open for read only",
                "input": 0o4,
                "expected": "O_RDONLY",
            },
            {
                "name": "open for create with read only",
                "input": 0o100,
                "expected": "O_RDONLY|O_CREAT",
            },
            {
                "name": "open for create with write only",
                "input": 0o101,
                "expected": "O_WRONLY|O_CREAT",
            },
            {
                "name": "open for create with read and write",
                "input": 0o102,
                "expected": "O_RDWR|O_CREAT",
            },
            {
                "name": "open for exclusive with read only",
                "input": 0o200,
                "expected": "O_RDONLY|O_EXCL",
            },
            {
                "name": "open for exclusive with write only",
                "input": 0o201,
                "expected": "O_WRONLY|O_EXCL",
            },
            {
                "name": "open for exclusive with read and write",
                "input": 0o202,
                "expected": "O_RDWR|O_EXCL",
            },
            {
                "name": "open for no ctty with read only",
                "input": 0o400,
                "expected": "O_RDONLY|O_NOCTTY",
            },
            {
                "name": "open for no ctty with write only",
                "input": 0o401,
                "expected": "O_WRONLY|O_NOCTTY",
            },
            {
                "name": "open for no ctty with read and write",
                "input": 0o402,
                "expected": "O_RDWR|O_NOCTTY",
            },
        ]

        for test_case in test_cases:
            self.assertEqual(test_case["expected"], tracee.container_tracer.open_flags_to_str(test_case["input"]),
                             test_case["name"])

    def test_get_sockaddr_from_buf(self):
        self.longMessage = True

        em = tracee.container_tracer.EventMonitor(start.parse_args([]))

        test_cases = [
            {
                "name": "unix type socket",
                "input": 1,
                "expected_sock_type": "AF_UNIX",
                "expected_cur_off": 2,
            },
            {
                "name": "unknown type socket",
                "input": 123,
                "expected_sock_type": "123",
                "expected_cur_off": 2,
            },
        ]

        for test_case in test_cases:
            sockaddr_str = em.get_sockaddr_from_buf(ctypes.c_short(test_case["input"]))
            self.assertEqual(test_case["expected_sock_type"], sockaddr_str, "returned sock_type should be equal")
            self.assertEqual(test_case["expected_cur_off"], em.cur_off, "current offset should be 2")


if __name__ == '__main__':
    unittest.main()
