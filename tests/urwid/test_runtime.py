"""Exercise the Urwid runtime's private event channel and TTY restoration."""

import errno
import io
import json
import os
import signal
import sys
import time
import unittest
from unittest.mock import patch

import runtime

if os.name == "posix":
    import fcntl
    import pty
    import select
    import struct
    import termios


def frame(event_type, **fields):
    return json.dumps(dict(type=event_type, **fields)).encode("utf-8") + b"\n"


class RuntimeProtocolTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.channel = runtime.WorkbenchChannel()

    def receive(self, data):
        return self.channel.receive(data, self.events.append)

    def test_split_frame_and_batched_progress_and_state(self):
        progress = frame("progress", complete=0, count=1, id="V-230264")
        state = frame("state", context={}, reset_selection=True, rows=[{"id": "V-230264"}])
        self.assertTrue(self.receive(progress[:14]))
        self.assertEqual(self.events, [])
        self.assertTrue(self.receive(progress[14:] + state))
        self.assertEqual([event["type"] for event in self.events], ["progress", "state"])

    def test_disconnect_after_a_complete_frame_and_during_a_frame(self):
        self.receive(frame("notice", message="Fixture notice"))
        with self.assertRaisesRegex(ValueError, "before the session ended"):
            self.receive(b"")
        self.receive(b'{"type":"state"')
        with self.assertRaisesRegex(ValueError, "during a message"):
            self.receive(b"")

    def test_terminal_event_must_match_the_operator_command(self):
        with patch.object(runtime, "send_to_backend") as sent:
            self.channel.send("accept", "fixture-token")
        sent.assert_called_once_with("accept", "fixture-token")
        with self.assertRaisesRegex(ValueError, "unexpected session acknowledgement"):
            self.receive(frame("closed"))
        self.assertTrue(self.receive(frame("accepted")))
        self.assertFalse(self.receive(b""))
        self.assertEqual(self.events, [])

    def test_error_clears_acknowledgement_until_an_explicit_retry(self):
        with patch.object(runtime, "send_to_backend"):
            self.channel.send("accept", "first-token")
            self.receive(frame("error", message="Review the scope again."))
            with self.assertRaisesRegex(ValueError, "unexpected session acknowledgement"):
                self.receive(frame("accepted"))
            self.channel.send("accept", "second-token")
        self.receive(frame("accepted"))
        self.assertFalse(self.receive(b""))
        self.assertEqual(self.events[0]["type"], "error")

    def test_terminal_event_must_be_last_in_its_batch(self):
        with patch.object(runtime, "send_to_backend"):
            self.channel.send("cancel")
        with self.assertRaisesRegex(ValueError, "data after the session ended"):
            self.receive(frame("closed") + b'{"type":')

    def test_rejects_invalid_framed_messages_before_dispatch(self):
        cases = [
            b'{"type":\n', b'[]\n', frame("unknown"),
            frame("state", context=None, reset_selection=True, rows=[]),
            frame("state", context={}, reset_selection=True, rows=[None]),
            frame("state", context={}, reset_selection=True, rows=[{"id": "V-230264", "result": []}]),
            frame("state", context={}, reset_selection=True, rows=[{"id": "x"}, {"id": "x"}]),
            frame("progress", complete=True, count=1, id=""),
            frame("progress", complete=2, count=1, id=""),
            frame("modal", kind="choice", title="Fixture", text="", choices=[{"id": "1"}]),
        ]
        for invalid in cases:
            with self.subTest(frame=invalid):
                self.channel = runtime.WorkbenchChannel()
                with self.assertRaises(ValueError):
                    self.receive(invalid)
        self.assertEqual(self.events, [])

    def test_size_limit_before_buffer_growth_and_for_complete_frames(self):
        with patch.object(runtime, "MAX_EVENT", 64):
            self.receive(b"a" * 64)
            with self.assertRaisesRegex(ValueError, "limit"):
                self.receive(b"b")
            self.assertEqual(len(self.channel.pending), 64)
            self.channel = runtime.WorkbenchChannel()
            with self.assertRaisesRegex(ValueError, "limit"):
                self.receive(b"a" * 65 + b"\n")

    def test_command_limit_counts_utf8_bytes_and_delimiter(self):
        command = "set"
        size = runtime.MAX_COMMAND - len(command) - 1
        field = "é" * (size // 2)
        output = io.StringIO()
        with patch.object(sys, "stdout", output):
            runtime.send_to_backend(command, field)
            with self.assertRaisesRegex(ValueError, "32 KiB"):
                runtime.send_to_backend(command, field + "é")
        self.assertEqual(len(output.getvalue().encode("utf-8")), runtime.MAX_COMMAND + 1)
        self.assertTrue(output.getvalue().endswith("\n"))


class FixtureWorkbench:
    def __init__(self, send):
        self.send = send
        self.label = runtime.urwid.Text("Fixture loading")
        self.widget = runtime.urwid.Filler(self.label)

    def handle_event(self, event):
        self.label.set_text("Fixture " + event["type"])

    def unhandled_input(self, key):
        if key == "q":
            self.send("cancel")


@unittest.skipUnless(os.name == "posix", "Requires a POSIX PTY and termios")
class RuntimeTerminalTests(unittest.TestCase):
    def setUp(self):
        reader, self.writer = os.pipe()
        self.pid, self.master = pty.fork()
        if self.pid == 0:
            os.close(self.writer)
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            terminal = os.dup(0)
            original = termios.tcgetattr(terminal)
            os.dup2(reader, 0)
            os.close(reader)
            os.environ["TERM"] = "xterm"
            runtime.Workbench = FixtureWorkbench
            runtime.WORKBENCH_PALETTE = []
            sys.argv = ["runtime", "workbench"]
            result = runtime.ui_main()
            restored = termios.tcgetattr(terminal) == original
            print("RUNTIME_RESULT={} TTY_RESTORED={:d}".format(result, restored), flush=True)
            os.close(terminal)
            os._exit(result)
        os.close(reader)
        self.addCleanup(self.stop_worker)
        self.output = b""
        os.write(self.writer, frame("state", context={}, reset_selection=True, rows=[]))
        self.expect(b"Fixture state")

    def expect(self, value):
        deadline = time.monotonic() + 5
        while value not in self.output:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.master], [], [], remaining)[0]:
                break
            try:
                data = os.read(self.master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                break
            if not data:
                break
            self.output += data
        self.assertIn(value, self.output[-4000:])

    def close_pipe(self):
        if self.writer is not None:
            os.close(self.writer)
            self.writer = None

    def wait_for_worker(self, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                self.pid = None
                return status
            time.sleep(0.01)
        return None

    def stop_worker(self):
        self.close_pipe()
        try:
            if self.pid is not None and self.wait_for_worker(0.5) is None:
                os.kill(self.pid, signal.SIGKILL)
                self.assertIsNotNone(self.wait_for_worker(2), "PTY fixture did not terminate")
        finally:
            os.close(self.master)

    def assert_done(self, code):
        self.expect("RUNTIME_RESULT={} TTY_RESTORED=1".format(code).encode("ascii"))
        status = self.wait_for_worker(2)
        self.assertIsNotNone(status)
        self.assertTrue(os.WIFEXITED(status))
        self.assertEqual(os.WEXITSTATUS(status), code)

    def test_explicit_close_restores_terminal(self):
        os.write(self.master, b"q")
        self.expect(b"cancel")
        close = frame("closed")
        os.write(self.writer, close[:10])
        os.write(self.writer, close[10:])
        self.close_pipe()
        self.assert_done(0)

    def test_partial_eof_reports_failure_and_restores_terminal(self):
        os.write(self.writer, b'{"type":"notice"')
        self.close_pipe()
        self.expect(b"connection closed during a message")
        self.assert_done(2)


if __name__ == "__main__":
    unittest.main()
