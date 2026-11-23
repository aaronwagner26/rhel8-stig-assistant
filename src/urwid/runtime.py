"""Terminal and private command channel for the embedded Urwid application."""

import io
import json
import os
import sys

import urwid


WIRE_SEPARATOR = "\x1f"
MAX_COMMAND = 32768  # Payload bytes, matching the Bash command reader.
MAX_EVENT = 4 * 1024 * 1024
EVENT_FIELDS = {
    "state": {"context": dict, "reset_selection": bool, "rows": list},
    "browse": {},
    "review": {"token": str, "focused": str, "text": str, "rows": list},
    "detail": {"id": str, "title": str, "text": str},
    "progress": {"complete": int, "count": int, "id": str},
    "modal": {"kind": str, "title": str, "text": str, "choices": list},
    "notice": {"message": str},
    "error": {"message": str},
    "accepted": {},
    "closed": {},
}
TERMINAL_EVENTS = {"accept": "accepted", "cancel": "closed"}


def send_to_backend(*fields):
    values = [str(field) for field in fields]
    if any(ord(character) < 32 or ord(character) == 127
           for value in values for character in value):
        raise ValueError("A command field contains a control character.")
    payload = WIRE_SEPARATOR.join(values)
    if len(payload.encode("utf-8")) > MAX_COMMAND:
        raise ValueError("The request exceeds the 32 KiB command limit.")
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def decode_workbench_event(frame):
    try:
        event = json.loads(frame.decode("utf-8", "surrogateescape"))
    except (ValueError, RecursionError):
        raise ValueError("The workbench received an invalid JSON message.") from None
    kind = event.get("type") if isinstance(event, dict) else None
    if not isinstance(kind, str) or kind not in EVENT_FIELDS:
        raise ValueError("The workbench received an unknown message type.")
    if any(type(event.get(field)) is not expected for field, expected in EVENT_FIELDS[kind].items()):
        raise ValueError("The workbench received an incomplete or invalid {} message.".format(kind))
    if kind in ("state", "review"):
        findings = set()
        for row in event["rows"]:
            finding = row.get("id") if isinstance(row, dict) else None
            if (not isinstance(finding, str) or not finding or finding in findings
                    or any(not isinstance(row.get(field, ""), str) for field in ("result", "outcome"))):
                raise ValueError("The workbench received an invalid finding row.")
            findings.add(finding)
    if kind == "progress" and not 0 <= event["complete"] <= event["count"]:
        raise ValueError("The workbench received an invalid progress count.")
    if kind == "modal" and (event["kind"] not in ("confirm", "choice", "input", "message")
                            or any(not isinstance(choice, dict) or not isinstance(choice.get("id"), str)
                                   or not isinstance(choice.get("label"), str) for choice in event["choices"])):
        raise ValueError("The workbench received an invalid prompt.")
    return event


class WorkbenchChannel:
    """Read bounded, newline-delimited records from the private Bash pipe."""

    def __init__(self):
        self.pending = bytearray()
        self.expected_end = None
        self.acknowledged = False

    def send(self, *fields):
        send_to_backend(*fields)
        expected = TERMINAL_EVENTS.get(fields[0])
        if expected:
            self.expected_end = expected

    def receive(self, data, handle_event):
        if not data:
            if self.pending:
                raise ValueError("The workbench connection closed during a message.")
            if not self.acknowledged:
                raise ValueError("The workbench connection closed before the session ended.")
            return False
        parts = data.split(b"\n")
        for part in parts[:-1]:
            if self.acknowledged:
                raise ValueError("The workbench received data after the session ended.")
            self.extend(part)
            event = decode_workbench_event(self.pending)
            self.pending.clear()
            kind = event["type"]
            if kind in ("accepted", "closed"):
                if kind != self.expected_end:
                    raise ValueError("The workbench received an unexpected session acknowledgement.")
                self.acknowledged = True
            else:
                if kind == "error":
                    self.expected_end = None
                handle_event(event)
        if self.acknowledged and parts[-1]:
            raise ValueError("The workbench received data after the session ended.")
        self.extend(parts[-1])
        return True

    def extend(self, data):
        if len(self.pending) + len(data) > MAX_EVENT:
            raise ValueError("The workbench message exceeds the 4 MiB limit.")
        self.pending.extend(data)


def run_workbench(tty):
    channel = WorkbenchChannel()
    app = Workbench(channel.send)
    screen = urwid.raw_display.Screen(input=tty, output=tty)
    color = os.environ.get("STIG_UI_COLOR", "1") == "1"
    screen.set_terminal_properties(colors=16, bright_is_bold=True, has_underline=True)
    if not color:
        screen.set_terminal_properties(colors=1)

    def resize():
        if hasattr(app, "resize"):
            width, height = screen.get_cols_rows()
            app.resize(width, height)

    def filter_input(keys, raw):
        if "window resize" in keys:
            resize()
        if hasattr(app, "input_filter"):
            return app.input_filter(keys, raw)
        return keys

    loop = urwid.MainLoop(
        app.widget, palette=WORKBENCH_PALETTE, screen=screen,
        input_filter=filter_input, unhandled_input=app.unhandled_input,
    )
    fd = sys.stdin.fileno()
    os.set_blocking(fd, False)

    def receive():
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            return
        if not channel.receive(data, app.handle_event):
            raise urwid.ExitMainLoop()

    loop.watch_file(fd, receive)
    resize()
    loop.run()


def run_one_shot(tty, path):
    with open(path, "rb") as request_file:
        data = request_file.read(MAX_EVENT + 1)
    if len(data) > MAX_EVENT:
        raise ValueError("The prompt request exceeds the UI limit.")
    request = json.loads(data.decode("utf-8", "surrogateescape"))
    if not isinstance(request, dict):
        raise ValueError("The prompt request is invalid.")
    result = run_prompt(request, tty)
    status = result.get("status")
    value = result.get("value", "")
    if type(status) is not int or status not in (0, 1, 2, 3) or not isinstance(value, str):
        raise ValueError("The terminal returned an invalid response.")
    send_to_backend("modal", status, value)


def ui_main():
    if len(sys.argv) not in (2, 3):
        return 2
    try:
        with io.TextIOWrapper(open("/dev/tty", "r+b", buffering=0),
                              encoding="utf-8", line_buffering=True,
                              write_through=True) as tty:
            if sys.argv[1:] == ["workbench"]:
                run_workbench(tty)
            elif len(sys.argv) == 3 and sys.argv[1] == "prompt":
                run_one_shot(tty, sys.argv[2])
            else:
                return 2
    except KeyboardInterrupt:
        return 1
    except (OSError, ValueError) as error:
        message = "".join(character for character in str(error)
                          if character.isprintable())
        print("Urwid interface: {}".format(message[:300]), file=sys.stderr, flush=True)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(ui_main())
