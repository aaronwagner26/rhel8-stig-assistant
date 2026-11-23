"""Urwid screens for attended decisions and completed runs."""

import os as _att_os
import select as _att_select
import unicodedata as _att_unicode

import urwid as _att_urwid


ATTENDED_PALETTE = [
    ("base", "default", "default", ""),
    ("header", "white,bold", "dark blue", "bold"),
    ("section", "light cyan,bold", "default", "bold"),
    ("muted", "light gray", "default", ""),
    ("accent", "light cyan,bold", "default", "bold"),
    ("focus", "black,bold", "light gray", "standout"),
    ("line_focus", "white", "dark blue", "standout"),
    ("button", "light cyan", "default", ""),
    ("input", "white", "dark blue", "underline"),
    ("success", "light green,bold", "default", "bold"),
    ("warning", "yellow,bold", "default", "bold"),
    ("danger", "light red,bold", "default", "bold"),
    ("diff_meta", "light cyan", "default", ""),
    ("diff_add", "light green", "default", "underline"),
    ("diff_remove", "light red", "default", "bold"),
    ("footer", "light gray", "dark blue", ""),
]

def _att_text(value):
    """Keep report formatting while preventing terminal or bidi controls."""
    return "".join(
        char for char in str(value or "")
        if char in "\n\t" or _att_unicode.category(char) not in ("Cc", "Cf", "Cs")
    ).expandtabs(4)


def _att_button(label, callback, style="button"):
    button = _att_urwid.Button(label, lambda _: callback())
    return _att_urwid.AttrMap(button, {None: style}, {None: "focus"})


class _AttLine(_att_urwid.Text):
    """Allow the list to position its viewport on every displayed line."""

    _selectable = True

    def keypress(self, size, key):
        return key


def _att_block(lines, selectable=True):
    widgets = []
    for style, content in lines:
        for line in _att_text(content).split("\n"):
            if selectable:
                widget = _AttLine((style, line), wrap="any")
            else:
                widget = _att_urwid.Text((style, line), wrap="any")
            widgets.append(widget)
    return widgets


class _AttFrame(_att_urwid.Frame):
    """Route page scrolling independently of the focused action."""

    def __init__(self, body, header, footer, buttons, focus_part, jump_keys):
        super().__init__(body, header, footer, focus_part=focus_part)
        self.buttons = buttons
        self.jump_keys = jump_keys

    def keypress(self, size, key):
        if key in ("tab", "shift tab"):
            if self.focus_position == "body":
                self.focus_position = "footer"
            elif len(self.buttons.contents) > 1:
                offset = -1 if key == "shift tab" else 1
                self.buttons.focus_position = (self.buttons.focus_position + offset) % len(
                    self.buttons.contents)
            return None
        if self.jump_keys and key in ("g", "G", "home", "end"):
            if self.body.body:
                self.body.set_focus(0 if key in ("g", "home") else len(self.body.body) - 1)
            return None
        if key in ("up", "down", "page up", "page down"):
            part = self.focus_position
            self.focus_position = "body"
            try:
                return super().keypress(size, key)
            finally:
                self.focus_position = part
        return super().keypress(size, key)


class _AttViewport(_att_urwid.WidgetPlaceholder):
    """Keep resize safe and prevent invoking options hidden by a tiny viewport."""

    def __init__(self, body):
        super().__init__(body)
        self.small = _att_urwid.Filler(_att_urwid.Text(
            "Enlarge the terminal to at least 48 columns and 12 rows. Esc goes back.", wrap="any"))

    @staticmethod
    def too_small(size):
        return size[0] < 48 or size[1] < 12

    def render(self, size, focus=False):
        if self.too_small(size):
            return self.small.render(size, focus)
        return super().render(size, focus)

    def keypress(self, size, key):
        if self.too_small(size):
            return key if key in ("esc", "ctrl c", "ctrl d") else None
        handled = super().keypress(size, key)
        # Urwid 1.3 can retain the previous composite while the terminal
        # holds its canvas, even after the list walker changes position.
        self.refresh_current()
        return handled

    def mouse_event(self, size, event, button, col, row, focus):
        if self.too_small(size):
            return False
        handled = super().mouse_event(size, event, button, col, row, focus)
        if handled:
            self.refresh_current()
        return handled

    def refresh_current(self):
        if isinstance(self.original_widget, _AttFrame):
            self.original_widget.body._invalidate()
        self.original_widget._invalidate()
        self._invalidate()


class _AttendedPrompt:
    def __init__(self, request):
        self.request = request
        self.kind = request.get("kind")
        self.answer = {"status": 2, "value": ""}
        self.view = _AttViewport(_att_urwid.SolidFill())
        self.page = ""
        self.artifact_path = None
        self.error = _att_urwid.Text("")
        self.current_editor = None
        self.allow_all = request.get("allow_all") is True
        self.rows = request.get("rows") or []

    def finish(self, status, value=""):
        self.answer = {"status": status, "value": value}
        raise _att_urwid.ExitMainLoop()

    def screen(self, title, subtitle, body, actions, focus, hint,
               focus_part="footer", jump_keys=True, body_focus=0):
        title_line = _att_urwid.AttrMap(
            _att_urwid.Text(" STIG Assistant  /  " + _att_text(title), wrap="clip"), "header")
        header = _att_urwid.Pile([
            title_line,
            _att_urwid.Text(("muted", _att_text(subtitle)), wrap="clip"),
            _att_urwid.Divider(),
        ])
        buttons = _att_urwid.GridFlow(
            [_att_button(label, callback, style) for label, callback, style in actions],
            max(len(label) for label, _, _ in actions) + 4, 1, 0, "left")
        buttons.focus_position = focus
        footer = _att_urwid.Pile([
            buttons,
            _att_urwid.AttrMap(_att_urwid.Text(" " + hint, wrap="any"), "footer"),
        ])
        walker = _att_urwid.SimpleFocusListWalker(body)
        if body:
            walker.set_focus(body_focus)
        box = _att_urwid.ListBox(walker)
        self.view.original_widget = _AttFrame(
            box, header, footer, buttons, focus_part, jump_keys)

    def approve(self, details=False):
        self.page = "approval_details" if details else "approval"
        risk = _att_text(self.request.get("risk")).lower()
        id_ = _att_text(self.request.get("id"))
        step = ""
        if self.request.get("position") and self.request.get("total"):
            step = "   Change {} of {}".format(
                self.request["position"], self.request["total"])
        lines = [("accent", self.request.get("title")),
                 ("success" if risk == "low" else "warning", risk.upper() + " operational risk"),
                 ("muted", "Skip is the default. Approval covers the targets in this reviewed change."),
                 ("base", "")]
        if self.request.get("revised"):
            lines.extend([("warning", "Plan changed. Review this version and decide separately."),
                          ("base", "")])
        elif self.request.get("review_each"):
            lines.extend([("muted", "Individual review is enabled."), ("base", "")])
        plan = _att_text(self.request.get("plan"))
        diff = _att_text(self.request.get("diff"))
        if diff and plan.startswith(diff + "\n"):
            plan = plan[len(diff) + 1:]
        if details:
            lines += [("section", "Assessment evidence"),
                      ("base", self.request.get("evidence") or "No additional evidence was recorded."),
                      ("base", "")]
        lines += [("section", "Proposed change"), ("base", plan or "No plan text was supplied.")]
        if diff:
            lines += [("base", ""), ("section", "Before / after"),
                      ("muted", "- Current    + Proposed")]
            for line in diff.splitlines():
                if line.startswith(("--- ", "+++ ", "@@ ")):
                    style = "diff_meta"
                elif line.startswith("-"):
                    style = "danger"
                elif line.startswith("+"):
                    style = "success"
                else:
                    style = "base"
                lines.append((style, line))
        actions = [
            ("Skip", lambda: self.finish(1), "warning"),
            ("Approve", lambda: self.finish(0), "success"),
        ]
        if self.allow_all:
            lines += [("base", ""), ("muted",
                       "Approve low-risk rest also covers unchanged, eligible low-risk plans. "
                       "Other changes still ask separately.")]
            actions.append(("Low-risk rest", lambda: self.finish(3), "success"))
        actions.append(("Overview" if details else "Details",
                        lambda: self.approve(not details), "button"))
        self.screen("Approve change", id_ + step, _att_block(lines), actions, 0,
                    "Y approve | N skip | D details | Esc stop"
                    + (" | A low-risk rest" if self.allow_all else ""))

    @staticmethod
    def row_status(row):
        action = row.get("action")
        result = row.get("assessment")
        if action in ("BLOCKED", "PENDING_ACTIVATION", "MANUAL_REQUIRED"):
            return "warning"
        if action == "SKIPPED":
            return "muted"
        if action == "FAILED" or result in ("FAIL", "ERROR"):
            return "danger"
        if result in ("NEEDS_REVIEW", "UNKNOWN"):
            return "warning"
        if action == "APPLIED" or result == "PASS":
            return "success"
        return "base"

    @staticmethod
    def needs_follow_up(row):
        return (row.get("action") in (
            "PENDING_ACTIVATION", "BLOCKED", "MANUAL_REQUIRED", "FAILED", "SKIPPED")
            or row.get("assessment") not in ("PASS", "NOT_APPLICABLE"))

    def result_actions(self):
        actions = [
            ("Overview", lambda: self.results("overview"), "button"),
            ("Follow-up", lambda: self.results("follow_up"), "button"),
            ("Reports", lambda: self.results("reports"), "button"),
            ("Recovery", lambda: self.results("recovery"), "button"),
            ("Close", lambda: self.finish(0), "button"),
        ]
        if self.page == "follow_up" and self.request.get("verification_command"):
            actions.insert(4, ("Run recheck", self.confirm_recheck, "button"))
        if self.page == "overview" and self.rows:
            actions.insert(-1, ("Findings", lambda: self.finish(0, "findings"), "button"))
        if self.page == "overview" and self.request.get("recheck_id"):
            actions.insert(-1, ("Compare recheck", lambda: self.finish(0, "compare-recheck"), "button"))
        return actions

    def confirm_recheck(self):
        self.page = "recheck_confirm"
        lines = [("section", "Recheck the saved scope"),
                 ("base", "Run Status on the findings from this run and save a new JSON report."),
                 ("muted", "This read-only assessment keeps the original report and uses the same build."),
                 ("muted", "A checklist asset mismatch still requires acknowledgment."),
                 ("base", ""),
                 ("accent", self.request.get("verification_command"))]
        self.screen("Confirm read-only recheck", "Back is selected", _att_block(lines),
                    [("Back", lambda: self.results("follow_up"), "button"),
                     ("Run Status", lambda: self.finish(0, "recheck"), "button")],
                    0, "Tab chooses an action | Esc goes back")

    def result_rows(self, rows):
        lines = []
        for row in rows:
            label = "{}  |  {}  |  {}".format(
                row.get("id", ""), row.get("action", "").replace("_", " "),
                row.get("assessment", "").replace("_", " "))
            lines += [(self.row_status(row), label),
                      ("base", row.get("title")), ("muted", row.get("evidence")), ("base", "")]
        return lines

    def results(self, page="overview", close_default=False, report_focus=None):
        self.page = page
        request = self.request
        rows = self.rows
        applied = [row.get("id", "") for row in rows if row.get("action") == "APPLIED"]
        follow_up = [row for row in rows if self.needs_follow_up(row)]
        pending = sum(row.get("action") == "PENDING_ACTIVATION" for row in rows)
        blocked = sum(row.get("action") == "BLOCKED" for row in rows)
        skipped = sum(row.get("action") == "SKIPPED" for row in rows)
        subtitle = "Run {}   |   {}".format(request.get("run_id", ""), request.get("mode", "").upper())
        focus_part = "footer"
        body_focus = 0
        if page == "reports":
            content = _att_block([("section", "Reports"), ("muted", request.get("run_dir")),
                                  ("base", "")])
            files = request.get("files") or []
            for item in files:
                path = item.get("path", "")
                if not isinstance(path, str):
                    continue
                basename = _att_os.path.basename(path)
                if basename in _HISTORY_ARTIFACT_TITLES:
                    if path == report_focus:
                        body_focus = len(content)
                    content.append(_att_button(
                        _HISTORY_ARTIFACT_TITLES[basename] + "  (" + basename + ")",
                        lambda path=path: self.artifact(path)))
            if len(content) == 3:
                content += _att_block([("muted", "No report files were provided.")])
            else:
                focus_part = "body"
                body_focus = body_focus or 3
            active = 2
        elif page == "follow_up":
            lines = [("section", "Follow-up  ({})".format(len(follow_up))),
                     ("muted", "Review Administrator actions for prerequisites and activation steps."),
                     ("base", "")]
            if request.get("verification_command"):
                lines += [("section", "Recheck this scope"),
                          ("accent", request["verification_command"]),
                          ("muted", "Use the same verified build and operator account after follow-up work."),
                          ("muted", "Use Results to compare the saved JSON reports."
                           if request.get("format") == "json" else
                           "Both runs need JSON reports for comparison."),
                          ("base", "")]
            lines += self.result_rows(follow_up) or [("muted", "No follow-up findings were recorded.")]
            content = _att_block(lines)
            active = 1
        elif page == "recovery":
            backups = request.get("backup_dir")
            lines = [("section", "Recovery")]
            if backups:
                lines += [("muted", "Backup directory"), ("base", backups), ("base", ""),
                          ("base", "Use the same verified build and the recorded run ID in a root terminal. "
                           "Review restored settings and any service or boot activation separately."),
                          ("base", "")]
                if request.get("rollback_command"):
                    lines += [("section", "Review rollback plan"),
                              ("accent", request["rollback_command"]),
                              ("muted", "Rollback requires its own attended approval.")]
            else:
                lines.append(("muted", "No backup run was recorded."))
            content = _att_block(lines)
            active = 3
        else:
            tally = "{} selected  |  {} applied  |  {} pending  |  {} blocked  |  {} skipped".format(
                len(rows), len(applied), pending, blocked, skipped)
            lines = [("section", "Overview"), ("base", tally), ("base", ""),
                     ("section", "Applied IDs  ({})".format(len(applied))),
                     ("success" if applied else "muted", ", ".join(applied) or "None"), ("base", "")]
            if request.get("approval_stopped"):
                lines[2:2] = [("warning", "Approval stopped. Review Follow-up before preparing a fresh plan.")]
            elif request.get("exit_code") == 70:
                lines[2:2] = [("danger", "The completed run recorded an error. Open Follow-up and Recovery.")]
            elif request.get("exit_code") == 69:
                lines[2:2] = [("warning", "An operation was blocked. See Follow-up for next steps.")]
            if request.get("recheck_note"):
                lines[2:2] = [("accent", request["recheck_note"])]
            if request.get("operator"):
                lines[2:2] = [("muted", "Operator " + _att_text(request["operator"]))]
            if rows:
                assessments = [row.get("assessment") for row in rows]
                labels = (("PASS", "Pass", "success"), ("FAIL", "Fail", "danger"),
                          ("NEEDS_REVIEW", "Review", "warning"), ("UNKNOWN", "Unknown", "warning"),
                          ("NOT_APPLICABLE", "Not applicable", "muted"), ("ERROR", "Error", "danger"))
                lines.append(("section", "Assessment outcomes"))
                lines += [(style, "{}  {}".format(label, assessments.count(value)))
                          for value, label, style in labels if value in assessments]
                lines += [("base", ""), ("muted", "Open Findings for evidence from a specific Vuln-ID.")]
            else:
                lines.append(("base", request.get("summary") or "No result rows were recorded."))
            content = _att_block(lines)
            active = 0
        title = "Implementation results" if request.get("mode") == "apply" else "Assessment results"
        actions = self.result_actions()
        if page == "overview" and close_default:
            active = len(actions) - 1
        self.screen(title, subtitle, content, actions, active,
                    "Tab or arrows to choose | PgUp/PgDn to scroll | Esc closes",
                    focus_part=focus_part, body_focus=body_focus)

    def artifact(self, path):
        self.page = "artifact"
        self.artifact_path = path
        try:
            self.view.original_widget = _history_report_preview(
                self.request.get("run_dir", ""), self.request.get("run_id", ""), path,
                self.back_to_artifact_list, lambda: self.finish(0))
        except ValueError as exc:
            lines = [("danger", "Report unavailable"), ("base", str(exc))]
            self.screen("Reports", "", _att_block(lines),
                        [("Back to reports", self.back_to_artifact_list, "button"),
                         ("Close", lambda: self.finish(0), "button")], 0, "Esc back")

    def back_to_artifact_list(self):
        self.results("reports", report_focus=self.artifact_path)

    def accept_input(self):
        value = self.current_editor.edit_text
        if len(value.encode("utf-8")) > 1024 or any(
                _att_unicode.category(char) in ("Cc", "Cf", "Cs") for char in value):
            self.error.set_text(("danger", "Enter at most 1,024 printable bytes."))
            return
        self.finish(0, value)

    def modal(self):
        self.page = self.kind
        title = self.request.get("title") or "Review"
        body = _att_block([("base", self.request.get("text")), ("base", "")], selectable=False)
        body_focus = 0
        if self.kind == "confirm":
            no = _att_text(self.request.get("no") or "Back")
            body += _att_block([("muted", no + " is the default. Tab moves focus.")])
            actions = [(no, lambda: self.finish(1), "button"),
                       (_att_text(self.request.get("yes") or "Continue"),
                        lambda: self.finish(0), "button")]
            footer_focus = 0
            part = "footer"
        elif self.kind == "choice":
            body_focus = len(body)
            for choice in self.request.get("choices") or []:
                option = choice.get("id", "")
                label = "{}  {}".format(_att_text(option), _att_text(choice.get("label")))
                body.append(_att_button(label, lambda option=option: self.finish(0, option)))
            actions = [("Back", lambda: self.finish(1), "button")]
            footer_focus = 0
            part = "body" if body_focus < len(body) else "footer"
            if part == "footer":
                body_focus = 0
        elif self.kind == "input":
            body_focus = len(body)
            initial = _att_text(self.request.get("initial"))
            self.current_editor = _att_urwid.Edit(edit_text=initial, edit_pos=len(initial))
            body.extend([self.current_editor, self.error])
            actions = [("Use value", self.accept_input, "button"),
                       ("Back", lambda: self.finish(1), "button")]
            footer_focus = 0
            part = "body"
        else:
            actions = [("Close", lambda: self.finish(0), "button")]
            footer_focus = 0
            part = "footer"
        self.screen(title, "", body, actions, footer_focus, "Tab or arrows to choose | Esc back",
                    focus_part=part, jump_keys=self.kind != "input", body_focus=body_focus)

    def key(self, key):
        if key in ("ctrl c", "ctrl d"):
            self.finish(2)
        if key == "esc":
            if self.kind == "approval":
                if self.page == "approval_details":
                    self.approve()
                else:
                    self.finish(2)
            elif self.page == "artifact":
                self.back_to_artifact_list()
            elif self.page == "recheck_confirm":
                self.results("follow_up")
            else:
                self.finish(0 if self.kind in ("message", "results") else 1)
        if self.kind == "approval":
            if isinstance(key, str) and key.lower() == "d":
                self.approve(self.page != "approval_details")
            elif isinstance(key, str) and key.lower() == "y":
                self.finish(0)
            elif isinstance(key, str) and key.lower() == "n":
                self.finish(1)
            elif isinstance(key, str) and key.lower() == "a" and self.allow_all:
                self.finish(3)
        elif self.kind == "input" and key == "enter":
            self.accept_input()


def run_prompt(request, tty):
    """Run one full-screen prompt. The caller owns the terminal descriptor."""
    prompt = _AttendedPrompt(request)
    panel, palette = prompt.view, ATTENDED_PALETTE
    outcomes = None
    if prompt.kind == "approval":
        prompt.approve()
    elif prompt.kind == "results":
        prompt.results(close_default=True)
    elif prompt.kind == "compare":
        history = RunHistory(request.get("report_dir", ""), lambda: prompt.finish(0), index_runs=False)
        history.open_recheck_comparison(request.get("original"), request.get("recheck"))
        panel, palette = history.widget, WORKBENCH_PALETTE
    elif prompt.kind == "outcomes":
        outcomes = CompletedOutcomes(request.get("run_id", ""), request.get("mode", ""),
                                     prompt.rows, lambda: prompt.finish(0))
        panel, palette = outcomes.widget, WORKBENCH_PALETTE
    elif prompt.kind in ("confirm", "choice", "input", "message"):
        prompt.modal()
    else:
        return prompt.answer

    screen = _att_urwid.raw_display.Screen(input=tty, output=tty)
    screen.set_terminal_properties(colors=(
        1 if _att_os.environ.get("STIG_UI_COLOR", "1") == "0" else 16
    ))
    poll = _att_select.poll()
    closed = _att_select.POLLHUP | _att_select.POLLERR | _att_select.POLLNVAL
    poll.register(tty.fileno(), closed)

    def filter_input(keys, raw):
        if any(mask & closed for _, mask in poll.poll(0)):
            prompt.finish(2)
        if outcomes is not None:
            if "window resize" in keys:
                outcomes.resize(*screen.get_cols_rows())
            return outcomes.filter_input(keys, raw)
        return keys

    def unhandled(key):
        if outcomes is not None and key not in ("ctrl c", "ctrl d"):
            outcomes.key(key)
        else:
            prompt.key(key)

    if outcomes is not None:
        outcomes.resize(*screen.get_cols_rows())

    loop = _att_urwid.MainLoop(panel, palette, screen=screen,
                                unhandled_input=unhandled, input_filter=filter_input)
    try:
        loop.run()
    except (KeyboardInterrupt, EOFError, OSError):
        prompt.answer = {"status": 2, "value": ""}
    return prompt.answer
