"""Focused, read-only navigation for the outcomes of one completed run."""

import urwid as _out_urwid


OUTCOME_ASSESSMENTS = {
    "PASS": "Pass", "FAIL": "Fail", "NEEDS_REVIEW": "Review", "UNKNOWN": "Unknown",
    "NOT_APPLICABLE": "N/A", "ERROR": "Error",
}
OUTCOME_VIEWS = (
    ("all", "All outcomes"), ("follow-up", "Needs follow-up"), ("applied", "Applied"),
    ("pending", "Pending activation"), ("skipped", "Skipped"),
)
OUTCOME_WIDTHS = (9, 7, 19)


def _outcome_label(row, field):
    value = wb_line(row.get(field))
    if field in ("before", "assessment"):
        return OUTCOME_ASSESSMENTS.get(value, value.replace("_", " ").title())
    return value.replace("_", " ").title()


def _outcome_style(row):
    action, assessment = row.get("action"), row.get("assessment")
    if action == "FAILED" or assessment in ("FAIL", "ERROR"):
        return "danger"
    if action in ("BLOCKED", "MANUAL_REQUIRED", "PENDING_ACTIVATION") or assessment in ("NEEDS_REVIEW", "UNKNOWN"):
        return "warning"
    return "success" if assessment == "PASS" else "muted"


class OutcomeRow(_out_urwid.Columns):
    """Single-line finding row with keyboard and pointer activation."""

    def __init__(self, row, open_row):
        self.open_row = open_row
        cells = [wb_line(row.get("id")), (_outcome_style(row), _outcome_label(row, "assessment")),
                 _outcome_label(row, "action")]
        columns = [(width, _out_urwid.Text(value, wrap="clip")) for width, value in zip(OUTCOME_WIDTHS, cells)]
        columns.append(WorkbenchSummaryCell("base", wb_line(row.get("title"))))
        super(OutcomeRow, self).__init__(columns, dividechars=1)

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key == "enter":
            self.open_row()
            return None
        return key

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.open_row()
            return True
        return False


class CompletedOutcomes:
    """Browse assessed results without invoking the rule engine."""

    def __init__(self, run_id, mode, rows, back):
        self.run_id = run_id
        self.mode = mode
        self.rows = rows
        self.back_to_results = back
        self.widget = _out_urwid.WidgetPlaceholder(_out_urwid.SolidFill())
        self.frame = None
        self.query = ""
        self.view = "all"
        self.focus_id = ""
        self.page = "list"
        self.modal = None
        self.window_too_small = False
        self.show_list()

    def resize(self, width, height):
        if width < 56 or height < 18:
            if not self.window_too_small:
                self.widget.original_widget = _out_urwid.Filler(_out_urwid.Text(
                    "Enlarge to at least 56 columns and 18 rows. Esc goes back.", align="center"))
            self.window_too_small = True
        elif self.window_too_small:
            self.window_too_small = False
            self.reload_screen()

    def reload_screen(self):
        if not self.window_too_small:
            self.widget.original_widget = self.modal or self.frame

    def frame_for(self, title, body, actions, hint, extra=()):
        header = _out_urwid.Pile([
            _out_urwid.AttrMap(_out_urwid.Text(" STIG Assistant  /  " + title, wrap="clip"), "header"),
            _out_urwid.Text(("muted", "Run {} | {}".format(self.run_id, self.mode.upper())), wrap="clip"),
            *extra,
        ])
        if extra:
            header.focus_position = 2
        buttons = WorkbenchActions([(len(label) + 4, wb_button(label, action)) for label, action in actions],
                                   dividechars=1)
        footer = _out_urwid.Pile([buttons, _out_urwid.Text(("muted", hint), wrap="clip")])
        self.frame = WorkbenchFrame(body, header=header, footer=footer, focus_part="body")
        self.reload_screen()

    def show_list(self):
        self.page = "list"
        self.search = WorkbenchEdit(" Search  ", self.query, submit=lambda _: self.focus_rows())
        _out_urwid.connect_signal(self.search, "change", self.update_search)
        self.summary = _out_urwid.Text("", wrap="clip")
        self.walker = _out_urwid.SimpleFocusListWalker([])
        self.list_box = WorkbenchForm(self.walker)
        self.visible = []
        headings = [(width, _out_urwid.Text(label, wrap="clip"))
                    for width, label in zip(OUTCOME_WIDTHS, ("Vuln-ID", "Result", "Action"))]
        headings.append(_out_urwid.Text("Finding", wrap="clip"))
        self.frame_for("Finding outcomes", self.list_box,
                       [("Views", self.open_views), ("Clear", self.clear_view), ("Back", self.back_to_results)],
                       "/ search  F2 views  Enter details  Esc back",
                       [_out_urwid.AttrMap(self.search, "input", "focus"), self.summary,
                        _out_urwid.AttrMap(_out_urwid.Columns(headings, dividechars=1), "section")])
        self.filter_rows()

    def focus_rows(self):
        self.frame.focus_position = "body" if self.visible else "footer"

    def current_focus(self):
        if self.visible:
            return self.visible[self.walker.focus]["id"]
        return self.focus_id

    def update_search(self, _, value):
        self.focus_id = self.current_focus()
        self.query = value
        self.filter_rows()

    def matches_view(self, row):
        action = row.get("action")
        if self.view == "follow-up":
            return (action in ("BLOCKED", "FAILED", "SKIPPED", "MANUAL_REQUIRED", "PENDING_ACTIVATION")
                    or row.get("assessment") not in ("PASS", "NOT_APPLICABLE"))
        actions = {"applied": "APPLIED", "pending": "PENDING_ACTIVATION", "skipped": "SKIPPED"}
        return self.view == "all" or action == actions[self.view]

    def filter_rows(self):
        terms = self.query.casefold().split()
        self.visible = []
        entries = []
        focus_styles = {style: "focus" for style in (None, "base", "success", "warning", "danger", "muted")}
        for row in self.rows:
            if not self.matches_view(row):
                continue
            text = " ".join((row["id"], wb_line(row.get("title")), wb_line(row.get("assessment")),
                             _outcome_label(row, "assessment"), wb_line(row.get("action")),
                             _outcome_label(row, "action"))).casefold()
            if all(term in text for term in terms):
                self.visible.append(row)
                entries.append(_out_urwid.AttrMap(OutcomeRow(row, lambda row=row: self.open_row(row)),
                                                  None, focus_styles))
        self.walker[:] = entries or [_out_urwid.Text(("muted", "No saved findings match this view."))]
        if self.visible:
            position = next((place for place, row in enumerate(self.visible) if row["id"] == self.focus_id), 0)
            self.walker.set_focus(position)
        self.summary.set_text(("accent", " {} of {} findings  |  {}".format(
            len(self.visible), len(self.rows), dict(OUTCOME_VIEWS)[self.view])))

    def clear_view(self):
        self.view = "all"
        self.search.set_edit_text("")
        self.filter_rows()
        self.focus_rows()

    def open_views(self):
        self.focus_id = self.current_focus()
        choices = [wb_button(label, lambda key=key: self.choose_view(key)) for key, label in OUTCOME_VIEWS]
        choices.append(wb_button("Back", self.close_views))
        view = _out_urwid.ListBox(_out_urwid.SimpleFocusListWalker(choices))
        view.set_focus(next(index for index, (name, _) in enumerate(OUTCOME_VIEWS) if name == self.view))
        self.modal = _out_urwid.Overlay(_out_urwid.LineBox(view, title="Outcome views"), self.frame,
                                       "center", ("relative", 76), "middle", 10)
        self.reload_screen()

    def close_views(self):
        self.modal = None
        self.reload_screen()

    def choose_view(self, value):
        self.view = value
        self.close_views()
        self.filter_rows()
        self.focus_rows()

    def open_row(self, row):
        self.focus_id = row["id"]
        self.page = "finding"
        assessment = "Recorded assessment " + _outcome_label(row, "assessment")
        if row.get("before"):
            assessment = "Before {}  |  After {}".format(
                _outcome_label(row, "before"), _outcome_label(row, "assessment"))
        body = wb_document("{}\n\n{}\nAction {}\n\nAssessment evidence\n{}".format(
            wb_text(row.get("title")), assessment, _outcome_label(row, "action"),
            wb_text(row.get("evidence")) or "No evidence was recorded."))
        self.frame_for(self.focus_id, body, [("Back", self.show_list)], "PgUp/PgDn scroll  Esc outcomes")

    def filter_input(self, keys, raw):
        if self.window_too_small:
            return [key for key in keys if key in ("esc", "ctrl c", "ctrl d")]
        return keys

    def key(self, key):
        if key == "esc":
            if self.modal is not None:
                self.close_views()
            elif self.page == "finding":
                self.show_list()
            elif not self.window_too_small and self.frame.focus_position == "header":
                self.focus_rows()
            else:
                self.back_to_results()
        elif not self.modal and self.page == "list":
            if key == "/":
                self.frame.focus_position = "header"
                self.frame.header.focus_position = 2
            elif key == "f2":
                self.open_views()
            elif key in ("home", "end") and self.visible and self.frame.focus_position == "body":
                self.walker.set_focus(0 if key == "home" else len(self.visible) - 1)
