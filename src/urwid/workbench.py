"""Urwid workbench. The Bash backend remains the authority for every change."""

import re
import unicodedata

import urwid
from urwid.util import calc_text_pos, calc_width


WORKBENCH_PALETTE = [
    ("base", "light gray", "default"),
    ("header", "white,bold", "dark blue", "standout"),
    ("section", "light cyan,bold", "default", "bold"),
    ("muted", "light gray", "default"),
    ("detail", "white", "default"),
    ("accent", "light cyan,bold", "default", "bold"),
    ("focus", "black,bold", "light cyan", "standout"),
    ("button", "light cyan", "default", "underline"),
    ("input", "white", "dark blue", "underline"),
    ("success", "light green,bold", "default", "bold"),
    ("warning", "yellow,bold", "default", "bold"),
    ("danger", "light red,bold", "default", "bold"),
    ("cyan", "light cyan,bold", "default", "bold"),
    ("diff_add", "light green", "default", "underline"),
    ("diff_remove", "light red", "default", "bold"),
    ("diff_meta", "light cyan", "default", "underline"),
]

RESULT_LABELS = {
    "PASS": "Pass", "FAIL": "Fail", "NEEDS_REVIEW": "Review",
    "NOT_APPLICABLE": "N/A", "UNKNOWN": "Unknown", "ERROR": "Error",
}
RESULT_STYLES = {
    "PASS": "success", "FAIL": "danger", "NEEDS_REVIEW": "warning",
    "UNKNOWN": "warning", "ERROR": "danger", "NOT_APPLICABLE": "muted",
}
SORT_FIELDS = {
    "ID": "id", "CAT": "cat", "Result": "result", "Handling": "handling",
    "Area": "area", "Finding": "title", "Proposed action": "action", "Risk": "risk",
}
SORT_NAMES = {field: name for name, field in SORT_FIELDS.items()}
SORT_RANKS = {
    "result": {"FAIL": 0, "NEEDS_REVIEW": 1, "UNKNOWN": 2, "ERROR": 3,
               "PASS": 4, "NOT_APPLICABLE": 5},
    "cat": {"I": 0, "II": 1, "III": 2},
    "risk": {"high": 0, "medium": 1, "low": 2},
}


def wb_text(value):
    """Preserve layout and printable text without forwarding terminal controls."""
    return "".join(char for char in str(value or "")
                   if char in "\n\t" or unicodedata.category(char)[0] != "C").expandtabs(4)


def wb_line(value):
    return " ".join(wb_text(value).split())


def wb_button(label, callback):
    return urwid.AttrMap(urwid.Button(label, lambda _button: callback()), "button", "focus")


def wb_finding_count(count, qualifier=""):
    return "{} {}finding{}".format(count, qualifier, "" if count == 1 else "s")


class WorkbenchActions(urwid.Columns):
    """A button row with explicit keyboard focus traversal."""

    def __init__(self, *args, **kwargs):
        self.wrap_tabs = kwargs.pop("wrap_tabs", False)
        super(WorkbenchActions, self).__init__(*args, **kwargs)

    def keypress(self, size, key):
        if key in ("tab", "shift tab"):
            shift = -1 if key == "shift tab" else 1
            next_position = self.focus_position + shift
            if self.wrap_tabs:
                self.focus_position = next_position % len(self.contents)
                return None
            if 0 <= next_position < len(self.contents):
                self.focus_position = next_position
                return None
            return key
        return super(WorkbenchActions, self).keypress(size, key)


class WorkbenchFrame(urwid.Frame):
    """Make Tab move between actionable regions if the focused widget yields it."""

    def keypress(self, size, key):
        unhandled = super(WorkbenchFrame, self).keypress(size, key)
        if unhandled in ("tab", "shift tab"):
            regions = [name for name in ("header", "body", "footer")
                       if getattr(self, name) is not None and getattr(self, name).selectable()]
            if regions:
                step = -1 if unhandled == "shift tab" else 1
                index = regions.index(self.focus_position) if self.focus_position in regions else -1
                self.focus_position = regions[(index + step) % len(regions)]
                return None
        return unhandled


class WorkbenchEdit(urwid.Edit):
    def __init__(self, caption="", edit_text="", submit=None):
        super(WorkbenchEdit, self).__init__(caption, edit_text)
        self.submit = submit

    def keypress(self, size, key):
        if key == "enter" and self.submit:
            self.submit(self.edit_text)
            return None
        return super(WorkbenchEdit, self).keypress(size, key)


class WorkbenchPasteInput(str):
    """Pass coalesced clipboard text through Urwid as one input event."""

    def __new__(cls, text):
        event = super(WorkbenchPasteInput, cls).__new__(cls, "paste input")
        event.text = text
        return event


class WorkbenchIdPaste(urwid.Edit):
    def __init__(self, text, preview):
        super(WorkbenchIdPaste, self).__init__(edit_text=text, multiline=True)
        self.preview = preview

    def keypress(self, size, key):
        if isinstance(key, WorkbenchPasteInput):
            self.insert_text(key.text)
            return None
        if key == "tab":
            self.insert_text(" ")
            return None
        if key == "f2":
            self.preview(self.edit_text)
            return None
        return super(WorkbenchIdPaste, self).keypress(size, key)


class WorkbenchCycle(urwid.WidgetWrap):
    """Compact form field with the current value visible even when unfocused."""

    def __init__(self, label, choices, selected):
        self.label = label
        self.choices = list(choices)
        try:
            self.index = [value for value, _label in self.choices].index(selected)
        except ValueError:
            self.index = 0
        self.button = urwid.Button(self.caption(), lambda _button: self.advance(1))
        super(WorkbenchCycle, self).__init__(urwid.AttrMap(self.button, "button", "focus"))

    @property
    def value(self):
        return self.choices[self.index][0]

    def caption(self):
        return "{}  {}".format(self.label, self.choices[self.index][1])

    def advance(self, shift):
        self.index = (self.index + shift) % len(self.choices)
        self.button.set_label(self.caption())

    def keypress(self, size, key):
        if key in ("left", "right"):
            self.advance(-1 if key == "left" else 1)
            return None
        return super(WorkbenchCycle, self).keypress(size, key)


class WorkbenchForm(urwid.ListBox):
    def keypress(self, size, key):
        if key in ("tab", "shift tab"):
            shift = -1 if key == "shift tab" else 1
            position = self.focus_position if len(self.body) else 0
            for index in range(position + shift, len(self.body) if shift == 1 else -1, shift):
                if self.body[index].selectable():
                    self.set_focus(index)
                    return None
            return key
        return super(WorkbenchForm, self).keypress(size, key)


class WorkbenchSummaryCell(urwid.Text):
    """Mark clipped summaries on older Urwid releases using terminal cell widths."""

    def __init__(self, style, value):
        self.style = style
        self.value = value
        self.width = calc_width(value, 0, len(value))
        super(WorkbenchSummaryCell, self).__init__((style, value), wrap="clip")

    def render(self, size, focus=False):
        columns, = size
        if self.width <= columns or columns <= 3:
            return super(WorkbenchSummaryCell, self).render(size, focus)
        end, _ = calc_text_pos(self.value, 0, len(self.value), columns - 3)
        return urwid.Text((self.style, self.value[:end].rstrip() + "..."), wrap="clip").render(size, focus)


class WorkbenchFinding(urwid.WidgetWrap):
    def __init__(self, row, fields, selected, toggle, detail):
        self.row = row
        self.toggle = toggle
        self.detail = detail
        self.selected = selected
        self.check = urwid.Text("[x]" if selected else "[ ]", wrap="clip")
        columns = [(3, self.check)]
        for key, label, width in fields:
            value = wb_line(row.get(key))
            style = "base"
            if key == "result":
                style = RESULT_STYLES.get(value, "muted")
                value = RESULT_LABELS.get(value, value)
            elif key == "cat":
                style = {"I": "danger", "II": "warning", "III": "cyan"}.get(value, "base")
                value = "CAT " + value
            elif key == "risk":
                style = {"high": "danger", "medium": "warning"}.get(value.lower(), "base")
            elif key == "title":
                value = wb_finding_title(row)
            elif key == "action":
                value = wb_plan_summary(row)
            if key in ("title", "action"):
                cell = WorkbenchSummaryCell(style, value)
            else:
                cell = urwid.Text((style, value), wrap="clip")
            columns.append((width, cell) if width else ("weight", 1, cell))
        grid = urwid.Columns(columns, dividechars=1)
        focus_styles = {None: "focus"}
        for attr in ("base", "success", "danger", "warning", "cyan", "muted"):
            focus_styles[attr] = "focus"
        super(WorkbenchFinding, self).__init__(urwid.AttrMap(grid, None, focus_styles))

    def set_checked(self, checked):
        if checked != self.selected:
            self.selected = checked
            self.check.set_text("[x]" if checked else "[ ]")

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key == " ":
            self.toggle(self.row["id"])
            return None
        if key == "enter":
            self.detail(self.row["id"])
            return None
        return key

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1 and col < 3:
            self.toggle(self.row["id"])
            return True
        return False


class WorkbenchFindingWalker(urwid.ListWalker):
    """Build and update finding widgets when Urwid visits their rows."""

    def __init__(self, widget_for, empty_message="No findings match. Clear search or change filters."):
        self.widget_for = widget_for
        self.visible = []
        self.focus = 0
        self.empty = urwid.Text(("muted", empty_message))

    def set_matches(self, visible, focus):
        self.visible = visible
        self.focus = focus
        self._modified()

    def __len__(self):
        return max(1, len(self.visible))

    def __getitem__(self, position):
        if not 0 <= position < len(self):
            raise IndexError(position)
        return self.widget_for(self.visible[position]) if self.visible else self.empty

    def next_position(self, position):
        return position + 1

    def prev_position(self, position):
        return position - 1

    def set_focus(self, position):
        if not 0 <= position < len(self):
            raise IndexError(position)
        self.focus = position
        self._modified()


class WorkbenchFindings(urwid.ListBox):
    def __init__(self, walker, on_focus):
        super(WorkbenchFindings, self).__init__(walker)
        self.on_focus = on_focus

    def keypress(self, size, key):
        before = self.focus_position
        if key in ("home", "end", "ctrl home", "ctrl end"):
            first = key.endswith("home")
            self.set_focus(0 if first else len(self.body) - 1, "below" if first else "above")
            unhandled = None
        else:
            unhandled = super(WorkbenchFindings, self).keypress(size, key)
        if self.focus_position != before:
            self.on_focus()
        return unhandled

    def mouse_event(self, size, event, button, col, row, focus):
        before = self.focus_position
        handled = super(WorkbenchFindings, self).mouse_event(size, event, button, col, row, focus)
        if self.focus_position != before:
            self.on_focus()
        return handled


class WorkbenchReviewedFinding(urwid.WidgetWrap):
    def __init__(self, row, inspect):
        self.inspect = lambda: inspect(row)
        result = wb_line(row.get("result"))
        columns = urwid.Columns([
            (9, urwid.Text(wb_line(row["id"]), wrap="clip")),
            (8, urwid.Text((RESULT_STYLES.get(result, "muted"), RESULT_LABELS.get(result, result)),
                           wrap="clip")),
            WorkbenchSummaryCell("base", wb_finding_title(row)),
        ], dividechars=1)
        focused = dict.fromkeys((None, "base", "muted", *RESULT_STYLES.values()), "focus")
        super(WorkbenchReviewedFinding, self).__init__(urwid.AttrMap(columns, None, focused))

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key in ("enter", " "):
            self.inspect()
            return None
        return key

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.inspect()
            return True
        return False


class WorkbenchReviewIndex:
    """Search findings in the current review."""

    def __init__(self, rows, inspect, focus_list):
        self.rows = {row["id"]: row for row in rows}
        self.widgets = {}
        self.inspect = inspect
        self.search = WorkbenchEdit(" Search  ", submit=lambda _query: focus_list())
        urwid.connect_signal(self.search, "change", self.search_changed)
        clear = wb_button("Clear", lambda: self.search.set_edit_text(""))
        self.search_row = WorkbenchActions(
            [urwid.AttrMap(self.search, "input", "focus"), (12, clear)], dividechars=1)
        self.count = urwid.Text("", wrap="clip")
        self.controls = urwid.Pile([self.search_row, self.count])
        self.walker = WorkbenchFindingWalker(
            self.widget_for, "No reviewed findings match. Clear or change the search.")
        self.listbox = WorkbenchFindings(self.walker, self.update_count)
        columns = urwid.Columns([
            (9, urwid.Text("Vuln-ID")), (8, urwid.Text("Result")), urwid.Text("Finding"),
        ], dividechars=1)
        self.body = urwid.LineBox(urwid.Frame(self.listbox, header=urwid.AttrMap(columns, "section")))
        self.search_text = {}
        for finding, row in self.rows.items():
            result = wb_line(row.get("result"))
            self.search_text[finding] = " ".join((
                wb_line(finding), wb_line(row.get("title")), wb_finding_title(row), result,
                result.replace("_", " "), RESULT_LABELS.get(result, result),
            )).casefold()
        self.search_changed(self.search, "")

    def widget_for(self, finding):
        if finding not in self.widgets:
            self.widgets[finding] = WorkbenchReviewedFinding(self.rows[finding], self.inspect)
        return self.widgets[finding]

    def search_changed(self, _edit, query):
        previous = self.walker.visible
        focused = previous[self.walker.focus] if previous else ""
        terms = query.casefold().split()
        matches = [finding for finding, text in self.search_text.items()
                   if all(term in text for term in terms)]
        self.walker.set_matches(matches, matches.index(focused) if focused in matches else 0)
        self.update_count()

    def update_count(self):
        matches = len(self.walker.visible)
        position = "Row {}/{}".format(self.walker.focus + 1, matches) if matches else "No matches"
        self.count.set_text(("accent", " {}  |  {} reviewed".format(position, len(self.rows))))


class WorkbenchSortHeading(urwid.Text):
    _selectable = True

    def __init__(self, label, width, activate):
        super(WorkbenchSortHeading, self).__init__(label, wrap="clip")
        self.label = label
        self.width = width
        self.activate = activate

    def show_direction(self, direction):
        if not direction:
            self.set_text(self.label)
            return
        separator = " " if not self.width or len(self.label) + 2 <= self.width else ""
        self.set_text(self.label + separator + direction)

    def keypress(self, size, key):
        if key in ("enter", " "):
            self.activate()
            return None
        return key

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.activate()
            return True
        return False


class WorkbenchFindingsTable(urwid.Frame):
    def keypress(self, size, key):
        if self.focus_position == "body" and key == "shift tab":
            self.focus_position = "header"
            return None
        if self.focus_position == "header" and key in ("down", "esc"):
            self.focus_position = "body"
            return None
        unhandled = super(WorkbenchFindingsTable, self).keypress(size, key)
        if self.focus_position == "header" and unhandled == "tab":
            self.focus_position = "body"
            return None
        return unhandled


def wb_finding_title(row):
    value = wb_line(row.get("title"))
    for prefix in ("The RHEL 8 ", "RHEL 8 ", "All RHEL 8 "):
        if value.startswith(prefix):
            value = ("All " if prefix.startswith("All") else "") + value[len(prefix):]
            return value[:1].upper() + value[1:]
    return value


def wb_plan_summary(row):
    return wb_line(str(row.get("plan", "")).split("\n", 1)[0]) or wb_finding_action(row)


def wb_sort_value(row, field):
    value = wb_line(row.get(field))
    if field in SORT_RANKS:
        return SORT_RANKS[field].get(value.lower() if field == "risk" else value, 9)
    if field == "title":
        return wb_finding_title(row).casefold()
    if field == "action":
        return wb_plan_summary(row).casefold()
    return value.casefold()


def wb_finding_action(row):
    if row.get("ready"):
        return "Guarded proposal available"
    if row.get("action"):
        return wb_line(row["action"])
    return {
        "PASS": "Already compliant",
        "NOT_APPLICABLE": "Not applicable",
    }.get(row.get("result"), {
        "PENDING_ACTIVATION": "Activation and verification pending",
        "BLOCKED": "Review the blocking prerequisite",
        "MANUAL_REQUIRED": "Administrator review",
    }.get(row.get("outcome"), "Review evidence"))


class WorkbenchDocumentLine(urwid.Text):
    """Anchor scrolling at any line on the supported Urwid 1.3 screen."""

    _selectable = True

    def keypress(self, size, key):
        return key


def wb_document(text):
    """Use real row boundaries so paging and terminal resize preserve readability."""
    widgets = []
    for line in wb_text(text).split("\n"):
        if line.startswith(("--- ", "+++ ", "@@ ", "diff ")):
            style = "diff_meta"
        elif line.startswith("- "):
            style = "diff_remove"
        elif line.startswith("+ "):
            style = "diff_add"
        elif line and (line.isupper() or line.startswith((
                    "Change ", "Proposed changes", "Other selected", "Current assessment",
                    "Handling:", "Evidence:", "Affected rule IDs", "Proposed change",
                    "Activation:", "Recovery:", "Assessment"))):
            style = "section"
        else:
            style = "base"
        widgets.append(WorkbenchDocumentLine((style, line)))
    return urwid.ListBox(urwid.SimpleFocusListWalker(widgets or [WorkbenchDocumentLine("")]))


class Workbench:
    def __init__(self, send):
        self.send = send
        self.widget = urwid.WidgetPlaceholder(urwid.Filler(urwid.Text(
            ("section", "Opening the STIG workspace…"), align="center")))
        self.base_frame = self.widget.original_widget
        self.context = {}
        self.rows = {}
        self.indexed_rows = None
        self.search_index = {}
        self.history = None
        self.path_browser = None
        self.selected = set()
        self.selection_before = None
        self.visible = []
        self.visible_positions = {}
        self.focus_id = ""
        self.query = ""
        self.filters = {"cat": "", "result": "", "handling": "", "area": "", "selected": "", "quick": ""}
        self.sort_name = "ID"
        self.sort_descending = False
        self.width = 80
        self.height = 25
        self.findings_width = None
        self.page = "loading"
        self.modal = None
        self.review = None
        self.review_scope = ()
        self.settings_after_review = False
        self.review_diff = False
        self.review_hidden = 0
        self.busy = True
        self.feedback = ""
        self.status_widget = urwid.Text("")
        self.count_widget = urwid.Text("")
        self.focus_panel = None
        self.initialized = False
        self.setting_fields = None
        self.request_name = ""
        self.request_retry = None
        self.too_small = False

    def resize(self, width, height):
        previous = self.layout_flags()
        was_small = self.too_small
        self.width, self.height = width, height
        self.too_small = width < 56 or height < 18
        if self.too_small or was_small:
            self.render_active_page()
        if not self.too_small and self.page == "findings" and not self.modal and (
                was_small or previous != self.layout_flags()):
            focus_region = self.base_frame.focus_position
            self.show_findings(focus_region)

    def render_active_page(self):
        if self.too_small:
            self.widget.original_widget = urwid.Filler(urwid.Text(
                ("warning", "Resize the terminal to at least 56 columns and 18 rows."), align="center"))
        elif self.history is not None:
            self.widget.original_widget = self.history.widget
        elif self.path_browser is not None:
            self.widget.original_widget = self.path_browser.widget
        else:
            self.widget.original_widget = self.modal["overlay"] if self.modal else self.base_frame

    def handle_event(self, event):
        kind = event.get("type")
        if kind == "modal":
            self.backend_modal(event)
            return
        if kind == "progress":
            current = wb_line(event.get("id"))
            self.feedback = "{}  |  {} of {} checked".format(
                "Assessing " + current if current else "Starting assessment",
                event.get("complete", 0), event.get("count", 0))
            self.status_widget.set_text(("accent", self.feedback))
            return
        completed = self.request_name
        retry = self.request_retry
        self.busy = False
        self.request_name = ""
        self.request_retry = None
        if kind == "state":
            self.close_modal()
            self.context = event.get("context", {})
            previous_focus = self.focus_id
            self.rows = {row["id"]: row for row in event.get("rows", [])}
            if event.get("reset_selection"):
                self.selected = {key for key, row in self.rows.items() if row.get("selected")}
                self.selection_before = None
            else:
                self.selected.intersection_update(self.rows)
                if self.selection_before is not None:
                    self.selection_before = self.selection_before.intersection(self.rows)
            self.focus_id = previous_focus if previous_focus in self.rows else ""
            if completed == "import":
                self.query, self.sort_name = "", "ID"
                self.sort_descending = False
                self.filters = {key: "" for key in self.filters}
            self.feedback = {
                "back": "", "scan": "Assessment refreshed.", "settings": "Run settings updated.",
                "import": "Checklist imported. Review the proposed scope.",
                "load": "Saved selection loaded.",
            }.get(completed, "")
            if not self.initialized:
                self.initialized = True
                self.show_settings()
            else:
                self.show_findings()
        elif kind == "review":
            self.close_modal()
            self.feedback = ""
            self.review = event
            self.show_review(self.review_diff)
        elif kind == "detail":
            self.close_modal()
            self.feedback = ""
            self.show_detail(event)
        elif kind in ("notice", "error"):
            self.feedback = wb_line(event.get("message"))
            self.status_widget.set_text(("warning" if kind == "error" else "muted", self.feedback))
            if kind == "error":
                message = wb_text(event.get("message"))
                if completed == "accept" and self.review:
                    self.review["token"] = ""
                    self.show_review(self.review_diff)
                    self.open_modal("Plan needs a fresh review", message,
                                    [("Review again", self.retry_review), ("Settings", self.open_run_settings),
                                     ("Back", self.close_modal)], default=2)
                elif retry is not None:
                    retry(message)
                else:
                    self.open_modal("Unable to continue", message, [("Back", self.close_modal)])

    def request(self, *fields, on_error=None):
        if self.busy:
            return
        self.close_modal()
        self.request_name = fields[1] if fields[0] == "setup" else fields[0]
        self.request_retry = on_error
        if fields[0] == "review":
            self.review_scope = fields[1:]
        self.busy = True
        self.feedback = {
            "scan": "Refreshing findings…", "review": "Building a fresh plan…",
            "detail": "Loading finding details…", "import": "Validating the checklist…",
            "settings": "Validating settings and refreshing…", "setup": "Validating run settings and scope…",
            "accept": "Preparing the attended run…",
        }.get(fields[0], "Working…")
        self.status_widget.set_text(("accent", self.feedback))
        try:
            self.send(*fields)
        except ValueError as error:
            self.request_name = ""
            self.request_retry = None
            self.busy = False
            if on_error is None:
                self.open_modal("Invalid request", wb_text(error), [("Back", self.close_modal)])
            else:
                on_error(wb_text(error))

    def title(self, subtitle):
        mode = wb_line(self.context.get("mode", "status")).upper()
        title = " STIG Assistant   /   {}   /   {}".format(subtitle, mode)
        run = " {}  |  {}".format(wb_line(self.context.get("host", "Local host")),
                                  wb_line(self.context.get("baseline", "RHEL 8")))
        return urwid.Pile([urwid.AttrMap(urwid.Text(title, wrap="clip"), "header"),
                          urwid.Text(("muted", run), wrap="clip")])

    def sections(self, subtitle, body, actions, hint, initial="body", extra_header=None):
        header = self.title(subtitle)
        if extra_header is not None:
            header = urwid.Pile([header, extra_header])
            header.focus_position = 1
        self.status_widget = urwid.Text(("muted", self.feedback), wrap="clip")
        footer = urwid.Pile([actions, self.status_widget, urwid.Text(("muted", hint), wrap="clip")])
        footer.focus_position = 0
        self.base_frame = WorkbenchFrame(body, header=header, footer=footer, focus_part=initial)
        self.render_active_page()

    def buttons(self, entries, default=0, cycle=False, packed=False):
        buttons = []
        for label, callback in entries:
            button = wb_button(label, callback)
            buttons.append((len(label) + 4, button) if packed else button)
        return WorkbenchActions(buttons, dividechars=1, focus_column=default, wrap_tabs=cycle)

    def show_settings(self):
        self.settings_after_review = self.page in ("review", "review index", "review item")
        self.page = "settings"
        can_apply = bool(self.context.get("can_apply"))
        modes = [("apply", "Apply")] if can_apply else [("status", "Status"), ("dry-run", "Dry run")]
        if not can_apply and self.context.get("diff_available", True):
            modes.append(("diff", "Diff"))
        cap = self.context.get("risk_cap") or "high"
        risk_options = ["low", "medium", "high"]
        if cap in risk_options:
            risk_options = risk_options[:risk_options.index(cap) + 1]
        activation = [("1", "Defer where supported")]
        if self.context.get("defer_required") not in (True, 1, "1"):
            activation.insert(0, ("0", "As proposed"))
        self.setting_fields = {
            "mode": WorkbenchCycle("Mode", modes, self.context.get("mode")),
            "risk": WorkbenchCycle("Risk ceiling", [(x, x.title()) for x in risk_options],
                                   self.context.get("risk")),
            "defer": WorkbenchCycle("Activation", activation,
                                    "1" if self.context.get("defer") in (True, 1, "1") else "0"),
            "format": WorkbenchCycle("Report format", [(x, x.upper()) for x in ("text", "json", "csv")],
                                     self.context.get("format")),
            "group": WorkbenchCycle("Text report order", [("", "Vuln-ID"), ("result", "Result group")],
                                    self.context.get("group")),
        }
        for field, caption in (("ticket", "Change ticket  "), ("site_config", "Site config  "),
                               ("report_dir", "Report directory  "), ("backup_dir", "Backup directory  ")):
            value = str(self.context.get(field) or "")
            self.setting_fields[field] = WorkbenchEdit(caption, value)
        source = self.context.get("source") or "Built-in selection"
        controls = [
            urwid.Text(("section", "Preflight")),
            urwid.Text("RHEL 8  |  {} findings  |  {}".format(
                self.context.get("scope_count", len(self.rows)), wb_line(self.context.get("version", "")))),
            urwid.Text("Scope source  {}".format(wb_line(source))),
            urwid.Text(("muted", "Apply was requested at launch. Changes require attended approval."
                        if can_apply else "Assessment only. Launch explicitly with --apply to request changes.")),
        ]
        host_details = [wb_line(self.context.get(field)) for field in ("arch", "boot_mode", "kernel")]
        if any(host_details):
            controls.append(urwid.Text(("muted", "  |  ".join(value for value in host_details if value))))
        if self.context.get("diff_available") is False:
            controls.append(urwid.Text(("warning", "File diffs need the diffutils package.")))
        if self.context.get("elevated") is False:
            controls.append(urwid.Text(("warning", "Some checks may need elevated read access.")))
        controls.extend([
            urwid.Divider(),
            urwid.Text(("section", "Run settings")),
            self.setting_fields["mode"],
            self.setting_fields["risk"],
            self.setting_fields["defer"],
            self.setting_fields["format"],
        ])
        if not can_apply:
            controls.append(self.setting_fields["group"])
        for key in ("ticket", "site_config", "report_dir", "backup_dir"):
            field = urwid.AttrMap(self.setting_fields[key], "input", "focus")
            if key == "site_config":
                field = WorkbenchActions([field, (12, wb_button("Browse", self.browse_site_config))], dividechars=1)
            controls.append(field)
        controls.extend([urwid.Divider(), urwid.Text(("section", "Scope")),
                         urwid.Text(("muted", "Findings, Import CKL, and Load use the settings above.")),
                         wb_button("Import Open findings from CKL", self.import_path),
                         wb_button("Load a saved selection", self.load_path)])
        form = WorkbenchForm(urwid.SimpleFocusListWalker(controls))
        self.initial_settings = self.settings_values()
        actions = self.buttons([("Findings", self.open_findings_from_settings),
                                ("Results", self.open_history), ("Check", self.inspect_settings),
                                ("Help", self.help_screen), ("Exit", self.confirm_exit)], packed=True)
        self.sections("Run settings", form, actions,
                      "F8 Check  |  F9 Results  |  Findings starts assessment",
                      initial="footer")

    def open_history(self):
        if self.busy or self.history is not None:
            return
        self.close_modal()
        self.history = RunHistory(self.context.get("report_dir", ""), self.close_history)
        self.render_active_page()

    def close_history(self):
        self.history = None
        if self.page == "findings" and self.findings_width != self.layout_flags():
            self.show_findings(self.base_frame.focus_position)
        else:
            self.render_active_page()

    def open_file_browser(self, initial, use_path, suffix):
        def choose(path):
            self.close_file_browser()
            use_path(path)

        self.path_browser = LocalFileBrowser(initial, choose, self.close_file_browser, suffix)
        self.render_active_page()

    def close_file_browser(self):
        self.path_browser = None
        if not self.modal and self.page == "findings" and self.findings_width != self.layout_flags():
            self.show_findings(self.base_frame.focus_position)
        else:
            self.render_active_page()

    def browse_site_config(self):
        field = self.setting_fields["site_config"]

        def use_path(path):
            field.set_edit_text(path)
            field.set_edit_pos(len(path))

        self.open_file_browser(field.edit_text, use_path, ".conf")

    def settings_values(self):
        fields = self.setting_fields
        format_names = ("mode", "ticket", "risk", "defer", "format", "group",
                        "site_config", "report_dir", "backup_dir")
        if self.context.get("can_apply"):
            fields["group"].index = 0
        return [fields[name].edit_text if isinstance(fields[name], urwid.Edit) else fields[name].value
                for name in format_names]

    def open_findings_from_settings(self):
        values = self.settings_values()
        if values == self.initial_settings and not self.context.get("site_config"):
            if self.context.get("assessed", True) and not self.settings_after_review:
                self.show_findings()
            else:
                self.request("scan")
        else:
            self.save_settings()

    def inspect_settings(self):
        self.request("inspect", *self.settings_values())

    def open_run_settings(self):
        self.close_modal()
        self.show_settings()

    def save_settings(self):
        values = self.settings_values()
        if any(any(unicodedata.category(char)[0] == "C" for char in item) for item in values):
            self.open_modal("Invalid setting", "Remove control characters from the fields.",
                            [("Back", self.close_modal)])
            return
        self.request("settings", *values)

    def side_width(self):
        return max(32, min(46, self.width // 4)) if self.width >= 108 else 0

    def layout_flags(self):
        side = self.side_width()
        columns = self.width - 2 - (side + 1 if side else 0)
        return bool(side), columns >= 66, columns >= 82, columns >= 104, self.width < 80, columns >= 128

    def field_layout(self):
        _, show_handling, show_area, show_action, _, show_risk = self.layout_flags()
        fields = [("id", "Vuln-ID", 9), ("cat", "CAT", 8), ("result", "Result", 8)]
        if show_handling:
            fields.append(("handling", "Handling", 9))
        if show_area:
            fields.append(("area", "Area", 11))
        fields.append(("title", "Finding", 0))
        if show_action:
            fields.append(("action", "Proposed action", 0))
        if show_risk:
            fields.append(("risk", "Risk", 8))
        return fields

    QUICK_VIEWS = [
        ("", "All"), ("attention", "Needs attention"), ("ready", "Ready to review"),
        ("blocked", "Blocked"), ("pending", "Pending activation"), ("selected", "Selected only"),
    ]

    def matches_quick_view(self, row):
        quick = self.filters.get("quick")
        result = row.get("result")
        outcome = row.get("outcome")
        if quick == "attention":
            return result not in ("PASS", "NOT_APPLICABLE") or outcome == "PENDING_ACTIVATION"
        if quick == "ready":
            return bool(row.get("ready"))
        if quick == "blocked":
            return row.get("handling") == "Blocked" and outcome != "PENDING_ACTIVATION"
        if quick == "pending":
            return outcome == "PENDING_ACTIVATION"
        if quick == "selected":
            return row["id"] in self.selected
        return True

    def match_rows(self):
        terms = self.query.casefold().split()
        # Each assessment supplies a new row mapping, even for repeated IDs.
        if self.indexed_rows is not self.rows:
            self.indexed_rows = self.rows
            self.search_index = {}
        facets = [(name, value.casefold()) for name, value in self.filters.items()
                  if value and name not in ("selected", "quick")]
        matches = []
        for row in self.rows.values():
            finding = row["id"]
            if self.filters["selected"] and finding not in self.selected:
                continue
            if not self.matches_quick_view(row):
                continue
            if any(wb_line(row.get(name)).casefold() != value for name, value in facets):
                continue
            if terms:
                haystack = self.search_index.get(finding)
                if haystack is None:
                    haystack = " ".join(wb_line(row.get(key)) for key in (
                        "id", "title", "cat", "result", "handling", "area", "action", "plan")).casefold()
                    self.search_index[finding] = haystack
                if not all(term in haystack for term in terms):
                    continue
            matches.append(row)
        field = SORT_FIELDS[self.sort_name]
        # The second stable sort keeps ID order for ties in either direction.
        matches.sort(key=lambda row: row["id"])
        matches.sort(key=lambda row: wb_sort_value(row, field), reverse=self.sort_descending)
        return matches

    def sort_by_header(self, name):
        if name == self.sort_name:
            self.sort_descending = not self.sort_descending
        else:
            self.sort_name = name
            self.sort_descending = False
        self.refresh_findings()

    def focus_sort_headers(self, name=None):
        self.base_frame.focus_position = "body"
        if self.focus_panel is not None:
            self.base_frame.body.focus_position = 0
        self.findings_table.focus_position = "header"
        names = list(self.sort_headers)
        if name not in self.sort_headers:
            name = self.sort_name
        self.sort_columns.focus_position = names.index(name) + 1 if name in self.sort_headers else 1

    def update_sort_headers(self):
        marker = "v" if self.sort_descending else "^"
        for name, heading in self.sort_headers.items():
            heading.show_direction(marker if name == self.sort_name else "")

    def show_findings(self, focus_region="body"):
        previous = getattr(self, "findings_table", None)
        rebuilding = self.page == "findings" and previous is not None
        keep_header_focus = rebuilding and focus_region == "body" and previous.focus_position == "header"
        focused_heading = None
        if keep_header_focus and self.sort_columns.focus_position:
            focused_heading = list(self.sort_headers)[self.sort_columns.focus_position - 1]
        search_caret = self.search.edit_pos if rebuilding else len(self.query)
        search_focus = self.search_row.focus_position if rebuilding else 0
        self.page = "findings"
        self.review = None
        self.findings_width = self.layout_flags()
        self.search = WorkbenchEdit(" Search  ", self.query)
        self.search.set_edit_pos(min(search_caret, len(self.query)))
        urwid.connect_signal(self.search, "change", self.search_changed)
        clear = wb_button("Clear", lambda: self.search.set_edit_text(""))
        self.search_row = WorkbenchActions(
            [urwid.AttrMap(self.search, "input", "focus"), (12, clear)], dividechars=1,
            focus_column=search_focus)
        self.count_widget = urwid.Text("", wrap="clip")
        self.filter_widget = urwid.Text("")
        field_columns = [(3, urwid.Text("Use"))]
        self.sort_headers = {}
        self.finding_fields = self.field_layout()
        for field, label, width in self.finding_fields:
            name = SORT_NAMES[field]
            column = WorkbenchSortHeading(label, width, lambda name=name: self.sort_by_header(name))
            self.sort_headers[name] = column
            heading = urwid.AttrMap(column, "section", "focus")
            field_columns.append((width, heading) if width else ("weight", 1, heading))
        self.sort_columns = WorkbenchActions(field_columns, dividechars=1, focus_column=1)
        heading = urwid.AttrMap(self.sort_columns, "section")
        self.row_widgets = {}
        self.walker = WorkbenchFindingWalker(self.finding_widget)
        self.finding_list = WorkbenchFindings(self.walker, self.update_focus)
        findings = self.findings_table = WorkbenchFindingsTable(self.finding_list, header=heading)
        self.focus_panel = None
        if self.side_width():
            self.focus_panel = urwid.WidgetPlaceholder(urwid.Filler(urwid.Text("")))
            body = urwid.Columns([("weight", 1, urwid.LineBox(findings)),
                                  (self.side_width(), urwid.LineBox(self.focus_panel))],
                                 dividechars=1)
        else:
            body = urwid.LineBox(findings)
        compact = self.width < 80
        action_entries = [("Filters", self.open_filters), ("Actions", self.open_actions),
                          ("Details", self.details),
                          ("Review" if compact else "Review plan", self.review_selection),
                          ("Exit", self.confirm_exit)]
        if self.width >= 108:
            action_entries.insert(3, ("Implement" if self.context.get("can_apply") else "Diff",
                                      self.review_focused if self.context.get("can_apply")
                                      else self.preview_finding_diff))
        if compact:
            actions = WorkbenchActions(
                [(len(label) + 4, wb_button(label, callback)) for label, callback in action_entries],
                dividechars=1)
        else:
            actions = self.buttons(action_entries)
        header_controls = urwid.Pile([self.search_row, self.filter_widget, self.count_widget])
        header_controls.focus_position = 0
        hint = "/ Search  S Sort  F6 Plan  F8 Scan  F9 Runs  F10 Views"
        if self.width >= 80:
            hint = "Space select  Home/End  / Search  S Sort  F6 Plan  F8 Scan  F9 Runs  F10 Views"
        self.sections("Findings", body, actions,
                      hint,
                      initial=focus_region, extra_header=header_controls)
        self.refresh_findings()
        if keep_header_focus:
            self.focus_sort_headers(focused_heading)

    def search_changed(self, _edit, value):
        self.query = value
        self.refresh_findings()

    def refresh_findings(self):
        matches = self.match_rows()
        self.visible = [row["id"] for row in matches]
        self.visible_positions = {finding: index for index, finding in enumerate(self.visible)}
        self.walker.set_matches(self.visible, self.visible_positions.get(self.focus_id, 0))
        self.update_sort_headers()
        self.update_filter_summary()
        self.update_focus()

    def finding_widget(self, finding):
        widget = self.row_widgets.get(finding)
        selected = finding in self.selected
        if widget is None:
            widget = self.row_widgets[finding] = WorkbenchFinding(
                self.rows[finding], self.finding_fields, selected, self.toggle, self.details)
        else:
            widget.set_checked(selected)
        return widget

    def update_focus(self):
        self.focus_id = self.visible[self.finding_list.focus_position] if self.visible else ""
        self.update_counts()
        if self.focus_panel is None:
            return
        row = self.rows.get(self.focus_id)
        components = [urwid.Text(("section", "Focused finding")), urwid.Divider()]
        if row:
            result = wb_line(row.get("result"))
            components.extend([
                urwid.Text(("accent", row["id"])),
                urwid.Text(wb_text(row.get("title"))),
                urwid.Divider(),
                urwid.Text([("muted", "CAT {}  |  ".format(wb_line(row.get("cat")))),
                            (RESULT_STYLES.get(result, "muted"), RESULT_LABELS.get(result, result))]),
                urwid.Text("{}  |  {} risk".format(wb_line(row.get("handling")),
                                                     wb_line(row.get("risk")))),
                urwid.Divider(),
                urwid.Text(("section", "Proposed action")),
                urwid.Text(wb_plan_summary(row)),
                urwid.Divider(),
                urwid.Text(("section", "Evidence")),
                urwid.Text(wb_text(row.get("evidence")) or "No local evidence was recorded."),
                urwid.Divider(),
                urwid.Text(("muted", "F4 Details  |  F6 Plan")),
            ])
            if row.get("ckl_status"):
                components.insert(5, urwid.Text(("muted", "At checklist export  " + wb_line(row["ckl_status"]))))
        else:
            components.append(urwid.Text("No matching finding is focused."))
        self.focus_panel.original_widget = urwid.ListBox(
            urwid.SimpleFocusListWalker(components))

    def update_counts(self):
        hidden = sum(finding not in self.visible_positions for finding in self.selected)
        position = ("Row {}/{}".format(self.finding_list.focus_position + 1, len(self.visible))
                    if self.visible else "No matches")
        self.count_widget.set_text(("accent", " {}  {} in scope  {} selected  {} hidden".format(
            position, len(self.rows), len(self.selected), hidden)))

    def update_filter_summary(self):
        labels = [("CAT", "cat"), ("Result", "result"), ("Handling", "handling"), ("Area", "area")]
        summary = ["Sort {} {}".format(self.sort_name,
                                       "descending" if self.sort_descending else "ascending")]
        if self.filters.get("quick"):
            summary.append("View " + dict(self.QUICK_VIEWS)[self.filters["quick"]])
        for label, key in labels:
            value = self.filters[key]
            if value:
                summary.append("{} {}".format(label, RESULT_LABELS.get(value, value)))
        if self.filters["selected"]:
            summary.append("Selected only")
        self.filter_widget.set_text(("muted", " " + "  |  ".join(summary)))

    def toggle(self, finding):
        self.selection_before = frozenset(self.selected)
        if finding in self.selected:
            self.selected.remove(finding)
        else:
            self.selected.add(finding)
        if self.filters["selected"] or self.filters.get("quick") == "selected":
            self.refresh_findings()
        else:
            self.finding_widget(finding)
            self.update_counts()

    def open_filters(self):
        widgets = []
        fields = {}
        for label, key, values in (
            ("Quick view", "quick", self.QUICK_VIEWS[1:]),
            ("CAT", "cat", [("I", "I"), ("II", "II"), ("III", "III")]),
            ("Result", "result", list(RESULT_LABELS.items())),
            ("Handling", "handling", [(item, item) for item in ("Automatic", "Manual", "Blocked")]),
            ("Area", "area", [(item, item) for item in sorted(
                {wb_line(row.get("area")) for row in self.rows.values()} - {""})]),
            ("Selection", "selected", [("1", "Selected only")]),
        ):
            fields[key] = WorkbenchCycle(label, [("", "All")] + values, self.filters[key])
            widgets.append(fields[key])
        sort = WorkbenchCycle("Order", [(item, item) for item in SORT_FIELDS], self.sort_name)
        direction = WorkbenchCycle("Direction", [("up", "Ascending"), ("down", "Descending")],
                                   "down" if self.sort_descending else "up")
        widgets.extend([sort, direction])

        def apply_filters():
            self.filters = {key: field.value for key, field in fields.items()}
            self.sort_name = sort.value
            self.sort_descending = direction.value == "down"
            self.close_modal()
            self.refresh_findings()

        def clear_filters():
            self.filters = {key: "" for key in self.filters}
            self.sort_name = "ID"
            self.sort_descending = False
            self.close_modal()
            self.search.set_edit_text("")
            self.refresh_findings()

        self.open_modal("Filters and sort", "Filters preserve your selection, including hidden findings.",
                        [("Show results", apply_filters), ("Clear all", clear_filters),
                         ("Back", self.close_modal)], widgets=widgets, initial="body")

    def open_actions(self):
        def action(callback):
            def selected():
                self.close_modal()
                callback()
            return selected
        ready = len(self.bulk_matches("ready"))
        failed = len(self.bulk_matches("failed"))
        selected = len(self.bulk_matches("clear"))
        hidden = len(self.selected) - selected
        items = []
        if self.focus_id:
            plan = "Implement" if self.context.get("can_apply") else "Preview"
            items.append(("{} {} (F6)".format(plan, self.focus_id), self.review_focused))
        items.extend([
            ("Quick triage views (F10)", self.open_quick_views),
            ("Paste Vuln-IDs", self.open_batch_selection),
            ("Select eligible matches ({})".format(ready), lambda: self.bulk("ready")),
            ("Select eligible failing matches ({})".format(failed), lambda: self.bulk("failed")),
            ("Clear selected matches ({})".format(selected), lambda: self.bulk("clear")),
            ("Clear all selected ({})".format(len(self.selected)), self.confirm_clear_selection),
        ])
        if self.selection_before is not None:
            items.append(("Undo last selection change", self.undo_last_selection))
        items.extend([
            ("Save selected IDs", self.save_path), ("Load saved selection", self.load_path),
            ("Import Open findings from CKL", self.import_path),
            ("Refresh local assessment (F8)", lambda: self.request("scan")),
            ("Run settings", self.show_settings), ("Saved results", self.open_history),
            ("Help", self.help_screen),
        ])
        title = "Actions  |  {} matching".format(len(self.visible))
        if hidden:
            title += "  |  {} selected outside".format(hidden)
        self.open_modal(title, "",
                        [("Back", self.close_modal)],
                        widgets=[wb_button(name, action(callback)) for name, callback in items],
                        initial="body")

    def open_quick_views(self):
        def choose(key):
            self.filters["quick"] = key
            self.close_modal()
            self.refresh_findings()

        self.open_modal(
            "Quick triage views",
            "Quick views combine with search and filters. Your selection is preserved.",
            [("Back", self.close_modal)],
            widgets=[wb_button(label, lambda key=key: choose(key))
                     for key, label in self.QUICK_VIEWS],
            initial="body",
        )

    def bulk_matches(self, behavior):
        if behavior == "clear":
            return [key for key in self.visible if key in self.selected]
        return [key for key in self.visible
                if key not in self.selected and self.rows[key].get("ready")
                and (behavior == "ready" or self.rows[key].get("result") == "FAIL")]

    def bulk(self, behavior):
        changed = self.bulk_matches(behavior)
        if changed:
            self.selection_before = frozenset(self.selected)
        if behavior == "clear":
            self.selected.difference_update(changed)
        else:
            self.selected.update(changed)
        verb = "Cleared" if behavior == "clear" else "Selected"
        self.selection_feedback("{} {}.".format(verb, wb_finding_count(len(changed), "matching ")))

    def confirm_clear_selection(self):
        count = len(self.selected)
        if not count:
            self.selection_feedback("No findings are selected.")
            return

        def clear_selection():
            self.close_modal()
            self.selection_before = frozenset(self.selected)
            self.selected.clear()
            self.selection_feedback("Cleared the selection ({}).".format(wb_finding_count(count)))

        hidden = len(self.selected - set(self.visible))
        message = "Clear the selection of {}?".format(wb_finding_count(count))
        if hidden:
            message += " This includes {} outside the current view.".format(hidden)
        self.open_modal("Clear selection", message, [("Clear all", clear_selection),
                        ("Keep selection", self.close_modal)], default=1)

    def undo_last_selection(self):
        if self.selection_before is None:
            return
        self.selected = set(self.selection_before)
        self.selection_before = None
        self.selection_feedback("Restored selection of {}.".format(wb_finding_count(len(self.selected))))

    def selection_feedback(self, text):
        self.feedback = text
        self.refresh_findings()
        self.status_widget.set_text(("accent", text))

    def open_batch_selection(self, text="", error=""):
        entry = WorkbenchIdPaste(text, self.preview_batch_selection)
        note = urwid.Text([
            ("danger", error + "\n") if error else "",
            ("muted", "Enter V-123456 or 123456, separated by commas or whitespace.\n"
                      "F2 previews. Shift+Tab goes to the buttons."),
        ])
        frame = self.open_modal("Paste Vuln-IDs", "",
                                [("Preview (F2)", lambda: self.preview_batch_selection(entry.edit_text)),
                                 ("Cancel", self.close_modal)],
                                widgets=[urwid.AttrMap(entry, "input", "focus")], initial="body",
                                header_note=note, form_class=urwid.ListBox)
        self.modal.update(paste_selection=True, paste_frame=frame)

    def preview_batch_selection(self, text):
        ids = set()
        duplicates = 0
        for token in filter(None, re.split(r"[\s,]+", text)):
            match = re.fullmatch(r"(?:[Vv]-)?([0-9]{6})", token)
            if not match:
                example = wb_line(token[:32]) or "(unprintable)"
                self.open_batch_selection(text, "Invalid ID: " + example)
                return
            finding = "V-" + match.group(1)
            duplicates += finding in ids
            ids.add(finding)
        if not ids:
            self.open_batch_selection(text, "Enter at least one Vuln-ID.")
            return

        matched = ids.intersection(self.rows)
        unknown = ids - matched
        hidden = matched.difference(self.visible)
        added = len(matched - self.selected)
        removed = len(self.selected - matched)
        widgets = [
            WorkbenchDocumentLine(("accent", "Matched {}   Unknown {}".format(len(matched), len(unknown)))),
            WorkbenchDocumentLine(("accent", "Hidden {}    Duplicates {}".format(len(hidden), duplicates))),
        ]
        if matched:
            widgets.extend([
                WorkbenchDocumentLine("Add {}   Total {}".format(added, len(self.selected | matched))),
                WorkbenchDocumentLine("Replace with {}   Remove {}".format(len(matched), removed)),
            ])
        else:
            widgets.append(WorkbenchDocumentLine(("warning", "None of these IDs are in the current scope.")))
        for label, group in (("Matched IDs", matched), ("Outside the current view", hidden),
                             ("Unknown in the current scope", unknown)):
            if group:
                ordered = sorted(group)
                widgets.append(WorkbenchDocumentLine(("section", label)))
                for start in range(0, len(ordered), 4):
                    widgets.append(WorkbenchDocumentLine(", ".join(ordered[start:start + 4])))

        actions = [("Edit", lambda: self.open_batch_selection(text)), ("Cancel", self.close_modal)]
        if matched:
            actions[0:0] = [
                ("Add", lambda: self.commit_batch_selection(matched, replace=False)),
                ("Replace", lambda: self.commit_batch_selection(matched, replace=True)),
            ]
        self.open_modal("Preview pasted selection", "", actions, widgets=widgets, default=len(actions) - 1)
        self.modal["paste_selection"] = True

    def commit_batch_selection(self, matched, replace):
        self.close_modal()
        selected = matched if replace else self.selected | matched
        if selected != self.selected:
            self.selection_before = frozenset(self.selected)
        if replace:
            feedback = "Replaced selection with {}.".format(wb_finding_count(len(matched)))
        else:
            added = len(matched - self.selected)
            feedback = "Added {} from pasted IDs.".format(wb_finding_count(added))
        self.selected = selected
        self.selection_feedback(feedback)

    def import_path(self):
        self.ask_path("Import CKL", "Enter the absolute path of a legacy DISA CKL XML file.",
                      "Review import", self.confirm_import, suffix=".ckl")

    def confirm_import(self, path, retry):
        self.open_modal(
            "Replace current scope",
            "Import Open findings from " + wb_text(path) + "?\n\n"
            "A successful import replaces the current scope and selection. Back is selected by default.",
            [("Import CKL", lambda: self.request_scope("import", path, retry)), ("Back", retry)],
            default=1, escape=retry,
        )

    def save_path(self):
        if not self.selected:
            self.open_modal("Save selection", "Select at least one finding first.",
                            [("Back", self.close_modal)])
            return
        chosen = ",".join(sorted(self.selected))
        self.ask_path("Save selection", "Enter a new absolute path for the selected Vuln-IDs.",
                      "Save", lambda path, retry: self.request("save", path, chosen, on_error=retry))

    def load_path(self):
        self.ask_path("Load selection", "Enter the absolute path of an existing Vuln-ID file.",
                      "Load", lambda path, retry: self.request_scope("load", path, retry), suffix=".txt")

    def request_scope(self, action, path, retry):
        if self.page == "settings" and (self.settings_values() != self.initial_settings or
                                        self.context.get("site_config")):
            self.request("setup", action, path, *self.settings_values(), on_error=retry)
        else:
            self.request(action, path, on_error=retry)

    def ask_path(self, title, message, label, callback, initial="", error="", suffix=""):
        feedback = urwid.Text(("warning", wb_text(error)))

        def use_path(value):
            self.ask_path(title, message, label, callback, value, suffix=suffix)

        def submit(value):
            if not value.startswith("/") or any(unicodedata.category(char)[0] == "C" for char in value):
                feedback.set_text(("warning", "Enter an absolute path that begins with / and uses printable characters."))
                return
            if len(value.encode("utf-8")) > 1024:
                feedback.set_text(("warning", "Enter a path of at most 1,024 bytes."))
                return
            callback(value, lambda problem="": self.ask_path(title, message, label, callback, value, problem, suffix))

        editor = WorkbenchEdit("Path  ", initial, submit=submit)
        editor.set_edit_pos(len(initial))
        actions = [(label, lambda: submit(editor.edit_text))]
        if suffix:
            actions.append(("Browse", lambda: self.open_file_browser(editor.edit_text, use_path, suffix)))
        actions.append(("Back", self.close_modal))
        self.open_modal(title, message, actions,
                        widgets=[urwid.AttrMap(editor, "input", "focus"), feedback], initial="body")

    def details(self, finding=None):
        key = finding or self.focus_id
        if key:
            self.request("detail", key)

    def show_detail(self, event):
        self.page = "details"
        key = wb_line(event.get("id"))
        body = wb_document(wb_text(event.get("text")))
        actions = self.buttons([("Back", self.show_findings),
                                ("Preview diff", lambda: self.preview_finding_diff(key))])
        self.sections("Details  " + key, body, actions,
                      "Arrows and Page Up/Down scroll  |  Tab to buttons  |  Esc returns to findings")

    def review_selection(self):
        if not self.selected:
            self.open_modal("Review plan", "Select at least one finding. Space toggles the focused row.",
                            [("Back", self.close_modal)])
            return
        self.review_hidden = len(self.selected - set(self.visible))
        self.review_diff = False
        self.request("review", ",".join(sorted(self.selected)), "")

    def review_focused(self):
        if self.focus_id:
            self.review_diff = False
            self.review_hidden = 0
            self.request("review", self.focus_id, self.focus_id)

    def preview_finding_diff(self, finding=None):
        key = finding or self.focus_id
        if key:
            self.review_diff = True
            self.review_hidden = 0
            self.request("review", key, key)

    def show_review(self, diff_only=False):
        self.page = "review"
        self.review_diff = diff_only
        focused = wb_line(self.review.get("focused"))
        can_apply = self.context.get("can_apply")
        rows = self.review.get("rows", [])
        name = ("Implement " if can_apply else "Preview ") + focused if focused else "Review plan"
        ledger = self.review_ledger()
        if diff_only:
            parts = []
            for row in rows:
                difference = wb_text(row.get("diff"))
                if difference:
                    parts.extend([row["id"] + "  " + wb_line(row.get("title")), difference, ""])
            notes = "\n".join(parts) or "No before/after differences are available for this scope."
        else:
            notes = wb_text(self.review.get("text"))
        actions = [("Back", self.return_from_review)]
        actions.append(("Plan" if diff_only else "Diffs", lambda: self.show_review(not diff_only)))
        if self.review.get("token"):
            actions.append(("Continue" if can_apply else "Save report", self.confirm_review))
        else:
            actions.append(("Review again", self.retry_review))
            ledger += "\nThis proposal needs a fresh review before continuing."
        if len(rows) > 1:
            actions.append(("Finding index", lambda: self.open_review_index(diff_only)))
        controls = WorkbenchActions(
            [(len(label) + 4, wb_button(label, callback)) for label, callback in actions],
            dividechars=1)
        self.sections(name, wb_document(ledger + "\n\n" + notes), controls,
                      "PgUp/PgDn scroll  Tab actions  F7 settings  Esc back")

    def retry_review(self):
        if self.review_scope:
            self.request("review", *self.review_scope)

    def review_ledger(self):
        rows = self.review.get("rows", [])
        operations = sum(bool(row.get("operation", row.get("ready") and not row.get("linked")))
                         for row in rows)
        blocked = sum(row.get("handling") == "Blocked" and row.get("outcome") != "PENDING_ACTIVATION"
                      for row in rows)
        pending = sum(row.get("outcome") == "PENDING_ACTIVATION" for row in rows)
        manual = sum(row.get("handling") == "Manual" and row.get("result") not in
                     ("PASS", "NOT_APPLICABLE") for row in rows)
        summary = "Findings {}  |  Proposals {}  |  Blocked {}  |  Manual {}  |  Pending {}".format(
            len(rows), operations, blocked, manual, pending)
        if self.context.get("can_apply") and operations:
            individual = sum(bool(row.get("operation", row.get("ready") and not row.get("linked")))
                             and (self.context.get("review_each") or row.get("risk") != "low")
                             for row in rows)
            summary += "\nIndividual approvals at preview  {} of {}".format(individual, operations)
        if self.review_hidden:
            summary += "\n{} selected outside this view. They are included in the plan.".format(self.review_hidden)
        return summary

    def open_review_index(self, diff_only):
        self.review_index_plan = (self.base_frame, self.status_widget)
        self.review_index = WorkbenchReviewIndex(self.review.get("rows", []), self.show_review_item,
                                                self.focus_review_list)
        self.page = "review index"
        label = "Back to diffs" if diff_only else "Back to plan"
        self.sections("Reviewed findings", self.review_index.body,
                      self.buttons([(label, self.close_review_index)]),
                      "/ Search  Enter open  Home/End  PgUp/PgDn  Esc back",
                      extra_header=self.review_index.controls)
        self.review_index_frame = (self.base_frame, self.status_widget)

    def focus_review_list(self):
        self.base_frame.focus_position = "body"

    def return_to_review_index(self):
        self.page = "review index"
        self.base_frame, self.status_widget = self.review_index_frame
        self.focus_review_list()
        self.render_active_page()

    def close_review_index(self):
        self.page = "review"
        self.base_frame, self.status_widget = self.review_index_plan
        self.review_index = self.review_index_frame = self.review_index_plan = None
        self.render_active_page()

    def show_review_item(self, row):
        self.page = "review item"
        notes = [wb_text(row.get("title")), "", "Assessment evidence", wb_text(row.get("evidence")),
                 "", "Proposed change", wb_text(row.get("plan") or row.get("action"))]
        actions = [("Back to index", self.return_to_review_index)]
        difference = wb_text(row.get("diff"))
        if difference:
            diff_line = "\n".join(notes).count("\n") + 2
            notes.extend(["", "BEFORE / AFTER", difference])

            def jump_to_diff():
                document.set_focus(diff_line, "above")
                document.set_focus_valign("top")
                self.base_frame.focus_position = "body"

            actions.append(("Jump to diff", jump_to_diff))
        document = wb_document("\n".join(notes))
        self.sections("Finding " + row["id"], document, self.buttons(actions),
                      "PgUp/PgDn scroll  g/G jump  Tab actions  Esc index")

    def return_from_review(self):
        self.request("back")

    def confirm_review(self):
        token = self.review.get("token")
        if not token:
            return
        if self.context.get("can_apply"):
            title, verb = "Confirm reviewed scope", "Continue"
            message = ("Continue with these reviewed findings? Each eligible change still needs "
                       "attended approval. Back is selected by default.")
        else:
            title, verb = "Save report", "Save report"
            message = "Save the assessment for these reviewed findings? Back is selected by default."
        self.open_modal(title, self.review_ledger() + "\n\n" + message,
                        [(verb, lambda: self.request("accept", token)),
                                        ("Back", self.close_modal)], default=1)

    def confirm_exit(self):
        self.open_modal("Exit Workbench", "Exit this selection session?",
                        [("Exit", lambda: self.request("cancel")), ("Back", self.close_modal)],
                        default=1)

    def help_screen(self):
        help_text = (
            "Type in Search for immediate filtering. Space toggles a finding. Enter opens Details. "
            "Home and End jump to the first and last matching findings without changing selection.\n\n"
            "From Search, Tab reaches Clear and Esc returns to the findings.\n\n"
            "Click a table header to sort. Press S to focus headers, use Left and Right to choose "
            "a column, and press Enter to sort or reverse. Down returns to the findings. "
            "A caret (^) means ascending and v means descending.\n\n"
            "F2 Filters   F3 or Ctrl+A Actions   F4 Details   F5 Review plan\n"
            "F6 Focused plan   F7 Run settings   F8 Reassess   F9 Results   F10 Quick views   F1 Help\n\n"
            "Selection is preserved when search, area, order or result changes. Review includes hidden selections.\n\n"
            "Automatic indicates a supported attended handler. Manual requires evidence or an administrator step. "
            "Blocked indicates a prerequisite or error. Pending activation identifies a change awaiting a service "
            "action or reboot. Review is an unresolved assessment.\n\n"
            "Results opens saved reports without scanning the host. Quick views help find approvals and follow-up work."
        )
        self.open_modal("Workbench help", help_text, [("Back", self.close_modal)])

    def open_modal(self, title, message, actions, widgets=None, default=0,
                   initial="footer", escape=None, header_note=None, form_class=WorkbenchForm):
        widgets = list(widgets or ())
        body_items = [urwid.Text(wb_text(message)), urwid.Divider()] if message else []
        body_items.extend(widgets)
        walker = urwid.SimpleFocusListWalker(body_items or [urwid.Text("")])
        for index, item in enumerate(walker):
            if item.selectable():
                walker.set_focus(index)
                break
        confirmation = not widgets and initial == "footer" and len(actions) > 1
        header = urwid.AttrMap(urwid.Text(" " + wb_line(title), wrap="clip"), "header")
        if header_note is not None:
            header = urwid.Pile([header, header_note])
        frame = WorkbenchFrame(form_class(walker), header=header,
                               footer=self.buttons(actions, default, cycle=confirmation), focus_part=initial)
        overlay = urwid.Overlay(urwid.LineBox(frame), self.base_frame, "center", ("relative", 85),
                                "middle", ("relative", 78))
        self.modal = {"escape": escape or self.close_modal, "overlay": overlay}
        self.render_active_page()
        return frame

    def close_modal(self):
        if self.modal:
            self.modal = None
            if (not self.too_small and self.page == "findings" and
                    self.findings_width != self.layout_flags()):
                self.show_findings(self.base_frame.focus_position)
            else:
                self.render_active_page()

    def backend_modal(self, event):
        kind, title, body = (event.get(key, "") for key in ("kind", "title", "text"))

        def respond(code, value=""):
            self.close_modal()
            self.send("modal", code, value)

        back = ("Back", lambda: respond("1"))
        escape = lambda: respond("1")
        if kind == "confirm":
            self.open_modal(title, body, [(wb_line(event.get("yes") or "Continue"),
                                          lambda: respond("0")), (wb_line(event.get("no") or "Back"),
                                          escape)], default=1, escape=escape)
        elif kind == "choice":
            options = [wb_button(wb_line(choice.get("label")), lambda item=choice: respond(
                "0", item["id"])) for choice in event.get("choices", [])]
            self.open_modal(title, body, [back], widgets=options, escape=escape)
        elif kind == "input":
            entry = WorkbenchEdit("Value  ", wb_line(event.get("initial")),
                                  submit=lambda value: respond("0", value))
            self.open_modal(title, body, [("Continue", lambda: respond("0", entry.edit_text)), back],
                            widgets=[urwid.AttrMap(entry, "input", "focus")], initial="body",
                            escape=escape)
        else:
            self.open_modal(title, body, [("Close", lambda: respond("0"))],
                            escape=lambda: respond("0"))

    def input_filter(self, keys, raw):
        if self.too_small:
            if self.history is not None and "esc" in keys:
                self.close_history()
            if self.path_browser is not None and "esc" in keys:
                self.close_file_browser()
            return []
        if self.history is not None or self.path_browser is not None:
            return keys
        if self.busy and self.modal is None:
            return []
        if self.modal and self.modal.get("paste_selection"):
            if "esc" in keys:
                self.close_modal()
                return []
            frame = self.modal.get("paste_frame")
            space = {"tab": " ", "enter": "\n"}
            if (frame is not None and frame.focus_position == "body" and len(keys) > 1 and
                    all(isinstance(key, str) and (len(key) == 1 or key in space) for key in keys)):
                return [WorkbenchPasteInput("".join(space.get(key, key) for key in keys))]
        passthrough = []
        for key in keys:
            if self.modal and key == "esc":
                self.modal["escape"]()
            elif not self.modal and not self.busy and key == "f9" and self.page in ("settings", "findings"):
                self.open_history()
            elif not self.modal and not self.busy and key == "f10" and self.page == "findings":
                self.open_quick_views()
            elif not self.modal and not self.busy and self.page == "findings" and key == "ctrl a" and \
                    self.base_frame.focus_position != "header":
                self.open_actions()
            elif not self.modal and self.page in ("review", "review item", "details") and key in ("g", "G"):
                body = self.base_frame.body
                body.set_focus(0 if key == "g" else len(body.body) - 1, "above" if key == "g" else "below")
                body._invalidate()
                self.base_frame._invalidate()
                self.widget._invalidate()
            else:
                passthrough.append(key)
        return passthrough

    def unhandled_input(self, key):
        if (not isinstance(key, str) or self.modal or self.busy or
                self.history is not None or self.path_browser is not None):
            return
        if self.page == "findings":
            if key == "/":
                self.base_frame.focus_position = "header"
                self.search_row.focus_position = 0
                return
            if key == "esc" and self.base_frame.focus_position == "header":
                self.base_frame.focus_position = "body"
                return
            actions = {"f1": self.help_screen, "f2": self.open_filters, "f3": self.open_actions,
                       "f4": self.details, "f5": self.review_selection, "f6": self.review_focused,
                       "f7": self.show_settings, "esc": self.confirm_exit,
                       "s": self.focus_sort_headers, "S": self.focus_sort_headers,
                       "f8": lambda: self.request("scan")}
            if key in actions:
                actions[key]()
        elif key == "f7" and self.page in ("review", "review index", "review item", "details"):
            self.open_run_settings()
        elif key == "f8" and self.page == "settings":
            self.inspect_settings()
        elif self.page == "review index":
            if key == "/":
                self.base_frame.focus_position = "header"
                self.review_index.search_row.focus_position = 0
            elif key == "esc":
                if self.base_frame.focus_position == "header":
                    self.focus_review_list()
                else:
                    self.close_review_index()
        elif key == "esc":
            if self.page == "review":
                self.return_from_review()
            elif self.page == "review item":
                self.return_to_review_index()
            elif self.page == "settings" and not self.context.get("assessed", True):
                self.confirm_exit()
            elif self.page == "settings" and self.settings_after_review:
                self.request("back")
            elif self.page in ("settings", "details"):
                self.show_findings()
