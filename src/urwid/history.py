"""A local, read-only browser for protected reports from prior STIG runs."""

import array as _history_array
import bisect as _history_bisect
import contextlib as _history_context
import hashlib as _history_hashlib
import json as _history_json
import os as _history_os
import re as _history_re
import stat as _history_stat
import unicodedata as _history_unicode

import urwid as _history_urwid


_HISTORY_RUN_ID = _history_re.compile(r"[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}\Z")
_HISTORY_MODE = r"(status|dry-run|diff|apply|rollback)"
_HISTORY_STAMP = r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"
_HISTORY_COMPLETE = _history_re.compile(
    r"^" + _HISTORY_STAMP + r" INFO completed with ([0-9]+) unresolved, "
    r"([0-9]+) pending, ([0-9]+) skipped$", _history_re.MULTILINE)
_HISTORY_INTERRUPTED = _history_re.compile(
    r"^" + _HISTORY_STAMP
    + r" (?:ERROR run interrupted; |BLOCKED V-[0-9]{6} approval input closed; )",
    _history_re.MULTILINE)
_HISTORY_INTERRUPTED_SUMMARY = "Run interrupted. Use the journal and inspect the actual target state before resuming."
_HISTORY_LOG_ERROR = _history_re.compile(r"^" + _HISTORY_STAMP + r" ERROR ", _history_re.MULTILINE)
_HISTORY_REPORT_ERROR = _history_re.compile(
    r"^V-[0-9]{6}[ \t]+[A-Z_]+[ \t]+(?:ERROR[ \t]+[A-Z_]+|[A-Z_]+[ \t]+FAILED)(?:[ \t]|$)",
    _history_re.MULTILINE)
_HISTORY_PAGE_SIZE = 100
_HISTORY_MAX_ENTRIES = 4096
_HISTORY_REPORT_LIMIT = 256 * 1024
_HISTORY_REPORT_LINES = 2000
_HISTORY_COMPARE_LIMIT = 2 * 1024 * 1024
_HISTORY_ASSESSMENTS = {"PASS", "FAIL", "NEEDS_REVIEW", "UNKNOWN", "ERROR", "NOT_APPLICABLE"}
_HISTORY_ACTIONS = {
    "UNCHANGED", "MANUAL_REQUIRED", "BLOCKED", "PENDING_ACTIVATION",
    "APPLIED", "FAILED", "SKIPPED", "ROLLED_BACK",
}
_HISTORY_FILES = (
    ("summary.txt", "Summary"),
    ("admin-actions.txt", "Administrator actions"),
    ("changes.txt", "Changes made"),
    ("preview.txt", "Reviewed proposal"),
    ("diff.txt", "Diff"),
    ("ckl-import.txt", "CKL import"),
    ("results.json", "JSON results"),
    ("results.csv", "CSV results"),
    ("run.log", "Run log"),
)
_HISTORY_ARTIFACT_TITLES = dict(_HISTORY_FILES)


def _history_text(value):
    return "".join(
        character for character in value
        if character in "\n\t" or _history_unicode.category(character)[0] != "C"
    ).expandtabs(4)


@_history_context.contextmanager
def _history_base(report_dir):
    """Open each path component without following links."""
    if (not isinstance(report_dir, str) or not report_dir.startswith("/")
            or report_dir.startswith("//") or report_dir == "/"
            or _history_os.path.normpath(report_dir) != report_dir
            or any(_history_unicode.category(character)[0] == "C" for character in report_dir)):
        raise ValueError("Choose an absolute, protected report directory in Run settings.")
    parts = report_dir[1:].split("/")
    if parts[0] in ("etc", "boot", "usr", "sys", "proc", "dev", "run", "bin", "sbin", "lib", "lib64"):
        raise ValueError("This directory cannot be used for saved reports.")
    flags = _history_os.O_RDONLY | _history_os.O_DIRECTORY | _history_os.O_NOFOLLOW
    uid = _history_os.geteuid()
    fd = _history_os.open("/", flags)
    try:
        for index, part in enumerate(parts):
            child = _history_os.open(part, flags, dir_fd=fd)
            _history_os.close(fd)
            fd = child
            meta = _history_os.fstat(fd)
            last = index == len(parts) - 1
            if last:
                valid = meta.st_uid == uid and meta.st_mode & 0o077 == 0
            else:
                sticky_root = meta.st_uid == 0 and meta.st_mode & _history_stat.S_ISVTX
                valid = meta.st_uid in (0, uid) and (meta.st_mode & 0o022 == 0 or sticky_root)
            if not valid:
                raise ValueError("The report path is not protected for the current account.")
        yield fd
    finally:
        _history_os.close(fd)


@_history_context.contextmanager
def _history_run(base_fd, run_id):
    if not _HISTORY_RUN_ID.fullmatch(run_id):
        raise ValueError("Invalid saved run ID.")
    fd = _history_os.open(
        run_id, _history_os.O_RDONLY | _history_os.O_DIRECTORY | _history_os.O_NOFOLLOW,
        dir_fd=base_fd,
    )
    try:
        meta = _history_os.fstat(fd)
        if meta.st_uid != _history_os.geteuid() or meta.st_mode & 0o077:
            raise ValueError("The saved run is not private to this account.")
        yield fd
    finally:
        _history_os.close(fd)


def _history_file_ok(meta):
    return (_history_stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1
            and meta.st_uid == _history_os.geteuid() and meta.st_mode & 0o077 == 0)


def _history_read(run_fd, name, limit, tail=False):
    meta = _history_os.stat(name, dir_fd=run_fd, follow_symlinks=False)
    if not _history_file_ok(meta):
        raise ValueError("The artifact is not a protected regular file.")
    fd = _history_os.open(
        name, _history_os.O_RDONLY | _history_os.O_NOFOLLOW | _history_os.O_NONBLOCK,
        dir_fd=run_fd,
    )
    with _history_os.fdopen(fd, "rb") as stream:
        info = _history_os.fstat(stream.fileno())
        if not _history_file_ok(info):
            raise ValueError("The artifact is no longer protected.")
        if tail and info.st_size > limit:
            stream.seek(info.st_size - limit)
        data = stream.read(limit + 1)
        return data[:limit], info.st_size > limit or len(data) > limit


def _history_optional(run_fd, name, limit, tail=False):
    try:
        data, _ = _history_read(run_fd, name, limit, tail)
    except (OSError, ValueError):
        return ""
    return data.decode("utf-8", "replace")


def _history_manifest(run_fd, run_id):
    data, limited = _history_read(run_fd, "manifest", 131072)
    fields = data.decode("utf-8", "replace").splitlines()
    schema = [field for field in fields if field.startswith("schema\t")]
    identity = [field for field in fields if field.startswith("run\t")]
    if limited or schema != ["schema\t1"] or identity != ["run\t" + run_id]:
        raise ValueError("The saved run manifest is invalid.")
    try:
        digest, limited = _history_read(run_fd, "manifest.sha256", 80)
    except FileNotFoundError:
        return fields, False
    if limited or _history_hashlib.sha256(data).hexdigest().encode("ascii") != digest.strip():
        raise ValueError("The saved run manifest checksum changed.")
    return fields, True


def _history_identity(fields):
    identifiers = {}
    for key in ("host", "archive", "script"):
        values = [field[len(key) + 1:] for field in fields if field.startswith(key + "\t")]
        if len(values) != 1 or not _history_re.fullmatch("[0-9a-f]{64}", values[0]):
            raise ValueError("Incomplete manifest metadata.")
        identifiers[key] = values[0]
    return identifiers


def _history_candidate(run_fd, identifiers, state):
    if state != "Completed" or identifiers is None:
        return None
    try:
        meta = _history_os.stat("results.json", dir_fd=run_fd, follow_symlinks=False)
    except OSError:
        return None
    if _history_file_ok(meta) and 0 < meta.st_size <= _HISTORY_COMPARE_LIMIT:
        return (identifiers["host"], identifiers["archive"])
    return None


def _history_final_state(run_fd, summary):
    ending = _history_optional(run_fd, "run.log", 32768, tail=True)
    finish = list(_HISTORY_COMPLETE.finditer(ending))
    if _HISTORY_INTERRUPTED.search(ending) or _HISTORY_INTERRUPTED_SUMMARY in summary.splitlines():
        state = "Interrupted"
    elif finish:
        state = "Completed"
    else:
        state = "Incomplete"
    return state, finish[-1].groups() if finish else (), bool(_HISTORY_LOG_ERROR.search(ending))


def _history_metadata(run_fd, run_id):
    fields, checksum = _history_manifest(run_fd, run_id)
    summary = _history_optional(run_fd, "summary.txt", 16384)
    start = _history_optional(run_fd, "run.log", 4096)
    state, counts, log_errors = _history_final_state(run_fd, summary)
    mode = _history_re.search(
        r"^Run " + _history_re.escape(run_id) + r" \| " + _HISTORY_STAMP
        + r" \| " + _HISTORY_MODE + r"$", summary, _history_re.MULTILINE)
    related = ""
    if mode:
        header = summary[mode.start():].split("\n\n", 1)[0]
        links = [line[len("Related run "):] for line in header.splitlines() if line.startswith("Related run ")]
        if len(links) == 1 and links[0] != run_id and _HISTORY_RUN_ID.fullmatch(links[0]):
            related = links[0]
    version = _history_re.search(r"^Script ([A-Za-z0-9.+_-]{1,64}) \| SHA-256 ",
                                  summary, _history_re.MULTILINE)
    start_record = _history_re.search(
        r"^" + _HISTORY_STAMP + r" INFO started " + _HISTORY_MODE
        + r" by .+; script ([A-Za-z0-9.+_-]{1,64}) [0-9a-f]{64}$",
        start, _history_re.MULTILINE)
    try:
        identifiers = _history_identity(fields) if checksum else None
    except ValueError:
        identifiers = None
    return {
        "id": run_id,
        "mode": mode.group(1) if mode else start_record.group(1) if start_record else "Unknown",
        "version": version.group(1) if version else start_record.group(2) if start_record else "Unknown",
        "state": state,
        "counts": counts,
        "checksum": checksum,
        "identity": identifiers,
        "related": related,
        "log_errors": log_errors,
        "report_errors": bool(_HISTORY_REPORT_ERROR.search(summary)),
        "comparison_key": _history_candidate(run_fd, identifiers, state),
    }


def _history_lookup(report_dir, run_id):
    with _history_base(report_dir) as base_fd, _history_run(base_fd, run_id) as run_fd:
        return _history_metadata(run_fd, run_id)


def _history_index(report_dir):
    """Index directory names without reading every report."""
    with _history_base(report_dir) as base_fd:
        candidates = []
        limited = False
        # Python 3.6 scandir takes a path. The proc descriptor keeps the opened
        # directory pinned while we walk it and bound work without listdir.
        with _history_os.scandir("/proc/self/fd/{}".format(base_fd)) as entries:
            for index, entry in enumerate(entries):
                if index >= _HISTORY_MAX_ENTRIES:
                    limited = True
                    break
                if _HISTORY_RUN_ID.fullmatch(entry.name) and entry.is_dir(follow_symlinks=False):
                    candidates.append(entry.name)
    return sorted(candidates, reverse=True), limited


def _history_load_page(report_dir, candidates):
    """Read protected metadata for one page of indexed IDs."""
    with _history_base(report_dir) as base_fd:
        runs = []
        omitted = 0
        for run_id in candidates:
            try:
                with _history_run(base_fd, run_id) as run_fd:
                    runs.append(_history_metadata(run_fd, run_id))
            except (OSError, ValueError):
                omitted += 1
    return runs, omitted


def _history_unique_fields(pairs):
    record = dict(pairs)
    if len(record) != len(pairs):
        raise ValueError("Duplicate structured result field.")
    return record


def _history_comparison_source(base_fd, run_id):
    with _history_run(base_fd, run_id) as run_fd:
        fields, checksum = _history_manifest(run_fd, run_id)
        state, _, _ = _history_final_state(run_fd, _history_optional(run_fd, "summary.txt", 4096))
        if state != "Completed":
            raise ValueError("Run {} is {}. Comparison requires completed runs.".format(
                run_id, state.lower()))
        if not checksum:
            raise ValueError("Run {} is missing its manifest checksum.".format(run_id))
        identifiers = _history_identity(fields)
        scope = [field.split("\t", 1)[1] for field in fields if field.startswith(("select\t", "skip\t"))]
        excluded = {field.split("\t", 1)[1] for field in fields if field.startswith("skip\t")}
        try:
            payload, limited = _history_read(run_fd, "results.json", _HISTORY_COMPARE_LIMIT)
        except FileNotFoundError:
            raise ValueError("Run {} has no results.json. Use --format json for runs you want to compare."
                             .format(run_id))
    if limited:
        raise ValueError("Run {} has results.json larger than the 2 MiB comparison limit.".format(run_id))
    try:
        record = _history_json.loads(payload.decode("utf-8"), object_pairs_hook=_history_unique_fields)
    except (ValueError, RecursionError):
        raise ValueError("Run {} does not contain readable structured results.".format(run_id))
    if (not isinstance(record, dict) or record.get("run_id") != run_id
            or record.get("host_id") != identifiers["host"]
            or record.get("archive_sha256") != identifiers["archive"]
            or record.get("script_sha256") != identifiers["script"]
            or not isinstance(record.get("results"), list) or len(record["results"]) > 4096):
        raise ValueError("Structured results for {} do not match the protected manifest.".format(run_id))
    rows = {}
    for row in record["results"]:
        if not isinstance(row, dict):
            raise ValueError("Run {} has an invalid finding record.".format(run_id))
        finding, assessment, action = row.get("id"), row.get("assessment"), row.get("action")
        if (not isinstance(finding, str) or not _history_re.fullmatch(r"V-[0-9]{6}", finding)
                or finding in rows or not isinstance(assessment, str)
                or assessment not in _HISTORY_ASSESSMENTS or not isinstance(action, str)
                or not _history_re.fullmatch(r"[A-Z_]{1,40}", action)):
            raise ValueError("Run {} has an invalid or duplicate finding record.".format(run_id))
        rows[finding] = (assessment, action)
    if len(scope) != len(rows) or set(scope) != set(rows):
        raise ValueError("Structured results for {} do not match the manifest scope.".format(run_id))
    mode = record.get("mode")
    mode = mode if isinstance(mode, str) and _history_re.fullmatch(_HISTORY_MODE, mode) else "Unknown"
    return identifiers, {finding: value for finding, value in rows.items() if finding not in excluded}, excluded, mode


def _history_compare(report_dir, first, second, recheck=False):
    if first == second:
        raise ValueError("Choose two different saved runs.")
    earlier, later = (first, second) if recheck else sorted((first, second))
    with _history_base(report_dir) as base_fd:
        before_ids, before, before_excluded, before_mode = _history_comparison_source(base_fd, earlier)
        after_ids, after, after_excluded, after_mode = _history_comparison_source(base_fd, later)
    if before_ids["host"] != after_ids["host"]:
        raise ValueError("The runs have different host fingerprints.")
    if before_ids["archive"] != after_ids["archive"]:
        raise ValueError("The runs use different STIG benchmark archives.")
    if recheck:
        if after_mode != "status":
            raise ValueError("The recheck must be a Status report.")
        if before_ids["script"] != after_ids["script"]:
            raise ValueError("The recheck and original use different script digests.")
        if before.keys() != after.keys() or before_excluded != after_excluded:
            raise ValueError("The recheck and original have different assessed or excluded scopes.")
    shared = sorted(before.keys() & after.keys())
    changed, unchanged, uncompared_actions = [], [], []
    unrecognized_action_count = 0
    for key in shared:
        old, new = before[key], after[key]
        record = (key, old, new)
        if old[1] not in _HISTORY_ACTIONS or new[1] not in _HISTORY_ACTIONS:
            unrecognized_action_count += 1
            if old[0] == new[0]:
                uncompared_actions.append(record)
                continue
        if old == new:
            unchanged.append(record)
        else:
            changed.append(record)
    assessment_changes = sum(old[0] != new[0] for _, old, new in changed)
    return {
        "earlier": earlier, "later": later,
        "earlier_mode": before_mode, "later_mode": after_mode,
        "changed": changed, "assessment_changes": assessment_changes,
        "action_only_changes": len(changed) - assessment_changes,
        "unchanged": unchanged,
        "uncompared_actions": uncompared_actions, "unrecognized_action_count": unrecognized_action_count,
        "only_earlier": sorted(before.keys() - after.keys()),
        "only_later": sorted(after.keys() - before.keys()),
        "excluded_earlier": sorted(before_excluded),
        "excluded_later": sorted(after_excluded),
    }


def _history_action_label(action):
    return action if action in _HISTORY_ACTIONS else "Unrecognized action ({})".format(action)


class _HistoryLine(_history_urwid.Text):
    _selectable = True

    def keypress(self, size, key):
        return key


class _HistoryPreview:
    """Bounded report text and the visual positions of its search matches."""

    def __init__(self, name, data, limited):
        self.name = name
        self.lines = _history_text(data.decode("utf-8", "replace")).split("\n", _HISTORY_REPORT_LINES)
        self.limited = limited or (len(self.lines) > _HISTORY_REPORT_LINES and bool(self.lines[-1]))
        if len(self.lines) > _HISTORY_REPORT_LINES or self.lines[-1] == "":
            self.lines.pop()
        self.text = "\n".join(self.lines)
        self.query = ""
        self.matches = _history_array.array("I")
        self.active = None
        self.width = None
        self.rows = []
        self.offsets = []

    def search(self, query):
        self.query = query
        self.matches = _history_array.array("I")
        if query and len(query) <= len(self.text):
            pattern = _history_re.compile(_history_re.escape(query), _history_re.IGNORECASE)
            self.matches.extend(hit.start() for hit in pattern.finditer(self.text))
        self.active = 0 if self.matches else None

    def match_bounds(self):
        if self.active is not None:
            start = self.matches[self.active]
            return start, start + len(self.query)
        return None

    def wrap(self, width):
        self.width = width
        self.rows, self.offsets = [], []
        start = 0
        for number, line in enumerate(self.lines, 1):
            end = start + len(line)
            style = "base"
            if self.name == "diff.txt" and line.startswith(("+", "-")):
                style = "diff_add" if line[0] == "+" else "diff_remove"
            position = start
            while True:
                stop, _ = _history_urwid.util.calc_text_pos(self.text, position, end, width)
                self.offsets.append(position)
                self.rows.append((stop, number, style))
                position = stop
                if position >= end:
                    break
            start = end + 1

    def row_for(self, offset):
        return max(0, _history_bisect.bisect_right(self.offsets, offset) - 1)

    def row_text(self, index):
        start = self.offsets[index]
        stop, _, style = self.rows[index]
        match = self.match_bounds()
        if match and match[0] < stop and match[1] > start:
            first, last = max(start, match[0]), min(stop, match[1])
            return [(style, self.text[start:first]), ("focus", self.text[first:last]),
                    (style, self.text[last:stop])]
        return style, self.text[start:stop]


def _history_button(label, callback):
    return _history_urwid.AttrMap(
        _history_urwid.Button(label, lambda _: callback()), "button", "focus")


def _history_report_preview(run_dir, run_id, path, on_back, on_close):
    """Open one advertised artifact without enumerating saved runs."""
    if (not isinstance(run_dir, str) or not isinstance(run_id, str) or not isinstance(path, str)
            or not _HISTORY_RUN_ID.fullmatch(run_id)
            or _history_os.path.normpath(run_dir) != run_dir):
        raise ValueError("The report path is unavailable.")
    base, expected_run = _history_os.path.split(run_dir)
    name = _history_os.path.basename(path)
    if (expected_run != run_id or name not in _HISTORY_ARTIFACT_TITLES
            or path != _history_os.path.join(run_dir, name)):
        raise ValueError("This report path is outside the recorded run directory.")
    browser = RunHistory(base, on_back, index_runs=False)
    browser.show_artifact(run_id, name, "Reports", [("Close", on_close)])
    return browser.widget


class _HistoryViewport(_history_urwid.WidgetPlaceholder):
    def __init__(self, owner):
        self.owner = owner
        self.small = _history_urwid.Filler(_history_urwid.Text(
            "Enlarge the terminal to at least 48 columns and 12 rows. Esc goes back."))
        super().__init__(self.small)

    @staticmethod
    def too_small(size):
        return size[0] < 48 or size[1] < 12

    def render(self, size, focus=False):
        if self.too_small(size):
            return self.small.render(size, focus)
        if self.owner.page == "artifact":
            self.owner.layout_artifact(size[0])
        return super().render(size, focus)

    def keypress(self, size, key):
        owner = self.owner
        if key == "esc":
            owner.back()
            return None
        if self.too_small(size):
            return None
        if owner.page == "artifact":
            owner.layout_artifact(size[0])
        if key == "f5" and owner.page == "runs":
            owner.refresh()
            return None
        if owner.entry is not None:
            editing = owner.frame.focus_position == "header"
            if key == "/" and not editing:
                owner.frame.focus_position = "header"
                return None
            if key == "ctrl u" and (editing or owner.page == "artifact"):
                owner.entry.set_edit_text("")
                if owner.page == "artifact":
                    owner.frame.focus_position = "header"
                    owner.find_artifact(keep_editing=True)
                return None
            if key == "enter" and editing:
                owner.submit_entry()
                return None
        if owner.page == "runs" and owner.frame.focus_position != "header":
            if key in ("[", "]"):
                owner.change_index_page(-1 if key == "[" else 1)
                return None
            if key == "f":
                owner.toggle_follow_up()
                return None
        if (owner.page == "compare" and owner.frame.focus_position != "header"
                and key in ("[", "]")):
            owner.change_comparison_page(-1 if key == "[" else 1)
            return None
        if owner.page == "artifact" and owner.frame.focus_position != "header" and key in ("n", "N"):
            owner.move_artifact_match(1 if key == "n" else -1)
            return None
        if (key in ("home", "end", "g", "G") and owner.page in ("artifact", "comparison")
                and owner.frame.focus_position != "header"):
            if owner.walker:
                owner.walker.set_focus(0 if key in ("g", "home") else len(owner.walker) - 1)
                owner.frame.body._invalidate()
                owner.frame._invalidate()
                self._invalidate()
            return None
        unhandled = super().keypress(size, key)
        if unhandled in ("tab", "shift tab"):
            step = 1 if unhandled == "tab" else -1
            if owner.frame.focus_position == "footer":
                candidate = owner.buttons.focus_position + step
                if 0 <= candidate < len(owner.buttons.contents):
                    owner.buttons.focus_position = candidate
                    return None
            positions = ("header", "body", "footer") if owner.entry is not None else ("body", "footer")
            position = positions.index(owner.frame.focus_position)
            owner.frame.focus_position = positions[(position + step) % len(positions)]
            return None
        return unhandled

    def mouse_event(self, size, event, button, col, row, focus):
        if self.too_small(size):
            return False
        return super().mouse_event(size, event, button, col, row, focus)


class RunHistory:
    """Show saved runs and their reports without starting a new assessment."""

    def __init__(self, report_dir, on_back, index_runs=True):
        self.report_dir = report_dir
        self.on_back = on_back
        self.page = "runs"
        self.runs = []
        self.matching = []
        self.indexed = []
        self.index_page = 0
        self.limit = False
        self.omitted = 0
        self.error = ""
        self.lookup_error = ""
        self.selected = None
        self.related_stack = []
        self.return_focus = None
        self.return_entry_pos = None
        self.artifact = None
        self.comparison = None
        self.comparison_input = ""
        self.comparison_partner = None
        self.comparison_typed = False
        self.direct_comparison = False
        self.direct_back = self.on_back
        self.direct_back_label = "Back to results"
        self.show_unchanged = False
        self.search = ""
        self.follow_up_only = False
        self.frame = None
        self.widget = _HistoryViewport(self)
        if index_runs:
            self.refresh()

    def back(self):
        if self.direct_comparison:
            self.direct_comparison = False
            self.direct_back()
        elif self.page == "artifact":
            self.preview = None
            if self.selected is None:
                self.on_back()
            else:
                self.open_run(self.selected, self.artifact)
        elif self.page == "compare":
            self.open_run(self.selected)
        elif self.page == "comparison":
            self.choose_comparison()
        elif self.page == "run":
            if self.related_stack:
                self.open_run(self.related_stack.pop(), "open-related")
            else:
                self.show_runs(self.return_focus)
                if self.return_entry_pos is not None:
                    self.entry.set_edit_pos(self.return_entry_pos)
                    self.frame.focus_position = "header"
        else:
            self.on_back()

    def refresh(self):
        focus_id = self.focused_run()
        header_position = None
        if self.frame is not None and self.page == "runs" and self.frame.focus_position == "header":
            header_position = self.entry.edit_pos
        self.indexed, self.limit, self.error, self.lookup_error = [], False, "", ""
        try:
            self.indexed, self.limit = _history_index(self.report_dir)
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            self.error = "Cannot read protected reports for this account and report directory."
        if focus_id in self.indexed:
            self.index_page = self.indexed.index(focus_id) // _HISTORY_PAGE_SIZE
        else:
            self.index_page = min(self.index_page, self.index_pages() - 1)
        self.load_index_page()
        self.show_runs(focus_id)
        if header_position is not None:
            self.entry.set_edit_pos(header_position)
            self.frame.focus_position = "header"

    def focused_run(self):
        if self.page == "runs" and self.matching and self.walker.focus < len(self.matching):
            return self.matching[self.walker.focus]["id"]
        return None

    def index_pages(self):
        return max(1, (len(self.indexed) + _HISTORY_PAGE_SIZE - 1) // _HISTORY_PAGE_SIZE)

    def index_candidates(self, page):
        start = page * _HISTORY_PAGE_SIZE
        return self.indexed[start:start + _HISTORY_PAGE_SIZE]

    def load_index_page(self):
        self.runs, self.omitted = [], 0
        candidates = self.index_candidates(self.index_page)
        if candidates:
            try:
                self.runs, self.omitted = _history_load_page(self.report_dir, candidates)
            except (OSError, ValueError):
                self.error = "Reports are unavailable. Refresh to rebuild the index."

    def change_index_page(self, step):
        destination = self.index_page + step
        if 0 <= destination < self.index_pages():
            footer_focused = self.frame.focus_position == "footer"
            button_position = self.buttons.focus_position
            self.index_page = destination
            self.error = self.lookup_error = ""
            self.load_index_page()
            self.show_runs()
            if footer_focused:
                self.frame.focus_position = "footer"
                self.buttons.focus_position = button_position

    def screen(self, title, subtitle, rows, actions, keys, entry=None, extra_header=()):
        self.entry = entry
        self.walker = _history_urwid.SimpleFocusListWalker(rows)
        body = _history_urwid.ListBox(self.walker)
        fields = [_history_urwid.AttrMap(entry, "input", "focus")] if entry is not None else []
        header = _history_urwid.Pile([
            _history_urwid.AttrMap(_history_urwid.Text(" STIG Assistant  /  Results  /  " + title,
                                                       wrap="clip"), "header"),
            _history_urwid.Text(("muted", _history_text(subtitle)), wrap="clip"),
            *fields,
            *extra_header,
        ])
        self.buttons = _history_urwid.Columns([
            (len(label) + 4, _history_button(label, callback)) for label, callback in actions
        ], dividechars=1)
        footer = _history_urwid.Pile([self.buttons, _history_urwid.Text(("muted", keys), wrap="clip")])
        self.frame = _history_urwid.Frame(body, header, footer)
        self.widget.original_widget = self.frame

    def show_runs(self, focus_id=None):
        self.page = "runs"
        search = _history_urwid.Edit("Filter page / run ID  ", self.search)
        _history_urwid.connect_signal(search, "change", self.change_search)
        self.match_label = _history_urwid.Text("", wrap="clip")
        self.index_notice = _history_urwid.Text("", wrap="clip")
        self.screen("Saved runs", self.report_dir, [], [
            ("Back", self.back), ("Reload", self.refresh),
            ("Prev", lambda: self.change_index_page(-1)),
            ("Next", lambda: self.change_index_page(1)),
            ("All" if self.follow_up_only else "Follow", self.toggle_follow_up),
        ], "[ ] pages  / search  f follow-up  Ctrl+U clear  Esc back",
                    search, (self.match_label, self.index_notice))
        self.filter_runs(focus_id)

    def change_search(self, _, value):
        focus_id = self.focused_run()
        self.search, self.lookup_error = value, ""
        self.filter_runs(focus_id)

    def submit_entry(self):
        if self.page == "artifact":
            self.find_artifact()
            return
        run_id = self.entry.edit_text.strip()
        if self.page == "compare":
            self.compare_with(run_id, typed=True)
        elif _HISTORY_RUN_ID.fullmatch(run_id):
            try:
                run = _history_lookup(self.report_dir, run_id)
            except (OSError, ValueError):
                self.lookup_error = "This run ID is unavailable in the protected report directory."
                self.filter_runs(self.focused_run())
            else:
                self.open_run(run)
        elif self.matching:
            self.frame.focus_position = "body"

    def toggle_follow_up(self):
        focus_id = self.focused_run()
        self.lookup_error = ""
        self.follow_up_only = not self.follow_up_only
        self.show_runs(focus_id)

    def filter_runs(self, focus_id=None):
        tokens = self.search.casefold().split()
        self.matching = []
        for run in self.runs:
            errors = run["report_errors"] or run["log_errors"]
            needs_attention = (run["state"] != "Completed" or not run["checksum"] or errors
                               or any(count != "0" for count in run["counts"]))
            if self.follow_up_only and not needs_attention:
                continue
            text = " ".join((run["id"], run["mode"], run["state"], run["version"],
                             "errors" if errors else "")).casefold()
            if all(token in text for token in tokens):
                self.matching.append(run)
        message = "Page {}/{}  |  {} matching".format(
            self.index_page + 1, self.index_pages(), len(self.matching))
        if self.follow_up_only:
            message += "  |  Follow-up only"
        self.match_label.set_text(("section", message))
        first = self.index_page * _HISTORY_PAGE_SIZE
        indexed = len(self.indexed)
        message = "Runs {}-{} of {} indexed".format(
            first + 1, min(first + _HISTORY_PAGE_SIZE, indexed), indexed) if indexed else "0 indexed runs"
        if self.omitted:
            message += "  |  {} unavailable".format(self.omitted)
        index_status = [("muted", message)]
        if self.limit:
            index_status.append(("warning", "\nIndex capped at {:,} entries. Paste an exact ID.".format(
                _HISTORY_MAX_ENTRIES)))
        self.index_notice.set_text(index_status)
        rows = []
        for run in self.matching:
            label = "{}  {:8}  {:11}  {}{}".format(
                run["id"], run["mode"], run["state"], run["version"],
                "  |  Errors recorded" if run["report_errors"] or run["log_errors"] else "")
            rows.append(_history_button(label, lambda run=run: self.open_run(run)))
        if self.error:
            rows.append(_history_urwid.Text(("warning", self.error)))
        elif self.lookup_error:
            rows.append(_history_urwid.Text(("warning", self.lookup_error)))
        elif not rows:
            if self.indexed:
                message = "No readable runs on this page." if not self.runs else "No runs match on this page."
                if self.index_pages() > 1:
                    message += " Browse another page with Prev or Next."
            else:
                message = "No saved runs in this report directory."
            rows.append(_history_urwid.Text(message))
        self.walker[:] = rows
        position = next((index for index, run in enumerate(self.matching) if run["id"] == focus_id), 0)
        self.walker.set_focus(position)

    def open_run(self, run, focused_item=None, notice=""):
        if self.page == "runs":
            self.return_focus = self.focused_run()
            self.return_entry_pos = self.entry.edit_pos if self.frame.focus_position == "header" else None
            if any(entry["id"] == run["id"] for entry in self.matching):
                self.return_focus = run["id"]
        self.selected = run
        self.page = "run"
        details = "{}  |  {}  |  {}".format(run["mode"], run["state"], run["version"])
        rows = [_history_urwid.Text(("section", "Reports for " + run["id"])),
                _history_urwid.Text(("muted", "Reports reflect the host at the time of this run."))]
        if run["counts"]:
            rows.append(_history_urwid.Text(
                "{} unresolved  |  {} pending activation  |  {} skipped".format(*run["counts"])))
        if run["report_errors"]:
            rows.append(_history_urwid.Text(("warning", "The saved summary records finding or action errors.")))
        elif run["log_errors"]:
            rows.append(_history_urwid.Text(("warning", "The run log records errors. Open it for context.")))
        if not run["checksum"]:
            rows.append(_history_urwid.Text(("warning", "Manifest checksum missing. Comparison is unavailable.")))
        if notice:
            rows.append(_history_urwid.Text(("warning", notice)))
        rows.append(_history_urwid.Divider())
        relationship_buttons, extra_header = [], []
        if run["related"]:
            extra_header.append(_history_urwid.Text(
                ("muted", "Related run " + run["related"]), wrap="clip"))
            relationship_buttons.append(("open-related", _history_button("Open related run", self.open_related)))
            if run["mode"] == "status" and run["comparison_key"] is not None:
                relationship_buttons.append(("compare-original", _history_button(
                    "Compare with original", self.compare_with_original)))
        artifact_buttons = []
        try:
            with _history_base(self.report_dir) as base, _history_run(base, run["id"]) as directory:
                _history_manifest(directory, run["id"])
                for name, label in _HISTORY_FILES:
                    try:
                        meta = _history_os.stat(name, dir_fd=directory, follow_symlinks=False)
                    except OSError:
                        continue
                    if _history_file_ok(meta) and meta.st_size:
                        artifact_buttons.append((name, _history_button(
                            label + " (" + name + ")", lambda filename=name: self.open_artifact(filename))))
        except (OSError, ValueError):
            rows.append(_history_urwid.Text(("warning", "This run is no longer available.")))
        else:
            if not artifact_buttons:
                rows.append(_history_urwid.Text("No readable report artifacts were recorded."))
        first_action = len(rows)
        available = relationship_buttons + artifact_buttons
        rows.extend(button for _, button in available)
        back_label = "Back to linked run" if self.related_stack else "Back to saved runs"
        self.screen("Run", details, rows, [
            (back_label, self.back), ("Compare runs", self.start_comparison),
        ],
                    "Enter open  |  Arrows move  |  Esc back", extra_header=extra_header)
        if available:
            default = len(relationship_buttons) if artifact_buttons else 0
            offset = next((index for index, (name, _) in enumerate(available)
                           if name == focused_item), default)
            self.walker.set_focus(first_action + offset)
        else:
            self.frame.focus_position = "footer"

    def open_related(self):
        origin = self.selected
        run_id = origin["related"]
        try:
            if any(run["id"] == run_id for run in self.related_stack):
                raise ValueError("The related run is already open. Use Back to return to it.")
            related = _history_lookup(self.report_dir, run_id)
            if origin["identity"] is None or related["identity"] is None:
                raise ValueError("The related run needs matching checksummed manifest metadata.")
            if origin["identity"] != related["identity"]:
                raise ValueError("The related run uses a different host, benchmark archive or script.")
        except OSError:
            self.open_run(origin, "open-related", "The related run is unavailable in this report directory.")
        except ValueError as exc:
            self.open_run(origin, "open-related", str(exc))
        else:
            self.related_stack.append(origin)
            self.open_run(related)

    def compare_with_original(self):
        run = self.selected
        self.open_recheck_comparison(run["related"], run["id"],
                                     lambda: self.open_run(run, "compare-original"))

    def open_artifact(self, name):
        if name not in _HISTORY_ARTIFACT_TITLES or self.selected is None:
            return
        self.show_artifact(self.selected["id"], name, "Back to run")

    def show_artifact(self, run_id, name, back_label, extra_actions=()):
        self.artifact = name
        self.page = "artifact"
        path = _history_os.path.join(self.report_dir, run_id, name)
        rows = [_HistoryLine(("section", _history_text(path)), wrap="any"), _HistoryLine("")]
        entry, notices = None, ()
        actions = [(back_label, self.back)]
        self.preview = None
        try:
            with _history_base(self.report_dir) as base, _history_run(base, run_id) as directory:
                _history_manifest(directory, run_id)
                data, limited = _history_read(directory, name, _HISTORY_REPORT_LIMIT)
        except (OSError, ValueError):
            rows.append(_HistoryLine(("warning", "This artifact is no longer available.")))
        else:
            self.preview = _HistoryPreview(name, data, limited)
            entry = _history_urwid.Edit("Find text or ID  ", wrap="clip")
            _history_urwid.connect_signal(entry, "change", self.change_artifact_search)
            self.artifact_status = _history_urwid.Text("", wrap="clip")
            notices = [self.artifact_status]
            if self.preview.limited:
                notices.append(_history_urwid.Text(
                    ("warning", "Preview limited to 256 KiB or 2,000 lines."), wrap="clip"))
            actions.extend((("Prev hit", lambda: self.move_artifact_match(-1)),
                            ("Next hit", lambda: self.move_artifact_match(1))))
            self.show_artifact_status()
        actions.extend(extra_actions)
        self.screen(_HISTORY_ARTIFACT_TITLES[name], "{}  |  {}".format(name, run_id),
                    rows, actions, "/ find  n/N hits  PgUp/PgDn  Ctrl+U clear  Esc",
                    entry, notices)

    def layout_artifact(self, width):
        preview = self.preview
        if preview is None or width == preview.width:
            return
        # Keep the source character in view even when resizing changes wrapping.
        position = self.walker.focus - 2
        offset = None
        if 0 <= position < len(preview.offsets):
            offset = preview.offsets[position]
            active = preview.match_bounds()
            if active and offset <= active[0] < preview.rows[position][0]:
                offset = active[0]
        preview.wrap(width)
        self.walker[2:] = [
            _HistoryLine(preview.row_text(index), wrap="clip") for index in range(len(preview.rows))
        ]
        if offset is not None and preview.rows:
            self.frame.body.set_focus(2 + preview.row_for(offset))
            self.frame.body.set_focus_valign("middle")

    def show_artifact_status(self, wrapped=False):
        preview = self.preview
        style = "muted"
        if preview.matches:
            line = preview.rows[preview.row_for(preview.matches[preview.active])][1]
            message = "Match {} of {}  |  Line {} of {}".format(
                preview.active + 1, len(preview.matches), line, len(preview.lines))
            if wrapped:
                message += "  |  Wrapped"
            style = "section"
        elif preview.query:
            message, style = "No matches in this preview.", "warning"
        elif preview.lines:
            message = "{} report lines  |  / searches preview".format(len(preview.lines))
        else:
            message = "This report is empty."
        self.artifact_status.set_text((style, message))

    def change_artifact_search(self, _, value):
        if value == self.preview.query:
            self.show_artifact_status()
        else:
            self.artifact_status.set_text(("section", "Enter to search this preview."))

    def find_artifact(self, keep_editing=False):
        preview = self.preview
        previous = preview.match_bounds()
        preview.search(self.entry.edit_text)
        self.highlight_artifact_match(previous)
        if not keep_editing and (preview.matches or not preview.query):
            self.frame.focus_position = "body"

    def move_artifact_match(self, step):
        preview = self.preview
        if preview is None:
            return
        if self.entry.edit_text != preview.query:
            self.find_artifact()
            if step > 0:
                return
        if not preview.matches:
            self.frame.focus_position = "header"
            return
        previous = preview.match_bounds()
        index = preview.active + step
        preview.active = index % len(preview.matches)
        self.highlight_artifact_match(previous, wrapped=index != preview.active and len(preview.matches) > 1)
        self.frame.focus_position = "body"

    def highlight_artifact_match(self, previous, wrapped=False):
        preview = self.preview
        current = preview.match_bounds()
        # Redraw the old and new highlight only. Recreating thousands of text
        # widgets on each n/N press would slow down navigation.
        for bounds in (previous, current):
            if bounds:
                first, last = preview.row_for(bounds[0]), preview.row_for(bounds[1] - 1)
                for index in range(first, last + 1):
                    self.walker[2 + index].set_text(preview.row_text(index))
        if current:
            self.frame.body.set_focus(2 + preview.row_for(current[0]))
            self.frame.body.set_focus_valign("middle")
        self.show_artifact_status(wrapped)

    def start_comparison(self):
        self.comparison_input, self.comparison_partner, self.comparison_typed = "", None, False
        self.comparison_key = None
        self.comparison_error = ""
        target = self.selected["id"]
        self.comparison_page = (self.indexed.index(target) // _HISTORY_PAGE_SIZE
                                if target in self.indexed else self.index_page)
        try:
            with _history_base(self.report_dir) as base_fd:
                identifiers, _, _, _ = _history_comparison_source(base_fd, target)
                self.comparison_key = (identifiers["host"], identifiers["archive"])
        except OSError:
            self.comparison_error = "This run is no longer available for comparison."
        except ValueError as exc:
            self.comparison_error = str(exc)
        self.load_comparison_page()
        self.choose_comparison()

    def load_comparison_page(self):
        self.comparison_runs = []
        self.comparison_page_error = ""
        if self.comparison_key is None:
            return
        try:
            if self.comparison_page == self.index_page:
                self.comparison_runs = self.runs
            else:
                self.comparison_runs, _ = _history_load_page(
                    self.report_dir, self.index_candidates(self.comparison_page))
        except (OSError, ValueError):
            self.comparison_page_error = "This page is unavailable. Reload saved runs to refresh the list."

    def change_comparison_page(self, step):
        destination = self.comparison_page + step
        if self.comparison_key is not None and 0 <= destination < self.index_pages():
            footer_focused = self.frame.focus_position == "footer"
            button_position = self.buttons.focus_position
            self.comparison_typed = False
            self.comparison_page = destination
            self.load_comparison_page()
            self.choose_comparison()
            if footer_focused:
                self.frame.focus_position = "footer"
                self.buttons.focus_position = button_position

    def change_comparison_input(self, _, value):
        self.comparison_input = value

    def choose_comparison(self, error="", focus_entry=False):
        self.page = "compare"
        target = self.selected["id"]
        rows, notices, actions = [], [], [("Back to run", self.back)]
        error = self.comparison_error or error or self.comparison_page_error
        if error:
            rows.append(_history_urwid.Text(("warning", _history_text(error))))
        first_choice = len(rows)
        focus = first_choice
        entry = None
        if self.comparison_key is not None:
            entry = _history_urwid.Edit("Other run ID  ", self.comparison_input)
            _history_urwid.connect_signal(entry, "change", self.change_comparison_input)
            for run in self.comparison_runs:
                if run["id"] == target or run["comparison_key"] != self.comparison_key:
                    continue
                if run["id"] == self.comparison_partner:
                    focus = len(rows)
                rows.append(_history_button(
                    "{}  |  {}  |  {}".format(run["id"], run["mode"], run["version"]),
                    lambda run=run: self.compare_with(run["id"])))
            count = len(rows) - first_choice
            page_info = "{} candidate{}  |  Page {}/{}".format(
                count, "" if count == 1 else "s", self.comparison_page + 1, self.index_pages())
            if self.limit:
                page_info += "  |  Index capped"
            notices.append(_history_urwid.Text(("section", page_info), wrap="clip"))
            if self.index_pages() > 1:
                actions.extend((("Prev", lambda: self.change_comparison_page(-1)),
                                ("Next", lambda: self.change_comparison_page(1))))
        has_choices = len(rows) > first_choice
        if not has_choices and not error and entry is not None:
            rows.append(_history_urwid.Text(
                "No other compatible runs on this page. Choose another page or enter a completed JSON run "
                "ID from this host and benchmark."))
        self.screen("Choose run", "Compare with " + target, rows, actions,
                    "[ ] pages  / run ID  Enter compare  Esc back", entry, notices)
        if entry is not None and (focus_entry or self.comparison_typed):
            self.frame.focus_position = "header"
        elif has_choices:
            self.walker.set_focus(focus)
        elif len(actions) > 1:
            self.frame.focus_position = "footer"
            self.buttons.focus_position = 2 if self.comparison_page < self.index_pages() - 1 else 1
        elif entry is not None:
            self.frame.focus_position = "header"
        else:
            self.frame.focus_position = "footer"

    def compare_with(self, other, typed=False):
        self.comparison_partner, self.comparison_typed = other, typed
        try:
            if not _HISTORY_RUN_ID.fullmatch(other):
                raise ValueError("Enter a full saved run ID.")
            self.comparison = _history_compare(self.report_dir, self.selected["id"], other)
        except OSError:
            self.choose_comparison("One of these runs is unavailable in the protected report directory.",
                                   focus_entry=typed)
            return
        except ValueError as exc:
            self.choose_comparison(str(exc), focus_entry=typed)
            return
        self.show_unchanged = False
        self.show_comparison()

    def toggle_unchanged(self):
        self.show_unchanged = not self.show_unchanged
        self.show_comparison()

    def open_recheck_comparison(self, original, recheck, return_to_run=None):
        self.direct_comparison = True
        self.direct_back = return_to_run or self.on_back
        self.direct_back_label = "Back to run" if return_to_run else "Back to results"
        self.comparison = None
        self.show_unchanged = False
        try:
            if any(not isinstance(run_id, str) or not _HISTORY_RUN_ID.fullmatch(run_id)
                   for run_id in (original, recheck)):
                raise ValueError("Two valid saved run IDs are required.")
            self.comparison = _history_compare(self.report_dir, original, recheck, recheck=True)
        except (OSError, ValueError) as exc:
            message = (str(exc) if isinstance(exc, ValueError) else
                       "One of these protected saved reports is unavailable.")
            self.page = "comparison unavailable"
            self.screen("Comparison unavailable", "Saved reports", [_HistoryLine(message)],
                        [(self.direct_back_label, self.back)], "Tab to Back | Esc back")
        else:
            self.show_comparison()

    def show_comparison(self):
        self.page = "comparison"
        result = self.comparison
        rows = [
            _HistoryLine(("section", "{}  to  {}".format(result["earlier"], result["later"])), wrap="any"),
            _HistoryLine("Earlier {}  |  Later {}".format(result["earlier_mode"], result["later_mode"])),
            _HistoryLine(
                "{} changed | {} unchanged | {} earlier only | {} later only".format(
                    len(result["changed"]), len(result["unchanged"]),
                    len(result["only_earlier"]), len(result["only_later"])), wrap="any"),
            _HistoryLine(
                "{} assessment changes  |  {} action-only changes".format(
                    result["assessment_changes"], result["action_only_changes"]), wrap="any"),
            _HistoryLine("Values show each run's final recorded assessment and action.", wrap="any"),
            _HistoryLine(""),
        ]
        if not (result["changed"] or result["unchanged"] or result["uncompared_actions"]):
            rows.append(_HistoryLine("No shared assessed Vuln-IDs."))
        if not self.direct_comparison and result["earlier"].split(".")[0] == result["later"].split(".")[0]:
            rows.insert(5, _HistoryLine("These runs share a start second. Run ID determines display order.",
                                        wrap="any"))
        categories = [("Changed", result["changed"])]
        unrecognized = result["unrecognized_action_count"]
        if unrecognized:
            rows.append(_HistoryLine(("warning", "Action comparison unavailable for {} shared {}.".format(
                unrecognized, "finding" if unrecognized == 1 else "findings")), wrap="any"))
            rows.append(_HistoryLine(""))
        if result["uncompared_actions"]:
            categories.append(("Action comparison unavailable", result["uncompared_actions"]))
        if self.show_unchanged:
            categories.append(("Unchanged", result["unchanged"]))
        for heading, findings in categories:
            rows.append(_HistoryLine(("section", heading)))
            if not findings:
                rows.append(_HistoryLine("None"))
            for finding, before, after in findings:
                rows.append(_HistoryLine(
                    "{}  {} / {}  to  {} / {}".format(
                        finding, before[0], _history_action_label(before[1]),
                        after[0], _history_action_label(after[1])), wrap="any"))
            rows.append(_HistoryLine(""))
        for label, key in (("Earlier only", "only_earlier"), ("Later only", "only_later"),
                           ("Excluded from earlier scope", "excluded_earlier"),
                           ("Excluded from later scope", "excluded_later")):
            if result[key]:
                rows.append(_HistoryLine(("section", label)))
                rows.extend(_HistoryLine(finding) for finding in result[key])
        back_label = self.direct_back_label if self.direct_comparison else "Back to run choices"
        self.screen("Compare runs", "Saved assessments  |  same host and benchmark archive", rows, [
            (back_label, self.back),
            ("Hide unchanged" if self.show_unchanged else "Show unchanged", self.toggle_unchanged),
        ], "PgUp/PgDn scroll  |  g start  |  G end  |  Esc back")
