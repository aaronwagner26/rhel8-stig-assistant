"""Read-only local path selection for the Urwid input forms."""

from collections import OrderedDict as _path_ordered_dict
from contextlib import contextmanager as _path_contextmanager
import errno as _path_errno
import os as _path_os
import stat as _path_stat
import unicodedata as _path_unicode

import urwid as _path_urwid


_PATH_SCAN_LIMIT = 2048
_PATH_REMEMBER_FOLDERS = 32


def _path_printable(value):
    return isinstance(value, str) and all(_path_unicode.category(char)[0] != "C" for char in value)


def _path_absolute(value, current):
    if not value or not _path_printable(value):
        raise ValueError("Enter a path using printable characters.")
    if value.startswith("~"):
        expanded = _path_os.path.expanduser(value)
        if expanded == value:
            raise ValueError("The home directory in this path is unavailable.")
        value = expanded
    if not _path_printable(value):
        raise ValueError("The expanded path contains unsupported characters.")
    return "/" + _path_os.path.normpath(_path_os.path.join(current, value)).lstrip("/")


@_path_contextmanager
def _path_directory(path):
    if not hasattr(_path_os, "O_NOFOLLOW") or not hasattr(_path_os, "O_DIRECTORY"):
        raise ValueError("The browser needs a Linux directory descriptor.")
    descriptor = _path_os.open(path, _path_os.O_RDONLY | _path_os.O_DIRECTORY | _path_os.O_NOFOLLOW)
    try:
        yield descriptor
    finally:
        _path_os.close(descriptor)


def _path_error(exc):
    if isinstance(exc, ValueError):
        return str(exc)
    if exc.errno in (_path_errno.ENOENT, _path_errno.ESTALE):
        return "That path is missing or no longer accessible."
    if exc.errno in (_path_errno.EACCES, _path_errno.EPERM):
        return "Access to that path was denied."
    if exc.errno in (_path_errno.ENOTDIR, _path_errno.ELOOP):
        return "The folder is unavailable or is a symbolic link."
    if exc.errno == _path_errno.ENAMETOOLONG:
        return "That path is too long for the filesystem."
    return "The filesystem could not provide that path."


def _path_read_entries(directory):
    rows = []
    skipped, capped = 0, False
    with _path_directory(directory) as descriptor:
        # Python 3.6 takes a path for scandir. The proc descriptor pins the
        # opened directory without reopening the path or following its final link.
        with _path_os.scandir("/proc/self/fd/{}".format(descriptor)) as entries:
            for index, entry in enumerate(entries):
                if index >= _PATH_SCAN_LIMIT:
                    capped = True
                    break
                if _path_printable(entry.name):
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            rows.append((entry.name, True))
                            continue
                        if entry.is_file(follow_symlinks=False):
                            rows.append((entry.name, False))
                            continue
                    except OSError:
                        pass
                skipped += 1
    rows.sort(key=lambda row: (not row[1], row[0].casefold(), row[0]))
    return rows, skipped, capped


class _PathChoice(_path_urwid.WidgetWrap):
    """Keep long filenames on one row while retaining keyboard and mouse selection."""

    def __init__(self, marker, name, action):
        super().__init__(_path_urwid.AttrMap(
            _path_urwid.Text("{:<7} {}".format(marker, name), wrap="clip"), "button", "focus"))
        self.action = action

    def selectable(self):
        return True

    def keypress(self, size, key):
        if key in ("enter", " "):
            self.action()
            return None
        return key

    def mouse_event(self, size, event, button, col, row, focus):
        if event == "mouse press" and button == 1:
            self.action()
            return True
        return False


class _PathViewport(_path_urwid.WidgetPlaceholder):
    def __init__(self, browser, frame):
        super().__init__(frame)
        self.browser = browser
        self.small = _path_urwid.Filler(_path_urwid.Text(
            "Resize to at least 56 columns and 18 rows. Esc goes back.", align="center"))

    @staticmethod
    def too_small(size):
        return size[0] < 56 or size[1] < 18

    def render(self, size, focus=False):
        if self.too_small(size):
            return self.small.render(size, focus)
        return super().render(size, focus)

    def mouse_event(self, size, event, button, col, row, focus):
        if self.too_small(size):
            return False
        return super().mouse_event(size, event, button, col, row, focus)

    def keypress(self, size, key):
        browser = self.browser
        if key == "esc":
            browser.on_back()
            return None
        if self.too_small(size):
            return None
        part = browser.frame.focus_position
        if key == "ctrl l":
            browser.focus_editor(1)
            return None
        if key == "/" and part != "header":
            browser.focus_editor(2)
            return None
        if key == "ctrl u" and part == "header":
            browser.active_editor().set_edit_text("")
            return None
        if key == "enter" and part == "header":
            if browser.header.focus_position == 1:
                browser.go_to_location()
            else:
                browser.frame.focus_position = "body"
            return None
        if key == "f5":
            browser.refresh()
            return None
        if key == "backspace" and part != "header":
            browser.go_parent()
            return None
        if key in ("tab", "shift tab"):
            browser.cycle_focus(1 if key == "tab" else -1)
            return None
        return super().keypress(size, key)


class LocalFileBrowser:
    """Browse without reading file contents. A chosen path returns to the input form."""

    def __init__(self, start_path, on_choose, on_back, preferred_suffix=""):
        self.on_choose, self.on_back = on_choose, on_back
        self.suffix = ("." + preferred_suffix.lstrip(".")
                       if preferred_suffix and _path_printable(preferred_suffix) else "")
        self.directory = ""
        self.entries, self.filtered = [], []
        self.skipped, self.capped = 0, False
        self.query = ""
        self.folder_state = _path_ordered_dict()

        self.location = _path_urwid.Edit("Location  ", wrap="clip")
        self.filter = _path_urwid.Edit("Filter    ", wrap="clip")
        _path_urwid.connect_signal(self.filter, "change", self.change_filter)
        self.counts = _path_urwid.Text("", wrap="clip")
        self.notice = _path_urwid.Text("", wrap="clip")
        self.error = _path_urwid.Text("", wrap="clip")
        _path_urwid.connect_signal(self.location, "change", self.change_location)
        headers = [
            _path_urwid.AttrMap(_path_urwid.Text(" STIG Assistant  /  Browse for file", wrap="clip"), "header"),
            _path_urwid.AttrMap(self.location, "input", "focus"),
            _path_urwid.AttrMap(self.filter, "input", "focus"),
            self.counts, self.notice, self.error,
        ]
        if self.suffix:
            headers.insert(5, _path_urwid.Text(
                ("muted", "* {} suggested. Any regular file can be chosen.".format(self.suffix)),
                wrap="clip"))
        self.header = _path_urwid.Pile(headers, focus_item=2)
        self.walker = _path_urwid.SimpleFocusListWalker([])
        self.buttons = _path_urwid.Columns([
            (len(label) + 4, _path_urwid.AttrMap(
                _path_urwid.Button(label, lambda _, action=callback: action()), "button", "focus"))
            for label, callback in (("Back", on_back), ("Parent", self.go_parent),
                                    ("Home", self.go_home), ("Refresh", self.refresh),
                                    ("Choose", self.activate_focus))
        ], dividechars=1)
        footer = _path_urwid.Pile([
            self.buttons,
            _path_urwid.Text(("muted", "Enter open/choose  / filter  Ctrl+L path  Esc back"), wrap="clip"),
            _path_urwid.Text(("muted", "PgUp/PgDn scroll  Backspace parent  F5 refresh"), wrap="clip"),
        ])
        self.frame = _path_urwid.Frame(_path_urwid.ListBox(self.walker), self.header, footer)
        self.widget = _PathViewport(self, self.frame)
        self.open_start(start_path)

    def open_start(self, start_path):
        try:
            current = _path_os.getcwd()
        except OSError:
            current = "/"
        if not _path_printable(current):
            current = "/"
        directory, focus, error = current, None, ""
        if start_path:
            try:
                path = _path_absolute(start_path, current)
                directory = _path_os.path.dirname(path)
                mode = _path_os.stat(path, follow_symlinks=False).st_mode
                if _path_stat.S_ISDIR(mode):
                    directory = path
                elif _path_stat.S_ISREG(mode):
                    focus = _path_os.path.basename(path)
                else:
                    error = "Start path is a link or is not an ordinary file or folder."
            except (OSError, ValueError) as exc:
                error = _path_error(exc)
        if not self.load_directory(directory, focus):
            error = self.error.get_text()[0]
            fallback = current if directory != current else "/"
            if not self.load_directory(fallback) and fallback != "/":
                self.load_directory("/")
        if error:
            self.error.set_text(("warning", error))

    def load_directory(self, path, focus_name=None):
        try:
            entries, skipped, capped = _path_read_entries(path)
        except (OSError, ValueError) as exc:
            self.error.set_text(("warning", _path_error(exc)))
            if not self.directory:
                self.walker[:] = [_path_urwid.Text("Use Location to try another folder.")]
            return False
        if self.directory and self.directory != path:
            self.folder_state[self.directory] = (self.query, self.focused_name())
            self.folder_state.move_to_end(self.directory)
            if len(self.folder_state) > _PATH_REMEMBER_FOLDERS:
                self.folder_state.popitem(last=False)
        if path == self.directory:
            search, remembered = self.query, self.focused_name()
        else:
            search, remembered = self.folder_state.get(path, ("", None))
        self.entries, self.skipped, self.capped = entries, skipped, capped
        self.directory, self.query = path, search
        self.location.set_edit_text(path)
        self.location.set_edit_pos(len(path))
        self.filter.set_edit_text(search)
        self.filter.set_edit_pos(len(search))
        self.error.set_text("")
        self.show_entries(focus_name if focus_name is not None else remembered)
        self.frame.focus_position = "body"
        return True

    def focused_name(self):
        if self.filtered and self.walker.focus < len(self.filtered):
            return self.filtered[self.walker.focus][0]
        return None

    def change_filter(self, _, value):
        if value != self.query:
            focused = self.focused_name()
            self.query = value
            self.show_entries(focused)

    def change_location(self, _, value):
        message = "" if value == self.directory else "Press Enter to open the path in Location."
        self.error.set_text(("muted", message))

    def show_entries(self, focus_name):
        query = self.query.casefold()
        self.filtered = [entry for entry in self.entries if query in entry[0].casefold()]
        rows = []
        for name, directory in self.filtered:
            marker = "Folder" if directory else "File"
            if not directory and self.suffix and name.casefold().endswith(self.suffix.casefold()):
                marker = "File *"
            rows.append(_PathChoice(marker, name, lambda row=(name, directory): self.activate(row)))
        if not rows:
            message = "No entries match the filter." if self.query else "No ordinary files or folders found."
            if self.capped:
                message += " Use Location for an exact path."
            rows.append(_path_urwid.Text(("muted", message)))
        self.walker[:] = rows
        self.walker.set_focus(next((index for index, entry in enumerate(self.filtered)
                                    if entry[0] == focus_name), 0))
        self.counts.set_text(("section", "{} of {} shown  |  Folders first".format(
            len(self.filtered), len(self.entries))))
        notices = []
        if self.capped:
            notices.append("First {:,} entries scanned; use Location for others.".format(_PATH_SCAN_LIMIT))
        if self.skipped:
            notices.append("{} links, special entries or unsupported names skipped.".format(self.skipped))
        self.notice.set_text(("warning" if self.capped else "muted", "\n".join(notices)))

    def refresh(self):
        if self.directory:
            part, active = self.frame.focus_position, self.header.focus_position
            location, position = self.location.edit_text, self.active_editor().edit_pos
            if self.load_directory(self.directory):
                self.frame.focus_position = part
                if part == "header":
                    self.header.focus_position = active
                    if active == 1:
                        self.location.set_edit_text(location)
                    self.active_editor().set_edit_pos(position)
        else:
            self.go_to_location()

    def go_parent(self):
        if self.directory and self.directory != "/":
            parent, name = _path_os.path.split(self.directory)
            self.load_directory(parent, name)

    def go_home(self):
        try:
            self.load_directory(_path_absolute("~", self.directory or "/"))
        except ValueError as exc:
            self.error.set_text(("warning", _path_error(exc)))

    def go_to_location(self):
        try:
            path = _path_absolute(self.location.edit_text, self.directory or "/")
            mode = _path_os.stat(path, follow_symlinks=False).st_mode
            if not (_path_stat.S_ISDIR(mode) or _path_stat.S_ISREG(mode)):
                raise ValueError("Choose an ordinary file or folder. Links are skipped.")
        except (OSError, ValueError) as exc:
            self.error.set_text(("warning", _path_error(exc)))
        else:
            if _path_stat.S_ISDIR(mode):
                self.load_directory(path)
            else:
                self.on_choose(path)

    def activate_focus(self):
        if self.filtered:
            self.activate(self.filtered[self.walker.focus])
        else:
            self.focus_editor(2)
            self.error.set_text(("warning", "Choose a file or change the filter."))

    def activate(self, entry):
        name, directory = entry
        path = _path_os.path.join(self.directory, name)
        if directory:
            self.load_directory(path)
            return
        try:
            with _path_directory(self.directory) as descriptor:
                mode = _path_os.stat(name, dir_fd=descriptor, follow_symlinks=False).st_mode
            if not _path_stat.S_ISREG(mode):
                raise ValueError("That entry is no longer an ordinary file. Refresh to update the list.")
        except (OSError, ValueError) as exc:
            self.error.set_text(("warning", _path_error(exc)))
        else:
            self.on_choose(path)

    def active_editor(self):
        return self.location if self.header.focus_position == 1 else self.filter

    def focus_editor(self, index):
        self.frame.focus_position = "header"
        self.header.focus_position = index

    def cycle_focus(self, step):
        part = self.frame.focus_position
        if part == "footer":
            target = self.buttons.focus_position + step
            if 0 <= target < len(self.buttons.contents):
                self.buttons.focus_position = target
            elif step > 0:
                self.focus_editor(1)
            else:
                self.frame.focus_position = "body"
        elif part == "body":
            if step > 0:
                self.frame.focus_position = "footer"
                self.buttons.focus_position = 0
            else:
                self.focus_editor(2)
        elif self.header.focus_position == 1:
            if step > 0:
                self.focus_editor(2)
            else:
                self.frame.focus_position = "footer"
                self.buttons.focus_position = len(self.buttons.contents) - 1
        elif step > 0:
            self.frame.focus_position = "body"
        else:
            self.focus_editor(1)
