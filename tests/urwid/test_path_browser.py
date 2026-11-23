"""Exercise local path browsing with protected, disposable fixtures."""

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import path_browser


SIZE = (56, 18)


def visible(browser, size=SIZE):
    return b"\n".join(browser.widget.render(size, True).text).decode("utf-8")


class LocalFileBrowserTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(dir="/var/tmp")
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.chosen = []
        self.back = []

    def create(self, relative):
        path = self.base / relative
        path.write_text("The picker must never read this content.\n", encoding="utf-8")
        return path

    def browser(self, start=None, suffix=".ckl"):
        return path_browser.LocalFileBrowser(str(start if start is not None else self.base),
                                             self.chosen.append, lambda: self.back.append(True), suffix)

    def key(self, browser, *keys):
        for key in keys:
            browser.widget.keypress(SIZE, key)

    def test_directory_first_and_preferred_extension_is_a_cue(self):
        (self.base / "z-folder").mkdir()
        self.create("a.OTHER")
        self.create("m.CkL")
        selected = self.create("operator’s IDs.custom")
        browser = self.browser(selected)
        self.assertEqual(browser.focused_name(), selected.name)
        self.assertEqual([name for name, _ in browser.entries],
                         ["z-folder", "a.OTHER", "m.CkL", selected.name])
        display = visible(browser)
        self.assertIn("Folder  z-folder", display)
        self.assertIn("File *  m.CkL", display)
        self.assertIn("Any regular file can be chosen.", display)
        self.assertEqual(self.chosen, [])
        self.key(browser, "enter")
        self.assertEqual(self.chosen, [str(selected)])

    def test_navigation_retains_folder_filter_and_the_child_focus(self):
        (self.base / "checklists").mkdir()
        (self.base / "other").mkdir()
        selected = self.create("checklists/lab data.ckl")
        self.create("checklists/unrelated.txt")
        browser = self.browser()
        self.key(browser, "/", *"check", "enter", "enter")
        self.assertEqual(browser.directory, str(self.base / "checklists"))
        self.assertEqual(browser.query, "")
        self.key(browser, "/", *"lab", "enter", "backspace")
        self.assertEqual(browser.directory, str(self.base))
        self.assertEqual(browser.query, "check")
        self.assertEqual(browser.focused_name(), "checklists")
        self.key(browser, "enter")
        self.assertEqual(browser.query, "lab")
        self.assertEqual(browser.focused_name(), selected.name)
        self.key(browser, "f5", "enter")
        self.assertEqual(self.chosen, [str(selected)])

    def test_mouse_selects_a_file_and_escape_returns_to_the_form(self):
        chosen = self.create("items.ids")
        browser = self.browser(suffix="ids")
        display = visible(browser)
        row = next(index for index, line in enumerate(display.splitlines()) if "items.ids" in line)
        self.assertTrue(browser.widget.mouse_event(SIZE, "mouse press", 1, 14, row, True))
        self.assertEqual(self.chosen, [str(chosen)])
        self.assertIn("Resize to at least", visible(browser, (45, 11)))
        browser.widget.keypress((45, 11), "enter")
        browser.widget.keypress((45, 11), "esc")
        self.assertEqual(self.chosen, [str(chosen)])
        self.assertEqual(self.back, [True])

    def test_bounded_list_accepts_an_exact_file_outside_the_scan(self):
        files = [self.create("file{}.custom".format(index)) for index in range(5)]
        with mock.patch.object(path_browser, "_PATH_SCAN_LIMIT", 2):
            browser = self.browser()
            self.assertIn("First 2 entries scanned", visible(browser))
            self.assertEqual(len(browser.entries), 2)
            missing = next(item for item in files if item.name not in dict(browser.entries))
            self.key(browser, "ctrl l")
            browser.location.set_edit_text(missing.name)
            self.assertIn("Press Enter to open the path in Location.", visible(browser))
            self.key(browser, "enter")
            self.assertEqual(self.chosen, [str(missing)])

    def test_special_files_and_control_names_are_omitted_and_links_fail_closed(self):
        target = self.create("ordinary.ckl")
        (self.base / "link.ckl").symlink_to(target)
        (self.base / "folder").mkdir()
        (self.base / "link-folder").symlink_to(self.base / "folder", target_is_directory=True)
        os.mkfifo(str(self.base / "pipe.ckl"))
        self.create("unsupported\nname")
        browser = self.browser()
        self.assertEqual([name for name, _ in browser.entries], ["folder", target.name])
        self.assertIn("4 links, special entries or unsupported names skipped.", visible(browser))
        self.key(browser, "ctrl l")
        for name in ("link.ckl", "link-folder", "pipe.ckl"):
            browser.location.set_edit_text(name)
            self.key(browser, "enter")
            self.assertIn("Choose an ordinary file or folder.", visible(browser))
        self.assertEqual(self.chosen, [])

    def test_stale_file_and_directory_are_revalidated_without_opening_a_file(self):
        selected = self.create("stale.ckl")
        target = self.create("target.txt")
        folder = self.base / "stale-folder"
        folder.mkdir()
        with mock.patch.object(path_browser._path_os, "open", wraps=os.open) as opened:
            browser = self.browser(selected)
            selected.unlink()
            selected.symlink_to(target)
            self.key(browser, "enter")
            self.assertIn("That entry is no longer an ordinary file.", visible(browser))
            folder.rmdir()
            folder.symlink_to(self.base, target_is_directory=True)
            browser.activate((folder.name, True))
            self.assertIn("The folder is unavailable or is a symbolic link.", visible(browser))
            browser.activate((target.name, False))
            self.assertEqual(self.chosen, [str(target)])
            self.assertTrue(all(call[0][1] & os.O_NOFOLLOW and call[0][1] & os.O_DIRECTORY
                                for call in opened.call_args_list))

    def test_missing_and_inaccessible_paths_leave_the_picker_recoverable(self):
        browser = self.browser(self.base / "missing.ckl")
        self.assertEqual(browser.directory, str(self.base))
        self.assertIn("That path is missing or no longer accessible.", visible(browser))
        with mock.patch.object(path_browser, "_path_read_entries",
                               side_effect=PermissionError(errno.EACCES, "fixture")):
            browser.refresh()
        self.assertIn("Access to that path was denied.", visible(browser))
        self.key(browser, "f5")
        self.assertNotIn("Access to that path was denied.", visible(browser))
        self.assertEqual(self.chosen, [])

    def test_tab_cycle_reaches_choose_and_editable_location(self):
        selected = self.create("selection.txt")
        browser = self.browser()
        self.key(browser, "tab", "tab", "tab", "tab", "tab")
        self.assertEqual(browser.frame.focus_position, "footer")
        self.assertEqual(browser.buttons.focus_position, 4)
        self.key(browser, "enter")
        self.assertEqual(self.chosen, [str(selected)])
        self.key(browser, "tab")
        self.assertEqual(browser.frame.focus_position, "header")
        self.assertEqual(browser.header.focus_position, 1)
        self.key(browser, "shift tab")
        self.assertEqual(browser.buttons.focus_position, 4)


if __name__ == "__main__":
    unittest.main()
