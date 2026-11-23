"""Exercise saved results with temporary protected runs and offscreen Urwid."""

import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

import history


COMPLETED = "20261120T180000Z.QWeRTy12"
INTERRUPTED = "20261120T190000Z.AaBbCcDd"
INCOMPLETE = "20261120T200000Z.AaBbCcDd"
UNSAFE = "20261120T210000Z.AaBbCcDd"
BAD_DIGEST = "20261120T220000Z.AaBbCcDd"
STAMP = "2026-11-20T18:00:00Z"
SHA = "1" * 64
HOST = "2" * 64
ARCHIVE = "3" * 64


def write_private(path, text):
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(text)
    os.chmod(path, 0o600)


def fixture_report(base, run_id, completed=False, interrupted=False, ticket="CHG-262",
                   host=HOST, archive=ARCHIVE, results=None, resolved=False, mode="apply",
                   excluded=(), log_error=False, script=SHA, related=""):
    path = os.path.join(base, run_id)
    os.mkdir(path, 0o700)
    manifest = "schema\t1\nrun\t{}\nscript\t{}\nhost\t{}\narchive\t{}\n".format(
        run_id, script, host, archive)
    scope = [row[0] for row in results] if results is not None else ["V-244531"]
    manifest += "".join("{}\t{}\n".format("skip" if finding in excluded else "select", finding)
                        for finding in scope)
    write_private(os.path.join(path, "manifest"), manifest)
    digest = hashlib.sha256(manifest.encode()).hexdigest()
    write_private(os.path.join(path, "manifest.sha256"), digest + "\n")
    log = "{} INFO started {} by root; script 0.5.4-dev {}\n".format(STAMP, mode, script)
    if log_error:
        log += STAMP + " ERROR V-244531 a preview assessment reported an error\n"
    if interrupted:
        log += STAMP + (" BLOCKED V-244531 approval input closed; further mutation stopped\n"
                        if mode == "apply"
                        else " ERROR run interrupted; inspect manifest, changes and backups before retrying\n")
    if completed:
        log += STAMP + " INFO completed with {} unresolved, {} pending, 0 skipped\n".format(
            0 if resolved else 2, 0 if resolved else 1)
        write_private(os.path.join(path, "summary.txt"),
                      "Run {} | {} | {}\nScript 0.5.4-dev | SHA-256 {}\n"
                      "Operator root | ticket {}\n"
                      .format(run_id, STAMP, mode, script, ticket)
                      + ("Related run " + related + "\n" if related else "")
                      + "\nReport fixture \x1b[31mwithout controls\n"
                      + "".join("{}  FAIL  {}  {}  Saved evidence\n".format(*row) for row in results or ()))
    write_private(os.path.join(path, "run.log"), log)
    if results is not None:
        write_private(os.path.join(path, "results.json"), json.dumps({
            "run_id": run_id, "script_sha256": script, "host_id": host, "archive_sha256": archive,
            "mode": mode,
            "results": [{"id": finding, "assessment": assessment, "action": action}
                        for finding, assessment, action in results],
        }))
    return path


def visible(screen, size=(75, 24)):
    return b"\n".join(row for row in screen.widget.render(size, focus=True).text).decode("utf-8")


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.base = tempfile.TemporaryDirectory(dir="/var/tmp")
        self.addCleanup(self.base.cleanup)

    def test_metadata_and_protected_enumeration(self):
        fixture_report(self.base.name, COMPLETED, completed=True)
        fixture_report(self.base.name, INTERRUPTED, completed=True, interrupted=True)
        fixture_report(self.base.name, INCOMPLETE)
        os.symlink(os.path.join(self.base.name, COMPLETED), os.path.join(self.base.name, UNSAFE))
        changed = fixture_report(self.base.name, BAD_DIGEST, completed=True)
        with open(os.path.join(changed, "manifest"), "a", encoding="ascii") as stream:
            stream.write("select\tV-230264\n")
        indexed, limited = history._history_index(self.base.name)
        runs, omitted = history._history_load_page(self.base.name, indexed)
        self.assertEqual([row["id"] for row in runs], [INCOMPLETE, INTERRUPTED, COMPLETED])
        self.assertEqual([row["state"] for row in runs], ["Incomplete", "Interrupted", "Completed"])
        self.assertEqual(runs[-1]["counts"], ("2", "1", "0"))
        self.assertEqual(runs[-1]["ticket"], "CHG-262")
        self.assertEqual(runs[0]["version"], "0.5.4-dev")
        self.assertEqual((limited, omitted), (False, 1))

    def test_refuses_parent_link_unsafe_mode_and_special_files(self):
        base_parent = os.path.join(self.base.name, "parent")
        os.mkdir(base_parent, 0o700)
        report = os.path.join(base_parent, "report")
        os.mkdir(report, 0o700)
        os.symlink(base_parent, os.path.join(self.base.name, "alias"))
        with self.assertRaises(OSError):
            history._history_index(os.path.join(self.base.name, "alias", "report"))
        os.chmod(base_parent, 0o777)
        with self.assertRaises(ValueError):
            history._history_index(report)
        os.chmod(base_parent, 0o700)
        run = fixture_report(report, COMPLETED, completed=True)
        summary = os.path.join(run, "summary.txt")
        os.link(summary, os.path.join(run, "results.json"))
        os.symlink(summary, os.path.join(run, "diff.txt"))
        os.mkfifo(os.path.join(run, "changes.txt"), 0o600)
        with history._history_base(report) as base_fd, history._history_run(base_fd, COMPLETED) as run_fd:
            for filename in ("summary.txt", "results.json", "changes.txt", "diff.txt"):
                with self.assertRaises(ValueError):
                    history._history_read(run_fd, filename, 32)

    def test_filter_keyboard_navigation_and_read_only_view(self):
        fixture_report(self.base.name, COMPLETED, completed=True)
        fixture_report(self.base.name, INCOMPLETE)
        calls = []
        screen = history.RunHistory(self.base.name, lambda: calls.append("back"))
        size = (75, 24)
        self.assertIn("Saved runs", visible(screen))
        self.assertIn(INCOMPLETE, visible(screen))
        screen.widget.keypress(size, "/")
        for char in "CHG-262":
            screen.widget.keypress(size, char)
        self.assertIn(COMPLETED, visible(screen))
        self.assertNotIn(INCOMPLETE, visible(screen))
        screen.widget.keypress(size, "enter")
        screen.widget.keypress(size, "enter")
        self.assertIn("Summary (summary.txt)", visible(screen))
        screen.widget.keypress(size, "enter")
        self.assertIn("Report fixture", visible(screen))
        self.assertNotIn("\x1b", visible(screen))
        screen.widget.keypress(size, "esc")
        screen.widget.keypress(size, "esc")
        self.assertEqual(screen.search, "CHG-262")
        screen.widget.keypress(size, "esc")
        self.assertEqual(calls, ["back"])

    def test_empty_small_and_limited_artifact(self):
        screen = history.RunHistory(self.base.name, lambda: None)
        self.assertIn("No saved runs", visible(screen))
        self.assertIn("Enlarge the terminal", visible(screen, (30, 10)))
        run = fixture_report(self.base.name, COMPLETED)
        write_private(os.path.join(run, "diff.txt"),
                      "- old\n+ new\n" + "a" * (history._HISTORY_REPORT_LIMIT + 1))
        screen.refresh()
        screen.open_run(screen.runs[0])
        screen.open_artifact("diff.txt")
        self.assertIn("+ new", visible(screen))
        screen.widget.keypress((75, 24), "G")
        self.assertIn("Preview limited", visible(screen))

    def test_follow_up_filter_and_artifact_focus(self):
        fixture_report(self.base.name, COMPLETED, completed=True, resolved=True)
        fixture_report(self.base.name, INCOMPLETE)
        screen = history.RunHistory(self.base.name, lambda: None)
        size = (75, 24)
        screen.widget.keypress(size, "f")
        self.assertIn(INCOMPLETE, visible(screen))
        self.assertNotIn(COMPLETED, visible(screen))
        screen.widget.keypress(size, "f")
        self.assertIn(COMPLETED, visible(screen))
        screen.open_run(screen.runs[-1])
        screen.open_artifact("run.log")
        screen.widget.keypress(size, "esc")
        screen.widget.keypress(size, "enter")
        self.assertIn("INFO started apply", visible(screen))

    def test_artifact_search_is_literal_and_navigates_both_ways(self):
        size = (48, 12)
        run = fixture_report(self.base.name, COMPLETED, completed=True)
        write_private(os.path.join(run, "admin-actions.txt"),
                      "Check [r.1] one\n" + "filler\n" * 20
                      + "CHECK [R.1] two\n" + "filler\n" * 20 + "Check [r.1] three\n")
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(screen.runs[0])
        screen.open_artifact("admin-actions.txt")
        screen.widget.keypress(size, "/")
        for character in "check [r.1]":
            screen.widget.keypress(size, character)
        self.assertIn("Enter to search this preview", visible(screen, size))
        screen.widget.keypress(size, "enter")
        self.assertIn("Match 1 of 3  |  Line 1 of 43", visible(screen, size))
        self.assertTrue(any(style == "focus" and data == b"Check [r.1]"
                            for row in screen.widget.render(size, focus=True).content()
                            for style, _, data in row))
        screen.widget.keypress(size, "n")
        self.assertIn("CHECK [R.1] two", visible(screen, size))
        self.assertIn("Match 2 of 3  |  Line 22 of 43", visible(screen, size))
        screen.widget.keypress(size, "N")
        screen.widget.keypress(size, "N")
        self.assertIn("Check [r.1] three", visible(screen, size))
        self.assertIn("Match 3 of 3  |  Line 43 of 43  |  Wrapped", visible(screen, size))
        button_row = visible(screen, size).split("\n")[-2]
        button_col = button_row.index("< Next hit >") + 3
        screen.widget.mouse_event(size, "mouse press", 1, button_col, size[1] - 2, True)
        self.assertIn("Match 1 of 3  |  Line 1 of 43  |  Wrapped", visible(screen, size))
        screen.widget.keypress(size, "ctrl u")
        self.assertIn("43 report lines", visible(screen, size))
        self.assertEqual(screen.frame.focus_position, "header")
        screen.entry.set_edit_text("nothing here")
        screen.widget.keypress(size, "enter")
        self.assertIn("No matches in this preview.", visible(screen, size))
        self.assertEqual(screen.frame.focus_position, "header")
        screen.widget.keypress(size, "ctrl u")
        self.assertIn("43 report lines", visible(screen, size))
        self.assertEqual(screen.entry.edit_text, "")
        screen.entry.set_edit_text("filler")
        screen.widget.keypress(size, "tab")
        screen.widget.keypress(size, "N")
        self.assertIn("Match 40 of 40  |  Line 42 of 43", visible(screen, size))
        screen.widget.keypress(size, "/")
        screen.entry.set_edit_text("check")
        screen.widget.keypress(size, "tab")
        screen.widget.keypress(size, "n")
        self.assertIn("Match 1 of 3  |  Line 1 of 43", visible(screen, size))
        screen.widget.keypress(size, "esc")
        screen.widget.keypress(size, "enter")
        self.assertEqual(screen.artifact, "admin-actions.txt")

    def test_artifact_search_jumps_into_a_long_wrapped_json_line(self):
        size = (48, 12)
        wide_text = "設定値" * 3500
        run = fixture_report(self.base.name, COMPLETED, completed=True)
        write_private(os.path.join(run, "results.json"), json.dumps({
            "results": [
                {"id": "V-230264", "evidence": wide_text},
                {"id": "V-244531", "evidence": "Saved marker"},
            ],
        }, ensure_ascii=False) + "\n")
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(screen.runs[0])
        screen.open_artifact("results.json")
        screen.widget.keypress(size, "/")
        screen.entry.set_edit_text("V-244531")
        screen.widget.keypress(size, "enter")
        for viewport in ((48, 12), (147, 24), (63, 17)):
            content = visible(screen, viewport)
            self.assertIn("Match 1 of 1  |  Line 1 of 1", content)
            canvas = screen.widget.render(viewport, focus=True)
            highlight = b"".join(data for row in canvas.content()
                                 for style, _, data in row if style == "focus")
            self.assertIn(b"V-244531", highlight)
            self.assertIn("Saved marker", content.replace("\n", ""))

    def test_artifact_search_is_limited_to_read_preview_and_handles_empty_reports(self):
        size = (48, 12)
        run = fixture_report(self.base.name, COMPLETED, completed=True)
        path = os.path.join(run, "diff.txt")
        write_private(path, "exact-number-of-lines\n" * 2000)
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(screen.runs[0])
        screen.open_artifact("diff.txt")
        self.assertNotIn("Preview limited", visible(screen, size))
        with open(path, "a", encoding="utf-8") as output:
            output.write("outside preview\n")
        screen.open_artifact("diff.txt")
        screen.widget.keypress(size, "/")
        screen.entry.set_edit_text("outside preview")
        screen.widget.keypress(size, "enter")
        self.assertIn("No matches in this preview.", visible(screen, size))
        self.assertIn("Preview limited to 256 KiB or 2,000 lines.", visible(screen, size))
        write_private(path, "")
        screen.open_artifact("diff.txt")
        self.assertIn("This report is empty.", visible(screen, size))

    def test_index_pages_read_only_visible_metadata_and_keep_focus_on_refresh(self):
        newest = "20261120T230000Z.Newest00"
        ids = [COMPLETED, INTERRUPTED, INCOMPLETE, UNSAFE, BAD_DIGEST]
        for run_id in ids:
            fixture_report(self.base.name, run_id, completed=True)
        with mock.patch.object(history, "_HISTORY_PAGE_SIZE", 2), mock.patch.object(
                history, "_history_metadata", wraps=history._history_metadata) as read_metadata:
            screen = history.RunHistory(self.base.name, lambda: None)
            size = (75, 24)
            self.assertEqual(read_metadata.call_count, 2)
            self.assertIn("Page 1/3  |  2 matching", visible(screen))
            self.assertIn("Runs 1-2 of 5 indexed", visible(screen))
            screen.widget.keypress(size, "/")
            screen.entry.set_edit_text("CHG-262")
            screen.widget.keypress(size, "enter")
            screen.widget.keypress(size, "]")
            self.assertEqual(read_metadata.call_count, 4)
            self.assertIn("Runs 3-4 of 5 indexed", visible(screen))
            self.assertEqual(screen.search, "CHG-262")
            screen.widget.keypress(size, "down")
            self.assertEqual(screen.focused_run(), INTERRUPTED)
            screen.widget.keypress(size, "enter")
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.focused_run(), INTERRUPTED)
            fixture_report(self.base.name, newest, completed=True)
            screen.widget.keypress(size, "f5")
            self.assertEqual(read_metadata.call_count, 6)
            self.assertIn("Runs 5-6 of 6 indexed", visible(screen))
            self.assertEqual(screen.focused_run(), INTERRUPTED)
            screen.widget.keypress(size, "/")
            screen.widget.keypress(size, "left")
            position = screen.entry.edit_pos
            screen.widget.keypress(size, "f5")
            self.assertEqual(screen.frame.focus_position, "header")
            self.assertEqual(screen.entry.edit_pos, position)
            screen.widget.keypress(size, "ctrl u")
            self.assertEqual(screen.search, "")
            self.assertIn("Page 3/3", visible(screen, (48, 12)))

    def test_exact_run_lookup_beyond_index_cap_preserves_protected_path_guards(self):
        size = (75, 24)
        ids = [COMPLETED, INCOMPLETE, INTERRUPTED]
        for run_id in ids:
            fixture_report(self.base.name, run_id, completed=True)
        os.symlink(os.path.join(self.base.name, COMPLETED), os.path.join(self.base.name, UNSAFE))
        with mock.patch.object(history, "_HISTORY_MAX_ENTRIES", 2):
            screen = history.RunHistory(self.base.name, lambda: None)
            self.assertIn("Index capped at 2 entries.", visible(screen))
            missing = next(run_id for run_id in ids if run_id not in screen.indexed)
            screen.widget.keypress(size, "/")
            screen.entry.set_edit_text(UNSAFE)
            screen.widget.keypress(size, "enter")
            self.assertIn("This run ID is unavailable", visible(screen))
            screen.entry.set_edit_text(missing)
            screen.widget.keypress(size, "enter")
            self.assertEqual(screen.page, "run")
            self.assertEqual(screen.selected["id"], missing)
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.search, missing)
            self.assertEqual(screen.frame.focus_position, "header")
            self.assertIn("No runs match on this page", visible(screen))

    def test_minimum_width_page_controls_have_full_labels_and_keyboard_focus(self):
        size = (48, 12)
        fixture_report(self.base.name, COMPLETED, completed=True)
        fixture_report(self.base.name, INCOMPLETE, completed=True)
        with mock.patch.object(history, "_HISTORY_PAGE_SIZE", 1):
            screen = history.RunHistory(self.base.name, lambda: None)
            self.assertIn("< Reload > < Prev > < Next > < Follow >", visible(screen, size))
            for _ in range(4):
                screen.widget.keypress(size, "tab")
            self.assertEqual(screen.frame.focus_position, "footer")
            self.assertEqual(screen.buttons.focus_position, 3)
            screen.widget.keypress(size, "enter")
            self.assertEqual(screen.frame.focus_position, "footer")
            self.assertEqual(screen.buttons.focus_position, 3)
            self.assertIn("Page 2/2", visible(screen, size))

    def test_compare_shared_findings_and_different_scope(self):
        fixture_report(self.base.name, COMPLETED, completed=True, results=[
            ("V-244531", "FAIL", "UNCHANGED"), ("V-230264", "NEEDS_REVIEW", "MANUAL_REQUIRED"),
            ("V-230385", "PASS", "UNCHANGED"),
        ])
        fixture_report(self.base.name, INCOMPLETE, completed=True, results=[
            ("V-244531", "PASS", "APPLIED"), ("V-230264", "NEEDS_REVIEW", "MANUAL_REQUIRED"),
            ("V-230390", "NEEDS_REVIEW", "PENDING_ACTIVATION"),
        ])
        result = history._history_compare(self.base.name, INCOMPLETE, COMPLETED)
        self.assertEqual(result["earlier"], COMPLETED)
        self.assertEqual(result["later"], INCOMPLETE)
        self.assertEqual(result["changed"], [("V-244531", ("FAIL", "UNCHANGED"), ("PASS", "APPLIED"))])
        self.assertEqual([item[0] for item in result["unchanged"]], ["V-230264"])
        self.assertEqual(result["only_earlier"], ["V-230385"])
        self.assertEqual(result["only_later"], ["V-230390"])
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(screen.runs[0])
        screen.start_comparison()
        screen.widget.keypress((75, 24), "enter")
        self.assertIn("1 changed | 1 unchanged | 1 earlier only | 1 later only", visible(screen))
        self.assertIn("V-244531  FAIL / UNCHANGED  to  PASS / APPLIED", visible(screen))
        self.assertNotIn("V-230264", visible(screen))
        screen.toggle_unchanged()
        self.assertIn("V-230264", visible(screen))

    def test_compare_with_an_older_run_id_and_preserve_it_on_return(self):
        size = (75, 24)
        fixture_report(self.base.name, COMPLETED, completed=True,
                       results=[("V-244531", "FAIL", "UNCHANGED")])
        fixture_report(self.base.name, INCOMPLETE, completed=True,
                       results=[("V-244531", "PASS", "APPLIED")])
        with mock.patch.object(history, "_HISTORY_PAGE_SIZE", 1):
            screen = history.RunHistory(self.base.name, lambda: None)
            screen.open_run(screen.runs[0])
            screen.start_comparison()
            self.assertEqual(screen.frame.focus_position, "footer")
            self.assertIn("No other compatible runs on this page", visible(screen))
            screen.widget.keypress(size, "/")
            screen.entry.set_edit_text("../../run.log")
            screen.widget.keypress(size, "enter")
            self.assertIn("Enter a full saved run ID", visible(screen))
            self.assertEqual(screen.frame.focus_position, "header")
            screen.entry.set_edit_text(COMPLETED)
            screen.widget.keypress(size, "enter")
            self.assertIn("V-244531  FAIL / UNCHANGED  to  PASS / APPLIED", visible(screen))
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.entry.edit_text, COMPLETED)
            self.assertEqual(screen.frame.focus_position, "header")
            screen.widget.keypress(size, "esc")
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.focused_run(), INCOMPLETE)

    def test_compare_browses_older_pages_without_requiring_an_exact_id(self):
        size = (48, 12)
        fixture_report(self.base.name, COMPLETED, completed=True,
                       results=[("V-244531", "FAIL", "UNCHANGED")])
        fixture_report(self.base.name, INCOMPLETE, completed=True, host="4" * 64,
                       results=[("V-244531", "PASS", "APPLIED")])
        fixture_report(self.base.name, BAD_DIGEST, completed=True,
                       results=[("V-244531", "PASS", "APPLIED")])
        with mock.patch.object(history, "_HISTORY_PAGE_SIZE", 1), mock.patch.object(
                history, "_history_metadata", wraps=history._history_metadata) as read_metadata:
            screen = history.RunHistory(self.base.name, lambda: None)
            screen.open_run(screen.runs[0])
            screen.start_comparison()
            self.assertIn("0 candidates  |  Page 1/3", visible(screen, size))
            self.assertEqual(read_metadata.call_count, 1)
            screen.widget.keypress(size, "]")
            self.assertIn("0 candidates  |  Page 2/3", visible(screen, size))
            self.assertNotIn(INCOMPLETE, visible(screen, size))
            screen.widget.keypress(size, "enter")
            self.assertIn("1 candidate  |  Page 3/3", visible(screen, size))
            self.assertIn(COMPLETED, visible(screen, size))
            self.assertEqual(read_metadata.call_count, 3)
            screen.widget.keypress(size, "/")
            screen.widget.keypress(size, "tab")
            screen.widget.keypress(size, "enter")
            self.assertEqual(screen.comparison["earlier"], COMPLETED)
            self.assertEqual(screen.comparison["later"], BAD_DIGEST)
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.frame.focus_position, "body")
            self.assertIn("1 candidate  |  Page 3/3", visible(screen, size))
            screen.widget.keypress(size, "esc")
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.focused_run(), BAD_DIGEST)
            self.assertIn("Page 1/3", visible(screen, size))

    def test_comparison_rejects_mismatches_missing_and_interrupted(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        fixture_report(self.base.name, COMPLETED, completed=True, results=sample)
        fixture_report(self.base.name, INCOMPLETE, completed=True, results=sample, host="4" * 64)
        fixture_report(self.base.name, BAD_DIGEST, completed=True, results=sample, archive="5" * 64)
        fixture_report(self.base.name, INTERRUPTED, completed=True, results=sample, interrupted=True)
        fixture_report(self.base.name, UNSAFE, completed=True)
        for other, error in (
            (INCOMPLETE, "different host fingerprints"),
            (BAD_DIGEST, "different STIG benchmark archives"),
            (INTERRUPTED, "interrupted"),
            (UNSAFE, "no results.json"),
        ):
            with self.assertRaisesRegex(ValueError, error):
                history._history_compare(self.base.name, COMPLETED, other)
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(next(run for run in screen.runs if run["id"] == COMPLETED))
        screen.start_comparison()
        self.assertIn("No other compatible runs", visible(screen))
        for run_id in (INCOMPLETE, BAD_DIGEST, INTERRUPTED, UNSAFE):
            self.assertNotIn(run_id, visible(screen))

    def test_comparison_requires_a_checksum_but_a_partial_run_can_still_be_inspected(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        fixture_report(self.base.name, COMPLETED, completed=True, results=sample)
        report = fixture_report(self.base.name, INCOMPLETE, completed=True, results=sample)
        os.unlink(os.path.join(report, "manifest.sha256"))
        indexed = history.RunHistory(self.base.name, lambda: None)
        indexed.open_run(indexed.runs[0])
        self.assertEqual(indexed.selected["id"], INCOMPLETE)
        self.assertIn("Manifest checksum missing.", visible(indexed))
        indexed.start_comparison()
        self.assertIn("missing its manifest checksum.", visible(indexed))
        with self.assertRaisesRegex(ValueError, "missing its manifest checksum"):
            history._history_compare(self.base.name, COMPLETED, INCOMPLETE)

    def test_comparison_checks_json_shape_and_scope_when_a_candidate_is_chosen(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        fixture_report(self.base.name, COMPLETED, completed=True, results=sample)
        report = fixture_report(self.base.name, INCOMPLETE, completed=True, results=sample)
        path = os.path.join(report, "results.json")
        with open(path, encoding="utf-8") as stream:
            good = stream.read()
        for payload, error in (
            (good.replace('"run_id":', '"run_id": "ambiguous", "run_id":', 1),
             "does not contain readable structured results"),
            (good.replace("V-244531", "V-230264"), "do not match the manifest scope"),
            ("[", "does not contain readable structured results"),
        ):
            write_private(path, payload)
            with self.assertRaisesRegex(ValueError, error):
                history._history_compare(self.base.name, COMPLETED, INCOMPLETE)
        screen = history.RunHistory(self.base.name, lambda: None)
        screen.open_run(screen.runs[-1])
        screen.start_comparison()
        self.assertIn("1 candidate", visible(screen))
        screen.widget.keypress((75, 24), "enter")
        self.assertIn("does not contain readable structured results", visible(screen))
        self.assertEqual(screen.page, "compare")

    def test_comparison_distinguishes_actual_assessments_actions_and_explicit_skips(self):
        fixture_report(self.base.name, COMPLETED, completed=True, mode="status", results=[
            ("V-244531", "PASS", "UNCHANGED"), ("V-230264", "FAIL", "UNCHANGED"),
            ("V-230390", "PASS", "UNCHANGED"),
        ])
        fixture_report(self.base.name, INCOMPLETE, completed=True, mode="apply",
                       excluded=("V-230390",), results=[
                           ("V-244531", "PASS", "APPLIED"), ("V-230264", "FAIL", "SKIPPED"),
                           ("V-230390", "UNKNOWN", "SKIPPED"),
                       ])
        fixture_report(self.base.name, UNSAFE, completed=True, mode="diff", results=[
            ("V-244531", "PASS", "UNCHANGED"), ("V-230264", "PASS", "UNCHANGED"),
            ("V-230390", "PASS", "UNCHANGED"),
        ])
        apply = history._history_compare(self.base.name, COMPLETED, INCOMPLETE)
        self.assertEqual((apply["earlier_mode"], apply["later_mode"]), ("status", "apply"))
        self.assertEqual((apply["assessment_changes"], apply["action_only_changes"]), (0, 2))
        self.assertEqual(apply["only_earlier"], ["V-230390"])
        self.assertEqual(apply["excluded_later"], ["V-230390"])
        diff = history._history_compare(self.base.name, INCOMPLETE, UNSAFE)
        self.assertEqual((diff["earlier_mode"], diff["later_mode"]), ("apply", "diff"))
        self.assertEqual((diff["assessment_changes"], diff["action_only_changes"]), (1, 1))
        self.assertEqual(diff["only_later"], ["V-230390"])
        self.assertEqual(diff["excluded_earlier"], ["V-230390"])

    def test_report_completion_error_and_interruption_are_distinct(self):
        fixture_report(self.base.name, COMPLETED, completed=True, resolved=True, log_error=True)
        fixture_report(self.base.name, INCOMPLETE, completed=True,
                       results=[("V-244531", "PASS", "FAILED")])
        report = fixture_report(self.base.name, INTERRUPTED, completed=True)
        with open(os.path.join(report, "summary.txt"), "a", encoding="utf-8") as stream:
            stream.write(history._HISTORY_INTERRUPTED_SUMMARY + "\n")
        os.unlink(os.path.join(report, "run.log"))
        screen = history.RunHistory(self.base.name, lambda: None)
        by_id = {run["id"]: run for run in screen.runs}
        self.assertEqual(by_id[INTERRUPTED]["state"], "Interrupted")
        self.assertEqual(by_id[COMPLETED]["state"], "Completed")
        self.assertEqual(by_id[INCOMPLETE]["state"], "Completed")
        screen.toggle_follow_up()
        self.assertIn(COMPLETED, [run["id"] for run in screen.matching])
        screen.open_run(by_id[COMPLETED])
        self.assertIn("The run log records errors.", visible(screen))
        screen.open_run(by_id[INCOMPLETE])
        self.assertIn("The saved summary records finding or action errors.", visible(screen))

    def test_direct_recheck_keeps_same_second_pair_order_and_reopens_read_only(self):
        original = "20261120T180000Z.ZZZZZZZZ"
        recheck = "20261120T180000Z.AAAAAAAA"
        fixture_report(self.base.name, original, completed=True, results=[("V-244531", "FAIL", "UNCHANGED")])
        fixture_report(self.base.name, recheck, completed=True, mode="status",
                       results=[("V-244531", "PASS", "UNCHANGED")])
        closed = []
        screen = history.RunHistory(self.base.name, lambda: closed.append(True), index_runs=False)
        for _ in range(2):
            screen.open_recheck_comparison(original, recheck)
            self.assertIn("V-244531  FAIL / UNCHANGED  to  PASS / UNCHANGED", visible(screen))
            self.assertEqual(screen.comparison["earlier"], original)
            self.assertEqual(screen.comparison["later"], recheck)
            screen.widget.keypress((75, 24), "esc")
        self.assertEqual(closed, [True, True])
        historical = history._history_compare(self.base.name, original, recheck)
        self.assertEqual(historical["earlier"], recheck)

    def test_direct_recheck_verifies_status_build_and_assessed_or_excluded_scope(self):
        sample = [("V-244531", "FAIL", "UNCHANGED"), ("V-230264", "UNKNOWN", "SKIPPED")]
        fixture_report(self.base.name, COMPLETED, completed=True, results=sample, excluded=("V-230264",))
        fixture_report(self.base.name, INCOMPLETE, completed=True, results=sample, mode="diff",
                       excluded=("V-230264",))
        fixture_report(self.base.name, UNSAFE, completed=True, results=sample, mode="status",
                       script="7" * 64, excluded=("V-230264",))
        fixture_report(self.base.name, BAD_DIGEST, completed=True, results=sample, mode="status")
        fixture_report(self.base.name, INTERRUPTED, completed=True, mode="status",
                       results=[("V-244531", "PASS", "UNCHANGED"), ("V-230390", "UNKNOWN", "SKIPPED")],
                       excluded=("V-230390",))
        screen = history.RunHistory(self.base.name, lambda: None, index_runs=False)
        for other, message in (
            (INCOMPLETE, "must be a Status report"),
            (UNSAFE, "different script digests"),
            (BAD_DIGEST, "different assessed or excluded scopes"),
            (INTERRUPTED, "different assessed or excluded scopes"),
        ):
            with self.subTest(other=other):
                screen.open_recheck_comparison(COMPLETED, other)
                self.assertIn(message, visible(screen))
                self.assertIsNone(screen.comparison)
                self.assertIn("Saved reports", visible(screen))
                self.assertIn("changed", history._history_compare(self.base.name, COMPLETED, other))

    def test_missing_recheck_shows_unavailable_and_back(self):
        fixture_report(self.base.name, COMPLETED, completed=True,
                       results=[("V-244531", "FAIL", "UNCHANGED")])
        back = []
        screen = history.RunHistory(self.base.name, lambda: back.append(True), index_runs=False)
        screen.open_recheck_comparison(COMPLETED, INCOMPLETE)
        self.assertEqual(screen.page, "comparison unavailable")
        self.assertIsNone(screen.comparison)
        text = visible(screen)
        self.assertIn("Saved reports", text)
        self.assertIn("One of these protected saved reports is unavailable.", text)
        self.assertNotIn("Recheck remains saved", text)
        screen.widget.keypress((75, 24), "esc")
        self.assertEqual(back, [True])

    def test_compare_keeps_assessment_changes_with_unrecognized_actions(self):
        fixture_report(self.base.name, COMPLETED, completed=True, results=[
            ("V-230224", "FAIL", "LEGACY_QUEUED"), ("V-230264", "FAIL", "UNCHANGED"),
            ("V-244531", "FAIL", "UNCHANGED"), ("V-244532", "PASS", "UNCHANGED"),
            ("V-244533", "PASS", "FUTURE_PENDING"),
        ])
        fixture_report(self.base.name, INCOMPLETE, completed=True, mode="status", results=[
            ("V-230224", "FAIL", "UNCHANGED"), ("V-230264", "PASS", "FUTURE_APPLIED"),
            ("V-244531", "FAIL", "BLOCKED"), ("V-244532", "PASS", "UNCHANGED"),
            ("V-244533", "PASS", "FUTURE_PENDING"),
        ])
        screen = history.RunHistory(self.base.name, lambda: None, index_runs=False)
        screen.open_recheck_comparison(COMPLETED, INCOMPLETE)
        result = screen.comparison
        self.assertEqual((result["assessment_changes"], result["action_only_changes"]), (1, 1))
        self.assertEqual([row[0] for row in result["changed"]], ["V-230264", "V-244531"])
        self.assertEqual([row[0] for row in result["unchanged"]], ["V-244532"])
        self.assertEqual([row[0] for row in result["uncompared_actions"]], ["V-230224", "V-244533"])
        text = visible(screen, (130, 34))
        self.assertIn("Action comparison unavailable for 3 shared findings.", text)
        self.assertIn("V-230264  FAIL / UNCHANGED  to  PASS / Unrecognized action (FUTURE_APPLIED)", text)
        self.assertIn("V-230224  FAIL / Unrecognized action (LEGACY_QUEUED)  to  FAIL / UNCHANGED", text)

    def test_direct_recheck_refuses_an_unsafe_or_interrupted_saved_report(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        fixture_report(self.base.name, COMPLETED, completed=True, results=sample)
        fixture_report(self.base.name, INTERRUPTED, completed=True, interrupted=True, mode="status",
                       results=sample)
        path = fixture_report(self.base.name, UNSAFE, completed=True, mode="status", results=sample)
        results = os.path.join(path, "results.json")
        os.unlink(results)
        os.symlink("summary.txt", results)
        screen = history.RunHistory(self.base.name, lambda: None, index_runs=False)
        screen.open_recheck_comparison(COMPLETED, INTERRUPTED)
        self.assertIn("is interrupted", visible(screen))
        screen.open_recheck_comparison(COMPLETED, UNSAFE)
        self.assertIn("The artifact is not a protected regular file.", visible(screen))
        self.assertIsNone(screen.comparison)

    def test_saved_recheck_compares_and_opens_original_outside_the_index_page(self):
        original = "20261120T180000Z.ZZZZZZZZ"
        recheck = "20261120T180000Z.AAAAAAAA"
        fixture_report(self.base.name, original, completed=True, results=[("V-244531", "FAIL", "UNCHANGED")])
        fixture_report(self.base.name, recheck, completed=True, related=original, mode="status",
                       ticket="CHG-RECHECK", results=[("V-244531", "PASS", "UNCHANGED")])
        size = (75, 24)
        with mock.patch.object(history, "_HISTORY_PAGE_SIZE", 1):
            screen = history.RunHistory(self.base.name, lambda: None)
            screen.widget.keypress(size, "]")
            self.assertEqual([run["id"] for run in screen.runs], [recheck])
            screen.widget.keypress(size, "/")
            screen.entry.set_edit_text("CHG-RECHECK")
            screen.widget.keypress(size, "enter")
            screen.widget.keypress(size, "enter")
            self.assertIn("Related run " + original, visible(screen))
            self.assertIn("Open related run", visible(screen))
            screen.widget.keypress(size, "up")
            screen.widget.keypress(size, "enter")
            self.assertIn("V-244531  FAIL / UNCHANGED  to  PASS / UNCHANGED", visible(screen))
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.walker[screen.walker.focus].original_widget.get_label(),
                             "Compare with original")
            screen.widget.keypress(size, "up")
            screen.widget.keypress(size, "enter")
            self.assertEqual(screen.selected["id"], original)
            screen.open_artifact("run.log")
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.walker[screen.walker.focus].original_widget.get_label(), "Run log (run.log)")
            screen.widget.keypress(size, "esc")
            self.assertEqual(screen.selected["id"], recheck)
            self.assertEqual(screen.walker[screen.walker.focus].original_widget.get_label(), "Open related run")
            screen.widget.keypress(size, "esc")
            self.assertEqual((screen.index_page, screen.search, screen.focused_run()), (1, "CHG-RECHECK", recheck))

    def test_saved_related_lookup_checks_missing_mismatched_and_interrupted_reports(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        fixture_report(self.base.name, COMPLETED, completed=True, interrupted=True, results=sample)
        fixture_report(self.base.name, INCOMPLETE, completed=True, mode="status",
                       related=COMPLETED, results=sample)
        fixture_report(self.base.name, BAD_DIGEST, completed=True, mode="rollback",
                       host="5" * 64, related=COMPLETED, results=sample)
        fixture_report(self.base.name, INTERRUPTED, completed=True, mode="status",
                       related=UNSAFE, results=sample)
        screen = history.RunHistory(self.base.name, lambda: None)
        records = {run["id"]: run for run in screen.runs}
        screen.open_run(records[BAD_DIGEST])
        self.assertNotIn("Compare with original", visible(screen))
        screen.open_related()
        self.assertIn("different host, benchmark archive or script", visible(screen))
        screen.open_run(records[INTERRUPTED])
        screen.open_related()
        self.assertIn("The related run is unavailable in this report directory.", visible(screen))
        screen.open_run(records[INCOMPLETE])
        screen.open_related()
        self.assertEqual(screen.selected["state"], "Interrupted")
        screen.back()
        screen.compare_with_original()
        self.assertIn("is interrupted", visible(screen))
        self.assertIsNone(screen.comparison)

    def test_related_ids_must_be_valid_unique_header_values(self):
        sample = [("V-244531", "FAIL", "UNCHANGED")]
        body_only = fixture_report(self.base.name, COMPLETED, completed=True, results=sample)
        with open(os.path.join(body_only, "summary.txt"), "a", encoding="utf-8") as stream:
            stream.write("Related run " + INCOMPLETE + "\n")
        fixture_report(self.base.name, INCOMPLETE, completed=True, related=INCOMPLETE, results=sample)
        fixture_report(self.base.name, INTERRUPTED, completed=True, related="../" + INCOMPLETE, results=sample)
        fixture_report(self.base.name, BAD_DIGEST, completed=True,
                       related=COMPLETED + "\nRelated run " + INCOMPLETE, results=sample)
        screen = history.RunHistory(self.base.name, lambda: None)
        self.assertTrue(all(not run["related"] for run in screen.runs))


if __name__ == "__main__":
    unittest.main()
