"""Exercise the return to an assessed Findings list without a new scan."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from runtime import decode_workbench_event
from workbench import Workbench


FIRST, SECOND, THIRD = "V-230245", "V-230247", "V-230248"
ROOT = Path(__file__).resolve().parents[2]
BACKEND = r"""
set -eo pipefail
source "$1/src/classic/rhel8-stig.sh"
source "$1/src/urwid/bridge.sh"
source "$1/src/urwid/hooks.sh"
init_options
register_rules
parse_args --apply --only V-230245,V-230247,V-230248
tui_seed_scope
declare -A TUI_ALLOWED=()
declare -a URWID_BROWSE_SCOPE=()
declare -A URWID_BROWSE_DATA=()
tui_index
RUN_DIR=$2 SCRIPT_HASH=fixture
URWID_ASSESSED=0 URWID_REVIEW_TOKEN='' URWID_REVIEW_SEQ=0
URWID_RISK_CAP=$MAX_RISK URWID_DEFER_CAP=$DEFER
fixture_fail_review=''

assess_one() {
    local id=$1
    printf '%s\n' "$id" >> "$RUN_DIR/checked"
    [[ $id != "$fixture_fail_review" ]] || return 1
    BEFORE[$id]=FAIL AFTER[$id]=FAIL ACTIONS[$id]=UNCHANGED
    DETAIL[$id]="Fixture evidence $(wc -l < "$RUN_DIR/checked") for $id"
    PREVIEW_KEY[$id]="fixture-plan-$id"
}
verify_script() { return 0; }

urwid_dispatch scan
urwid_dispatch detail V-230247
urwid_dispatch review V-230245 V-230245 || exit $?
stale_token=$URWID_REVIEW_TOKEN
urwid_dispatch back
urwid_dispatch detail V-230247
urwid_dispatch accept "$stale_token"
fixture_fail_review=V-230248
urwid_dispatch review V-230248 V-230248 || exit $?
fixture_fail_review=''
urwid_dispatch detail V-230247
urwid_dispatch scan
urwid_dispatch review V-230245 V-230245 || exit $?
status=0
urwid_dispatch accept "$URWID_REVIEW_TOKEN" || status=$?
[[ $status == 3 && ${SCOPE[*]} == V-230245 ]]
"""


class FindingsNavigationTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.workbench = Workbench(lambda *fields: self.requests.append(fields))
        self.rows = [dict(id=finding, title=title, cat="II", result="FAIL",
                          area=area, selected=finding != FIRST, evidence="Browse evidence")
                     for finding, title, area in (
                         (FIRST, "Log permissions", "Logging"),
                         (SECOND, "Log group", "Logging"),
                         (THIRD, "Directory permissions", "Storage"))]
        self.workbench.initialized = True
        self.workbench.handle_event(dict(type="state", rows=self.rows, reset_selection=True,
                                         context=dict(assessed=True, can_apply=True, mode="apply")))
        self.workbench.search.set_edit_text("log")
        self.workbench.filters["area"] = "Logging"
        self.workbench.sort_descending = True
        self.workbench.refresh_findings()
        self.workbench.finding_list.set_focus(0)
        self.workbench.update_focus()
        self.assertEqual(self.workbench.focus_id, SECOND)

    def click_back(self):
        button = self.workbench.base_frame.footer.contents[0][0].contents[0][0].base_widget
        self.assertEqual(button.get_label(), "Back")
        self.assertTrue(button.mouse_event((10,), "mouse press", 1, 4, 0, True))

    def show_review(self):
        self.workbench.handle_event(dict(type="review", rows=[self.rows[1]], focused=SECOND,
                                         text="Fixture review", token="fixture-token"))

    def accept_back_event(self):
        self.assertEqual(self.requests[-1], ("back",))
        self.workbench.handle_event(decode_workbench_event(b'{"type":"browse"}'))

    def assert_findings_preserved(self):
        self.assertEqual(self.workbench.page, "findings")
        self.assertIsNone(self.workbench.review)
        self.assertEqual(list(self.workbench.rows.values()), self.rows)
        self.assertEqual(self.workbench.focus_id, SECOND)
        self.assertEqual(self.workbench.query, "log")
        self.assertEqual(self.workbench.filters["area"], "Logging")
        self.assertTrue(self.workbench.sort_descending)
        self.assertEqual(self.workbench.visible, [SECOND, FIRST])
        self.assertEqual(self.workbench.selected, {SECOND, THIRD})

    def test_enter_to_details_and_click_back_keeps_findings(self):
        self.workbench.finding_widget(SECOND).keypress((65,), "enter")
        self.assertEqual(self.requests, [("detail", SECOND)])
        self.workbench.handle_event(dict(type="detail", id=SECOND, text="Fixture details"))
        self.click_back()
        self.assert_findings_preserved()
        self.assertEqual(self.requests, [("detail", SECOND)])

    def test_diff_back_retains_findings_and_f8_is_an_explicit_scan(self):
        self.workbench.preview_finding_diff()
        self.show_review()
        self.click_back()
        self.accept_back_event()
        self.assert_findings_preserved()
        self.assertEqual(self.requests, [("review", SECOND, SECOND), ("back",)])
        self.workbench.unhandled_input("f8")
        self.assertEqual(self.requests[-1], ("scan",))

    def test_escape_from_plan_and_unchanged_settings_do_not_scan(self):
        for leave in ("escape", "settings"):
            with self.subTest(leave=leave):
                self.requests.clear()
                self.workbench.review_focused()
                self.show_review()
                if leave == "settings":
                    self.workbench.unhandled_input("f7")
                    self.workbench.open_findings_from_settings()
                else:
                    self.workbench.unhandled_input("esc")
                self.accept_back_event()
                self.assert_findings_preserved()
                self.assertEqual(self.requests, [("review", SECOND, SECOND), ("back",)])

    def test_changing_a_run_setting_still_requests_fresh_assessment(self):
        self.workbench.review_focused()
        self.show_review()
        self.workbench.unhandled_input("f7")
        self.workbench.setting_fields["format"].advance(1)
        self.workbench.open_findings_from_settings()
        self.assertEqual(self.requests[-1][0], "settings")
        self.assertEqual(self.requests[-1][1:], tuple(self.workbench.settings_values()))


class FindingsBridgeTests(unittest.TestCase):
    def test_back_restores_original_evidence_and_disarms_the_review(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", "--noprofile", "--norc", "-p", "-c", BACKEND,
                                     "findings-fixture", str(ROOT), directory],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    universal_newlines=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            checked = Path(directory, "checked").read_text().splitlines()
        events = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual([event["type"] for event in events],
                         ["state", "detail", "review", "browse", "detail", "error",
                          "error", "detail", "state", "review", "accepted"])
        self.assertEqual(events[1]["text"], events[4]["text"])
        self.assertEqual(events[1]["text"], events[7]["text"])
        self.assertIn("Fixture evidence 2", events[4]["text"])
        self.assertEqual([row["id"] for row in events[2]["rows"]], [FIRST])
        self.assertIn("Fixture evidence 4", events[2]["rows"][0]["evidence"])
        self.assertEqual([row["id"] for row in events[8]["rows"]], [FIRST, SECOND, THIRD])
        self.assertEqual(checked, [FIRST, SECOND, THIRD, FIRST, THIRD, FIRST, SECOND, THIRD, FIRST])
