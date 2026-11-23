"""Exercise the selected implementation scope and its attended approval entry point."""

import unittest

from workbench import Workbench


SCREEN = (115, 32)
APPLY_CONTEXT = {"mode": "apply", "can_apply": True, "scope_count": 22}


def row(number, **fields):
    finding = dict(id="V-{}".format(number), title="Synthetic finding", selected=True,
                   risk="medium", result="FAIL", outcome="UNCHANGED",
                   handling="Automatic", operation=False, ready=False)
    finding.update(fields)
    return finding


class BatchWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.commands = []
        self.ui = Workbench(lambda *fields: self.commands.append(fields))
        self.ui.resize(*SCREEN)

    def view_text(self, size=SCREEN):
        return b"\n".join(self.ui.widget.render(size, True).text).decode("utf-8", "replace")

    def assessed(self, rows):
        self.ui.initialized = True
        self.ui.handle_event(dict(type="state", context=dict(APPLY_CONTEXT, assessed=True),
                                  rows=rows, reset_selection=True))

    def review(self, rows):
        self.ui.handle_event(dict(type="review", rows=rows, focused="",
                                  token="fixture-token", text="Full review preview"))

    def test_batch_action_requests_all_22_selected_ids(self):
        findings = [row(number) for number in range(230224, 230246)]
        self.assessed(findings)
        self.ui.search.set_edit_text("230224")
        self.ui.open_actions()
        contents = self.view_text()
        self.assertIn("Implement selected (22)", contents)
        self.assertIn("Implement only V-230224 (F6)", contents)
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertEqual(self.commands, [("review", ",".join(finding["id"] for finding in findings), "")])

    def test_review_lists_what_can_be_approved_and_what_needs_follow_up(self):
        findings = [
            row(230224, ready=True, operation=True),
            row(230225, ready=True, linked="V-230224"),
            row(230226, handling="Manual", outcome="MANUAL_REQUIRED"),
            row(230227, outcome="BLOCKED", handling="Blocked"),
            row(230228, outcome="PENDING_ACTIVATION", handling="Blocked"),
            row(230229, result="PASS"),
            row(230230, result="NOT_APPLICABLE"),
            row(230231, outcome="SKIPPED"),
            row(230232, result="ERROR", handling="Blocked"),
        ]
        self.assessed(findings)
        self.review(findings)
        contents = self.view_text()
        for label, finding in zip(("READY FOR APPROVAL", "INCLUDED IN ANOTHER APPROVAL",
                                   "MANUAL WORK OR EVIDENCE", "BLOCKED", "PENDING ACTIVATION",
                                   "ALREADY COMPLIANT", "NOT APPLICABLE", "SKIPPED",
                                   "ASSESSMENT ERRORS"), findings):
            self.assertIn("{} (1)".format(label), contents)
            self.assertIn(finding["id"], contents)
        self.assertIn("Start approvals", contents)
        self.ui.resize(56, 18)
        self.assertIn("Start approvals", self.view_text((56, 18)))

    def test_confirmation_defaults_to_back_and_passes_the_reviewed_token(self):
        findings = [row(230224, ready=True, operation=True)]
        self.assessed(findings)
        self.review(findings)
        self.ui.confirm_review()
        self.assertIn("Back is selected by default.", self.view_text())
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertIsNone(self.ui.modal)
        self.assertEqual(self.commands, [])
        self.ui.confirm_review()
        self.ui.widget.keypress(SCREEN, "shift tab")
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertEqual(self.commands, [("accept", "fixture-token")])

    def test_explicit_apply_scope_opens_findings_after_read_only_scan(self):
        self.ui.handle_event(dict(type="state", rows=[], context=dict(
            APPLY_CONTEXT, assessed=False, assess_selected_on_open=True)))
        self.assertEqual(self.commands, [("scan",)])
        self.assertIn("Assessing selected findings", self.view_text())
        self.ui.handle_event(dict(type="progress", id="V-230224", complete=1, count=22))
        self.assertIn("1 of 22 checked", self.view_text())
        findings = [row(number) for number in range(230224, 230246)]
        self.ui.handle_event(dict(type="state", context=dict(APPLY_CONTEXT, assessed=True),
                                  rows=findings, reset_selection=True))
        self.assertEqual(self.ui.page, "findings")
        self.assertEqual(self.ui.selected, {finding["id"] for finding in findings})
        self.assertEqual(self.commands, [("scan",)])

    def test_initial_scan_error_leaves_settings_available(self):
        self.ui.handle_event(dict(type="state", rows=[], context=dict(
            APPLY_CONTEXT, assessed=False, assess_selected_on_open=True)))
        self.ui.handle_event(dict(type="error", message="Synthetic scan failure."))
        self.assertEqual(self.ui.page, "settings")
        self.assertIn("Synthetic scan failure.", self.view_text())
        self.ui.modal["escape"]()
        self.assertIsNone(self.ui.modal)
        self.assertIn("Exit", self.view_text())
        self.assertEqual(self.commands, [("scan",)])
