"""Exercise resolution navigation and explicit operator inputs without changing a host."""

import unittest

from workbench import Workbench


SCREEN = (100, 28)
TIME = "V-230484"
SSH = "V-272482"
INTEGRITY = "V-251710"
RELATED = "V-288829"
CONTEXT = dict(mode="apply", can_apply=True, assessed=True)
TIME_FIELD = {"key": "approved-time-source", "label": "Approved time source",
              "prompt": "Enter the authoritative source approved for this host.", "value": ""}
NOTE_FIELD = {"key": "evidence-note", "label": "Record evidence",
              "prompt": "Enter your evidence reference.", "value": ""}


def row(finding, selected=True):
    return dict(id=finding, title="Synthetic finding " + finding, selected=selected,
                risk="high", result="FAIL", outcome="BLOCKED", handling="Blocked")


class ResolutionWorkbenchTests(unittest.TestCase):
    def setUp(self):
        self.commands = []
        self.ui = Workbench(lambda *fields: self.commands.append(fields))
        self.ui.resize(*SCREEN)
        self.ui.initialized = True
        self.ui.handle_event(dict(type="state", context=CONTEXT,
                                  rows=[row(TIME), row(SSH), row(INTEGRITY, selected=False)],
                                  reset_selection=True))

    def screen(self):
        return b"\n".join(self.ui.widget.render(SCREEN, True).text).decode("utf-8", "replace")

    @staticmethod
    def press_button(contents, label):
        button, = (entry.base_widget for entry in contents
                   if hasattr(entry.base_widget, "get_label") and entry.base_widget.get_label() == label)
        button.keypress((36,), "enter")

    def footer_buttons(self, frame=None):
        frame = frame or self.ui.base_frame
        return [entry for entry, _ in frame.footer.contents[0][0].contents]

    def resolution(self, finding, inputs=()):
        event = dict(type="resolution", id=finding, title="Synthetic policy",
                     text="OBSERVED EVIDENCE\nThe source is missing.\n\n"
                          "VERIFICATION\nCheck persistent configuration and live state.",
                     inputs=list(inputs))
        self.ui.handle_event(event)

    def test_details_routes_to_resolution_and_back_preserves_page(self):
        self.ui.details(TIME)
        self.ui.handle_event(dict(type="detail", id=TIME, text="Synthetic details"))
        self.press_button(self.footer_buttons(), "Resolve")
        self.assertEqual(self.commands[-1], ("resolve", TIME))
        self.resolution(TIME, [TIME_FIELD])
        self.assertIn("The source is missing.", self.screen())
        self.assertIn("Check persistent configuration and live state.", self.screen())
        self.ui.unhandled_input("esc")
        self.assertEqual(self.ui.page, "details")
        self.assertEqual(self.ui.selected, {TIME, SSH})
        self.assertEqual(self.commands, [("detail", TIME), ("resolve", TIME)])

    def test_shared_ssh_review_displays_related_findings_and_starts_one_approval(self):
        leader = "V-230251"
        self.ui.focus_id = SSH
        self.ui.rows[SSH]["ssh_shared"] = True
        self.ui.open_actions()
        self.assertIn("Review SSH change for " + SSH, self.screen())
        self.ui.close_modal()
        self.ui.review_focused()
        reviewed = [dict(row(leader, selected=False), scope_added=True, operation=True),
                    dict(row(SSH), linked=leader),
                    dict(row(RELATED, selected=False), scope_added=True)]
        self.ui.handle_event(dict(type="review", rows=reviewed, focused=SSH, text="Synthetic preview",
                                  token="plan-token", ssh_single=True))
        self.assertIn("Related findings included automatically", self.screen())
        self.assertIn(leader, self.screen())
        self.assertIn(RELATED, self.screen())
        self.ui.open_review_index(False)
        self.ui.show_review_item(reviewed[0])
        self.press_button(self.footer_buttons(), "Resolve")
        self.resolution(leader, [NOTE_FIELD])
        self.assertEqual(self.ui.resolution_selection(), SSH)
        self.ui.close_resolution()
        self.ui.return_to_review_index()
        self.ui.close_review_index()
        self.press_button(self.footer_buttons(), "Start approval")
        self.assertIsNone(self.ui.modal)
        self.assertEqual(self.commands, [("review", SSH, SSH), ("resolve", leader), ("accept", "plan-token")])
        self.assertEqual(self.ui.selected, {TIME, SSH})

    def test_input_preserves_entered_value_after_backend_error(self):
        self.ui.open_resolution(TIME)
        self.resolution(TIME, [TIME_FIELD])
        self.ui.edit_resolution_input(TIME, TIME_FIELD, "ntp.example.org")
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertIn("Use this input to build a fresh plan", self.screen())
        self.assertEqual(self.commands, [("resolve", TIME)])
        self.ui.widget.keypress(SCREEN, "shift tab")
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertEqual(self.commands[-1], ("resolve-input", TIME, "approved-time-source",
                                             "ntp.example.org", TIME + "," + SSH))
        self.ui.handle_event(dict(type="error", message="Synthetic validation error"))
        self.assertIn("ntp.example.org", self.screen())
        self.assertIn("Synthetic validation error", self.screen())

    def test_evidence_acknowledgment_keeps_original_navigation(self):
        self.ui.open_resolution(INTEGRITY)
        self.resolution(INTEGRITY, [NOTE_FIELD])
        self.ui.edit_resolution_input(INTEGRITY, NOTE_FIELD, "Reviewed the approved baseline.")
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertIn("Record this evidence note", self.screen())
        self.ui.widget.keypress(SCREEN, "shift tab")
        self.ui.widget.keypress(SCREEN, "enter")
        self.assertEqual(self.commands[-1], ("resolve-input", INTEGRITY, "evidence-note",
                                             "Reviewed the approved baseline.", TIME + "," + SSH))
        self.resolution(INTEGRITY, [dict(NOTE_FIELD, value="Reviewed the approved baseline.")])
        self.assertIn("Evidence note recorded.", self.screen())
        self.ui.unhandled_input("esc")
        self.assertEqual(self.ui.page, "findings")
        self.assertEqual(self.ui.selected, {TIME, SSH})
