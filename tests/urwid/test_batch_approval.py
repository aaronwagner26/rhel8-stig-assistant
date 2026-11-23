"""Exercise each attended decision without running a host transaction."""

import unittest

import urwid

from attended import _AttendedPrompt


def fixture_prompt(**options):
    request = dict(kind="approval", id="V-288831", title="Example audit activity",
                   risk="medium", position=4, total=22, allow_all=False,
                   plan="/etc/audit/rules.d/example.rules\nRecovery: remove the staged file.",
                   diff="--- before /etc/audit/rules.d/example.rules\n"
                        "+++ after /etc/audit/rules.d/example.rules\n"
                        "@@ -0,0 +1 @@\n+ exact proposed line",
                   evidence="Original observation")
    request.update(options)
    prompt = _AttendedPrompt(request)
    prompt.approve()
    return prompt


def approval_body(prompt):
    return "\n".join(widget.text for widget in prompt.view.original_widget.body.body)


class BatchApprovalTests(unittest.TestCase):
    def assert_decision(self, prompt, callback, status):
        with self.assertRaises(urwid.ExitMainLoop):
            callback()
        self.assertEqual(prompt.answer, {"status": status, "value": ""})

    def test_overview_shows_diff_and_details_keeps_evidence(self):
        prompt = fixture_prompt()
        screen = "\n".join(row.decode() for row in prompt.view.render((80, 15), True).text)
        self.assertIn("V-288831   Change 4 of 22", screen)
        self.assertIn("MEDIUM operational risk", screen)
        self.assertIn("Before / after", screen)
        body = approval_body(prompt)
        self.assertIn("+ exact proposed line", body)
        self.assertLess(body.index("Before / after"), body.index("Proposed change"))
        prompt.key("D")
        self.assertIn("Assessment evidence\nOriginal observation", approval_body(prompt))
        self.assertIn("Recovery: remove the staged file.", approval_body(prompt))
        prompt.key("esc")
        self.assertEqual(prompt.page, "approval")

    def test_enter_defaults_to_skip_and_stop_ends_the_batch(self):
        prompt = fixture_prompt()
        self.assert_decision(prompt, lambda: prompt.view.keypress((80, 22), "enter"), 1)
        prompt = fixture_prompt()
        for _ in range(3):
            prompt.view.keypress((80, 22), "tab")
        self.assertEqual(prompt.view.original_widget.buttons.focus.base_widget.get_label(), "Stop")
        self.assert_decision(prompt, lambda: prompt.view.keypress((80, 22), "enter"), 2)

    def test_yes_and_bulk_decisions_are_distinct(self):
        prompt = fixture_prompt(revised=True)
        self.assertIn("Plan changed.", approval_body(prompt))
        prompt.key("a")
        self.assertEqual(prompt.answer["status"], 2)
        self.assert_decision(prompt, lambda: prompt.key("y"), 0)
        prompt = fixture_prompt(risk="low", allow_all=True)
        self.assertIn("remaining unchanged, eligible low-risk changes", approval_body(prompt))
        self.assert_decision(prompt, lambda: prompt.key("A"), 3)


if __name__ == "__main__":
    unittest.main()
