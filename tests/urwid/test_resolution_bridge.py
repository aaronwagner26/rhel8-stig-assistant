"""Check resolution controls and their effects on the reviewed scope."""

from pathlib import Path
import subprocess
import tempfile
import unittest

from runtime import decode_workbench_event


ROOT = Path(__file__).resolve().parents[2]
PROGRAM = r"""
set -e -o pipefail
source "$1/src/classic/rhel8-stig.sh"
source "$1/src/urwid/bridge.sh"
source "$1/src/urwid/hooks.sh"
init_options
register_rules
parse_args --apply --only V-230251,V-230252,V-272482,V-272483,V-230484,V-251710
tui_seed_scope
declare -a URWID_BROWSE_SCOPE=()
declare -A URWID_BROWSE_DATA=() TUI_ALLOWED=()
tui_index
RUN_DIR=$2 SCRIPT_HASH=fixture SCRIPT_PATH=/fixture/rhel8-stig-urwid.sh
URWID_ASSESSED=0 URWID_REVIEW_TOKEN='' URWID_REVIEW_SEQ=0
URWID_RISK_CAP=$MAX_RISK URWID_DEFER_CAP=$DEFER

assess_one() {
    local id=$1
    printf '%s\n' "$id" >> "$RUN_DIR/checked"
    BEFORE[$id]=FAIL AFTER[$id]=FAIL ACTIONS[$id]=BLOCKED
    DETAIL[$id]="Observed fixture $id"
    case $id in
        V-230251|V-230252|V-272482|V-272483)
            if [[ ! ${EFFECTIVE[V-288829]+selected} ]]; then
                DISPLAY_PLAN[$id]='shared effect would change skipped or unselected V-288829'
            else
                ACTIONS[$id]=UNCHANGED PREVIEW_KEY[$id]="fixture-$id"
            fi ;;
        V-230484)
            if [[ $CHRONY_RUN_SERVER == ntp.example.org ]]; then
                ACTIONS[$id]=UNCHANGED PREVIEW_KEY[$id]="fixture-$id"
            fi ;;
        V-251710) AFTER[$id]=NEEDS_REVIEW ACTIONS[$id]=MANUAL_REQUIRED ;;
    esac
    return 0
}
verify_script() { return 0; }

urwid_dispatch scan
group=V-230251,V-230252,V-272482,V-272483
urwid_dispatch review "$group" '' || exit $?
token=$URWID_REVIEW_TOKEN
urwid_dispatch resolve V-230251
[[ $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-input V-230251 evidence-note 'Site record E-1' "$group"
[[ $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-scope V-230251 V-230484 "$group"
[[ ! ${TUI_ALLOWED[V-288829]+added} && $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-scope V-230251 V-288829 "$group"
[[ ${TUI_ALLOWED[V-288829]+added} && ${TUI_SELECTED[V-288829]+selected} && ! $URWID_REVIEW_TOKEN ]]
urwid_dispatch accept "$token"
urwid_dispatch resolve-input V-230484 approved-time-source 'invalid address' "$group"
urwid_dispatch resolve-input V-230484 approved-time-source ntp.example.org "$group,V-288829"
[[ $CHRONY_RUN_SERVER == ntp.example.org ]]
urwid_dispatch resolve-input V-251710 evidence-note 'Baseline approval E-2' "$group,V-288829"
[[ ${AFTER[V-251710]} == NEEDS_REVIEW && ! ${PREVIEW_KEY[V-251710]+planned} ]]
write_admin_actions > "$RUN_DIR/admin-actions.txt"
"""


class ResolutionBridgeTests(unittest.TestCase):
    def test_only_confirmed_inputs_change_scope_and_evidence_preserves_the_result(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", "-c", PROGRAM, "resolution-fixture", str(ROOT), directory],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            events = [decode_workbench_event(line) for line in result.stdout.splitlines()]
            self.assertEqual([event["type"] for event in events],
                             ["state", "review", "resolution", "resolution", "error", "state",
                              "error", "error", "state", "resolution"])
            self.assertEqual(events[2]["dependency"]["id"], "V-288829")
            self.assertEqual(events[3]["inputs"][0]["value"], "Site record E-1")
            self.assertIn("V-288829", [row["id"] for row in events[5]["rows"] if row["selected"]])
            self.assertIn("preview is unavailable", events[6]["message"])
            chrony = next(row for row in events[8]["rows"] if row["id"] == "V-230484")
            self.assertTrue(chrony["operation"])
            self.assertIn("Assessment NEEDS_REVIEW", events[9]["text"])
            written_report = (Path(directory) / "admin-actions.txt").read_text()
            self.assertIn("Operator-provided evidence reference: Baseline approval E-2", written_report)
            self.assertIn("--approved-time-source ntp.example.org", written_report)
            checked = (Path(directory) / "checked").read_text().splitlines()
            # Initial scope, a four-ID review, and two new seven-ID observations.
            self.assertEqual(len(checked), 6 + 4 + 7 + 7)


if __name__ == "__main__":
    unittest.main()
