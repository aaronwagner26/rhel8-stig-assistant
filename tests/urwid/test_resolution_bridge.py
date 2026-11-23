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
parse_args --apply --only V-230251,V-230484,V-251710
tui_seed_scope
declare -a URWID_BROWSE_SCOPE=()
declare -A URWID_BROWSE_DATA=() TUI_ALLOWED=()
tui_index
RUN_DIR=$2 SCRIPT_HASH=fixture SCRIPT_PATH=/fixture/rhel8-stig-urwid.sh
URWID_ASSESSED=0 URWID_REVIEW_TOKEN='' URWID_REVIEW_SEQ=0
URWID_RISK_CAP=$MAX_RISK URWID_DEFER_CAP=$DEFER

tui_backend_refresh() {
    local phase=$1 id
    init_results
    SCOPE=() EFFECTIVE=() SSH_SCOPE_ADDED=()
    for id in "${TUI_IDS[@]}"; do
        if [[ $phase == review && ! ${TUI_SELECTED[$id]+selected} ]]; then continue; fi
        SCOPE+=("$id") EFFECTIVE[$id]=1
    done
    if [[ ${EFFECTIVE[V-230251]+selected} ]]; then
        for id in V-230252 V-272482 V-272483 V-288829; do
            SCOPE+=("$id") EFFECTIVE[$id]=1 SSH_SCOPE_ADDED[$id]=1
            PLANNED_BY[$id]=V-230251
        done
        PREVIEW_KEY[V-230251]=fixture-ssh PREVIEW_RISK[V-230251]=high
        DISPLAY_PLAN[V-230251]='Fixture SSH policy proposal with related scope'
    fi
    for id in "${SCOPE[@]}"; do
        BEFORE[$id]=FAIL AFTER[$id]=FAIL ACTIONS[$id]=UNCHANGED
        DETAIL[$id]="Observed fixture $id"
        case $id in
            V-230484)
                if [[ $CHRONY_RUN_SERVER == ntp.example.org ]]; then
                    PREVIEW_KEY[$id]="fixture-$id" PREVIEW_RISK[$id]=medium
                fi ;;
            V-251710) AFTER[$id]=NEEDS_REVIEW ACTIONS[$id]=MANUAL_REQUIRED ;;
        esac
    done
}
verify_script() { return 0; }

urwid_dispatch scan
urwid_dispatch review V-230251 V-230251 || exit $?
ssh_token=$URWID_REVIEW_TOKEN
urwid_dispatch resolve V-288829
[[ $URWID_REVIEW_TOKEN == "$ssh_token" && ! ${TUI_SELECTED[V-288829]+selected} ]]
urwid_dispatch back
[[ ${SSH_SCOPE_ADDED[V-288829]+restored} && ${TUI_SELECTED[V-251710]+restored} ]]
urwid_dispatch review V-288829 V-288829
group=V-230484,V-251710
urwid_dispatch review "$group" '' || exit $?
token=$URWID_REVIEW_TOKEN
urwid_dispatch resolve V-251710
[[ $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-input V-251710 evidence-note 'Baseline approval E-2' "$group"
[[ $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-input V-230484 approved-time-source 'invalid address' "$group"
[[ $URWID_REVIEW_TOKEN == "$token" ]]
urwid_dispatch resolve-input V-230484 approved-time-source ntp.example.org "$group"
[[ $CHRONY_RUN_SERVER == ntp.example.org && ! $URWID_REVIEW_TOKEN ]]
urwid_dispatch accept "$token"
[[ ${AFTER[V-251710]} == NEEDS_REVIEW && ! ${PREVIEW_KEY[V-251710]+planned} ]]
write_admin_actions > "$RUN_DIR/admin-actions.txt"
"""


class ResolutionBridgeTests(unittest.TestCase):
    def test_related_ssh_rows_are_review_only_and_operator_inputs_preserve_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["bash", "-c", PROGRAM, "resolution-fixture", str(ROOT), directory],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            events = [decode_workbench_event(line) for line in result.stdout.splitlines()]
            self.assertEqual([event["type"] for event in events],
                             ["state", "review", "resolution", "browse", "error", "review",
                              "resolution", "resolution", "error", "state", "error"])
            self.assertEqual([row["id"] for row in events[0]["rows"]],
                             ["V-230251", "V-230484", "V-251710"])
            self.assertTrue(events[0]["rows"][0]["ssh_shared"])
            self.assertTrue(events[1]["ssh_single"])
            self.assertEqual([row["id"] for row in events[1]["rows"] if row["scope_added"]],
                             ["V-230252", "V-272482", "V-272483", "V-288829"])
            self.assertEqual(events[2]["id"], "V-288829")
            self.assertIn("available findings", events[4]["message"])
            self.assertFalse(events[5]["ssh_single"])
            self.assertIn("Assessment NEEDS_REVIEW", events[6]["text"])
            self.assertEqual(events[7]["inputs"][0]["value"], "Baseline approval E-2")
            chrony = next(row for row in events[9]["rows"] if row["id"] == "V-230484")
            self.assertTrue(chrony["operation"])
            self.assertIn("preview is unavailable", events[10]["message"])
            written_report = (Path(directory) / "admin-actions.txt").read_text()
            self.assertIn("Operator-provided evidence reference: Baseline approval E-2", written_report)
            self.assertIn("--approved-time-source ntp.example.org", written_report)


if __name__ == "__main__":
    unittest.main()
