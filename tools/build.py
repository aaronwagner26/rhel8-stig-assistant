"""Build the classic and Urwid editions from the same pinned backend."""

import hashlib
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parent.parent
URWID_SOURCE = ROOT / "src" / "urwid"
BACKEND = ROOT / "src" / "classic" / "rhel8-stig.sh"
BACKEND_SHA256 = "a538106dff71c056d9b3c86e2efc9e7421d8c3017c24fcee40a9d6306630a8bc"
CLASSIC_VERSION = "0.5.8-dev"
VERSION = "0.6.8-urwid-dev"
OUTPUT = ROOT / "dist" / "rhel8-stig-urwid.sh"
CLASSIC_OUTPUT = OUTPUT.with_name(BACKEND.name)
DELIMITER = "__RHEL_STIG_EMBEDDED_URWID__"
ENTRY = 'if [[ ${BASH_SOURCE[0]} == "$0" ]]; then\n'
LEGACY_INTERFACE = "# Interactive findings worklist."
ORCHESTRATION = "# 9. Main orchestration and final summary"
SHARED_TUI_HELPERS = (
    "tui_size", "tui_area", "tui_assessment", "tui_handling",
    "tui_action_summary", "tui_index", "tui_save_directory",
    "tui_save_selection", "tui_load_selection", "tui_details_text", "tui_implement_preview",
)


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise SystemExit("Pinned backend structure changed near {!r}".format(before[:80]))
    return source.replace(before, after)


def keep_shared_tui_helpers(shell):
    start = shell.index(LEGACY_INTERFACE)
    end = shell.index(ORCHESTRATION, start)
    original = shell[start:end]
    pieces = ["# Shared selection, assessment and plan helpers.\n"]
    for name in SHARED_TUI_HELPERS:
        pattern = r"^" + name + r"\(\) \{\n.*?^}\n"
        matches = re.findall(pattern, original, re.MULTILINE | re.DOTALL)
        if len(matches) != 1:
            raise SystemExit("Pinned backend helper unavailable: " + name)
        helper = matches[0]
        if name == "tui_load_selection":
            helper = replace_once(helper, "    local path id TRIMMED result",
                                  "    local path id TRIMMED result line_number=0 problem")
            helper = replace_once(helper, "        trim_line \"$id\"",
                                  "        (( line_number += 1 ))\n        trim_line \"$id\"")
            helper = replace_once(helper,
                                  "'The file contains an unknown or out-of-scope ID. The current selection is unchanged.'",
                                  '"$problem"')
            helper = replace_once(helper, "            tui_message 'Selection could not be loaded'",
                                  """            if [[ $TRIMMED =~ ^V-[0-9]{6}$ ]]; then
                problem="Line $line_number references $TRIMMED, which is outside the available scope."
            else
                problem="Line $line_number must contain one Vuln-ID such as V-230264."
            fi
            tui_message 'Selection could not be loaded'""")
        pieces.append(helper)
    return replace_once(shell, original, "\n".join(pieces) + "\n")


def build():
    baseline = BACKEND.read_bytes()
    if hashlib.sha256(baseline).hexdigest() != BACKEND_SHA256:
        raise SystemExit("The pinned {} backend does not match its release hash.".format(CLASSIC_VERSION))
    shell = keep_shared_tui_helpers(baseline.decode("utf-8"))
    shell = replace_once(shell, "# rhel8-stig.sh — Attended",
                         "# rhel8-stig-urwid.sh — Attended")
    shell = replace_once(shell, "# {} | 2026-11-23 | Clear batch review and audit previews.".format(CLASSIC_VERSION),
                         "# {} | 2026-11-23 | Selected-scope Apply and clearer batch approvals.".format(VERSION))
    shell = replace_once(shell, "readonly SCRIPT_VERSION=" + CLASSIC_VERSION,
                         "readonly SCRIPT_VERSION=" + VERSION)
    shell = replace_once(shell, "readonly ASSESSMENT_CACHE_DEFAULT=1",
                         "readonly ASSESSMENT_CACHE_DEFAULT=0")
    classic_heading = CLASSIC_VERSION + " (2026-11-23)"
    shell = replace_once(shell, classic_heading, VERSION + """ (2026-11-23)
  Assess an explicitly selected Apply scope at startup. Show batch outcomes
  before approvals and place the before/after diff near each decision.
0.6.7-urwid-dev (2026-11-23)
  Restore the existing Findings list when leaving a preview.
0.6.6-urwid-dev (2026-11-23)
  Remove the Change ticket field and its handoff from the workbench.
0.6.5-urwid-dev (2026-11-23)
  Fix GNU awk parsing for UEFI GRUB password and GNOME logout checks.
0.6.4-urwid-dev (2026-11-23)
  Extend the shared catalog with 96 additional attended remediation paths.
  Show the same checks, previews and activation requirements in both editions.
0.6.3-urwid-dev (2026-11-20)
  Preserve Findings focus on resize and return to sort headers from evidence.
  Keep assessment comparisons clear when a report action is unfamiliar.
  Keep the Workbench connected while a shell prompt timeout is inherited.
0.6.2-urwid-dev (2026-11-20)
  Check launch readiness, browse source files, paste IDs and search plans.
  Search saved reports and outcomes, generate a ticket handoff, and compare
  an attended read-only recheck with its original scope. Guard effective site
  settings, restore the terminal on disconnect, and keep error reports visible.
  The 68-rule registry is pinned. Resume and rollback require the matching build.
0.6.1-urwid-dev (2026-11-20)
  Open saved Results and compare compatible JSON runs from the home screen.
  Assess on demand with per-finding progress. Add sortable column headers,
  quick triage views, and a review index with outcome counts.
0.6.0-urwid-dev (2026-11-20)
  Add the Urwid terminal workspace, preflight, focused evidence and diffs,
  attended approvals, and report and recovery views. Preserve the 0.5.4-dev
  rule engine, existing CLI, plan signatures, and guarded transactions.
""" + classic_heading)
    shell = replace_once(shell, "Usage: rhel8-stig.sh [mode] [options]",
                         "Usage: rhel8-stig-urwid.sh [mode] [options]")
    shell = replace_once(shell, "  --version | --changelog | --self-hash | --help",
                         "  --ui-check                     Check the host and Urwid prerequisites.\n"
                         "  --version | --changelog | --self-hash | --help")
    shell = replace_once(shell, "  --max-risk low|medium|high     Maximum",
                         "  --expect-site-settings SHA256  Require the recorded effective settings for a\n"
                         "                                 read-only --status --resume with --config.\n"
                         "  --max-risk low|medium|high     Maximum")
    shell = replace_once(shell, "    MODPROBE_MANAGED=unknown GPGCHECK_ALTERNATE_REPOS=''\n    declare -gA REQUESTED",
                         "    MODPROBE_MANAGED=unknown GPGCHECK_ALTERNATE_REPOS='' EXPECTED_SITE_SETTINGS=''\n"
                         "    URWID_APPROVAL_STOPPED=0\n"
                         "    declare -gA REQUESTED")
    shell = replace_once(shell, "--ckl|--ckl-section|--ack-ckl-host)",
                         "--ckl|--ckl-section|--ack-ckl-host|--expect-site-settings)")
    shell = replace_once(shell, "                    --config) CONFIG_FILE=$value ;;",
                         "                    --config) CONFIG_FILE=$value ;;\n"
                         "                    --expect-site-settings) EXPECTED_SITE_SETTINGS=$value ;;")
    shell = replace_once(shell, '    if [[ -n $CONFIG_FILE ]]; then read_site_config "$CONFIG_FILE" || return; fi',
                         """    if [[ -n $CONFIG_FILE ]]; then read_site_config "$CONFIG_FILE" || return; fi
    if [[ -n $EXPECTED_SITE_SETTINGS ]]; then
        if [[ ! $EXPECTED_SITE_SETTINGS =~ ^[0-9a-f]{64}$ || $MODE != status ||
              -z $RESUME_ID || -z $CONFIG_FILE ]] || (( GUI )); then
            usage_error '--expect-site-settings needs SHA-256, --status --resume, and --config in CLI mode'
            return
        fi
        if [[ $(urwid_site_settings_digest) != "$EXPECTED_SITE_SETTINGS" ]]; then
            blocked 'effective site settings differ from the recorded run. Review the changes before reassessing.'
            return
        fi
    fi""")
    shell = replace_once(shell, "        if [[ ! -e $step ]]; then\n            (( create )) && mkdir -m 0700 -- \"$step\" || return 1",
                         """        if [[ ! -e $step ]]; then
            if [[ $create == probe ]]; then
                URWID_PROBE_DIRECTORY=${step%/*}
                URWID_PROBE_DIRECTORY=${URWID_PROBE_DIRECTORY:-/}
                [[ -w $URWID_PROBE_DIRECTORY && -x $URWID_PROBE_DIRECTORY ]]
                return
            fi
            (( create )) && mkdir -m 0700 -- "$step" || return 1""")
    shell = replace_once(shell, '    [[ $owner == "$EUID" ]] && (( (8#$mode & 077) == 0 ))\n}',
                         """    [[ $owner == "$EUID" ]] && (( (8#$mode & 077) == 0 )) || return 1
    if [[ $create == probe ]]; then
        [[ -w $step && -x $step ]] || return 1
        URWID_PROBE_DIRECTORY=$step
    fi
    return 0
}""")
    shell = replace_once(shell, """  --gui | --tui                 Open the optional dialog checklist and plan review.
                                 Compatible with status, dry-run and apply.""",
                         """  --gui | --tui                 Open the Urwid workspace with Python 3 and python3-urwid.
                                 Compatible with status, dry-run, diff and apply.""")
    shell = replace_once(shell, """revisions control mapping. CKLB is a separate format. The GUI needs a compatible
dialog and a terminal. With no explicit selection source it starts unchecked.""",
                         """revisions control mapping. CKLB is a separate format. The Urwid workspace needs
a controlling terminal. With no explicit selection source it starts unchecked.""")
    shell = shell.replace("./rhel8-stig.sh --", "./rhel8-stig-urwid.sh --")
    shell = replace_once(shell, "--diff|--apply|--list|--version|--changelog|--self-hash|--help)",
                         "--diff|--apply|--list|--ui-check|--version|--changelog|--self-hash|--help)")
    shell = replace_once(shell, "list|version|changelog|self-hash|help|explain)",
                         "list|ui-check|version|changelog|self-hash|help|explain)")
    shell = replace_once(shell, "        version) printf 'rhel8-stig.sh",
                         "        ui-check) urwid_ui_check; return ;;\n"
                         "        version) printf 'rhel8-stig-urwid.sh")
    shell = replace_once(shell, """    [[ ${MODE-} == diff || ${IMPLEMENT_DIFF:-0} == 1 ]]""",
                         """    [[ ${MODE-} == diff || ${IMPLEMENT_DIFF:-0} == 1 || ${GUI:-0} == 1 ]]""")
    shell = replace_once(shell, """    [[ $COLOR == always ]] ||
        [[ $COLOR == auto && -z ${NO_COLOR+x} && ${TERM:-dumb} != dumb && -t $1 ]]""",
                         """    if [[ $COLOR == always ]]; then return 0; fi
    [[ $COLOR == auto && -z ${NO_COLOR+x} && ${TERM:-dumb} != dumb && -t $1 ]] || return 1
    (( ! ${GUI:-0} || ${TUI_COLOR:-0} ))""")
    shell = replace_once(shell, 'verify_selection_source() {\n', """verify_selection_source() {
    if ! urwid_site_snapshot_matches; then
        blocked 'effective site settings changed. Reload Run settings and review the scope again.'
        return 1
    fi
""")
    site_start = shell.index("read_site_config() {\n")
    site_end = shell.index("\nresolve_scope() {", site_start)
    old_site_parser = shell[site_start:site_end]
    site_parser = replace_once(old_site_parser, "local file=$1 line TRIMMED key value",
                               "local file=$1 line TRIMMED key value line_number=0")
    site_parser = replace_once(site_parser, '        trim_line "$line"',
                               '        (( line_number += 1 ))\n        trim_line "$line"')
    site_parser = replace_once(site_parser, "            usage_error 'invalid or duplicate site setting'; return",
                               '            usage_error "site line $line_number needs one recognized KEY=value setting"; return')
    site_parser = replace_once(site_parser, "if [[ ${seen[$key]+specified} ]]; then usage_error 'invalid or duplicate site setting'; return; fi",
                               'if [[ ${seen[$key]+specified} ]]; then usage_error "site line $line_number repeats $key"; return; fi')
    site_parser = replace_once(site_parser, "usage_error 'invalid MODPROBE_MANAGED setting'",
                               'usage_error "invalid MODPROBE_MANAGED setting on site line $line_number. Use yes or no."')
    site_parser = replace_once(site_parser, "usage_error 'GPGCHECK_ALTERNATE_REPOS needs comma-separated DNF repository IDs'",
                               'usage_error "GPGCHECK_ALTERNATE_REPOS on site line $line_number needs comma-separated DNF repository IDs"')
    site_parser = replace_once(site_parser, "*) usage_error 'invalid or duplicate site setting'; return ;;",
                               '*) usage_error "site line $line_number uses an unsupported key"; return ;;')
    shell = replace_once(shell, old_site_parser, site_parser)
    shell = replace_once(shell, "        tui_seed_scope && tui_backend_refresh browse || return 70",
                         "        tui_seed_scope || return 70")
    shell = replace_once(shell, """    : > "$RUN_DIR/run.log" || return 1
    init_results
    status_cache_begin
    for id in "${SCOPE[@]}"; do assess_one "$id" || return 1; done
    status_cache_finish && status_check_counts""",
                         """    : > "$RUN_DIR/run.log" || return 1
    init_results
    status_cache_begin
    local position=0
    urwid_progress 0 "${#SCOPE[@]}" '' || return 1
    for id in "${SCOPE[@]}"; do
        urwid_progress "$position" "${#SCOPE[@]}" "$id" || return 1
        assess_one "$id" || return 1
        position=$(( position + 1 ))
    done
    status_cache_finish && status_check_counts""")
    shell = replace_once(shell, """            show_apply_item "$id" "$position" "$total" |
                display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 1
            apply_choice "$id" "$PLAN_RISK" "$allow_all" "$revised"
            reply=$?""",
                         """            if (( GUI )); then
                urwid_approve_change "$id" "$PLAN_RISK" "$allow_all" "$revised" "$position" "$total"
            else
                show_apply_item "$id" "$position" "$total" |
                    display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 1
                apply_choice "$id" "$PLAN_RISK" "$allow_all" "$revised"
            fi
            reply=$?""")
    shell = replace_once(shell, "ui_result reviewed=0 run_result",
                         "ui_result reviewed=0 run_result reports_complete=0")
    completed_event = '    event INFO "completed with $UNRESOLVED unresolved, $PENDING_COUNT pending, $SKIPPED_COUNT skipped" || return 70'
    shell = replace_once(shell, completed_event, completed_event + "\n    reports_complete=1")
    shell = replace_once(shell, """    if (( GUI && reviewed && run_result != 70 )) && [[ $MODE == apply ]]; then
        if tui_prepare; then
            tui_apply_results || true
            tui_close || true
        fi
    fi""", """    if (( GUI && reviewed )); then
        trap 'urwid_stop_presentation "$run_result"' INT TERM HUP
        urwid_release_result_lock
        if (( reports_complete )); then
            if tui_prepare; then
                tui_apply_results "$run_result" || true
                tui_close || true
            fi
        else
            notice ERROR "Reports incomplete. Inspect ${RUN_DIR:-the journal}${BACKUP_RUN:+ and backups at $BACKUP_RUN}."
        fi
    fi""")
    shell = replace_once(shell,
                         '    write_admin_actions | tr',
                         '    (urwid_outcome_summary && write_admin_actions && urwid_write_follow_up) | tr')
    python_source = "\n\n".join((URWID_SOURCE / name).read_text(encoding="utf-8").strip()
                                for name in ("workbench.py", "path_browser.py", "outcomes.py",
                                             "attended.py", "history.py", "runtime.py"))
    compile(python_source, OUTPUT.name + ":embedded Python", "exec")
    if DELIMITER in python_source:
        raise SystemExit("The Python text conflicts with the embedding delimiter.")
    embed = "urwid_program() {{\n    cat <<'{}'\n{}\n{}\n}}\n".format(
        DELIMITER, python_source, DELIMITER)
    bridge = (URWID_SOURCE / "bridge.sh").read_text(encoding="utf-8").strip()
    hooks = (URWID_SOURCE / "hooks.sh").read_text(encoding="utf-8").strip()
    result = replace_once(shell, ENTRY, "\n".join((embed, bridge, hooks, "", ENTRY)))
    write_artifact(CLASSIC_OUTPUT, baseline)
    write_artifact(OUTPUT, result.encode("utf-8"))


def write_artifact(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".sh.tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    digest = hashlib.sha256(data).hexdigest()
    path.with_suffix(".sh.sha256").write_bytes(
        "{}  {}\n".format(digest, path.name).encode("ascii"))
    print("{}  {}".format(digest, path.name))


if __name__ == "__main__":
    build()
