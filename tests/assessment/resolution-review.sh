#!/bin/bash
# Exercise Classic resolution prompts inside a private, offline fixture.
set -eo pipefail
[[ -f /.dockerenv && $# == 1 && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]] || exit 64
source "$1"
init_options
register_rules

fixture=$(mktemp -d -- /var/tmp/stig-resolution.XXXXXXXX)
TUI_TEMP=$fixture SCRIPT_PATH=/fixture/rhel8-stig.sh
declare -A TUI_ALLOWED=()
init_results
MODE=apply
SCOPE=(V-230251 V-230484 V-251710)
TUI_IDS=("${SCOPE[@]}")
for rule in "${SCOPE[@]}"; do
    TUI_ALLOWED[$rule]=1 TUI_SELECTED[$rule]=1 EFFECTIVE[$rule]=1
    AFTER[$rule]=NEEDS_REVIEW ACTIONS[$rule]=MANUAL_REQUIRED
    DETAIL[$rule]='Observed fixture state'
done
ACTIONS[V-230251]=BLOCKED
DISPLAY_PLAN[V-230251]='shared effect would change skipped or unselected V-288829'

tui_view() {
    [[ $1 == 'Resolve | '* && $2 == Options ]] || return 2
    grep -q 'Observed fixture state' "$TUI_TEMP/view.txt" || return 2
}

tui_choose() {
    case $1 in
        *V-251710) TUI_CHOICE=Evidence ;;
        *V-230484) TUI_CHOICE=Source ;;
        *V-230251) TUI_CHOICE=Scope ;;
        *) return 2 ;;
    esac
}

tui_input() {
    case $1 in
        'Evidence reference') TUI_REPLY='Approval record E-22' ;;
        'Approved time source') TUI_REPLY=ntp.example.org ;;
        *) return 2 ;;
    esac
}

tui_message() { [[ $1 == Resolve && $2 == *'save a report'* ]]; }
tui_confirm() {
    [[ $4 == Back ]] || return 2
    if [[ $1 == 'Include V-288829' ]]; then return "${scope_result:-1}"; fi
    [[ $1 == 'Use approved source' && $2 == *ntp.example.org* ]] || return 2
}

tui_backend_refresh() {
    [[ $1 == browse && $CHRONY_RUN_SERVER == ntp.example.org ]]
}

tui_resolution V-251710
[[ ${AFTER[V-251710]} == NEEDS_REVIEW && ${RESOLUTION_NOTES[V-251710]} == 'Approval record E-22' ]]
render_admin_action V-251710 > "$fixture/report"
grep -Fq 'Operator-provided evidence reference: Approval record E-22' "$fixture/report"
tui_resolution V-230484
[[ $CHRONY_RUN_SERVER == ntp.example.org ]]
tui_resolution V-230251 || exit $?
[[ ! ${REQUESTED[V-288829]+included} ]]
scope_result=0 tui_resolution V-230251
[[ ${REQUESTED[V-288829]+included} && ${TUI_SELECTED[V-288829]+selected} ]]
printf '%s\n' 'PASS Classic Resolve, evidence preservation, approved time source, and Back-default scope extension.'
