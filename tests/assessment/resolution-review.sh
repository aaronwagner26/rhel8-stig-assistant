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
SCOPE=(V-230484 V-251710)
TUI_IDS=("${SCOPE[@]}")
for rule in "${SCOPE[@]}"; do
    TUI_ALLOWED[$rule]=1 TUI_SELECTED[$rule]=1 EFFECTIVE[$rule]=1
    AFTER[$rule]=NEEDS_REVIEW ACTIONS[$rule]=MANUAL_REQUIRED
    DETAIL[$rule]='Observed fixture state'
done

tui_view() {
    [[ $1 == 'Resolve | '* && $2 == Options ]] || return 2
    grep -q 'Observed fixture state' "$TUI_TEMP/view.txt" || return 2
}

tui_choose() {
    case $1 in
        *V-251710) TUI_CHOICE=Evidence ;;
        *V-230484) TUI_CHOICE=Source ;;
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

TUI_SELECTED=([V-272482]=1)
tui_backend_refresh() {
    [[ $1 == review ]] || return 2
    SCOPE=(V-230251 V-230252 V-272482 V-272483 V-288829)
    EFFECTIVE[V-272482]=1 PREVIEW_KEY[V-230251]=reviewed PREVIEW_RISK[V-230251]=high
    PLANNED_BY[V-272482]=V-230251 ACTIONS[V-272482]=UNCHANGED AFTER[V-272482]=FAIL
    DETAIL[V-272482]='Observed client MACs'
    DISPLAY_PLAN[V-230251]='Stage shared policy'
    DISPLAY_DIFF[V-230251]='+ FIPS:RHEL8STIGOPENSSH'
    SSH_SCOPE_ADDED[V-230251]=shared SSH_SCOPE_ADDED[V-288829]=impact
}
tui_highlighted_view() {
    [[ $1 == 'Implement | V-272482' && $2 == 'Start approval' && $3 == preview ]] &&
        grep -Fq 'Shared operation led by V-230251' "$TUI_TEMP/view.txt" &&
        grep -Fq 'V-288829 is included for the OpenSSL impact only.' "$TUI_TEMP/view.txt" &&
        grep -Fq '+ FIPS:RHEL8STIGOPENSSH' "$TUI_TEMP/view.txt" || return 2
}
tui_confirm() { return 2; } # The shared preview proceeds directly to the actual approval.
tui_review V-272482
printf '%s\n' 'PASS Classic Resolve, approved time source, evidence, and shared SSH preview.'
