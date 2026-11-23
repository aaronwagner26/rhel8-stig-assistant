#!/bin/bash
# Run with a private temporary directory in an offline disposable fixture.
set -euo pipefail
[[ $# == 1 && -f /.dockerenv && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]] || exit 64
source "$1"

init_options
register_rules
tui_filters_clear
TUI_TEMP=$(mktemp -d /var/tmp/stig-batch-review.XXXXXXXX)
trap 'rm -f -- "$TUI_TEMP/view.txt"; rmdir -- "$TUI_TEMP"' EXIT

MODE=apply
TUI_COLOR=0
TUI_ACTION_SHORTCUT=0
TUI_IMPLEMENT=0
TUI_FOCUS=V-288831
TUI_SEARCH=fixture
TUI_IDS=(V-288831 V-230224 V-230264 V-274877 V-230404 V-230406)
declare -A TUI_VISIBLE=()
declare -a TUI_MATCH=() refresh_trace=()
proposed=V-288831
manual=V-230224
blocked_id=V-230264
pending=V-274877
compliant=V-230404
grouped=V-230406
choice=Implement-Selected
confirmation_response=1
preview_title='' preview_action='' preview='' confirmation='' menu=''

fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

contains() {
    [[ $1 == *"$2"* ]] || fail "missing '$2' in '$1'"
}

tui_matches() {
    local id
    TUI_HIDDEN=0
    TUI_MATCH=() TUI_VISIBLE=()
    for id in "${TUI_IDS[@]}"; do
        if [[ $id == "$pending" ]]; then
            if [[ ${TUI_SELECTED[$id]+selected} ]]; then (( TUI_HIDDEN += 1 )); fi
            continue
        fi
        TUI_MATCH+=("$id")
        TUI_VISIBLE[$id]=1
    done
}

tui_backend_refresh() {
    local phase=$1 id
    refresh_trace+=("$phase")
    init_results
    SCOPE=() EFFECTIVE=()
    for id in "${TUI_IDS[@]}"; do
        if [[ $phase == review && ! ${TUI_SELECTED[$id]+selected} ]]; then continue; fi
        SCOPE+=("$id")
        EFFECTIVE[$id]=1
        DETAIL[$id]='Fixture observation.'
        AFTER[$id]=FAIL
        case $id in
            "$proposed")
                PREVIEW_KEY[$id]='fixture-proposal'
                PREVIEW_RISK[$id]=medium
                ACTIONS[$id]=UNCHANGED
                DISPLAY_PLAN[$id]='Fixture planned edit.'
                DISPLAY_DIFF[$id]=$'+ new audit rule' ;;
            "$manual") ACTIONS[$id]=MANUAL_REQUIRED ;;
            "$blocked_id") ACTIONS[$id]=BLOCKED ;;
            "$pending") ACTIONS[$id]=PENDING_ACTIVATION ;;
            "$compliant") ACTIONS[$id]=UNCHANGED; AFTER[$id]=PASS ;;
            "$grouped") ACTIONS[$id]=UNCHANGED; PLANNED_BY[$id]=$proposed ;;
        esac
    done
}

do_apply() { fail 'review tried to make changes'; }

tui_size() { TUI_COLS=120; TUI_ROWS=45; }

tui_dialog() {
    local title=$2
    case $title in
        Actions)
            menu="$*"
            TUI_REPLY=$choice ;;
        Implement)
            contains "$*" 'Choose exactly one finding'
            contains "$*" "$proposed"
            TUI_REPLY=$proposed ;;
        'Implement selected findings'|"Implement | $proposed")
            preview_title=$title
            shift 2
            [[ $1 == --exit-label && $3 == --textbox ]] || fail 'expected the review to open a proposed-changes screen'
            preview_action=$2
            preview=$(< "$4") ;;
        'Confirm reviewed scope')
            contains "$*" "--defaultno --yes-label $preview_action --no-label Back"
            contains "$*" 'Back is the default.'
            confirmation="$*"
            return "$confirmation_response" ;;
        *) fail "unexpected dialog $title" ;;
    esac
}

for id in "${TUI_IDS[@]}"; do TUI_SELECTED[$id]=1; done
tui_actions || fail 'Back did not return cleanly to Actions'
contains "$menu" 'Implement-Selected Review all 6 selected findings'
contains "$menu" 'Implement-One Choose one finding to review separately'
contains "$preview_title" 'Implement selected findings'
contains "$preview" "6 selected | 1 proposed changes"
contains "$preview" $'Proposed changes (1)\n  '"$proposed"
contains "$preview" $'Included in another change (1)\n  '"$grouped"
contains "$preview" $'Manual work or evidence (1)\n  '"$manual"
contains "$preview" $'Blocked (1)\n  '"$blocked_id"
contains "$preview" $'Pending activation (1)\n  '"$pending"
contains "$preview" $'Already compliant (1)\n  '"$compliant"
contains "$preview" '+ new audit rule'
contains "$confirmation" '6 selected | 1 proposed changes | 1 hidden by filters.'
contains "$confirmation" 'Each still needs attended approval.'
[[ $preview_action == 'Start approvals' && $TUI_IMPLEMENT == 0 ]] || fail 'Back started approvals'
[[ ${refresh_trace[*]} == 'review browse' ]] || fail 'Back did not restore the browsing scope'

confirmation_response=0
tui_actions || fail 'Start approvals did not return cleanly from Actions'
[[ $TUI_IMPLEMENT == 1 && ${SCOPE[*]} == "${TUI_IDS[*]}" ]] || fail 'Start approvals did not keep the full selected scope'

confirmation_response=1
TUI_IMPLEMENT=0
choice=Implement-One
tui_actions || fail 'Back from the one-finding review failed'
contains "$preview_title" "Implement | $proposed"
contains "$confirmation" "Continue with $proposed only?"
[[ $TUI_IMPLEMENT == 0 && ${#TUI_SELECTED[@]} == ${#TUI_IDS[@]} ]] || fail 'One-finding Back discarded the batch selection'

choice=Implement-Selected
TUI_SELECTED=(["$manual"]=1)
tui_actions || fail 'Back from the report-only review failed'
[[ $preview_action == 'Save report' && $TUI_IMPLEMENT == 0 ]] || fail 'A selection without a proposal offered approval'
contains "$confirmation" 'Save the findings and follow-up actions to a report?'

printf 'PASS Classic batch inventory, focused scope, Start approvals, and default Back\n'
