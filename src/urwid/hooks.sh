# One-shot Urwid panels for prompts before discovery and after reviewed scope.
urwid_one_shot() (
    local request=$1 directory temporary='' request_file
    if [[ -n ${TUI_TEMP-} && -f $TUI_TEMP/app.py ]]; then
        directory=$TUI_TEMP
    else
        temporary=$(mktemp -d -- /var/tmp/rhel8-stig-urwid-prompt.XXXXXXXX) || return 2
        directory=$temporary
    fi
    request_file=$directory/prompt.json
    trap '
        rm -f -- "$request_file"
        if [[ $temporary ]]; then
            rm -f -- "$temporary/app.py"
            rmdir -- "$temporary"
        fi
    ' EXIT
    if [[ $temporary ]]; then urwid_program > "$directory/app.py" || return 2; fi
    printf '%s\n' "$request" > "$request_file" || return 2
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C.UTF-8 TERM="${TUI_TERM:-dumb}" \
        STIG_UI_COLOR="${TUI_COLOR:-0}" PYTHONIOENCODING=UTF-8 \
        "$URWID_PYTHON" -I "$directory/app.py" prompt "$request_file"
)

urwid_prompt_value() {
    printf ','
    json_string "$1"
    printf ':'
    json_string "$2"
}

urwid_prompt_boolean() {
    if (( $1 )); then printf true; else printf false; fi
}

urwid_approval_request() {
    local id=$1 risk=$2 allow_all=$3 revised=$4 position=$5 total=$6
    printf '{"kind":"approval"'
    urwid_prompt_value id "$id"
    urwid_prompt_value title "${TITLE[$id]}"
    urwid_prompt_value risk "$risk"
    urwid_prompt_value plan "$PLAN_TEXT"
    urwid_prompt_value diff "${PLAN_DIFF-}"
    urwid_prompt_value evidence "${DETAIL[$id]-}"
    printf ',"position":%s,"total":%s,"allow_all":' "$position" "$total"
    urwid_prompt_boolean "$allow_all"
    printf ',"revised":'
    urwid_prompt_boolean "$revised"
    printf ',"review_each":'
    urwid_prompt_boolean "$REVIEW_EACH"
    printf '}'
}

urwid_approve_change() {
    local id=$1 risk=$2 allow_all=$3 revised=$4 position=$5 total=$6
    local request response kind status value
    request=$(urwid_approval_request "$id" "$risk" "$allow_all" "$revised" "$position" "$total") ||
        return 2
    if ! response=$(urwid_one_shot "$request"); then
        URWID_APPROVAL_STOPPED=1
        return 2
    fi
    IFS=$'\037' read -r kind status value <<< "$response"
    if [[ $kind != modal || -n $value ]]; then
        URWID_APPROVAL_STOPPED=1
        return 2
    fi
    case $status in
        0|1) return "$status" ;;
        3)
            if (( allow_all && ! revised && ! REVIEW_EACH )) && [[ $risk == low ]]; then
                return 3
            fi ;;
    esac
    URWID_APPROVAL_STOPPED=1
    return 2
}

urwid_site_settings_digest() {
    local digest
    digest=$(printf '%s\0' 'effective-site-settings-v1' "$MODPROBE_MANAGED" "$GPGCHECK_ALTERNATE_REPOS" |
        sha256sum) || return 1
    printf '%s' "${digest%% *}"
}

urwid_read_site_snapshot() (
    local site=$1
    MODPROBE_MANAGED=unknown GPGCHECK_ALTERNATE_REPOS=''
    if [[ -n $site ]]; then read_site_config "$site" || return; fi
    printf '%s|%s\n' "$MODPROBE_MANAGED" "$GPGCHECK_ALTERNATE_REPOS"
)

urwid_site_snapshot_matches() {
    local recorded
    [[ -n ${CONFIG_FILE-} ]] || return 0
    recorded=$(urwid_read_site_snapshot "$CONFIG_FILE") || return 1
    [[ $recorded == "$MODPROBE_MANAGED|$GPGCHECK_ALTERNATE_REPOS" ]]
}

urwid_set_recheck_args() {
    local site digest
    URWID_RECHECK_ARGS=(--status --resume "$RUN_ID" --output-dir "$REPORT_BASE" --format json --max-risk "$MAX_RISK")
    if [[ -n $CONFIG_FILE ]]; then
        site=$(realpath -m -- "$CONFIG_FILE") || site=$CONFIG_FILE
        digest=$(urwid_site_settings_digest) || return 1
        URWID_RECHECK_ARGS+=(--config "$site" --expect-site-settings "$digest")
    fi
    if (( DEFER )); then URWID_RECHECK_ARGS+=(--defer-service-actions); fi
    if [[ $REPORT_GROUP_BY == result ]]; then URWID_RECHECK_ARGS+=(--group-by result); fi
    return 0
}

urwid_recheck_command() {
    local command
    local -a URWID_RECHECK_ARGS=()
    (( ${#SCOPE[@]} )) || return 0
    urwid_set_recheck_args || return 1
    printf -v command '%q ' "$SCRIPT_PATH" "${URWID_RECHECK_ARGS[@]}"
    printf '%s' "${command% }"
}

urwid_write_follow_up() {
    local verify_command
    verify_command=$(urwid_recheck_command) || return 1
    [[ -n $verify_command ]] || return 0
    printf '\nRecheck this scope\n' || return 1
    printf '%s\n' 'Run the following read-only command with the same verified build and operator account.' \
        "$verify_command" || return 1
    if [[ $FORMAT == json ]]; then
        printf '%s\n' 'Both runs can be compared in Results after the recheck completes.' || return 1
    else
        printf '%s\n' 'Use JSON on both runs for result comparison.' || return 1
    fi
    if [[ -n $CKL_PATH ]]; then
        printf '%s\n' 'If the checklist asset needs acknowledgment again, review it at the terminal before running the assessment.'
    fi
}

urwid_outcome_group() {
    local label=$1 offset
    shift
    local -a ids=("$@")
    local IFS=' '
    (( ${#ids[@]} )) || return 0
    printf '%s (%s)\n' "$label" "${#ids[@]}" || return 1
    for (( offset=0; offset<${#ids[@]}; offset+=6 )); do
        printf '  %s\n' "${ids[*]:offset:6}" || return 1
    done
}

urwid_outcome_summary() {
    local id assessment action described=0
    local -a verified_apply_ids=() applied_open=() activation_pending=() blocked_ids=() failed=() skipped=() manual=() open_ids=() restored=()
    printf 'Run outcomes\nRun %s | %s | Build %s %s\n' \
        "$RUN_ID" "$MODE" "$SCRIPT_VERSION" "$SCRIPT_HASH" || return 1
    printf 'Selected findings %s\n' "${#SCOPE[@]}" || return 1
    for id in "${SCOPE[@]}"; do
        assessment=${AFTER[$id]} action=${ACTIONS[$id]}
        case $action in
            APPLIED)
                if [[ $assessment == PASS ]]; then verified_apply_ids+=("$id"); else applied_open+=("$id"); fi ;;
            PENDING_ACTIVATION) activation_pending+=("$id") ;;
            BLOCKED) blocked_ids+=("$id") ;;
            FAILED) failed+=("$id") ;;
            SKIPPED) skipped+=("$id") ;;
            MANUAL_REQUIRED) manual+=("$id") ;;
            ROLLED_BACK) restored+=("$id") ;;
            *)
                if [[ $assessment != PASS && $assessment != NOT_APPLICABLE ]]; then open_ids+=("$id");
                else continue; fi ;;
        esac
        described=1
    done
    if (( ! described )); then
        printf '%s\n' 'No changes or outstanding findings recorded.' || return 1
    fi
    urwid_outcome_group 'Applied and verified' "${verified_apply_ids[@]}" &&
        urwid_outcome_group 'Applied, verification still open' "${applied_open[@]}" &&
        urwid_outcome_group 'Pending activation' "${activation_pending[@]}" &&
        urwid_outcome_group 'Blocked' "${blocked_ids[@]}" &&
        urwid_outcome_group 'Failed operation' "${failed[@]}" &&
        urwid_outcome_group 'Skipped' "${skipped[@]}" &&
        urwid_outcome_group 'Manual follow-up' "${manual[@]}" &&
        urwid_outcome_group 'Other unresolved checks' "${open_ids[@]}" &&
        urwid_outcome_group 'Restored, review active state' "${restored[@]}" &&
        printf '%s\n\n' 'Full evidence and diffs are in the protected run reports.'
}

urwid_results_request() {
    local result=$1 recheck_note=$2 recheck_id=$3 kind=${4:-results}
    local id file delimiter='' rollback_command='' verify_command
    verify_command=$(urwid_recheck_command) || return 1
    if [[ -n ${BACKUP_RUN-} && -n ${SCRIPT_PATH-} ]]; then
        printf -v rollback_command '%q --rollback %q --output-dir %q' "$SCRIPT_PATH" "$RUN_ID" "$REPORT_BASE"
        if [[ $BACKUP_BASE != /var/lib/rhel8-stig/backups ]]; then
            printf -v rollback_command '%s --backup-dir %q' "$rollback_command" "$BACKUP_BASE"
        fi
    fi
    printf '{"kind":'
    json_string "$kind"
    printf ',"exit_code":%s' "$result"
    printf ',"approval_stopped":'
    urwid_prompt_boolean "${URWID_APPROVAL_STOPPED:-0}"
    urwid_prompt_value mode "$MODE"
    urwid_prompt_value run_id "$RUN_ID"
    urwid_prompt_value run_dir "$RUN_DIR"
    urwid_prompt_value backup_dir "${BACKUP_RUN-}"
    urwid_prompt_value rollback_command "$rollback_command"
    urwid_prompt_value verification_command "$verify_command"
    urwid_prompt_value recheck_note "$recheck_note"
    if [[ $FORMAT == json ]] && (( ! ${URWID_APPROVAL_STOPPED:-0} )); then
        urwid_prompt_value recheck_id "$recheck_id"
    fi
    urwid_prompt_value format "$FORMAT"
    urwid_prompt_value operator "${OPERATOR-}"
    urwid_prompt_value summary "$(render_applied_ids)"
    printf ',"rows":['
    for id in "${SCOPE[@]}"; do
        printf '%s{"id":' "$delimiter"
        json_string "$id"
        urwid_prompt_value title "${TITLE[$id]}"
        urwid_prompt_value before "${BEFORE[$id]}"
        urwid_prompt_value assessment "${AFTER[$id]}"
        urwid_prompt_value action "${ACTIONS[$id]}"
        urwid_prompt_value evidence "${DETAIL[$id]}"
        printf '}'
        delimiter=,
    done
    printf '],"files":['
    delimiter=''
    for file in summary.txt diff.txt preview.txt admin-actions.txt changes.txt ckl-import.txt \
                results.json results.csv run.log; do
        [[ -f $RUN_DIR/$file && ! -L $RUN_DIR/$file ]] || continue
        printf '%s{"name":' "$delimiter"
        json_string "$file"
        urwid_prompt_value path "$RUN_DIR/$file"
        printf '}'
        delimiter=,
    done
    printf ']}'
}

urwid_invoke_recheck() {
    /bin/bash -p "$SCRIPT_PATH" "$@"
}

urwid_recheck_report_id() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$URWID_PYTHON" -I -c '
import json, re, sys
try:
    with open(sys.argv[1], "rb") as report:
        data = report.read(4 * 1024 * 1024 + 1)
    if len(data) > 4 * 1024 * 1024:
        raise ValueError()
    result = json.loads(data.decode("utf-8"))
    run_id = result["run_id"]
    if (not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}", run_id)
        or result["mode"] != "status"
        or [result[key] for key in ("host_id", "script_sha256", "archive_sha256")] != sys.argv[2:]):
        raise ValueError()
except (OSError, ValueError, TypeError, KeyError, RecursionError):
    sys.exit(1)
print(run_id)
' "$1" "$HOST_ID" "$SCRIPT_HASH" "$ARCHIVE_SHA256"
}

urwid_run_recheck() {
    local result new_id output=$TUI_TEMP/recheck.json recheck_color=never
    local -a URWID_RECHECK_ARGS=()
    URWID_RECHECK_ID=''
    URWID_RECHECK_NOTE='Recheck could not start. Use the recorded command with the same verified build.'
    (( ${#SCOPE[@]} )) && verify_script && urwid_set_recheck_args || return 0
    if (( EUID == 0 )) && ! trust_script_location; then return 0; fi
    if (( TUI_COLOR )); then recheck_color=$COLOR; fi

    printf '\n%s\n' 'Running a read-only Status recheck of the saved scope.' >&"$TUI_FD"
    urwid_invoke_recheck "${URWID_RECHECK_ARGS[@]}" --color "$recheck_color" > "$output"
    result=$?
    if new_id=$(urwid_recheck_report_id "$output") && [[ $new_id != "$RUN_ID" ]] &&
       verify_digest "$REPORT_BASE/$new_id/manifest"; then
        URWID_RECHECK_ID=$new_id
        URWID_RECHECK_NOTE="Recheck saved $new_id (Status exit $result)."
        if (( ${URWID_APPROVAL_STOPPED:-0} )); then
            URWID_RECHECK_NOTE+=' Compare completed runs from history.'
        elif [[ $FORMAT == json ]]; then
            URWID_RECHECK_NOTE+=' Use Compare recheck to review changes.'
        else
            URWID_RECHECK_NOTE+=' Both runs need JSON reports for comparison.'
        fi
    else
        URWID_RECHECK_NOTE="Recheck ended with status $result without a verified result."
        if ! urwid_site_snapshot_matches 2>/dev/null; then
            URWID_RECHECK_NOTE+=' Effective site settings differ from the recorded run.'
        elif ! verify_digest "$RUN_DIR/manifest" 2>/dev/null; then
            URWID_RECHECK_NOTE+=' The original manifest could not be verified.'
        else
            URWID_RECHECK_NOTE+=' Review the terminal messages.'
        fi
    fi
    rm -f -- "$output"
}

tui_apply_results() {
    local result=$1 request response kind status action
    local URWID_RECHECK_NOTE='' URWID_RECHECK_ID=''
    while :; do
        request=$(urwid_results_request "$result" "$URWID_RECHECK_NOTE" "$URWID_RECHECK_ID") || return 2
        response=$(urwid_one_shot "$request") || return 2
        IFS=$'\037' read -r kind status action <<< "$response"
        [[ $kind == modal ]] || return 2
        if [[ -z $action && $status =~ ^[012]$ ]]; then return 0; fi
        case $status:$action in
            0:recheck) urwid_run_recheck || return 2 ;;
            0:findings)
                request=$(urwid_results_request "$result" "" "" outcomes) || return 2
                urwid_one_shot "$request" > /dev/null || return 2 ;;
            0:compare-recheck)
                [[ $FORMAT == json && -n $URWID_RECHECK_ID ]] && (( ! ${URWID_APPROVAL_STOPPED:-0} )) || return 2
                request=$(urwid_recheck_comparison_request) || return 2
                urwid_one_shot "$request" > /dev/null || return 2 ;;
            *) return 2 ;;
        esac
    done
}

urwid_recheck_comparison_request() {
    printf '{"kind":"compare"'
    urwid_prompt_value report_dir "$REPORT_BASE"
    urwid_prompt_value original "$RUN_ID"
    urwid_prompt_value recheck "$URWID_RECHECK_ID"
    printf '}'
}

urwid_release_result_lock() {
    if [[ -n ${LOCK_FD-} ]]; then
        exec {LOCK_FD}>&-
        LOCK_FD=''
    fi
}

urwid_stop_presentation() {
    URWID_FORCE_TTY_RESTORE=1
    exit "$1"
}

urwid_ui_check() {
    local result=0 interpreter terminal=${TERM:-dumb}
    printf 'Urwid STIG Assistant %s\n\n' "$SCRIPT_VERSION" || return 70
    if preflight; then
        printf 'Host       RHEL 8.10 %s, %s, kernel %s\n' "$ARCH" "$BOOT_MODE" "$KERNEL"
    else
        result=69
    fi
    if interpreter=$(urwid_find_python); then
        printf 'Interface  '
        env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$interpreter" -I -c \
            'import sys, urwid; print("Python {} / Urwid {}".format(sys.version.split()[0], urwid.__version__))' ||
            return 70
    else
        printf '%s\n' 'Interface  install python3-urwid from approved RHEL repositories or the verified RHEL 8.10 DVD'
        result=69
    fi
    if [[ -t 0 && $terminal != dumb && $terminal =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$ ]]; then
        printf 'Terminal   %s\n' "$terminal"
    else
        printf '%s\n' 'Terminal   open an interactive terminal with a supported TERM value'
        result=69
    fi
    if have_tools diff; then
        printf '%s\n' 'Diff       diffutils available'
    else
        printf '%s\n' 'Diff       install diffutils to enable file-content differences'
    fi
    if urwid_ckl_python_available; then
        printf '%s\n' 'Legacy CKL python3 with Expat available'
    else
        printf '%s\n' 'Legacy CKL install python3 with Expat to import .ckl files'
    fi
    if (( EUID == 0 )); then
        printf '%s\n' 'Access     root. Apply still needs a trusted script path and attended approval.'
    else
        printf '%s\n' 'Access     standard account. Some checks need sudo for evidence. Apply and rollback require root.'
    fi
    return "$result"
}
