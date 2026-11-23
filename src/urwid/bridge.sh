# Urwid edition only. The original CLI, scope resolver, planners, and
# transaction guards remain the authority for findings and changes.

urwid_find_python() {
    local python
    for python in /usr/bin/python3 /usr/libexec/platform-python; do
        [[ -x $python ]] || continue
        if env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C \
            "$python" -I -c 'import sys, urwid; sys.exit(int(sys.version_info < (3, 6)))' >/dev/null 2>&1; then
            printf '%s\n' "$python"
            return
        fi
    done
    return 1
}

urwid_ckl_python_available() {
    have_tools python3 && timeout 3 python3 -I -c 'import xml.parsers.expat' >/dev/null 2>&1
}

urwid_color_enabled() {
    local terminal=$1 colors
    if [[ $COLOR == always ]]; then return 0; fi
    [[ $COLOR == auto && ! ${NO_COLOR+x} && $terminal != dumb ]] || return 1
    if have_tools tput && colors=$(TERM="$terminal" tput colors 2>/dev/null); then
        [[ $colors =~ ^[0-9]+$ ]] && (( colors >= 8 ))
        return
    fi
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C "$URWID_PYTHON" -I -c \
        'import curses, sys; curses.setupterm(sys.argv[1]); sys.exit(curses.tigetnum("colors") < 8)' \
        "$terminal" >/dev/null 2>&1
}

tui_prepare() {
    TUI_TEMP='' TUI_FD='' TUI_TERM=${TERM:-dumb} TUI_COLOR=0
    URWID_IN='' URWID_OUT='' URWID_CHILD='' URWID_TTY_STATE=''
    if [[ ! -t 0 || ! $TUI_TERM =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$ || $TUI_TERM == dumb ]]; then
        blocked 'Urwid needs an interactive controlling terminal and a supported TERM value'
        return
    fi
    if ! URWID_PYTHON=$(urwid_find_python); then
        blocked 'Urwid needs Python 3.6 or later and python3-urwid. Use sudo dnf install python3 python3-urwid with approved RHEL repositories or the verified RHEL 8.10 DVD, or run without --gui.'
        return
    fi
    if ! TUI_TEMP=$(mktemp -d -- /var/tmp/rhel8-stig-urwid.XXXXXXXX) ||
       ! { exec {TUI_FD}<> /dev/tty; } 2>/dev/null || [[ ! -t $TUI_FD ]] ||
       ! URWID_TTY_STATE=$(stty -g <&"$TUI_FD") ||
       ! urwid_program > "$TUI_TEMP/app.py"; then
        tui_close
        operational_error 'could not prepare the private Urwid terminal session'
        return
    fi
    if urwid_color_enabled "$TUI_TERM"; then TUI_COLOR=1; fi
    return 0
}

urwid_stop_workbench() {
    local attempt result=0
    if [[ -n ${URWID_OUT-} ]]; then
        exec {URWID_OUT}>&-
        URWID_OUT=''
    fi
    if [[ -n ${URWID_IN-} ]]; then
        exec {URWID_IN}<&-
        URWID_IN=''
    fi
    if [[ -n ${URWID_CHILD-} ]]; then
        for (( attempt=0; attempt<20; attempt++ )); do
            kill -0 "$URWID_CHILD" 2>/dev/null || break
            sleep 0.05
        done
        if kill -0 "$URWID_CHILD" 2>/dev/null; then
            result=1
            kill -TERM "$URWID_CHILD" 2>/dev/null || true
            sleep 0.2
        fi
        if kill -0 "$URWID_CHILD" 2>/dev/null; then
            kill -KILL "$URWID_CHILD" 2>/dev/null || true
            for (( attempt=0; attempt<20; attempt++ )); do
                kill -0 "$URWID_CHILD" 2>/dev/null || break
                sleep 0.05
            done
        fi
        if ! kill -0 "$URWID_CHILD" 2>/dev/null; then
            wait "$URWID_CHILD" 2>/dev/null || result=1
        else
            result=1
        fi
        URWID_CHILD=''
    fi
    if [[ -n ${URWID_TTY_STATE-} && -n ${TUI_FD-} ]]; then
        stty "$URWID_TTY_STATE" <&"$TUI_FD" 2>/dev/null || result=1
        if (( result || ${URWID_FORCE_TTY_RESTORE:-0} )) && have_tools tput; then
            TERM="$TUI_TERM" tput rmcup 1>&"$TUI_FD" 2>/dev/null || true
            TERM="$TUI_TERM" tput cnorm 1>&"$TUI_FD" 2>/dev/null || true
        fi
        URWID_TTY_STATE=''
    fi
    return "$result"
}

tui_close() {
    urwid_stop_workbench || true
    if [[ -n ${TUI_FD-} ]]; then
        exec {TUI_FD}>&-
        TUI_FD=''
    fi
    if [[ ${TUI_TEMP-} =~ ^/var/tmp/rhel8-stig-urwid\.[A-Za-z0-9]{8}$ && -d $TUI_TEMP && ! -L $TUI_TEMP ]]; then
        rm -f -- "$TUI_TEMP/app.py" "$TUI_TEMP/ui.log" "$TUI_TEMP/backend.log" \
            "$TUI_TEMP/selection.ids" "$TUI_TEMP/request.json" "$TUI_TEMP/prompt.json" \
            "$TUI_TEMP/view.txt" "$TUI_TEMP/recheck.json" || true
        rmdir -- "$TUI_TEMP" || true
        TUI_TEMP=''
    fi
    return 0
}

# Encode with the existing JSON writer, removing controls other than tabs and
# newlines. A finding title, path or evidence never becomes shell source.
urwid_json_string() {
    local unsafe=$'[\001-\010\013-\037\177]'
    json_string "${1//$unsafe/}"
}

urwid_json_fields() {
    local separator=''
    while (( $# >= 2 )); do
        printf '%s"%s":' "$separator" "$1"
        urwid_json_string "$2"
        separator=,
        shift 2
    done
}

urwid_event() {
    local kind=$1
    printf '{'
    urwid_json_fields type "$kind" message "$2"
    printf '}\n'
}

urwid_rows() {
    local phase=${1:-browse} id result handling area action status ready selected separate linked history
    local scope_added ssh_shared
    local spacer=''
    printf '['
    for id in "${SCOPE[@]}"; do
        if [[ $phase == browse && ! ${TUI_ALLOWED[$id]+allowed} ]]; then continue; fi
        tui_assessment "$id"; result=$REPLY
        tui_handling "$id"; handling=$REPLY
        tui_area "$id"; area=$REPLY
        tui_action_summary "$id"; action=$REPLY
        status=${ACTIONS[$id]-UNCHANGED}
        ready=false selected=false separate=false linked=${PLANNED_BY[$id]-} history=''
        scope_added=false ssh_shared=false
        if [[ ${CKL_PATH-} ]]; then history=${CKL_HISTORY[$id]-}; fi
        if [[ ${PREVIEW_KEY[$id]+planned} ]]; then separate=true; ready=true; fi
        if [[ $linked ]]; then ready=true; fi
        if [[ ${TUI_SELECTED[$id]+selected} ]]; then selected=true; fi
        if [[ ${SSH_SCOPE_ADDED[$id]+added} ]]; then scope_added=true; fi
        if attended_ssh_id "$id"; then ssh_shared=true; fi
        printf '%s{' "$spacer"
        urwid_json_fields id "$id" title "${TITLE[$id]}" cat "${CATEGORY[$id]}" \
            risk "${PREVIEW_RISK[$id]:-${RISK[$id]}}" result "$result" handling "$handling" area "$area" \
            evidence "${DETAIL[$id]-}" action "$action" outcome "$status" \
            plan "${DISPLAY_PLAN[$id]-}" diff "${DISPLAY_DIFF[$id]-}" linked "$linked" \
            ckl_status "$history"
        printf ',"ready":%s,"selected":%s,"operation":%s,"scope_added":%s,"ssh_shared":%s}' \
            "$ready" "$selected" "$separate" "$scope_added" "$ssh_shared"
        spacer=,
    done
    printf ']'
}

urwid_state() {
    local reset=$1 can_apply=false diff_available=false elevated=false assessed=false assess_on_open=false
    if [[ $MODE == apply ]]; then
        can_apply=true
        if (( SELECT_EXPLICIT )); then assess_on_open=true; fi
    fi
    if have_tools diff; then diff_available=true; fi
    if (( EUID == 0 )); then elevated=true; fi
    if (( URWID_ASSESSED )); then assessed=true; fi
    printf '{"type":"state","context":{'
    urwid_json_fields host "${HOST_NAME:-unavailable}" mode "$MODE" version "$SCRIPT_VERSION" \
        baseline "$BASELINE" source "${CKL_UI_SUMMARY:-Embedded catalog}" \
        risk "$MAX_RISK" risk_cap "$URWID_RISK_CAP" format "$FORMAT" group "$REPORT_GROUP_BY" \
        site_config "$CONFIG_FILE" report_dir "$REPORT_BASE" backup_dir "$BACKUP_BASE" \
        arch "${ARCH:-unavailable}" kernel "${KERNEL:-unavailable}" boot_mode "${BOOT_MODE:-unavailable}" \
        archive_sha256 "$ARCHIVE_SHA256" script_sha256 "${SCRIPT_HASH:-unavailable}" \
        ckl_path "$CKL_PATH" ckl_sha256 "$CKL_SHA256" resume "$RESUME_ID" operator "${OPERATOR-}"
    printf ',"can_apply":%s,"diff_available":%s,"elevated":%s,"defer":%s,"defer_required":%s,"assessed":%s,"scope_count":%s,"review_each":%s,"assess_selected_on_open":%s},' \
        "$can_apply" "$diff_available" "$elevated" "$DEFER" "$URWID_DEFER_CAP" "$assessed" \
        "${#TUI_IDS[@]}" "$REVIEW_EACH" "$assess_on_open"
    printf '"reset_selection":%s,"rows":' "$reset"
    if (( URWID_ASSESSED )); then urwid_rows; else printf '[]'; fi
    printf '}\n'
}

urwid_progress() {
    local complete=$1 count=$2 id=$3
    [[ -n ${URWID_OUT-} ]] || return 0
    {
        printf '{"type":"progress","complete":%s,"count":%s,"id":' "$complete" "$count"
        json_string "$id"
        printf '}\n'
    } >&"$URWID_OUT"
}

urwid_browse() {
    local reset=${1:-false}
    if (( ! URWID_ASSESSED )); then reset=true; fi
    tui_backend_refresh browse || return 1
    URWID_ASSESSED=1
    urwid_state "$reset"
}

# Review uses the transaction engine's live result maps. Keep the earlier
# browse results available for navigation and subsequent Details requests.
readonly -a URWID_BROWSE_FIELDS=(EFFECTIVE TUI_SELECTED BEFORE AFTER ACTIONS DETAIL DISPLAY_PLAN DISPLAY_DIFF
    PLANNED_BY GROUPED_BY PREVIEW_KEY PREVIEW_RISK PREVIEW_GROUP ASSESSMENT_SOURCE ASSESSMENT_AT SSH_SCOPE_ADDED)

urwid_hold_browse() {
    if (( ${#URWID_BROWSE_SCOPE[@]} )); then return 0; fi
    local field id
    URWID_BROWSE_SCOPE=("${SCOPE[@]}")
    for field in "${URWID_BROWSE_FIELDS[@]}"; do
        local -n result_map="$field"
        for id in "${!result_map[@]}"; do
            URWID_BROWSE_DATA["$field:$id"]=${result_map[$id]}
        done
    done
}

urwid_restore_browse() {
    if (( ! ${#URWID_BROWSE_SCOPE[@]} )); then return 0; fi
    local field id key
    SCOPE=("${URWID_BROWSE_SCOPE[@]}")
    for field in "${URWID_BROWSE_FIELDS[@]}"; do
        local -n result_map="$field"
        result_map=()
        for id in "${SCOPE[@]}"; do
            key=$field:$id
            if [[ ${URWID_BROWSE_DATA[$key]+saved} ]]; then
                result_map[$id]=${URWID_BROWSE_DATA[$key]}
            fi
        done
    done
    URWID_BROWSE_SCOPE=() URWID_BROWSE_DATA=() URWID_REVIEW_TOKEN=''
}

urwid_modal_json() {
    local kind=$1 title=$2 prompt=$3 yes=$4 no=$5 initial=$6 spacer=''
    shift 6
    printf '{'
    urwid_json_fields type modal kind "$kind" title "$title" text "$prompt" \
        yes "$yes" no "$no" initial "$initial"
    printf ',"choices":['
    while (( $# >= 2 )); do
        printf '%s{' "$spacer"
        urwid_json_fields id "$1" label "$2"
        printf '}'
        spacer=,
        shift 2
    done
    printf ']}\n'
}

urwid_split_command() {
    local line=$1 separator=$'\x1f' field
    URWID_FIELDS=()
    (( ${#line} <= 32768 )) || return 1
    while [[ $line == *"$separator"* ]]; do
        field=${line%%"$separator"*}
        [[ $field != *[[:cntrl:]]* ]] || return 1
        URWID_FIELDS+=("$field")
        (( ${#URWID_FIELDS[@]} <= 16 )) || return 1
        line=${line#*"$separator"}
    done
    [[ $line != *[[:cntrl:]]* ]] || return 1
    URWID_FIELDS+=("$line")
}

urwid_read_command() {
    local line
    # This pipe carries submitted commands. The operator may be reading or typing without sending one.
    TMOUT=0 IFS= read -r -n 32769 -u "$URWID_IN" line || return 1
    urwid_split_command "$line" || return 2
}

urwid_modal() {
    local payload answer
    # Modal replies are nested during CKL transfer. Keep the outer command
    # fields in the enclosing dispatcher intact.
    local -a URWID_FIELDS=()
    payload=$(urwid_modal_json "$@") || return 2
    if [[ -n ${URWID_OUT-} ]]; then
        printf '%s\n' "$payload" 1>&"$URWID_OUT" || return 2
        urwid_read_command || return 2
    else
        answer=$(urwid_one_shot "$payload") || return 2
        urwid_split_command "$answer" || return 2
    fi
    if (( ${#URWID_FIELDS[@]} != 3 )) || [[ ${URWID_FIELDS[0]} != modal ]]; then return 2; fi
    case ${URWID_FIELDS[1]} in
        0) TUI_REPLY=${URWID_FIELDS[2]}; return 0 ;;
        1) return 1 ;;
        *) return 2 ;;
    esac
}

tui_message() {
    local result
    if (( ${URWID_CAPTURE_MESSAGE:-0} )); then
        URWID_INLINE_TITLE=$1
        URWID_INLINE_MESSAGE=$2
        return 0
    fi
    urwid_modal message "$1" "$2" OK Back ''
    result=$?
    if (( result == 2 )); then return 2; fi
    return 0
}

tui_confirm() {
    local result
    urwid_modal confirm "$1" "$2" "$3" "$4" ''
    result=$?
    if [[ $1 == 'Load selection' ]] && (( result == 0 )); then URWID_LOAD_ACCEPTED=1; fi
    return "$result"
}

tui_choose() {
    local title=$1 description=$2 result index tag
    shift 2
    local -a choices=("$@")
    if (( ${#choices[@]} == 0 || ${#choices[@]} % 2 )); then return 2; fi
    TUI_CHOICE=''
    urwid_modal choice "$title" "$description" Select Back '' "${choices[@]}"
    result=$?
    if (( result != 0 )); then return "$result"; fi
    for (( index=0; index<${#choices[@]}; index+=2 )); do
        tag=${choices[index]}
        if [[ $TUI_REPLY == "$tag" && $tag =~ ^[A-Za-z0-9_-]+$ ]]; then
            TUI_CHOICE=$tag
            return 0
        fi
    done
    return 2
}

tui_input() {
    if [[ -n ${URWID_INLINE_PATH-} && ( $1 == 'Save selection' || $1 == 'Load selection' ) ]]; then
        TUI_REPLY=$URWID_INLINE_PATH
        return 0
    fi
    urwid_modal input "$1" "$2" Continue Back "$3" || return
    [[ ${#TUI_REPLY} -le 1024 && $TUI_REPLY != *[[:cntrl:]]* ]] || return 2
}

urwid_set_selected() {
    local csv=$1 id
    local -a ids=()
    local -A validated=()
    [[ $csv =~ ^V-[0-9]{6}(,V-[0-9]{6})*$ ]] || return 1
    IFS=, read -r -a ids <<< "$csv"
    (( ${#ids[@]} <= ${#TUI_IDS[@]} )) || return 1
    for id in "${ids[@]}"; do
        [[ ${TUI_ALLOWED[$id]+allowed} && ! ${validated[$id]+duplicate} ]] || return 1
        validated[$id]=1
    done
    TUI_SELECTED=()
    for id in "${ids[@]}"; do TUI_SELECTED[$id]=1; done
}

urwid_allowed_id() {
    known_id "$1" && [[ ${TUI_ALLOWED[$1]+allowed} ]]
}

urwid_assessed_id() {
    known_id "$1" && [[ ${AFTER[$1]+assessed} && ( ${TUI_ALLOWED[$1]+allowed} || ${SSH_SCOPE_ADDED[$1]+related} ) ]]
}

urwid_review_token() {
    local id
    {
        printf '%s\0' "$SCRIPT_HASH" "$CKL_SHA256" "$MODE" "$MAX_RISK" "$DEFER" "$URWID_REVIEW_SEQ"
        for id in "${SCOPE[@]}"; do
            printf '%s\0' "$id" "${PREVIEW_KEY[$id]-}" "${AFTER[$id]-}" "${DISPLAY_PLAN[$id]-}" \
                "${SSH_SCOPE_ADDED[$id]-}"
        done
    } | sha256sum
}

urwid_send_review() {
    local csv=$1 focused=$2 review
    local IMPLEMENT_DIFF=1
    if ! urwid_site_snapshot_matches; then
        urwid_event error 'The site configuration changed. Press F7 for Run settings, then rebuild the preview.'
        return
    fi
    if (( ! URWID_ASSESSED )) || [[ -n $focused && $focused != "$csv" ]]; then
        urwid_event error 'Select one or more available findings. An individual review requires exactly its focused ID.'
        return
    fi
    urwid_hold_browse
    if ! urwid_set_selected "$csv"; then
        urwid_restore_browse
        urwid_event error 'Select one or more available findings. An individual review requires exactly its focused ID.'
        return
    fi
    if ! tui_backend_refresh review || (( ! ${#SCOPE[@]} )); then
        urwid_restore_browse
        urwid_event error 'Could not reassess the requested scope. Refresh it or reimport the source checklist.'
        return
    fi
    (( URWID_REVIEW_SEQ++ ))
    if ! URWID_REVIEW_TOKEN=$(urwid_review_token); then return 2; fi
    URWID_REVIEW_TOKEN=${URWID_REVIEW_TOKEN%% *}
    if [[ $focused && $MODE == apply ]]; then
        review=$(tui_implement_preview "$focused") || return 2
    else
        review=$(render_apply_preview) || return 2
    fi
    printf '{'
    urwid_json_fields type review token "$URWID_REVIEW_TOKEN" focused "$focused" text "$review"
    printf ',"rows":'
    urwid_rows review
    printf '}\n'
}

urwid_send_detail() {
    local id=$1 body
    if ! urwid_allowed_id "$id"; then
        urwid_event error 'This finding is outside the available scope.'
        return
    fi
    body=$(tui_details_text "$id" && printf '\nOfficial check\n%s\n\nOfficial fix reference\n%s\n' \
        "${OFFICIAL_CHECK[$id]}" "${OFFICIAL_FIX[$id]}") || return 2
    printf '{'
    urwid_json_fields type detail id "$id" title "${TITLE[$id]}" text "$body"
    printf '}\n'
}

urwid_resolution_field() {
    printf '{'
    urwid_json_fields key "$1" label "$2" prompt "$3" value "$4"
    printf '}'
}

urwid_send_resolution() {
    local id=$1 body
    if ! urwid_assessed_id "$id"; then
        urwid_event error 'Assess this finding within the available scope before opening Resolve.'
        return
    fi
    if resolution_supported "$id"; then body=$(resolution_text "$id") || return 2
    else body=$(render_admin_action "$id") || return 2; fi
    printf '{'
    urwid_json_fields type resolution id "$id" title "${TITLE[$id]}" text "$body"
    printf ',"inputs":['
    if resolution_supported "$id"; then
        urwid_resolution_field evidence-note 'Record evidence reference' \
            'Enter a non-sensitive reference to approved evidence. The note is saved with this finding in the run report.' \
            "${RESOLUTION_NOTES[$id]-}"
        if [[ $id == V-230484 ]]; then
            printf ','
            urwid_resolution_field approved-time-source 'Set approved time source' \
                'Enter the DNS hostname or IPv4 address your site approved. The tool will reassess before proposing any edit.' \
                "${CHRONY_RUN_SERVER:-${CHRONY_APPROVED_SERVER-}}"
        fi
    fi
    printf ']'
    if [[ $id == V-251710 ]]; then printf ',"aide_check":true'; fi
    printf '}\n'
}

urwid_check_aide() {
    if [[ $1 != V-251710 ]] || ! urwid_assessed_id "$1"; then
        urwid_event error 'Assess V-251710 before collecting its AIDE evidence.'
        return
    fi
    resolution_aide_check || return 2
    urwid_send_resolution "$1"
}

urwid_reassess_time_source() {
    local value=$1 csv=$2 previous_server=${CHRONY_RUN_SERVER-}
    if ! urwid_site_snapshot_matches || ! verify_selection_source; then
        urwid_event error 'The site configuration or checklist changed. Recheck the source before proceeding.'
        return
    fi
    urwid_restore_browse
    URWID_REVIEW_TOKEN=''
    urwid_hold_browse
    if [[ $csv ]]; then
        if ! urwid_set_selected "$csv"; then
            urwid_restore_browse
            urwid_event error 'Select only findings currently available in this session.'
            return
        fi
    else
        TUI_SELECTED=()
    fi
    CHRONY_RUN_SERVER=$value
    if ! tui_backend_refresh browse; then
        CHRONY_RUN_SERVER=$previous_server
        urwid_restore_browse
        urwid_event error 'Reassessment could not finish. The previous time source and selection were restored.'
        return
    fi
    URWID_BROWSE_SCOPE=() URWID_BROWSE_DATA=()
    urwid_state true
}

urwid_resolution_input() {
    local id=$1 key=$2 value=$3 csv=$4
    if ! urwid_assessed_id "$id"; then
        urwid_event error 'Choose an assessed finding in the current view.'
        return
    fi
    case $key in
        evidence-note)
            if resolution_note_set "$id" "$value"; then urwid_send_resolution "$id"
            else urwid_event error 'Use at most 512 bytes and omit control characters.'; fi ;;
        approved-time-source)
            if [[ $id == V-230484 ]] && chrony_valid_approved_server "$value"; then
                urwid_reassess_time_source "$value" "$csv"
            else
                urwid_event error 'Use a valid site-approved DNS hostname or IPv4 address for V-230484.'
            fi ;;
        *) urwid_event error 'This finding has no input with that name.' ;;
    esac
}

urwid_prepare_scope() {
    local action=$1 path=$2 result
    local URWID_INLINE_PATH=$path URWID_LOAD_ACCEPTED=0 URWID_CAPTURE_MESSAGE=1
    local URWID_INLINE_TITLE='' URWID_INLINE_MESSAGE=''
    URWID_SCOPE_MESSAGE=''
    if [[ $action != scan ]] && { [[ ${#path} -gt 1024 ]] || ! valid_output_path "$path"; }; then
        if [[ $action == import ]]; then URWID_SCOPE_MESSAGE='Use an absolute local path to a legacy CKL file.'
        else URWID_SCOPE_MESSAGE='Use an absolute local selection file path.'; fi
        return 1
    fi
    case $action in
        scan)
            if tui_backend_refresh browse; then return 0; fi
            URWID_SCOPE_MESSAGE='Could not assess these settings. Refresh the scope or reimport its checklist.'
            return 1 ;;
        import)
            tui_backend_import "$path"
            result=$?
            URWID_SCOPE_MESSAGE=$URWID_INLINE_MESSAGE
            if (( result == 0 )); then tui_index || return 2; fi
            return "$result" ;;
        load)
            tui_load_selection || return 2
            URWID_SCOPE_MESSAGE=$URWID_INLINE_MESSAGE
            if (( ! URWID_LOAD_ACCEPTED )); then return 1; fi
            tui_backend_refresh browse || return 2
            return 0 ;;
        *) return 2 ;;
    esac
}

urwid_scope_response() {
    local action=$1 result=$2 problem=$3 reset=false
    case $result in
        0)
            if (( ! URWID_ASSESSED )) || [[ $action != scan ]]; then reset=true; fi
            URWID_ASSESSED=1
            urwid_state "$reset" ;;
        1)
            if [[ -n $problem ]]; then urwid_event error "$problem"
            else urwid_event notice 'Scope and run settings kept.'; fi ;;
        *) return 2 ;;
    esac
}

urwid_probe_destination() {
    local target=$1 allow_sticky=$2 detail free
    local URWID_PROBE_DIRECTORY=''
    if ! secure_directory "$target" probe "$allow_sticky"; then
        printf '%s' 'Unavailable. Use a private directory or a writable protected parent with no symbolic links.'
        return 1
    fi
    if ! local_filesystem "$URWID_PROBE_DIRECTORY"; then
        printf '%s' 'Unavailable. Use a supported local filesystem.'
        return 1
    fi
    if [[ $target == "$URWID_PROBE_DIRECTORY" ]]; then
        detail='Existing private directory.'
    else
        detail='Private directory can be created when needed.'
    fi
    free=$(df -Pk -- "$URWID_PROBE_DIRECTORY" 2>/dev/null | awk 'END {print $4}') || free=''
    if [[ $free =~ ^[0-9]+$ ]]; then detail+=" Available space $(( free / 1024 )) MiB."; fi
    printf '%s' "$detail"
}

urwid_inspect_setup() {
    local mode=$1 risk=$2 defer=$3 format=$4 reports=$5 report_status=$6 backups=$7 backup_status=$8
    local site_status=${9:-'Using built-in site defaults.'}
    local text activation='as proposed' diff_status='available' ckl_status='available'
    if (( defer )); then activation='defer where supported'; fi
    if ! have_tools diff; then diff_status='diffutils is required for file previews'; fi
    if ! urwid_ckl_python_available; then
        ckl_status='Python 3 with Expat is required for legacy CKL'
    fi
    printf -v text 'Host %s  |  %s  |  %s\nBash %s  |  Urwid interpreter %s\nDiff %s\nLegacy CKL %s\n\nMode %s  |  Risk ceiling %s  |  Format %s\nActivation %s\n%s\n\nReport directory\n%s\n%s\n\nBackup directory\n%s\n%s' \
        "${HOST_NAME:-unavailable}" "$ARCH" "$BOOT_MODE" "$BASH_VERSION" "$URWID_PYTHON" \
        "$diff_status" "$ckl_status" "$mode" "$risk" "$format" "$activation" "$site_status" \
        "$reports" "$report_status" "$backups" "$backup_status"
    tui_message 'Run readiness' "$text" || return 2
    urwid_event notice 'Readiness checked. Run settings are still editable.'
}

urwid_set_settings() {
    local action=$1 path=$2
    shift 2
    local mode=$1 risk=$2 defer=$3 format=$4 group=$5 site=$6 reports=$7 backups=$8
    local previous_mode=$MODE previous_risk=$MAX_RISK previous_defer=$DEFER
    local previous_format=$FORMAT previous_group=$REPORT_GROUP_BY previous_config=$CONFIG_FILE
    local previous_reports=$REPORT_BASE previous_backups=$BACKUP_BASE
    local new_managed new_alternates new_chrony previous_managed=$MODPROBE_MANAGED previous_alternates=$GPGCHECK_ALTERNATE_REPOS
    local previous_chrony=${CHRONY_APPROVED_SERVER-}
    local result URWID_SCOPE_MESSAGE='' report_status backup_status='Only used during Apply or Rollback.'
    local site_data site_status='Using built-in site defaults.'
    local report_ok=1 backup_ok=1
    if [[ $MODE == apply ]]; then
        if [[ $mode != apply || -n $group ]]; then
            urwid_event error 'This session was launched for attended Apply. Report grouping applies to read-only runs.'
            return
        fi
    elif [[ ! $mode =~ ^(status|dry-run|diff)$ ]]; then
        urwid_event error 'Launch with --apply to authorize a separate attended Apply session.'
        return
    fi
    if [[ $mode == diff ]] && ! have_tools diff; then
        urwid_event error 'Diff mode requires diffutils from an approved RHEL repository or local media.'
        return
    fi
    if [[ ! $risk =~ ^(low|medium|high)$ || ! $defer =~ ^[01]$ || ! $format =~ ^(text|json|csv)$ ||
          ( -n $group && $group != result ) ]]; then
        urwid_event error 'Check the risk, activation, format, and grouping settings.'
        return
    fi
    if (( $(risk_level "$risk") > $(risk_level "$URWID_RISK_CAP") || defer < URWID_DEFER_CAP )); then
        urwid_event error 'Settings cannot raise the launch risk ceiling or relax required deferred activation.'
        return
    fi
    if ! valid_state_path "$reports" || ! valid_state_path "$backups" ||
       { [[ -n $site && $site != "$CONFIG_FILE" ]] && ! valid_output_path "$site"; }; then
        urwid_event error 'Choose clean absolute report and backup directories and an absolute local site file.'
        return
    fi
    # Parse site data in a subshell; a partially rejected file cannot leave
    # changed options in the live workbench. Returned values use safe grammars.
    if ! site_data=$(urwid_read_site_snapshot "$site" 2>&1); then
        if [[ $site_data == 'Argument error: '* ]]; then urwid_event error "${site_data#Argument error: }"
        else urwid_event error 'Could not read the site file. Use the documented settings in a small local text file.'; fi
        return
    fi
    if ! IFS='|' read -r new_managed new_alternates new_chrony <<< "$site_data"; then
        urwid_event error 'Could not decode the validated site settings.'
        return
    fi
    report_status=$(urwid_probe_destination "$reports" yes) || report_ok=0
    if [[ $mode == apply ]]; then backup_status=$(urwid_probe_destination "$backups" no) || backup_ok=0; fi
    if [[ $action == check ]]; then
        if [[ -n $site ]]; then
            site_status='Site file validated for this assessment.'
            if [[ $site_data != "$MODPROBE_MANAGED|$GPGCHECK_ALTERNATE_REPOS|${CHRONY_APPROVED_SERVER-}" ]]; then
                site_status='Site settings differ from the current session. Findings will reassess with the edited file.'
            fi
        fi
        urwid_inspect_setup "$mode" "$risk" "$defer" "$format" "$reports" "$report_status" \
            "$backups" "$backup_status" "$site_status"
        return
    fi
    if (( ! report_ok )); then
        urwid_event error "Report directory. $report_status"
        return
    fi
    if (( ! backup_ok )); then
        urwid_event error "Backup directory. $backup_status"
        return
    fi
    MODE=$mode MAX_RISK=$risk DEFER=$defer FORMAT=$format
    REPORT_GROUP_BY=$group CONFIG_FILE=$site REPORT_BASE=$reports BACKUP_BASE=$backups
    MODPROBE_MANAGED=$new_managed GPGCHECK_ALTERNATE_REPOS=$new_alternates CHRONY_APPROVED_SERVER=$new_chrony
    urwid_prepare_scope "$action" "$path"
    result=$?
    if (( result != 0 )); then
        MODE=$previous_mode MAX_RISK=$previous_risk DEFER=$previous_defer FORMAT=$previous_format
        REPORT_GROUP_BY=$previous_group CONFIG_FILE=$previous_config REPORT_BASE=$previous_reports BACKUP_BASE=$previous_backups
        MODPROBE_MANAGED=$previous_managed GPGCHECK_ALTERNATE_REPOS=$previous_alternates CHRONY_APPROVED_SERVER=$previous_chrony
    fi
    urwid_scope_response "$action" "$result" "$URWID_SCOPE_MESSAGE"
}

urwid_save_selection() {
    local path=$1 csv=$2
    local URWID_INLINE_PATH=$path URWID_CAPTURE_MESSAGE=1
    local URWID_INLINE_TITLE='' URWID_INLINE_MESSAGE=''
    if [[ ${#path} -gt 1024 ]] || ! valid_output_path "$path"; then
        urwid_event error 'Use an absolute local selection file path.'
        return
    fi
    if ! urwid_set_selected "$csv"; then
        urwid_event error 'Select at least one available finding to save.'
        return
    fi
    tui_save_selection || return 2
    if [[ $URWID_INLINE_TITLE == 'Selection saved' ]]; then
        urwid_event notice "$URWID_INLINE_MESSAGE"
    else
        urwid_event error "${URWID_INLINE_MESSAGE:-Could not save these IDs.}"
    fi
}

urwid_dispatch() {
    local command=$1
    shift
    local scope_result URWID_SCOPE_MESSAGE=''
    case $command:$# in
        resolve:1) urwid_send_resolution "$1"; return ;;
        resolve-input:4) urwid_resolution_input "$@"; return ;;
        resolve-aide:1) urwid_check_aide "$1"; return ;;
    esac
    if [[ $command != accept && $command != detail ]]; then URWID_REVIEW_TOKEN=''; fi
    if [[ $command != accept && $command != review ]]; then urwid_restore_browse; fi
    case $command:$# in
        back:0) printf '{"type":"browse"}\n' ;;
        scan:0)
            urwid_browse || urwid_event error 'Assessment refresh stopped. Check the scope and source checklist.' ;;
        review:2) urwid_send_review "$1" "$2" ;;
        detail:1) urwid_send_detail "$1" ;;
        settings:8) urwid_set_settings scan '' "$@" ;;
        inspect:8) urwid_set_settings check '' "$@" ;;
        setup:10)
            if [[ $1 == import || $1 == load ]]; then urwid_set_settings "$@"
            else urwid_event error 'Choose a supported selection source.'; fi ;;
        import:1|load:1)
            urwid_prepare_scope "$command" "$1"
            scope_result=$?
            urwid_scope_response "$command" "$scope_result" "$URWID_SCOPE_MESSAGE" ;;
        save:2) urwid_save_selection "$@" ;;
        accept:1)
            local current
            if [[ -z $URWID_REVIEW_TOKEN || $1 != "$URWID_REVIEW_TOKEN" ]] ||
               ! verify_selection_source || ! verify_script || ! current=$(urwid_review_token) ||
               [[ ${current%% *} != "$URWID_REVIEW_TOKEN" ]]; then
                URWID_REVIEW_TOKEN=''
                urwid_event error 'That preview is unavailable or changed. Review the scope again.'
                return
            fi
            printf '{"type":"accepted"}\n' || return 2
            return 3 ;;
        cancel:0)
            printf '{"type":"closed"}\n' || return 2
            return 4 ;;
        *) urwid_event error 'Unsupported workbench action.' ;;
    esac
}

tui_run() {
    local result=2 action_status read_fd write_fd diagnostic
    local URWID_REVIEW_TOKEN='' URWID_REVIEW_SEQ=0 URWID_RISK_CAP=$MAX_RISK URWID_DEFER_CAP=$DEFER
    local URWID_ASSESSED=0
    local -a URWID_FIELDS=() URWID_BROWSE_SCOPE=()
    local -A TUI_ALLOWED=() URWID_BROWSE_DATA=()
    tui_index || return 2
    URWID_TTY_STATE=$(stty -g <&"$TUI_FD") || return 2
    coproc URWID_PIPE {
        exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C.UTF-8 \
            TERM="$TUI_TERM" STIG_UI_COLOR="$TUI_COLOR" PYTHONIOENCODING=UTF-8 \
            "$URWID_PYTHON" -I "$TUI_TEMP/app.py" workbench 2> "$TUI_TEMP/ui.log"
    }
    URWID_CHILD=${URWID_PIPE_PID-} read_fd=${URWID_PIPE[0]-} write_fd=${URWID_PIPE[1]-}
    if [[ -z $URWID_CHILD || -z $read_fd || -z $write_fd ]] ||
       ! { exec {URWID_IN}<&"$read_fd" {URWID_OUT}>&"$write_fd"; }; then
        urwid_stop_workbench || true
        return 2
    fi
    exec {read_fd}<&-
    exec {write_fd}>&-
    # Treat a closed private pipe as an I/O failure without ending the shell.
    trap ':' PIPE
    if urwid_state false 1>&"$URWID_OUT"; then
        while urwid_read_command; do
            urwid_dispatch "${URWID_FIELDS[@]}" 1>&"$URWID_OUT" 2>> "$TUI_TEMP/backend.log"
            action_status=$?
            case $action_status in
                0) ;;
                3) result=0; break ;;
                4) result=1; break ;;
                *) break ;;
            esac
        done
    fi
    trap - PIPE
    if ! urwid_stop_workbench; then result=2; fi
    if (( result == 2 )) && [[ -s $TUI_TEMP/ui.log ]]; then
        diagnostic=$(head -c 512 -- "$TUI_TEMP/ui.log" | tr -cd '\012\040-\176' |
            awk '/^Urwid interface: / { print; exit }') || diagnostic=''
        if [[ -n $diagnostic ]]; then printf '%s\n' "$diagnostic" >&2; fi
    fi
    return "$result"
}
