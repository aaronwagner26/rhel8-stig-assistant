#!/bin/bash -p
# rhel8-stig.sh — Attended DISA RHEL 8 assessment and remediation utility.
# 0.5.11-dev | 2026-11-23 | Guided selection, grouped approvals, and follow-up.
# Target: genuine RHEL 8.10 x86_64 with systemd. Boot behavior needs guest validation.
# Baseline: DISA RHEL 8 STIG Version 2 Release 9 (Sunset, 2026-10-05).
# Archive: U_RHEL_8_V2R9_STIG.zip
# SHA-256: 620bdff4d4a5b07b58817297dd5255a3f8f981a7227405c07b098588fe55cdee
#
# 1. Metadata, compatibility, and change history

readonly SCRIPT_VERSION=0.5.11-dev
readonly BASELINE='RHEL 8 STIG V2R9 (Sunset)'
readonly ARCHIVE_SHA256=620bdff4d4a5b07b58817297dd5255a3f8f981a7227405c07b098588fe55cdee
readonly ARCHIVE_URL=https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R9_STIG.zip
readonly ASSESSMENT_CACHE_DEFAULT=1

changelog() {
    cat <<'EOF'
0.5.11-dev (2026-11-23)
  Select the 22 guided findings with --guided. Review verified shared
  module, authentication and audit changes in fewer decisions, run the
  read-only AIDE evidence check, and see outstanding work in Next steps.
0.5.10-dev (2026-11-23)
  Start the shared SSH crypto-policy review from any of its four findings.
  Show all affected IDs and the exact policy diff before one approval.
0.5.9-dev (2026-11-23)
  Guide resolution for 22 findings. Collect approved time sources and
  evidence references, and review the OpenSSL dependency when required.
0.5.8-dev (2026-11-23)
  Separate batch and individual implementation. Show grouped outcomes and
  the exact proposed additions for authored audit rule files.
0.5.7-dev (2026-11-23)
  Remove the optional change ticket field from settings and reports.
0.5.6-dev (2026-11-23)
  Reuse verified unchanged results during Classic Status. Add --fresh and
  report the checks performed live. Fix GRUB and GNOME AWK expressions.
0.5.5-dev (2026-11-23)
  Expand the default coverage from 68 to 164 V2R9 rules. Add guarded
  password policy, audit, sysctl, SSH, metadata, and desktop plans.
  Keep proofs of effective state and activation separate from file staging.
0.5.4-dev (2026-11-20)
  Start read-only text reports with outcome counts. Group by result when
  requested, keeping Vuln-ID order within each group. List applied IDs
  in the Apply results. Highlight the per-change approval prompt and
  the terminal interface's Implementation results screen.
0.5.3-dev (2026-11-20)
  Highlight the focused terminal button. Add navigable Continue and Back
  buttons to the colored Implement preview and identify the Back default
  on confirmation.
0.5.2-dev (2026-11-20)
  Color the headings, assessment and diff in the scrollable individual
  Implement preview. Use the stock text viewer when color is disabled
  or the terminal's Python curses support is unavailable.
0.5.1-dev (2026-11-20)
  Format the individual GUI Implement preview into sections and show
  its redacted before/after diff at the bottom. Remove repeated native
  deltas from the plain-text diff report.
0.5.0-dev (2026-11-20)
  Add 19 guarded attended handlers. Add --diff, --review-each,
  colored approval output, and focused implementation from the GUI.
  Recovery records require the exact script release that created them.
0.4.0-dev (2026-11-20)
  Import legacy DISA CKL XML as historical scope, with exact revision
  checks, recorded asset acknowledgment, and fresh local assessment.
  Browse and select findings with dialog. Review the complete current
  plan, then see each operation alongside its attended approval prompt.
0.3.0-dev (2026-11-20)
  Present all selected changes before attended approval. Accept y/n and allow
  a for remaining unchanged low-risk operations. Stage additional scoped repo,
  boot and desktop changes. Higher-impact plans still need individual approval.
  Genuine RHEL integration remains open. Recovery requires the matching script hash.
0.2.0-dev (2026-11-20)
  Updated the default scope to the 68 requested V2R9 IDs. Added plan previews
  in status and dry-run and scoped file and metadata operations. The default
  risk ceiling is high and all mutations still require attended approval.
  Use reports and backups with the matching script hash. Guest tests remain open.
0.1.0-dev (2026-11-20)
  Initial development release for the 39 requested V2R9 IDs. Includes the pinned
  catalog, selected local checks and guarded staging for module policy candidates.
  RHEL guest apply, activation and recovery verification remain release gates.
EOF
}

# 2. Usage and argument parsing

usage() {
    cat <<'EOF'
Usage: rhel8-stig.sh [mode] [options]

Modes (choose one):
  --status                       Assess current state and show eligible plans (default).
  --dry-run                      Assess and show eligible changes without applying.
  --diff                         Show proposed before/after changes without applying.
  --apply                        Preview all selected changes, then request approval.
                                 Requires root and an interactive terminal.
  --rollback RUN-ID              Preview and confirm supported restoration.
  --list                         List registered rules and available handling.
  --explain V-ID                 Show policy, handling, risk and verification guidance.
  --version | --changelog | --self-hash | --help

Options for run modes:
  --gui | --tui                 Open the optional dialog checklist and plan review.
                                 Compatible with status, dry-run and apply.
  --ckl FILE                    Import Open findings from legacy DISA CKL XML.
  --ckl-section NUMBER          Choose a displayed RHEL 8 section in this CKL.
  --ack-ckl-host SHA256         Acknowledge missing or mismatched host metadata for
                                 exactly this checklist digest. Otherwise prompt.
  --only V-ID[,V-ID...]          Select explicit IDs. May be repeated.
  --guided                       Select all 22 findings with guided resolution.
  --ids-file FILE                Add explicit IDs from a local text file; one per line.
  --skip V-ID[,V-ID...]          Exclude IDs; may be repeated. Skip takes precedence.
  --config FILE                  Read site data such as MODPROBE_MANAGED=yes|no and
                                 GPGCHECK_ALTERNATE_REPOS=repo1,repo2.
  --approved-time-source HOST    Use this site-approved hostname or IPv4 address
                                 when reviewing V-230484.
  --max-risk low|medium|high     Maximum eligible operational risk (default high).
  --review-each                  Ask about each --apply operation individually.
  --defer-service-actions        Allow only changes with safe deferred activation.
  --output-dir DIR               Local report base (default /var/tmp/rhel8-stig-UID).
  --backup-dir DIR               Backup base (default /var/lib/rhel8-stig/backups).
  --format text|json|csv         Stdout and saved result format (default text).
  --group-by result              Group status, dry-run and diff text reports by
                                 result. The default is Vuln-ID order.
  --resume RUN-ID                Reassess a previous run using its original scope.
                                 Use with --apply to request fresh attended changes.
  --fresh                        Check every selected Status finding live.
  --color auto|always|never      Explicit choice wins. Auto honors NO_COLOR/TERM=dumb.
  --no-color                     Same as --color never.
  --verbose                      Show redacted detail in terminal diagnostics.

Repeated --only and --ids-file form a union. The reviewed 164-ID default applies
only when no explicit selector is supplied. ID files accept blank lines and
whole-line # comments. Status and dry-run write protected reports and may use
temporary files. Treat every unresolved finding as open until independently verified.
CKL import needs Python 3 (standard library) and intersects any explicit ID
selection before removing skipped IDs. The approved baseline and exact rule
revisions control mapping. CKLB is a separate format. The GUI needs a compatible
dialog and a terminal. With no explicit selection source it starts unchecked.

Attended apply asks y for a single approved plan, n or Enter to skip, and a
to approve this and remaining unchanged low-risk plans from the full preview.
Sensitive and revised changes require individual approval. EOF stops writes.

Examples:
  ./rhel8-stig.sh --status --only V-230287,V-230494
  ./rhel8-stig.sh --diff --group-by result
  ./rhel8-stig.sh --dry-run --ids-file scope.txt --skip V-230503 --format json
  sudo ./rhel8-stig.sh --apply --only V-230494 --max-risk medium
  sudo ./rhel8-stig.sh --gui --apply --ckl '/path/server.ckl'
  sudo ./rhel8-stig.sh --rollback 20261120T174000Z.A1b2C3d4 --max-risk medium

Exit codes: 0 clean or information, 2 unresolved, 64 usage, 69 blocked,
70 operational error. A self-hash identifies bytes; compare it with a trusted
external digest or signature to establish authenticity.
EOF
}

init_options() {
    MODE=status MODE_SET=0 SELECT_EXPLICIT=0 CONFIG_FILE='' RESUME_ID='' ROLLBACK_ID=''
    EXPLAIN_ID='' COLOR=auto FORMAT=text REPORT_GROUP_BY='' DEFER=0 VERBOSE=0 MAX_RISK=high
    GUI=0 REVIEW_EACH=0 IMPLEMENT_DIFF=0 FORCE_FRESH=0 CKL_FILE='' CKL_PATH='' CKL_SHA256='' CKL_SECTION_OPT='' CKL_HOST_ACK=''
    CKL_UI_SUMMARY='' CKL_ACK_RECORD='' SELECTION_WORK='' TUI_SCANNING=0
    CKL_RESUME_PATH='' CKL_RESUME_SHA256='' CKL_RESUME_SECTION=''
    CHRONY_RUN_SERVER='' SSH_IMPACT_ONLY=0 RESOLUTION_AIDE_RESULT=''
    declare -gA RESOLUTION_NOTES=() SSH_SCOPE_ADDED=()
    declare -gA CKL_MAPPED=() TUI_SELECTED=()
    declare -ga TUI_IDS=()
    REPORT_BASE="/var/tmp/rhel8-stig-$EUID" BACKUP_BASE=/var/lib/rhel8-stig/backups
    CHRONY_APPROVED_SERVER=''
    MODPROBE_MANAGED=unknown GPGCHECK_ALTERNATE_REPOS=''
    declare -gA REQUESTED=() SKIPPED=() EFFECTIVE=()
    declare -ga SCOPE=()
}

usage_error() {
    printf 'Argument error: %s\n' "$1" >&2
    return 64
}

set_mode() {
    if (( MODE_SET )); then usage_error 'choose one mode'; return; fi
    MODE=$1 MODE_SET=1
}

known_id() {
    [[ $1 =~ ^V-[0-9]{6}$ ]] && [[ ${TITLE[$1]+registered} ]]
}

select_ids() {
    local destination=$1 list=$2 id
    local -a ids
    if [[ ! $list =~ ^V-[0-9]{6}(,V-[0-9]{6})*$ ]]; then
        usage_error 'expected a comma-separated list of V-IDs'; return
    fi
    IFS=, read -r -a ids <<< "$list"
    for id in "${ids[@]}"; do
        if ! known_id "$id"; then usage_error "unknown ID $id"; return; fi
        if [[ $destination == REQUESTED ]]; then REQUESTED[$id]=1; else SKIPPED[$id]=1; fi
    done
}

trim_line() {
    TRIMMED=${1%$'\r'}
    TRIMMED=${TRIMMED#"${TRIMMED%%[!$' \t']*}"}
    TRIMMED=${TRIMMED%"${TRIMMED##*[!$' \t']}"}
}

small_regular_file() {
    local size
    [[ -f $1 && ! -L $1 && -r $1 ]] || return 1
    size=$(stat -c '%s' -- "$1") || return 1
    [[ $size =~ ^[0-9]+$ ]] && (( size <= 131072 ))
}

text_input_file() {
    local filtered size
    small_regular_file "$1" || return 1
    size=$(wc -c < "$1") || return 1
    filtered=$(tr -d '\000-\010\013\014\016-\037\177' < "$1" | wc -c) || return 1
    (( size == filtered ))
}

read_ids_file() {
    local file=$1 line TRIMMED seen=0
    if ! text_input_file "$file"; then
        usage_error 'ID file must be small, readable regular text'; return
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        trim_line "$line"
        [[ -n $TRIMMED && $TRIMMED != \#* ]] || continue
        if ! known_id "$TRIMMED"; then usage_error 'invalid or unknown ID in ID file'; return; fi
        REQUESTED[$TRIMMED]=1
        seen=1
    done < "$file"
    if (( ! seen )); then usage_error 'ID file contains no IDs'; fi
}

valid_run_id() {
    [[ $1 =~ ^[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}$ ]]
}

valid_output_path() {
    [[ $1 == /* && $1 != / && $1 != */ && $1 != *//* ]] &&
        [[ $1 != */./* && $1 != */../* && $1 != */. && $1 != */.. ]] &&
        [[ $1 != *[[:cntrl:]]* ]]
}

valid_state_path() {
    valid_output_path "$1" || return 1
    case $1/ in /etc/*|/boot/*|/usr/*|/sys/*|/proc/*|/dev/*|/run/*|/bin/*|/sbin/*|/lib/*|/lib64/*)
        return 1 ;;
    esac
    return 0
}

parse_args() {
    local flag value id run_options=0
    while (( $# )); do
        flag=$1
        shift
        case $flag in
            --status|--dry-run|--diff|--apply|--list|--version|--changelog|--self-hash|--help)
                set_mode "${flag#--}" || return ;;
            --explain|--rollback|--only|--skip|--ids-file|--config|--max-risk|--output-dir|\
            --backup-dir|--format|--group-by|--resume|--color|--approved-time-source|--ckl|--ckl-section|--ack-ckl-host)
                if (( $# == 0 )) || [[ -z $1 || $1 == --* ]]; then
                    usage_error "$flag needs a value"; return
                fi
                value=$1
                shift
                if [[ $flag != --explain && $flag != --rollback ]]; then run_options=1; fi
                case $flag in
                    --explain) set_mode explain || return; EXPLAIN_ID=$value ;;
                    --rollback) set_mode rollback || return; ROLLBACK_ID=$value ;;
                    --only) select_ids REQUESTED "$value" || return; SELECT_EXPLICIT=1 ;;
                    --skip) select_ids SKIPPED "$value" || return ;;
                    --ids-file) read_ids_file "$value" || return; SELECT_EXPLICIT=1 ;;
                    --config) CONFIG_FILE=$value ;;
                    --approved-time-source)
                        if ! chrony_valid_approved_server "$value"; then
                            usage_error '--approved-time-source requires a DNS hostname or IPv4 address'; return
                        fi
                        CHRONY_RUN_SERVER=$value ;;
                    --max-risk) MAX_RISK=$value ;;
                    --output-dir) REPORT_BASE=$value ;;
                    --backup-dir) BACKUP_BASE=$value ;;
                    --format) FORMAT=$value ;;
                    --group-by)
                        if [[ $value != result ]]; then usage_error '--group-by expects result'; return; fi
                        REPORT_GROUP_BY=$value ;;
                    --resume) RESUME_ID=$value ;;
                    --color) COLOR=$value ;;
                    --ckl)
                        if [[ -n $CKL_FILE ]]; then usage_error 'supply a single --ckl file'; return; fi
                        CKL_FILE=$value ;;
                    --ckl-section) CKL_SECTION_OPT=$value ;;
                    --ack-ckl-host) CKL_HOST_ACK=$value ;;
                esac ;;
            --gui|--tui) GUI=1; run_options=1 ;;
            --guided)
                for id in "${RULE_IDS[@]}"; do
                    if resolution_supported "$id"; then REQUESTED[$id]=1; fi
                done
                SELECT_EXPLICIT=1 run_options=1 ;;
            --review-each) REVIEW_EACH=1; run_options=1 ;;
            --fresh) FORCE_FRESH=1; run_options=1 ;;
            --no-color) COLOR=never; run_options=1 ;;
            --defer-service-actions) DEFER=1; run_options=1 ;;
            --verbose) VERBOSE=1; run_options=1 ;;
            *) usage_error 'unrecognized option. See --help'; return ;;
        esac
    done

    case $MODE in
        list|version|changelog|self-hash|help|explain)
            if (( run_options )); then usage_error 'information modes take no run options'; return; fi ;;
    esac
    if [[ $MODE == explain ]] && ! known_id "$EXPLAIN_ID"; then
        usage_error 'unknown ID for --explain'; return
    fi
    if [[ $MODE == rollback && ( $GUI == 1 || -n $CKL_FILE ) ]]; then
        usage_error 'GUI and CKL import are available for status, dry-run, diff and apply'; return
    fi
    if (( REVIEW_EACH )) && [[ $MODE != apply ]]; then
        usage_error '--review-each requires --apply'; return
    fi
    if (( FORCE_FRESH )) && [[ $MODE != status ]]; then
        usage_error '--fresh requires --status'; return
    fi
    if [[ $REPORT_GROUP_BY == result && $MODE != status && $MODE != dry-run && $MODE != diff ]]; then
        usage_error '--group-by result requires --status, --dry-run, or --diff'; return
    fi
    if [[ -n $CKL_SECTION_OPT && ! $CKL_SECTION_OPT =~ ^[1-9][0-9]{0,3}$ ]] ||
       [[ -n $CKL_HOST_ACK && ! $CKL_HOST_ACK =~ ^[0-9a-fA-F]{64}$ ]] ||
       [[ -n $CKL_SECTION_OPT && -z $CKL_FILE ]] ||
       [[ -n $CKL_HOST_ACK && -z $CKL_FILE && -z $RESUME_ID ]]; then
        usage_error 'CKL section requires --ckl and a positive number; host acknowledgment requires a SHA-256 and --ckl or --resume'; return
    fi
    if [[ ! $FORMAT =~ ^(text|json|csv)$ || ! $COLOR =~ ^(auto|always|never)$ ||
          ! $MAX_RISK =~ ^(low|medium|high)$ ]]; then
        usage_error 'invalid format, color, or risk value'; return
    fi
    if ! valid_state_path "$REPORT_BASE" || ! valid_state_path "$BACKUP_BASE"; then
        usage_error 'output and backup directories must be clean absolute paths'; return
    fi
    if [[ -n $RESUME_ID ]]; then
        if ! valid_run_id "$RESUME_ID" || [[ -n $CKL_FILE ]] || (( SELECT_EXPLICIT || ${#SKIPPED[@]} )); then
            usage_error 'resume needs a valid run ID and uses the original selection'; return
        fi
    fi
    if [[ $MODE == rollback ]]; then
        if ! valid_run_id "$ROLLBACK_ID" || [[ -n $RESUME_ID || -n $CONFIG_FILE || -n $CHRONY_RUN_SERVER ]] ||
           (( SELECT_EXPLICIT || ${#SKIPPED[@]} || DEFER )); then
            usage_error 'rollback needs a valid run ID and the original scope'; return
        fi
    fi
    if [[ -n $CONFIG_FILE ]]; then read_site_config "$CONFIG_FILE" || return; fi
    return 0
}

read_site_config() {
    local file=$1 line TRIMMED key value
    local -A seen=()
    if ! text_input_file "$file"; then
        usage_error 'site configuration must be small, readable regular text'; return
    fi
    while IFS= read -r line || [[ -n $line ]]; do
        trim_line "$line"
        [[ -n $TRIMMED && $TRIMMED != \#* ]] || continue
        if [[ ! $TRIMMED =~ ^([A-Z_]+)=(.+)$ ]]; then
            usage_error 'invalid or duplicate site setting'; return
        fi
        key=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
        if [[ ${seen[$key]+specified} ]]; then usage_error 'invalid or duplicate site setting'; return; fi
        case $key in
            MODPROBE_MANAGED)
                if [[ ! $value =~ ^(yes|no)$ ]]; then usage_error 'invalid MODPROBE_MANAGED setting'; return; fi
                MODPROBE_MANAGED=$value ;;
            GPGCHECK_ALTERNATE_REPOS)
                if [[ ! $value =~ ^[A-Za-z0-9_.:-]+(,[A-Za-z0-9_.:-]+)*$ ]]; then
                    usage_error 'GPGCHECK_ALTERNATE_REPOS needs comma-separated DNF repository IDs'; return
                fi
                GPGCHECK_ALTERNATE_REPOS=$value ;;
            CHRONY_APPROVED_SERVER)
                if ! chrony_valid_approved_server "$value"; then
                    usage_error 'CHRONY_APPROVED_SERVER needs one approved DNS name or unicast IPv4 address'; return
                fi
                CHRONY_APPROVED_SERVER=$value ;;
            *) usage_error 'invalid or duplicate site setting'; return ;;
        esac
        seen[$key]=1
    done < "$file"
    return 0
}

resolve_scope() {
    local id
    SCOPE=()
    EFFECTIVE=()
    for id in "${RULE_IDS[@]}"; do
        if [[ -n $CKL_PATH ]]; then
            [[ ${CKL_MAPPED[$id]+imported} && ! ${SKIPPED[$id]+excluded} ]] || continue
        fi
        if (( SELECT_EXPLICIT )); then
            [[ ${REQUESTED[$id]+selected} ]] || continue
        elif [[ -z $CKL_PATH ]]; then
            [[ ${DEFAULT_RULE[$id]} == yes ]] || continue
        fi
        SCOPE+=("$id")
        if [[ ! ${SKIPPED[$id]+excluded} ]]; then EFFECTIVE[$id]=1; fi
    done
    (( ${#SCOPE[@]} > 0 || GUI )) || [[ -n $CKL_PATH ]]
}

# 3. Terminal rendering, logging, and report generation

clean_text() {
    printf '%s' "$1" | tr -d '\000-\010\013-\037\177'
}

terminal_colors() {
    [[ $COLOR == always ]] ||
        [[ $COLOR == auto && -z ${NO_COLOR+x} && ${TERM:-dumb} != dumb && -t $1 ]]
}

plan_diff_requested() {
    [[ ${MODE-} == diff || ${IMPLEMENT_DIFF:-0} == 1 ]]
}

display_terminal_text() {
    local fd=$1 line tint
    if ! terminal_colors "$fd"; then cat; return; fi
    while IFS= read -r line || [[ $line ]]; do
        case $line in
            '+++ '*|'--- '*|'@@'*) tint=36 ;;
            '- '*) tint=31 ;;
            '+ '*) tint=32 ;;
            *' | PASS | '*|*' | PASS'|*' APPLIED'*) tint=32 ;;
            *' | FAIL | '*|*' | FAIL'|*'high risk'*) tint=31 ;;
            *'medium risk'*|*'NEEDS_REVIEW'*|*'BLOCKED'*) tint=33 ;;
            *'low risk'*|'Full '*|'Change '*|'PROPOSED CHANGE') tint=36 ;;
            *) tint='' ;;
        esac
        if [[ $tint ]]; then printf '\033[%sm%s\033[0m\n' "$tint" "$line" || return 1
        else printf '%s\n' "$line" || return 1; fi
    done
}

notice() {
    local level=$1 message=$2 code=''
    case $level in
        PASS) code=32 ;; FAIL|ERROR) code=31 ;; NEEDS_REVIEW|WARN|BLOCKED|PENDING_ACTIVATION) code=33 ;;
        INFO) code=36 ;;
    esac
    if [[ $code ]] && terminal_colors 2; then
        printf '\033[%sm%s\033[0m %s\n' "$code" "$level" "$message" >&2
    else
        printf '%s %s\n' "$level" "$message" >&2
    fi
}

event() {
    local level=$1 message
    message=$(clean_text "$2") || return 1
    printf '%s %s %s\n' "$(date -u +%FT%TZ)" "$level" "$message" >> "$RUN_DIR/run.log" || return
    if (( ! TUI_SCANNING )) && { (( VERBOSE )) || [[ $level != INFO ]]; }; then
        notice "$level" "$message"
    fi
}

json_string() {
    local value=$1
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    value=${value//$'\n'/\\n}
    value=${value//$'\t'/\\t}
    printf '"%s"' "$value"
}

csv_string() {
    local value=${1//\"/\"\"}
    printf '"%s"' "$value"
}

csv_row() {
    local value delimiter=
    for value in "$@"; do
        printf '%s' "$delimiter"
        csv_string "$value"
        delimiter=,
    done
    printf '\r\n'
}

report_metadata() {
    printf 'Run %s | %s | %s\n' "$RUN_ID" "$RUN_TIMESTAMP" "$MODE"
    printf 'Script %s | SHA-256 %s\n' "$SCRIPT_VERSION" "$SCRIPT_HASH"
    printf 'Baseline %s | archive SHA-256 %s\n' "$BASELINE" "$ARCHIVE_SHA256"
    printf 'Host %s | RHEL 8.10 %s | %s | kernel %s\n' "$HOST_ID" "$ARCH" "$BOOT_MODE" "$KERNEL"
    printf 'Operator %s\n' "$OPERATOR"
    printf 'Scope %s | risk ceiling %s\n' "${SCOPE[*]}" "$MAX_RISK"
    if [[ $MODE == status ]]; then
        printf 'Fresh checks %s | reused results %s\n' "$STATUS_FRESH_COUNT" "$STATUS_REUSED_COUNT"
    fi
    if [[ -n ${CKL_PATH-} ]]; then printf '%s | see ckl-import.txt\n' "$CKL_UI_SUMMARY"; fi
    if (( ${#SKIPPED[@]} )); then printf 'Requested skip %s\n' "${!SKIPPED[*]}"; fi
    if [[ -n $RESUME_ID || -n $ROLLBACK_ID ]]; then
        printf 'Related run %s\n' "${RESUME_ID:-$ROLLBACK_ID}"
    fi
}

report_json() {
    local id delimiter='' record_key record_value
    local -a keys=(run_id timestamp operator host_id script_version script_sha256 baseline
        archive_sha256 mode os architecture boot_mode kernel)
    local -a values=("$RUN_ID" "$RUN_TIMESTAMP" "$OPERATOR" "$HOST_ID" "$SCRIPT_VERSION"
        "$SCRIPT_HASH" "$BASELINE" "$ARCHIVE_SHA256" "$MODE" 'RHEL 8.10' "$ARCH" "$BOOT_MODE"
        "$KERNEL")
    local i
    printf '{'
    for i in "${!keys[@]}"; do
        record_key=${keys[i]} record_value=${values[i]}
        json_string "$record_key"; printf ':'; json_string "$record_value"; printf ','
    done
    if [[ $MODE == status ]]; then
        printf '"fresh_checks":%s,"reused_results":%s,' "$STATUS_FRESH_COUNT" "$STATUS_REUSED_COUNT"
    fi
    printf '"results":['
    for id in "${SCOPE[@]}"; do
        printf '%s{"id":' "$delimiter"; json_string "$id"
        printf ',"title":'; json_string "${TITLE[$id]}"
        printf ',"before":'; json_string "${BEFORE[$id]}"
        printf ',"assessment":'; json_string "${AFTER[$id]}"
        if [[ -n ${CKL_PATH-} ]]; then
            printf ',"ckl_status":'; json_string "${CKL_HISTORY[$id]:-unavailable}"
        fi
        printf ',"action":'; json_string "${ACTIONS[$id]}"
        printf ',"evidence":'; json_string "${DETAIL[$id]}"
        if [[ $MODE == status ]]; then
            printf ',"assessment_source":'; json_string "${ASSESSMENT_SOURCE[$id]-}"
            printf ',"assessment_observed_at":'; json_string "${ASSESSMENT_AT[$id]-}"
        fi
        printf ',"plan":'; json_string "${DISPLAY_PLAN[$id]-}"
        if [[ $MODE == diff ]]; then printf ',"diff":'; json_string "${DISPLAY_DIFF[$id]-}"; fi
        printf '}'
        delimiter=,
    done
    printf ']}\n'
}

report_csv() {
    local id
    local -a extra=()
    if [[ $MODE == diff ]]; then extra=(diff); fi
    if [[ $MODE == status ]]; then extra=(assessment_source assessment_observed_at); fi
    csv_row run_id timestamp operator host_id script_version script_sha256 baseline archive_sha256 \
        mode os architecture boot_mode kernel id title before assessment action evidence plan "${extra[@]}"
    for id in "${SCOPE[@]}"; do
        if [[ $MODE == diff ]]; then extra=("${DISPLAY_DIFF[$id]-}"); fi
        if [[ $MODE == status ]]; then extra=("${ASSESSMENT_SOURCE[$id]-}" "${ASSESSMENT_AT[$id]-}"); fi
        csv_row "$RUN_ID" "$RUN_TIMESTAMP" "$OPERATOR" "$HOST_ID" "$SCRIPT_VERSION" \
            "$SCRIPT_HASH" "$BASELINE" "$ARCHIVE_SHA256" "$MODE" 'RHEL 8.10' "$ARCH" "$BOOT_MODE" \
            "$KERNEL" "$id" "${TITLE[$id]}" "${BEFORE[$id]}" "${AFTER[$id]}" \
            "${ACTIONS[$id]}" "${DETAIL[$id]}" "${DISPLAY_PLAN[$id]-}" "${extra[@]}"
    done
}

report_result_group() {
    local id=$1
    case ${ACTIONS[$id]}:${AFTER[$id]} in
        SKIPPED:*) REPLY='Skipped' ;;
        BLOCKED:*) REPLY='Blocked' ;;
        PENDING_ACTIVATION:*) REPLY='Pending activation' ;;
        *:ERROR) REPLY='Errors' ;;
        *)
            if [[ ${PREVIEW_KEY[$id]+planned} || ${PLANNED_BY[$id]+grouped} ]]; then
                REPLY='Ready'
            else
                case ${AFTER[$id]} in
                    PASS) REPLY='Passed' ;;
                    NOT_APPLICABLE) REPLY='Not applicable' ;;
                    *) REPLY='Needs review' ;;
                esac
            fi ;;
    esac
}

report_text_finding() {
    local id=$1
    printf '%-10s %-16s %-16s %-20s %s\n' "$id" "${BEFORE[$id]}" "${AFTER[$id]}" \
        "${ACTIONS[$id]}" "${DETAIL[$id]}" || return 1
    if [[ $MODE == status && ${ASSESSMENT_SOURCE[$id]-} == reused ]]; then
        printf '  Reused result | checked %s\n' "${ASSESSMENT_AT[$id]}" || return 1
    fi
    if [[ ${DISPLAY_PLAN[$id]-} ]]; then printf '  %s\n' "${DISPLAY_PLAN[$id]}" || return 1; fi
    if [[ $MODE == diff && ${DISPLAY_DIFF[$id]-} && ${HANDLING[$id]-} != attended-action ]]; then
        printf '%s\n' "${DISPLAY_DIFF[$id]}" || return 1
    fi
}

report_text() {
    local id group label REPLY
    local -a groups=('Ready' 'Blocked' 'Needs review' 'Pending activation'
        'Errors' 'Passed' 'Not applicable' 'Skipped')
    local -A counts=() group_by_id=()
    case $MODE in
        status|dry-run|diff)
            for id in "${SCOPE[@]}"; do
                report_result_group "$id"
                group_by_id[$id]=$REPLY
                counts[$REPLY]=$(( ${counts[$REPLY]:-0} + 1 ))
            done
            printf '%s selected' "${#SCOPE[@]}" || return 1
            for group in "${groups[@]}"; do
                [[ ${counts[$group]+counted} ]] || continue
                label=${group,,}
                if [[ $group == Errors && ${counts[$group]} == 1 ]]; then label=error; fi
                printf ' | %s %s' "${counts[$group]}" "$label" || return 1
            done
            printf '\n\n' || return 1 ;;
    esac
    report_metadata || return 1
    printf '\n%-10s %-16s %-16s %-20s %s\n' ID BEFORE ASSESSMENT ACTION EVIDENCE || return 1
    # Scope already follows the registry's Vuln-ID order.
    if [[ ${REPORT_GROUP_BY-} == result ]]; then
        for group in "${groups[@]}"; do
            [[ ${counts[$group]+counted} ]] || continue
            printf '\n%s (%s)\n' "$group" "${counts[$group]}" || return 1
            for id in "${SCOPE[@]}"; do
                [[ ${group_by_id[$id]} == "$group" ]] || continue
                report_text_finding "$id" || return 1
            done
        done
    else
        for id in "${SCOPE[@]}"; do
            report_text_finding "$id" || return 1
        done
    fi
    printf '\n%s selected | %s unresolved | %s pending activation | %s skipped\n' \
        "${#SCOPE[@]}" "$UNRESOLVED" "$PENDING_COUNT" "$SKIPPED_COUNT" || return 1
    printf 'Run directory %s\n' "$RUN_DIR" || return 1
    if [[ -n ${BACKUP_RUN-} ]]; then
        printf 'Backup directory %s\n' "$BACKUP_RUN"
    fi
}

render_admin_action() {
    local id=$1 fn quoted_script verification_args=''
    printf -v quoted_script '%q' "$SCRIPT_PATH"
    printf '%s — %s\n' "$id" "${TITLE[$id]}"
    printf '%s / %s. %s\n' "${AFTER[$id]}" "${ACTIONS[$id]}" "${DETAIL[$id]}"
    if [[ ${ACTIONS[$id]} == BLOCKED && ${DISPLAY_PLAN[$id]-} ]]; then
        printf 'Blocking prerequisite: %s\n' "${DISPLAY_PLAN[$id]}"
    fi
    if [[ ${RESOLUTION_NOTES[$id]-} ]]; then
        printf 'Operator-provided evidence reference: %s\n' "${RESOLUTION_NOTES[$id]}"
    fi
    if [[ $id == V-251710 && ${RESOLUTION_AIDE_RESULT-} ]]; then
        printf 'V-251710 read-only AIDE evidence: %s\n' "$RESOLUTION_AIDE_RESULT"
    fi
    fn="rule_${id//-/_}_admin"
    if declare -F "$fn" >/dev/null; then
        "$fn"
    else
        printf '1. System administrator: review the check and fix references below.\n'
        printf '2. Record site dependencies and approval, then follow the reviewed local procedure.\n'
        printf '   Check %s | Fix %s\n' "${CHECK_REF[$id]}" "${FIX_REF[$id]}"
    fi
    if [[ $id == V-230484 && ${CHRONY_RUN_SERVER:-${CHRONY_APPROVED_SERVER-}} ]]; then
        printf -v verification_args ' --approved-time-source %q' "${CHRONY_RUN_SERVER:-$CHRONY_APPROVED_SERVER}"
    fi
    printf 'Scoped verification: %s --status --only %s%s\n\n' "$quoted_script" "$id" "$verification_args"
}

write_admin_actions() {
    local id
    for id in "${SCOPE[@]}"; do
        if [[ ${SKIPPED[$id]+excluded} ]]; then continue; fi
        if [[ ${AFTER[$id]} =~ ^(PASS|NOT_APPLICABLE)$ &&
              ! ${RESOLUTION_NOTES[$id]+recorded} &&
              ! ${ACTIONS[$id]} =~ ^(BLOCKED|PENDING_ACTIVATION|FAILED|ROLLED_BACK)$ ]]; then continue; fi
        render_admin_action "$id"
    done
}

# 4. Preflight, environment discovery, and dependency checks

have_tools() {
    local name
    for name in "$@"; do command -v "$name" >/dev/null || return 1; done
}

blocked() {
    notice BLOCKED "$1"
    return 69
}

operational_error() {
    notice ERROR "$1"
    return 70
}

sha256_file() {
    local checksum
    checksum=$(sha256sum < "$1") || return 1
    printf '%s\n' "${checksum%% *}"
}

identify_script() {
    SCRIPT_PATH=$(realpath -e -- "${BASH_SOURCE[0]}") || return 1
    [[ -f $SCRIPT_PATH && -r $SCRIPT_PATH ]] || return 1
    SCRIPT_HASH=$(sha256_file "$SCRIPT_PATH") || return 1
    [[ $SCRIPT_HASH =~ ^[0-9a-f]{64}$ ]]
}

verify_script() {
    local current name_identity executed_identity executed_checksum fd=/proc/$$/fd/255
    [[ -f $SCRIPT_PATH && ! -L $SCRIPT_PATH ]] || return 1
    current=$(sha256_file "$SCRIPT_PATH") || return 1
    [[ $current == "$SCRIPT_HASH" && -f $fd ]] || return 1
    name_identity=$(stat -Lc '%d:%i' -- "$SCRIPT_PATH") &&
        executed_identity=$(stat -Lc '%d:%i' -- "$fd") &&
        executed_checksum=$(sha256_file "$fd") || return 1
    [[ $name_identity == "$executed_identity" && $executed_checksum == "$SCRIPT_HASH" ]]
}

trust_script_location() {
    local path=$SCRIPT_PATH owner mode
    while [[ $path != / ]]; do
        [[ ! -L $path ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$path") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        path=$(dirname -- "$path") || return 1
    done
}

preflight() {
    local release identity virt_result machine_id machine_uuid=
    if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
        blocked 'Bash 4.4 or newer is required'; return
    fi
    if [[ $(uname -s) != Linux || ! -r /etc/redhat-release ]]; then
        blocked 'requires genuine Red Hat Enterprise Linux 8.10 x86_64'; return
    fi
    if ! have_tools rpm systemd-detect-virt sha256sum realpath stat mktemp awk grep sort timeout \
        findmnt id date tr wc od dirname mkdir cat chmod; then
        blocked 'required local preflight or reporting tools are missing'; return
    fi
    IFS= read -r release < /etc/redhat-release || return 69
    ARCH=$(uname -m) KERNEL=$(uname -r)
    if [[ $release != 'Red Hat Enterprise Linux release 8.10 (Ootpa)' || $ARCH != x86_64 ]]; then
        blocked 'requires genuine Red Hat Enterprise Linux 8.10 x86_64'; return
    fi
    identity=$(timeout 15 rpm -q --qf '%{NAME}|%{VERSION}|%{VENDOR}\n' redhat-release 2>/dev/null) ||
        { blocked 'cannot establish the Red Hat release package identity'; return; }
    if [[ $identity != 'redhat-release|8.10|Red Hat, Inc.' || $(< /proc/1/comm) != systemd ]]; then
        blocked 'Red Hat release package or systemd boot identity is unresolved'; return
    fi
    systemd-detect-virt --container --quiet
    virt_result=$?
    if (( virt_result != 1 )) || [[ $KERNEL == *[Mm]icrosoft* || -f /.dockerenv ]]; then
        blocked 'requires a full booted RHEL system outside a container or WSL'; return
    fi
    if [[ -d /sys/firmware/efi ]]; then BOOT_MODE=UEFI; else BOOT_MODE=BIOS; fi
    if ! read -r machine_id < /etc/machine-id || [[ ! $machine_id =~ ^[[:xdigit:]]{32}$ ]]; then
        blocked 'valid system machine ID is unavailable'; return
    fi
    if [[ -r /sys/class/dmi/id/product_uuid ]]; then
        read -r machine_uuid < /sys/class/dmi/id/product_uuid || machine_uuid=
    fi
    HOST_ID=$(printf '%s\n' "$machine_id" "$machine_uuid" | sha256sum) || return 69
    HOST_ID=${HOST_ID%% *}
    if ! read -r BOOT_ID < /proc/sys/kernel/random/boot_id ||
       [[ ! $BOOT_ID =~ ^[0-9a-f-]{36}$ ]]; then
        blocked 'kernel boot identity is unavailable'; return
    fi
    OPERATOR="$(id -un) (uid $EUID)"
    if [[ ${SUDO_USER-} =~ ^[A-Za-z0-9_.@-]+$ ]]; then OPERATOR="$SUDO_USER via $OPERATOR"; fi
    if ! identify_script; then blocked 'cannot identify and hash the regular script file'; return; fi
}

secure_directory() {
    local path=$1 create=$2 permit_sticky=$3 rest component step='' mode owner
    valid_output_path "$path" || return 1
    rest=${path#/}
    while [[ -n $rest ]]; do
        component=${rest%%/*}
        step+=/$component
        if [[ $rest == */* ]]; then rest=${rest#*/}; else rest=; fi
        [[ ! -L $step ]] || return 1
        if [[ ! -e $step ]]; then
            (( create )) && mkdir -m 0700 -- "$step" || return 1
        fi
        [[ -d $step && ! -L $step ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$step") || return 1
        [[ $mode =~ ^[0-7]{3,4}$ && ( $owner == 0 || $owner == "$EUID" ) ]] || return 1
        if (( 8#$mode & 022 )); then
            [[ $permit_sticky == yes && $owner == 0 && $step != "$path" ]] || return 1
            (( 8#$mode & 01000 )) || return 1
        fi
    done
    [[ $owner == "$EUID" ]] && (( (8#$mode & 077) == 0 ))
}

local_filesystem() {
    local fs
    fs=$(findmnt -n -o FSTYPE -T "$1") || return 1
    case $fs in xfs|ext4|ext3|ext2|btrfs|tmpfs) return 0 ;; esac
    return 1
}

collect_host_context() {
    local selinux=unavailable remote=no failed=unavailable auth=unavailable packages
    local space
    if [[ -n ${SSH_CONNECTION-} || -n ${SSH_TTY-} ]]; then remote=yes; fi
    if have_tools getenforce; then
        selinux=$(getenforce 2>/dev/null) || selinux=unavailable
    fi
    if have_tools systemctl; then
        failed=$(timeout 8 systemctl --failed --plain --no-legend --no-pager 2>/dev/null |
            awk 'NF {n++} END {print n+0}') || failed=unavailable
    fi
    if have_tools authselect; then
        auth=$(timeout 8 authselect current -r 2>/dev/null) || auth=unavailable
        if [[ ! $auth =~ ^[a-zA-Z0-9_./[:blank:]-]+$ ]]; then auth=unavailable; fi
    fi
    packages=$(timeout 12 rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' bash coreutils kmod systemd 2>/dev/null) ||
        packages='package versions could not all be read'
    space=$(df -Pk -- "$RUN_DIR" | awk 'END {print $4}') || space=unavailable
    [[ $space =~ ^[0-9]+$ ]] || space=unavailable
    event INFO "Bash $BASH_VERSION; SELinux $selinux; SSH context $remote; failed units $failed; report free KiB $space" &&
        event INFO "authselect profile/features: $auth; core packages: ${packages//$'\n'/; }"
}

create_run() {
    local stem file
    secure_directory "$REPORT_BASE" 1 yes && local_filesystem "$REPORT_BASE" || return 1
    stem=$(date -u +%Y%m%dT%H%M%SZ) || return 1
    RUN_TIMESTAMP=$(date -u +%FT%TZ) || return 1
    RUN_DIR=$(mktemp -d -- "$REPORT_BASE/$stem.XXXXXXXX") || return 1
    RUN_ID=${RUN_DIR##*/}
    for file in summary.txt run.log admin-actions.txt changes.txt; do
        : > "$RUN_DIR/$file" || return 1
    done
    write_manifest "$RUN_DIR/manifest" || return 1
    event INFO "started $MODE by $OPERATOR; script $SCRIPT_VERSION $SCRIPT_HASH"
}

# 5. Approval, locking, and run-state management

write_manifest() {
    local id
    {
        printf 'schema\t1\nrun\t%s\nhost\t%s\nboot\t%s\nscript\t%s\narchive\t%s\n' \
            "$RUN_ID" "$HOST_ID" "$BOOT_ID" "$SCRIPT_HASH" "$ARCHIVE_SHA256"
        if [[ -n ${CKL_PATH-} ]]; then
            printf 'ckl_path\t%s\nckl_sha256\t%s\nckl_section\t%s\n' "$CKL_PATH" "$CKL_SHA256" "$CKL_SECTION"
        fi
        for id in "${SCOPE[@]}"; do
            if [[ ${SKIPPED[$id]+excluded} ]]; then printf 'skip\t%s\n' "$id"
            elif [[ $id == V-288829 && ${SSH_SCOPE_ADDED[$id]+included} ]]; then printf 'ssh_impact\t%s\n' "$id"
            else printf 'select\t%s\n' "$id"; fi
        done
    } > "$1"
}

load_manifest() {
    local file=$1 run=$2 key value rest
    local host='' script='' archive='' schema='' manifest_run='' boot=''
    local ckl_path='' ckl_sha256='' ckl_section='' ssh_impact=0
    local -A selections=() exclusions=() seen=()
    text_input_file "$file" || return 1
    while IFS=$'\t' read -r key value rest; do
        [[ -n $key && -n $value && -z $rest ]] || return 1
        case $key in
            schema|run|host|boot|script|archive|ckl_path|ckl_sha256|ckl_section)
                [[ ! ${seen[$key]+present} ]] || return 1
                seen[$key]=1
                case $key in
                    ckl_path) ckl_path=$value ;;
                    ckl_sha256) ckl_sha256=$value ;;
                    ckl_section) ckl_section=$value ;;
                    schema) schema=$value ;; run) manifest_run=$value ;; host) host=$value ;;
                    boot) boot=$value ;; script) script=$value ;; archive) archive=$value ;;
                esac ;;
            select|skip|ssh_impact)
                known_id "$value" && [[ ! ${selections[$value]+selected} ]] || return 1
                selections[$value]=1
                if [[ $key == skip ]]; then exclusions[$value]=1
                elif [[ $key == ssh_impact ]]; then
                    [[ $value == V-288829 ]] || return 1
                    ssh_impact=1
                fi ;;
            *) return 1 ;;
        esac
    done < "$file"
    [[ $schema == 1 && $manifest_run == "$run" && $host == "$HOST_ID" &&
       $script == "$SCRIPT_HASH" && $archive == "$ARCHIVE_SHA256" &&
       $boot =~ ^[0-9a-f-]{36}$ ]] && (( ${#selections[@]} )) || return 1
    if [[ -n $ckl_path || -n $ckl_sha256 || -n $ckl_section ]]; then
        [[ $ckl_path == /* && $ckl_path != *[[:cntrl:]]* && $ckl_sha256 =~ ^[0-9a-f]{64}$ &&
           $ckl_section =~ ^[1-9][0-9]{0,3}$ ]] || return 1
        if [[ $MODE != rollback ]]; then
            CKL_RESUME_PATH=$ckl_path CKL_RESUME_SHA256=$ckl_sha256 CKL_RESUME_SECTION=$ckl_section
        fi
    fi
    SELECT_EXPLICIT=1
    REQUESTED=() SKIPPED=()
    for value in "${!selections[@]}"; do REQUESTED[$value]=1; done
    for value in "${!exclusions[@]}"; do SKIPPED[$value]=1; done
    PRIOR_BOOT=$boot SSH_IMPACT_ONLY=$ssh_impact
}

open_attended_terminal() {
    if (( EUID != 0 )); then blocked 'apply and rollback require root'; return; fi
    if [[ ! -t 0 ]] || ! { exec {TTY_FD}<> /dev/tty; } 2>/dev/null; then
        blocked 'apply and rollback require an interactive terminal and terminal stdin'; return
    fi
    if [[ ! -t $TTY_FD ]]; then blocked 'controlling input is not a terminal'; return; fi
    return 0
}

lock_mutation() {
    if ! have_tools flock || ! secure_directory /run/rhel8-stig 1 no; then return 1; fi
    [[ ! -L /run/rhel8-stig/mutation.lock ]] || return 1
    exec {LOCK_FD}>> /run/rhel8-stig/mutation.lock || return 1
    flock -n "$LOCK_FD"
}

approve() {
    local token=$1 response
    printf '\nType %s to approve this operation. Press Enter to skip.\n> ' "$token" >&"$TTY_FD" || return 2
    IFS= read -r -u "$TTY_FD" response || return 2
    [[ $response == "$token" ]]
}

prepare_backup() {
    if [[ -n ${BACKUP_RUN-} ]]; then return 0; fi
    secure_directory "$BACKUP_BASE" 1 no && local_filesystem "$BACKUP_BASE" || return 1
    BACKUP_RUN=$BACKUP_BASE/$RUN_ID
    mkdir -m 0700 -- "$BACKUP_RUN" || return 1
    write_manifest "$BACKUP_RUN/manifest" || return 1
    record_digest "$BACKUP_RUN/manifest"
}

record_digest() {
    local digest
    digest=$(sha256_file "$1") || return 1
    printf '%s\n' "$digest" > "$1.sha256" && verify_digest "$1"
}

verify_digest() {
    local actual expected
    [[ ! -L $1 && ! -L $1.sha256 && -f $1 && -f $1.sha256 ]] || return 1
    read -r expected < "$1.sha256" || return 1
    [[ $expected =~ ^[0-9a-f]{64}$ ]] || return 1
    actual=$(sha256_file "$1") && [[ $actual == "$expected" ]]
}

# 6. Backups, staging, validation, activation, and restoration

# An operation in this version creates one module-policy file with an absent
# predecessor. Existing configuration and other system resources are out of scope.

module_path() {
    printf '/etc/modprobe.d/90-rhel8-stig-%s.conf\n' "${MODULE[$1]}"
}

module_bytes() {
    printf '# rhel8-stig %s created-boot %s\n' "$1" "$2"
    printf 'install %s /bin/false\nblacklist %s\n' "${MODULE[$1]}" "${MODULE[$1]}"
}

file_identity() {
    local digest metadata label
    [[ -f $1 && ! -L $1 ]] || return 1
    metadata=$(stat -c '%d:%i:%u:%g:%a:%s:%h:%Y:%Z' -- "$1") || return 1
    label=$(stat -c '%C' -- "$1" 2>/dev/null) || label=unavailable
    digest=$(sha256_file "$1") || return 1
    printf '%s %s %s\n' "$metadata" "$label" "$digest"
}

trusted_module_directory() {
    local item user mode
    for item in /etc /etc/modprobe.d; do
        [[ -d $item && ! -L $item ]] || return 1
        read -r user mode < <(stat -c '%u %a' -- "$item") || return 1
        [[ $user == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
    done
    local_filesystem /etc/modprobe.d
}

module_signature() {
    local module=$1 settings
    local config=/usr/lib/modules/$KERNEL/modules.builtin loaded=/proc/modules
    [[ -r $loaded && -f $config && -r $config ]] || return 1
    settings=$(timeout 12 modprobe --showconfig 2>/dev/null) || return 1
    {
        printf '%s\n' "$settings"
        printf 'builtin '; sha256_file "$config" || return 1
        printf 'loaded %s\n' "$(awk -v name="${module//-/_}" '$1 == name {print $1}' "$loaded")"
    } | sha256sum
}

module_plan() {
    local id=$1 name=${MODULE[$1]} target settings evidence resolve
    PLAN_REASON='' PLAN_TEXT='' PLAN_SIGNATURE=''
    if [[ $MODPROBE_MANAGED == yes ]]; then PLAN_REASON='modprobe policy is managed by the site'; return 1; fi
    if ! have_tools modprobe modinfo ln rm getfattr getfacl df; then
        PLAN_REASON='staging requires kmod, ACL and extended-attribute utilities'; return 1
    fi
    if ! trusted_module_directory; then PLAN_REASON='module policy directory is unsuitable'; return 1; fi
    target=$(module_path "$id")
    if [[ -e $target || -L $target ]]; then PLAN_REASON='the proposed path already exists'; return 1; fi
    settings=$(module_settings "$name") || { PLAN_REASON='effective module policy could not be read'; return 1; }
    if [[ -n $settings ]]; then
        PLAN_REASON='existing module-specific directives need review and an adjacent edit where valid'
        return 1
    fi
    resolve=$(timeout 10 modinfo -n -- "$name" 2>/dev/null) || {
        PLAN_REASON='the module could not be resolved for the running kernel'; return 1;
    }
    if [[ $resolve != /lib/modules/* && $resolve != /usr/lib/modules/* ]]; then
        PLAN_REASON='module is built in or returned an unexpected module path'; return 1
    fi
    evidence=$(module_runtime "$name") || { PLAN_REASON='module use could not be determined'; return 1; }
    if [[ $evidence != absent ]]; then PLAN_REASON='the module is loaded or built in; review local dependencies'; return 1; fi
    PLAN_SIGNATURE=$(module_signature "$name") || { PLAN_REASON='module policy fingerprint failed'; return 1; }
    PLAN_TEXT=$(printf '%s (new 0644 root:root file)\n%s\nReview the next-boot initramfs and kdump. Reboot in a maintenance window and reassess.' \
        "$target" "$(module_bytes "$id" "$BOOT_ID")")
}

created_metadata() {
    # Hash the security metadata via a fixed path while omitting file names from
    # the digest. An unavailable metadata reader must prevent removal.
    local acl attrs
    acl=$(getfacl -cp -- "$1" 2>/dev/null) || return 1
    attrs=$(getfattr --absolute-names -d -m - --encoding=hex -- "$1" 2>/dev/null) || return 1
    attrs=${attrs#*"$1"}
    printf '%s\n%s\n' "$acl" "$attrs" | sha256sum
}

apply_module_plan() {
    local id=$1 accepted=$2 name=${MODULE[$1]} target stage expected identity attrs now bytes acl
    target=$(module_path "$id") || return 1
    if ! verify_script || ! module_plan "$id" || [[ $PLAN_SIGNATURE != "$accepted" ]]; then
        event BLOCKED "$id module configuration changed after approval; reassess"; return 1
    fi
    if ! prepare_backup; then event ERROR "$id backup destination or manifest failed"; return 1; fi
    bytes=$(df -Pk /etc/modprobe.d "$BACKUP_RUN" | awk 'NR>1 && $4+0 < 1024 {print "low"}') || return 1
    if [[ -n $bytes ]]; then event ERROR "$id insufficient local staging or backup space"; return 1; fi
    stage=$(mktemp -- /etc/modprobe.d/.rhel8-stig.XXXXXXXX) || return 1
    STAGING_FILE=$stage
    if ! module_bytes "$id" "$BOOT_ID" > "$stage" || ! chmod 0644 -- "$stage" ||
       [[ $(stat -c '%u:%g:%a:%h' -- "$stage") != '0:0:644:1' ]]; then
        event ERROR "$id staging file validation failed"; return 1
    fi
    acl=$(getfacl -cp -- "$stage" 2>/dev/null) || return 1
    if [[ $acl != $'user::rw-\ngroup::r--\nother::r--' ]]; then
        event ERROR "$id parent policy inherited an extended ACL; review the staging location"; return 1
    fi
    if ! have_tools getenforce || [[ $(getenforce 2>/dev/null) != Disabled ]]; then
        if ! have_tools matchpathcon chcon || ! matchpathcon -n -- "$target" > "$RUN_DIR/$id.selinux" ||
           ! IFS= read -r expected < "$RUN_DIR/$id.selinux" || [[ -z $expected ]] ||
           ! chcon -- "$expected" "$stage"; then
            event ERROR "$id cannot establish the required SELinux label"; return 1
        fi
    fi
    if ! settings_from_stage "$stage" "$name"; then
        event ERROR "$id kmod validation failed"; return 1
    fi
    expected=$(sha256_file "$stage") || return 1
    attrs=$(created_metadata "$stage") || return 1
    printf 'absent\t%s\t%s\n' "$target" "$expected" > "$BACKUP_RUN/$id.pre" &&
        record_digest "$BACKUP_RUN/$id.pre" || return 1
    now=$(module_signature "$name") || return 1
    [[ $accepted == "$now" && ! -e $target && ! -L $target ]] &&
        verify_script && trusted_module_directory || return 1
    event INFO "$id committing the approved new file $target" || return 1
    if ! ln -T -- "$stage" "$target"; then return 1; fi
    if ! rm -- "$stage"; then return 1; fi
    STAGING_FILE=
    identity=$(file_identity "$target") || return 1
    [[ $identity == *" $expected" && $(created_metadata "$target") == "$attrs" ]] || return 1
    printf '%s\n%s\n' "$identity" "$attrs" > "$BACKUP_RUN/$id.post" &&
        record_digest "$BACKUP_RUN/$id.post" || return 1
    rule_dispatch "$id"
    if [[ $ASSESSMENT != NEEDS_REVIEW || $CHECK_PENDING != 1 ]]; then
        event ERROR "$id verification failed; inspect the journal before further changes"; return 1
    fi
    printf '%s approved creation of %s; reboot and reassessment pending\n' "$id" "$target" >> "$RUN_DIR/changes.txt"
}

settings_from_stage() {
    local stage=$1 name=$2 config
    config=$(timeout 10 modprobe -C "$stage" --showconfig 2>/dev/null) || return 1
    printf '%s\n' "$config" | inspect_module_settings "$name" |
        awk '$1 == "install" && $3 == "/bin/false" {i++}
             $1 == "blacklist" {b++} END {exit !(i == 1 && b == 1 && NR == 2)}'
}

guided_module_id() {
    [[ $1 == V-23049[4-9] ]]
}

guided_module_validate() {
    local candidate=$1 target=$2 member name config
    for member in V-230494 V-230495 V-230496 V-230497 V-230498 V-230499; do
        if [[ $target != "$(module_path "$member")" ]]; then continue; fi
        name=${MODULE[$member]}
        [[ $(< "$candidate") == "$(module_bytes "$member" "$BOOT_ID")" &&
           $(module_runtime "$name") == absent ]] && settings_from_stage "$candidate" "$name" || return 1
        config=$(module_settings "$name") || return 1
        if [[ $candidate == "$target" ]]; then
            awk '$1 == "install" && $3 == "/bin/false" && NF == 3 {i++}
                 $1 == "blacklist" && NF == 2 {b++}
                 END {exit !(i == 1 && b == 1 && NR == 2)}' <<< "$config"
            return
        fi
        [[ -z $config ]]
        return
    done
    return 1
}

guided_module_add() {
    local id=$1 payload
    payload=$(module_bytes "$id" "$BOOT_ID") || return 1
    edit_content "$(module_path "$id")" 0644 "$payload" guided_module_validate <<< "$payload"
}

guided_module_plan() {
    local id=$1 member signature
    module_plan "$id" || return 1
    EDIT_CONTEXT=$PLAN_SIGNATURE
    guided_module_add "$id" || return 1
    for member in V-230494 V-230495 V-230496 V-230497 V-230498 V-230499; do
        if [[ $member == "$id" || ! ${EFFECTIVE[$member]+selected} ||
              ${PREVIEW_KEY[$member]+planned} ||
              ( ${PLANNED_BY[$member]+grouped} && ${PLANNED_BY[$member]} != "$id" ) ]]; then continue; fi
        signature=$(
            allow_rule_plan "$id" "$member" && rule_dispatch "$member" && check_supports_plan "$member" &&
                module_plan "$member" && printf '%s' "$PLAN_SIGNATURE"
        ) || continue
        if ! guided_module_add "$member"; then PLAN_REASON=''; continue; fi
        EDIT_GROUPED+=" $member"
        EDIT_CONTEXT+=" $member $signature"
    done
    EDIT_GROUPED=${EDIT_GROUPED# }
    EDIT_RELATED=$EDIT_GROUPED
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Review dependencies for each listed module and any documented operational need. The tool verified that each target is an unused, loadable module with no competing directives.'
    EDIT_ACTIVATION='Review the next-boot initramfs and kdump once for the listed modules. Reboot in an approved window and recheck the effective module policy and runtime state.'
}

rollback_module() {
    local id=$1 old=$2 target expected_attrs expected_metadata actual attrs hash pre_path type
    target=$(module_path "$id") || return 2
    if [[ ! -e $old/$id.pre && ! -L $old/$id.pre ]]; then return 1; fi
    if ! verify_digest "$old/$id.pre" || ! verify_digest "$old/$id.post"; then return 2; fi
    IFS=$'\t' read -r type pre_path hash < "$old/$id.pre" || return 2
    [[ $type == absent && $pre_path == "$target" && $hash =~ ^[0-9a-f]{64}$ ]] || return 2
    {
        IFS= read -r expected_metadata && IFS= read -r expected_attrs
    } < "$old/$id.post" || return 2
    actual=$(file_identity "$target") && attrs=$(created_metadata "$target") || return 2
    [[ $actual == "$expected_metadata" && $actual == *" $hash" && $attrs == "$expected_attrs" ]] || return 2
    printf '%s\n' "$id removes $target and restores its recorded absence. Runtime state may require a reboot." >&2
    approve "restore-$id"
    case $? in 1) return 3 ;; 2) return 4 ;; esac
    verify_script && trusted_module_directory || return 2
    actual=$(file_identity "$target") && attrs=$(created_metadata "$target") || return 2
    [[ $actual == "$expected_metadata" && $attrs == "$expected_attrs" ]] || return 2
    event INFO "$id approved restoration of absent predecessor for $target" || return 2
    rm -- "$target" && [[ ! -e $target && ! -L $target ]] || return 2
    printf '%s removed %s; review active and next-boot module state\n' "$id" "$target" >> "$RUN_DIR/changes.txt"
}

# 7. Shared configuration and assessment helpers

rule_result() {
    ASSESSMENT=$1 EVIDENCE=$2
}

inspect_module_settings() {
    awk -v mod="$1" '
        BEGIN {gsub(/_/, "-", mod)}
        {key=$2; gsub(/_/, "-", key)}
        key == mod && $1 ~ /^(blacklist|install|softdep|options|alias|remove)$/ {print}
    '
}

module_settings() {
    timeout 12 modprobe --showconfig 2>/dev/null | inspect_module_settings "$1"
}

module_runtime() {
    local module=${1//-/_} implementation
    [[ -r /proc/modules && -r /usr/lib/modules/$KERNEL/modules.builtin ]] || return 1
    if [[ -e /sys/module/$module ]]; then printf 'active\n'; return 0; fi
    implementation=$(awk -v name="$module" '
        {sub(/^.*\//,"",$0); sub(/\.ko$/,"",$0); gsub(/-/,"_",$0)}
        $0 == name {print "built-in"; exit}
    ' "/usr/lib/modules/$KERNEL/modules.builtin") || return 1
    if [[ -n $implementation ]]; then printf '%s\n' "$implementation"; return 0; fi
    awk -v name="$module" '$1 == name {active=1} END {print active ? "active" : "absent"}' /proc/modules
}

check_module() {
    local id=$1 module=${MODULE[$1]} effective local_policy runtime target first
    if ! have_tools modprobe; then rule_result NEEDS_REVIEW 'kmod is missing'; return; fi
    effective=$(module_settings "$module") || { rule_result ERROR 'kmod configuration query failed'; return; }
    runtime=$(module_runtime "$module") || { rule_result NEEDS_REVIEW 'module runtime status unavailable'; return; }
    local_policy=$(inspect_local_module_policy "$module") || {
        rule_result NEEDS_REVIEW 'local module policy includes unreadable, linked or ambiguous entries'; return;
    }
    if [[ $runtime != absent ]]; then
        rule_result FAIL "module $module is $runtime; review documented operational need"; return
    fi
    if [[ $local_policy != present ]] || ! printf '%s\n' "$effective" | awk '
            $1 == "install" {i++; if ($3 == "/bin/false" && NF == 3) f++}
            $1 == "blacklist" {b++} END {exit !(i == 1 && f == 1 && b >= 1)}'; then
        rule_result FAIL "required local/effective install and blacklist policy is incomplete for $module"; return
    fi
    if printf '%s\n' "$effective" | awk 'NF && $1 !~ /^(install|blacklist)$/ {other=1} END {exit !other}'; then
        rule_result NEEDS_REVIEW "effective module policy for $module has competing directives"; return
    fi
    target=$(module_path "$id")
    if [[ -f $target && ! -L $target ]] && IFS= read -r first < "$target" &&
       [[ $first == "# rhel8-stig $id created-boot $BOOT_ID" ]]; then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW "persistent local policy verified for $module; scheduled reboot pending"
        return
    fi
    rule_result PASS "local and effective modprobe configuration deny $module and it is inactive"
}

inspect_local_module_policy() {
    local module=$1 file
    local -a files=()
    [[ -d /etc/modprobe.d && -r /etc/modprobe.d && -x /etc/modprobe.d ]] || return 1
    for file in /etc/modprobe.d/*.conf; do
        if [[ ! -e $file && ! -L $file ]]; then continue; fi
        [[ -f $file && ! -L $file && -r $file ]] || return 1
        files+=("$file")
    done
    if (( ! ${#files[@]} )); then printf 'missing\n'; return; fi
    cat -- "${files[@]}" | inspect_module_settings "$module" | awk '
        $1 == "install" && $3 == "/bin/false" && NF == 3 {i++}
        $1 == "blacklist" && NF == 2 {b++}
        END {print i && b ? "present" : "missing"}'
}

module_admin() {
    local id=$1 name=${MODULE[$1]}
    printf '1. System administrator and application owner: review dependencies and verify any ISSO\n'
    printf '   operational-need record for %s. Preserve required access, storage and recovery paths.\n' "$name"
    printf '2. Review modprobe --showconfig and the loaded module state. For an unmanaged,\n'
    printf '   unused module, check eligibility with --dry-run --max-risk %s --only %s.\n' "${RISK[$id]}" "$id"
    printf '   If an existing definition controls the module, use its authoritative config source.\n'
    printf '3. Inspect the next-boot initramfs with lsinitrd and check kdump applicability.\n'
    printf '   If the module is included, review Red Hat KB 41278 before changing boot images.\n'
    printf '4. Schedule reboot with console recovery. Verify effective policy and module absence.\n'
}

# Scoped content and metadata operations. A plan contains only explicit paths,
# never shell commands. Apply constructs the same plan again under the lock.

edit_reset() {
    if [[ ${EDIT_TEMP-} == "$RUN_DIR"/.plan.* && -d $EDIT_TEMP && ! -L $EDIT_TEMP ]]; then
        rm -rf -- "$EDIT_TEMP" || return 1
    fi
    EDIT_TEMP=''
    EDIT_DISPOSITION=live EDIT_ACTIVATION='' EDIT_CONTEXT='' EDIT_REQUIREMENTS='' EDIT_RELATED='' EDIT_GROUPED=''
    EDIT_PATHS=() EDIT_KINDS=() EDIT_PRE=() EDIT_MODE=() EDIT_GROUP=()
    EDIT_OLD_MODE=() EDIT_OLD_GROUP=() EDIT_VALIDATOR=() EDIT_DIFF=() EDIT_BYTES=()
}

edit_fail() {
    PLAN_REASON=$1
    return 1
}

edit_safe_path() {
    local path=$1 parent owner mode
    valid_output_path "$path" || return 1
    case $path in /etc/*|/var/log|/var/log/*|/usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/sbin/*|/tmp|/var/tmp|/boot/grub2/grubenv) ;;
        /home/*/.bash_profile|/home/*/.bash_login|/home/*/.profile|/home/*/.bashrc)
            [[ $path =~ ^/home/[a-zA-Z0-9_.@-]+/\.(bash_profile|bash_login|profile|bashrc)$ ]] || return 1 ;;
        *) return 1 ;;
    esac
    [[ $path != *[[:cntrl:]]* && ! -L $path ]] || return 1
    parent=$(dirname -- "$path") || return 1
    local_filesystem "$parent" || return 1
    if [[ -e $path ]]; then local_filesystem "$path" || return 1; fi
    while [[ $parent != / ]]; do
        [[ -d $parent && ! -L $parent ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$parent") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        parent=$(dirname -- "$parent") || return 1
    done
}

edit_target_metadata() {
    local path=$1 owner links
    [[ ! -L $path && ( -f $path || -d $path ) ]] || return 1
    read -r owner EDIT_ORIGINAL_MODE EDIT_ORIGINAL_GROUP links < <(stat -c '%u %a %g %h' -- "$path") || return 1
    [[ $owner == 0 && $EDIT_ORIGINAL_MODE =~ ^[0-7]{1,4}$ && $EDIT_ORIGINAL_GROUP =~ ^[0-9]+$ ]] || return 1
    [[ -d $path || $links == 1 ]]
}

edit_properties() {
    local details attributes
    details=$(stat -c '%u:%g:%a' -- "$1") && attributes=$(created_metadata "$1") || return 1
    printf '%s %s\n' "$details" "$attributes"
}

edit_xattrs() {
    local attrs
    attrs=$(getfattr --absolute-names -d -m - --encoding=hex -- "$1" 2>/dev/null) || return 1
    attrs=${attrs#*"$1"}
    printf '%s\n' "$attrs" | sha256sum
}

edit_identity() {
    local kind=$1 path=$2 identity attributes times bytes=-
    if [[ ! -e $path && ! -L $path ]]; then printf 'absent\n'; return; fi
    edit_target_metadata "$path" || return 1
    identity=$(stat -c '%d:%i:%u:%g:%a:%h:%W' -- "$path") && attributes=$(created_metadata "$path") || return 1
    if [[ $kind == content ]]; then
        bytes=$(sha256_file "$path") && times=$(stat -c '%y:%z' -- "$path") || return 1
        identity+=:$times
    fi
    printf '%s\n%s\n%s\n' "$identity" "$attributes" "$bytes" | sha256sum | awk '{print $1}'
}

edit_unique() {
    local known
    for known in "${EDIT_PATHS[@]}"; do [[ $known != "$1" ]] || return 1; done
}

edit_content() {
    local path=$1 mode=$2 diff=$3 validator=${4:--} i=${#EDIT_PATHS[@]}
    local candidate="$EDIT_TEMP/edit-$i" original props
    if ! edit_safe_path "$path" || ! edit_unique "$path"; then
        edit_fail "unsafe or duplicate config path $path"; return
    fi
    original=$(edit_identity content "$path") || { edit_fail "could not identify $path"; return; }
    if [[ $original == absent ]]; then
        [[ $mode == 0644 || $mode == 0600 ]] || { edit_fail "new file $path needs an explicit safe mode"; return; }
    else
        if [[ $mode != keep || ! -f $path ]] || ! edit_target_metadata "$path" ||
           (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
            edit_fail "existing $path is outside the supported root-controlled staging layout"; return
        fi
    fi
    cat > "$candidate" && text_input_file "$candidate" && [[ -s $candidate ]] || {
        edit_fail "replacement for $path was unreadable, empty, oversized or contained control bytes"; return;
    }
    if [[ $validator != - ]] && { ! declare -F "$validator" >/dev/null || ! "$validator" "$candidate" "$path"; }; then
        edit_fail "staged validation failed for $path"; return
    fi
    props=$(sha256_file "$candidate") || return 1
    if [[ $original != absent && $props == "$(sha256_file "$path")" ]]; then
        edit_fail "proposed content leaves $path unchanged"; return
    fi
    EDIT_PATHS+=("$path") EDIT_KINDS+=(content) EDIT_PRE+=("$original") EDIT_MODE+=("$mode")
    EDIT_OLD_MODE+=(-) EDIT_OLD_GROUP+=(-) EDIT_GROUP+=(-)
    EDIT_VALIDATOR+=("$validator") EDIT_DIFF+=("$diff") EDIT_BYTES+=("$props")
}

edit_basic_acl() {
    local acl pattern=$'^user::[rwx-]{3}\ngroup::[rwx-]{3}\nother::[rwx-]{3}$'
    acl=$(getfacl -cp -- "$1" 2>/dev/null) || return 1
    [[ $acl =~ $pattern ]]
}

edit_metadata() {
    local path=$1 mode=$2 group=$3 diff=$4 original attrs
    if ! edit_safe_path "$path" || ! edit_unique "$path" || ! edit_target_metadata "$path" ||
       ! edit_basic_acl "$path"; then
        edit_fail "metadata edit requires a trusted path with a basic ACL ($path)"; return
    fi
    [[ $mode == keep || $mode =~ ^0[0-7]{3,4}$ ]] && [[ $group == keep || $group =~ ^[0-9]+$ ]] || {
        edit_fail "invalid requested metadata for $path"; return;
    }
    if [[ $mode == keep ]]; then mode=0$EDIT_ORIGINAL_MODE; fi
    if [[ $group == keep ]]; then group=$EDIT_ORIGINAL_GROUP; fi
    if (( 8#$mode == 8#$EDIT_ORIGINAL_MODE )) && [[ $group == "$EDIT_ORIGINAL_GROUP" ]]; then
        return 0
    fi
    if [[ $group != "$EDIT_ORIGINAL_GROUP" ]]; then
        attrs=$(getfattr --absolute-names -d -m - -- "$path" 2>/dev/null) || return 1
        if [[ $attrs == *security.capability=* ]] || (( 8#$EDIT_ORIGINAL_MODE & 07000 )); then
            edit_fail "group change could remove special mode bits or capabilities on $path"; return
        fi
    fi
    original=$(edit_identity metadata "$path") || { edit_fail "metadata changed or is unreadable for $path"; return; }
    EDIT_PATHS+=("$path") EDIT_KINDS+=(metadata) EDIT_PRE+=("$original") EDIT_MODE+=("$mode")
    EDIT_OLD_MODE+=("0$EDIT_ORIGINAL_MODE") EDIT_OLD_GROUP+=("$EDIT_ORIGINAL_GROUP") EDIT_GROUP+=("$group")
    EDIT_VALIDATOR+=(-) EDIT_DIFF+=("$diff") EDIT_BYTES+=(-)
}

# An exact zero-context diff is limited to recognized setting lines. Shared
# configuration sources can contain credentials, comments and site details.
edit_public_diff() {
    local i=$1 path=${EDIT_PATHS[$1]} original id public_additions='' public_removals=''
    if [[ ${EDIT_KINDS[i]} == metadata ]]; then
        printf -- '--- before %s\n+++ after %s\n- mode %s, group %s\n+ mode %s, group %s\n' \
            "$path" "$path" "${EDIT_OLD_MODE[i]}" "${EDIT_OLD_GROUP[i]}" "${EDIT_MODE[i]}" "${EDIT_GROUP[i]}"
        return
    fi
    if ! have_tools diff; then return 0; fi
    original=$path
    if [[ ${EDIT_PRE[i]} == absent ]]; then
        original=/dev/null
        # Only publish exact lines authored by the built-in audit planners.
        # A path or validator name alone does not make candidate text public.
        if [[ $path =~ ^/etc/audit/rules\.d/90-rhel8-stig-v([0-9]{6})\.rules$ ]]; then
            id=${BASH_REMATCH[1]}
            case ${EDIT_VALIDATOR[i]}:$id in
                audit_rule_dropin_validate:288831) public_additions=$(audit_rule_dropin_payload useradd '') || public_additions='' ;;
                audit_rule_dropin_validate:274877) public_additions=$(audit_rule_dropin_payload cron '') || public_additions='' ;;
                expansion_audit_validate_dropin:*) public_additions=$(expansion_audit_payload "V-$id") || public_additions='' ;;
            esac
        fi
        if [[ $path == "/etc/crypto-policies/policies/modules/$ATTENDED_SSH_MODULE.pmod" &&
              ${EDIT_VALIDATOR[i]} == attended_crypto_module_validate ]]; then
            public_additions=$(attended_ssh_module) || return 1
        fi
        if [[ ${EDIT_VALIDATOR[i]} == guided_module_validate ]]; then
            public_additions=${EDIT_DIFF[i]}
        fi
    fi
    if [[ $path == /etc/crypto-policies/config && ${EDIT_VALIDATOR[i]} == attended_crypto_config_validate ]]; then
        public_additions=$(printf '%s\n' "FIPS:$ATTENDED_SSH_MODULE" \
            '# rhel8-stig original policy: DEFAULT' '# rhel8-stig original policy: FIPS') || return 1
        public_removals=$'DEFAULT\nFIPS'
    fi
    {
        local status=0
        diff -U0 --label "before $path" --label "after $path" -- "$original" "$EDIT_TEMP/edit-$i" || status=$?
        (( status < 2 ))
    } | awk -v public_additions="$public_additions" -v public_removals="$public_removals" '
        BEGIN {
            n=split(public_additions, additions, /\n/)
            for (i=1; i<=n; i++) public_add[additions[i]]=1
            n=split(public_removals, removals, /\n/)
            for (i=1; i<=n; i++) public_remove[removals[i]]=1
        }
        (NR <= 2 && /^(--- before |\+\+\+ after )/) ||
          /^@@ -[0-9]+(,[0-9]+)? \+[0-9]+(,[0-9]+)? @@$/ {print; next}
        /^[+-]/ {
            mark=substr($0,1,1); v=substr($0,2)
            if ((mark == "+" && (v in public_add)) || (mark == "-" && (v in public_remove)) ||
                v ~ /^[[:space:]]*(umask[[:space:]]+[0-7]{1,4}|(PermitRootLogin|GSSAPIAuthentication|PermitEmptyPasswords|PermitUserEnvironment|X11Forwarding|StrictModes|IgnoreRhosts|CREATE_HOME)[[:space:]]+(yes|no)|gpgcheck[[:space:]]*=[[:space:]]*[01]|idle-delay[[:space:]]*=[[:space:]]*uint32[[:space:]]+[0-9]+|disable-user-list[[:space:]]*=[[:space:]]*(true|false)|logout[[:space:]]*=[[:space:]]*\047\047|StopIdleSessionSec[[:space:]]*=[[:space:]]*[0-9]+)[[:space:]]*$/ ||
                v ~ /^[[:space:]]*(ClientAliveCountMax|ClientAliveInterval|PASS_(MIN|MAX|WARN)_DAYS)[[:space:]]+[0-9]+[[:space:]]*$/ ||
                v ~ /^[[:space:]]*(fs\.protected_(hardlinks|symlinks)|kernel\.(dmesg_restrict|perf_event_paranoid|randomize_va_space|kptr_restrict)|net\.ipv[46]\.conf\.(all|default)\.(accept_redirects|accept_source_route|send_redirects|log_martians)|net\.ipv4\.icmp_echo_ignore_broadcasts)[[:space:]]*=[[:space:]]*[0-9]+[[:space:]]*$/ ||
                v ~ /^[[:space:]]*(difok|minlen|minclass|[dulo]credit|maxrepeat|maxclassrepeat|maxsequence|retry|clean_requirements_on_remove)[[:space:]]*=[[:space:]]*-?[0-9]+[[:space:]]*$/ ||
                v ~ /^[[:space:]]*(local_events[[:space:]]*=[[:space:]]*(yes|no)|log_format[[:space:]]*=[[:space:]]*(RAW|ENRICHED)|CtrlAltDelBurstAction[[:space:]]*=[[:space:]]*none|banner-message-enable[[:space:]]*=[[:space:]]*(true|false))[[:space:]]*$/)
                print mark " " v
            else
                print mark " [source line omitted; see reviewed change above]"
        }
    '
}

file_plan() {
    local id=$1 fn="rule_${1//-/_}_plan" i record related
    local -a planner=("$fn")
    PLAN_REASON='' PLAN_TEXT='' PLAN_SIGNATURE=''
    edit_reset || { edit_fail 'could not remove previous temporary plan'; return; }
    if ! have_tools getfacl getfattr cp mv ln rm chgrp findmnt df; then
        edit_fail 'file plans require ACL, extended-attribute and local filesystem tools'; return
    fi
    EDIT_TEMP=$(mktemp -d -- "$RUN_DIR/.plan.XXXXXXXX") || return 1
    if guided_module_id "$id" && (( ! REVIEW_EACH )); then planner=(guided_module_plan "$id"); fi
    if ! "${planner[@]}"; then
        PLAN_REASON=${PLAN_REASON:-'the observed configuration did not meet the edit prerequisites'}
        return 1
    fi
    if (( ! ${#EDIT_PATHS[@]} )); then edit_fail 'no eligible targets were identified'; return; fi
    allow_rule_plan "$id" "$EDIT_RELATED" || return 1
    for related in $EDIT_GROUPED; do
        if [[ $related == "$id" || " $EDIT_RELATED " != *" $related "* ]]; then
            edit_fail 'a grouped change must also declare its sibling rule as affected'; return
        fi
    done
    for i in "${!EDIT_PATHS[@]}"; do
        if [[ ${EDIT_TOUCHED[${EDIT_PATHS[i]}]+changed} ]]; then
            edit_fail "an earlier rule changed ${EDIT_PATHS[i]}. Reassess it in a separate run for independent recovery"
            return
        fi
    done
    if [[ ! $EDIT_DISPOSITION =~ ^(live|pending)$ || ( $EDIT_DISPOSITION == pending && ! $EDIT_ACTIVATION ) ]]; then
        edit_fail 'the rule supplied an invalid activation plan'; return
    fi
    if (( DEFER )); then
        if [[ $EDIT_DISPOSITION == live || " ${EDIT_KINDS[*]} " == *' metadata '* ]]; then
            edit_fail 'the operation takes effect immediately and cannot be staged with --defer-service-actions'; return
        fi
    fi
    {
        printf '%s\n' "$id" "$EDIT_DISPOSITION" "$EDIT_CONTEXT" "$EDIT_ACTIVATION" "$EDIT_REQUIREMENTS" \
            "$EDIT_RELATED" "$EDIT_GROUPED"
        for i in "${!EDIT_PATHS[@]}"; do
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "${EDIT_KINDS[i]}" "${EDIT_PATHS[i]}" \
                "${EDIT_PRE[i]}" "${EDIT_MODE[i]}" "${EDIT_GROUP[i]}" "${EDIT_BYTES[i]}"
        done
    } > "$EDIT_TEMP/signature" || return 1
    PLAN_SIGNATURE=$(sha256_file "$EDIT_TEMP/signature") || return 1
    PLAN_TEXT=$(for i in "${!EDIT_PATHS[@]}"; do
            printf '%s\n' "${EDIT_PATHS[i]}"
            printf '%s\n' "${EDIT_DIFF[i]}"
        done
        if [[ $EDIT_REQUIREMENTS ]]; then printf 'Before applying: %s\n' "$EDIT_REQUIREMENTS"; fi
        if [[ $EDIT_RELATED ]]; then printf 'Related rule IDs: %s\n' "$EDIT_RELATED"; fi
        if [[ $EDIT_DISPOSITION == pending ]]; then printf 'Activation: %s\n' "$EDIT_ACTIVATION"; fi
        printf '%s\n' 'Recovery: restore the recorded original only while the resulting state still matches.') || return 1
    record=$(clean_text "$PLAN_TEXT") || return 1
    PLAN_TEXT=$record
    if plan_diff_requested || { [[ $MODE == apply ]] && attended_ssh_id "$id"; }; then
        PLAN_DIFF=$(for i in "${!EDIT_PATHS[@]}"; do edit_public_diff "$i" || exit 1; done) || return 1
    fi
}

edit_set_metadata() {
    local path=$1 expected=$2 mode=$3 group=$4 fd pinned device actual_group actual_mode before_attrs
    [[ $(edit_identity metadata "$path") == "$expected" ]] || return 1
    before_attrs=$(edit_xattrs "$path") || return 1
    device=$(stat -c '%d:%i' -- "$path") || return 1
    exec {fd}< "$path" || return 1
    pinned=/proc/$$/fd/$fd
    if [[ $(stat -Lc '%d:%i' -- "$pinned") != "$device" || $(edit_identity metadata "$path") != "$expected" ]]; then
        exec {fd}<&-
        return 1
    fi
    read -r actual_group actual_mode < <(stat -Lc '%g %a' -- "$pinned") || { exec {fd}<&-; return 1; }
    if [[ $actual_group != "$group" ]] && ! chgrp -- "+$group" "$pinned"; then exec {fd}<&-; return 1; fi
    if (( 8#$actual_mode != 8#$mode )) && ! chmod -- "$mode" "$pinned"; then exec {fd}<&-; return 1; fi
    exec {fd}<&-
    [[ $(stat -c '%d:%i %g' -- "$path") == "$device $group" &&
       $(edit_xattrs "$path") == "$before_attrs" ]] || return 1
    actual_mode=$(stat -c '%a' -- "$path") || return 1
    (( 8#$actual_mode == 8#$mode ))
}

edit_new_label() {
    local stage=$1 path=$2 expected
    chmod -- "$3" "$stage" || return 1
    [[ $(stat -c '%u:%g:%h' -- "$stage") == 0:0:1 ]] || return 1
    edit_basic_acl "$stage" || return 1
    if ! have_tools getenforce || [[ $(getenforce 2>/dev/null) != Disabled ]]; then
        have_tools matchpathcon chcon || return 1
        expected=$(matchpathcon -n -- "$path" 2>/dev/null) || return 1
        [[ $expected && $expected != '<<none>>' ]] && chcon -- "$expected" "$stage" || return 1
    fi
}

edit_make_stage() {
    local path=$1 source=$2 mode=$3 original=$4 stage before_props after_props
    stage=$(mktemp -- "$(dirname -- "$path")/.rhel8-stig.XXXXXXXX") || return 1
    STAGING_FILE=$stage
    if [[ $original == absent ]]; then
        cat -- "$source" > "$stage" && edit_new_label "$stage" "$path" "$mode"
    else
        cp --preserve=all -- "$path" "$stage" && cat -- "$source" > "$stage" &&
            before_props=$(edit_properties "$path") && after_props=$(edit_properties "$stage") &&
            [[ $before_props == "$after_props" ]]
    fi
}

edit_write_journal() {
    local txn=$1 index=$2 kind=${EDIT_KINDS[$2]} path=${EDIT_PATHS[$2]} before=${EDIT_PRE[$2]}
    local before_bytes saved_bytes before_props saved_props
    [[ $(edit_identity "$kind" "$path") == "$before" ]] || return 1
    if [[ $kind == content && $before != absent ]]; then
        cp --preserve=all -- "$path" "$txn/$index.original" &&
            before_bytes=$(sha256_file "$path") && saved_bytes=$(sha256_file "$txn/$index.original") &&
            before_props=$(edit_properties "$path") && saved_props=$(edit_properties "$txn/$index.original") &&
            [[ $before_bytes == "$saved_bytes" && $before_props == "$saved_props" ]] &&
            record_digest "$txn/$index.original" || return 1
        printf '%s\n' "$saved_props" > "$txn/$index.original.meta" &&
            record_digest "$txn/$index.original.meta" || return 1
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$path" "$before" \
        "${EDIT_OLD_MODE[index]}" "${EDIT_OLD_GROUP[index]}" >> "$txn/operations"
}

apply_file_plan() {
    local id=$1 accepted=$2 txn i kind path before validator post space
    if ! verify_script || ! file_plan "$id" || [[ $PLAN_SIGNATURE != "$accepted" ]]; then
        event BLOCKED "$id plan, supporting configuration or executing bytes changed after review"
        return 1
    fi
    prepare_backup || return 1
    space=$(df -Pk -- "$BACKUP_RUN" | awk 'END {print $4}') || return 1
    [[ $space =~ ^[0-9]+$ ]] && (( space >= 1024 )) || return 1
    txn=$BACKUP_RUN/$id.edits
    mkdir -m 0700 -- "$txn" && : > "$txn/operations" || return 1
    for i in "${!EDIT_PATHS[@]}"; do edit_write_journal "$txn" "$i" || return 1; done
    record_digest "$txn/operations" || return 1
    printf '%s\n%s\n' "$EDIT_DISPOSITION" "$EDIT_ACTIVATION" > "$txn/disposition" &&
        record_digest "$txn/disposition" || return 1
    printf '%s\n' "$EDIT_RELATED" > "$txn/affected" && record_digest "$txn/affected" || return 1
    printf '%s\n' "$EDIT_GROUPED" > "$txn/grouped" && record_digest "$txn/grouped" || return 1
    for i in "${!EDIT_PATHS[@]}"; do
        kind=${EDIT_KINDS[i]} path=${EDIT_PATHS[i]} before=${EDIT_PRE[i]} validator=${EDIT_VALIDATOR[i]}
        edit_safe_path "$path" && [[ $(edit_identity "$kind" "$path") == "$before" ]] && verify_script || return 1
        event INFO "$id verified original and approved $kind operation on $path" || return 1
        if [[ $kind == content ]]; then
            edit_make_stage "$path" "$EDIT_TEMP/edit-$i" "${EDIT_MODE[i]}" "$before" || return 1
            [[ $(sha256_file "$STAGING_FILE") == "${EDIT_BYTES[i]}" ]] || return 1
            if [[ $validator != - ]] && ! "$validator" "$STAGING_FILE" "$path"; then return 1; fi
            [[ $(edit_identity "$kind" "$path") == "$before" ]] && verify_script || return 1
            if [[ $before == absent ]]; then
                ln -T -- "$STAGING_FILE" "$path" && rm -- "$STAGING_FILE" || return 1
            else
                mv -fT -- "$STAGING_FILE" "$path" || return 1
            fi
            STAGING_FILE=''
            [[ $(sha256_file "$path") == "${EDIT_BYTES[i]}" ]] || return 1
        else
            edit_set_metadata "$path" "$before" "${EDIT_MODE[i]}" "${EDIT_GROUP[i]}" || return 1
        fi
        post=$(edit_identity "$kind" "$path") && [[ $post != absent ]] || return 1
        printf '%s\n' "$post" > "$txn/$i.post" && record_digest "$txn/$i.post" || return 1
        EDIT_TOUCHED[$path]=1
        printf '%s changed %s (%s)\n' "$id" "$path" "$kind" >> "$RUN_DIR/changes.txt" || return 1
        if [[ $validator != - ]] && ! "$validator" "$path" "$path"; then return 1; fi
    done
    rule_dispatch "$id"
    if [[ $EDIT_DISPOSITION == pending ]]; then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW "Persistent change verified. $EDIT_ACTIVATION"
    elif [[ $ASSESSMENT != PASS ]]; then
        event WARN "$id applied the approved change. The independent check still reports $ASSESSMENT" || return 1
    fi
    return 0
}

read_edit_row() {
    IFS=$'\t' read -r ROW_KIND ROW_PATH ROW_BEFORE ROW_MODE ROW_GROUP ROW_EXTRA <<< "$1"
    [[ ! $ROW_EXTRA && $ROW_KIND =~ ^(content|metadata)$ &&
       $ROW_BEFORE =~ ^(absent|[0-9a-f]{64})$ && $ROW_MODE =~ ^(-|0[0-7]{1,4})$ &&
       $ROW_GROUP =~ ^(-|[0-9]+)$ ]] && edit_safe_path "$ROW_PATH"
}

edit_rollback_precheck() {
    local txn=$1 i=$2 current saved attrs
    verify_digest "$txn/$i.post" && read -r saved < "$txn/$i.post" || return 1
    current=$(edit_identity "$ROW_KIND" "$ROW_PATH") && [[ $current == "$saved" && $current != absent ]] || return 1
    if [[ $ROW_KIND == content && $ROW_BEFORE != absent ]]; then
        verify_digest "$txn/$i.original" && verify_digest "$txn/$i.original.meta" &&
            read -r attrs < "$txn/$i.original.meta" && [[ $(edit_properties "$txn/$i.original") == "$attrs" ]] || return 1
    fi
}

rollback_file_plan() {
    local id=$1 old=$2 txn i reply expected backup_attrs original_bytes restored_bytes related grouped
    local ROW_KIND ROW_PATH ROW_BEFORE ROW_MODE ROW_GROUP ROW_EXTRA
    local -a rows=()
    txn=$old/$id.edits
    if [[ ! -e $txn && ! -L $txn ]]; then return 1; fi
    secure_directory "$txn" 0 no && verify_digest "$txn/operations" &&
        text_input_file "$txn/operations" && mapfile -t rows < "$txn/operations" || return 2
    verify_digest "$txn/affected" && read -r related < "$txn/affected" && allow_rule_plan "$id" "$related" || return 2
    verify_digest "$txn/grouped" && read -r grouped < "$txn/grouped" || return 2
    for i in $grouped; do
        [[ $i != "$id" && " $related " == *" $i "* ]] || return 2
    done
    (( ${#rows[@]} )) || return 2
    for i in "${!rows[@]}"; do
        read_edit_row "${rows[i]}" && edit_rollback_precheck "$txn" "$i" || return 2
        printf '%s restore %s (%s)\n' "$id" "$ROW_PATH" "$ROW_KIND" >&2
    done
    printf '%s\n' 'Review any service or mount activation separately after file restoration.' >&2
    approve "restore-$id"; reply=$?
    case $reply in 1) return 3 ;; 2) return 4 ;; esac
    for i in "${!rows[@]}"; do
        verify_script && read_edit_row "${rows[i]}" && edit_rollback_precheck "$txn" "$i" || return 2
        event INFO "$id approved restoration of $ROW_PATH" || return 2
        case $ROW_KIND:$ROW_BEFORE in
            metadata:*)
                read -r expected < "$txn/$i.post" &&
                    edit_set_metadata "$ROW_PATH" "$expected" "$ROW_MODE" "$ROW_GROUP" &&
                    [[ $(edit_identity metadata "$ROW_PATH") == "$ROW_BEFORE" ]] || return 2 ;;
            content:absent)
                rm -- "$ROW_PATH" && [[ ! -e $ROW_PATH && ! -L $ROW_PATH ]] || return 2 ;;
            content:*)
                STAGING_FILE=$(mktemp -- "$(dirname -- "$ROW_PATH")/.rhel8-stig.XXXXXXXX") || return 2
                cp --preserve=all -- "$txn/$i.original" "$STAGING_FILE" &&
                    read -r backup_attrs < "$txn/$i.original.meta" &&
                    original_bytes=$(sha256_file "$txn/$i.original") &&
                    [[ $(sha256_file "$STAGING_FILE") == "$original_bytes" &&
                       $(edit_properties "$STAGING_FILE") == "$backup_attrs" ]] &&
                    edit_rollback_precheck "$txn" "$i" && mv -fT -- "$STAGING_FILE" "$ROW_PATH" || return 2
                STAGING_FILE=''
                restored_bytes=$(sha256_file "$ROW_PATH") &&
                    [[ $restored_bytes == "$original_bytes" &&
                   $(edit_properties "$ROW_PATH") == "$backup_attrs" ]] || return 2 ;;
        esac
        printf '%s restored %s\n' "$id" "$ROW_PATH" >> "$RUN_DIR/changes.txt" || return 2
    done
    for i in $grouped; do GROUPED_BY[$i]=$id; done
}

# Attended native operations. Each rule defines how to observe, change and
# restore one typed target. Reports and journals contain state, never commands.
action_field() {
    [[ -n $1 && ${#1} -le 512 && $1 != *[^[:print:]]* ]]
}

action_add() {
    local target=$1 before=$2 desired=$3 entry
    action_field "$target" && action_field "$before" && action_field "$desired" &&
        [[ $before != "$desired" && ${#ACTION_TARGETS[@]} -lt 128 ]] ||
        { edit_fail 'native action has an invalid or oversized state'; return; }
    for entry in "${ACTION_TARGETS[@]}"; do
        if [[ $entry == "$target" ]]; then edit_fail "duplicate native action for $target"; return; fi
    done
    ACTION_TARGETS+=("$target") ACTION_BEFORE+=("$before") ACTION_DESIRED+=("$desired")
    ACTION_OLD_TEXT+=("$4") ACTION_NEW_TEXT+=("$5")
}

action_preview_delta() {
    local index
    for index in "${!ACTION_TARGETS[@]}"; do
        printf '%s\n- %s\n+ %s\n' "${ACTION_TARGETS[index]}" \
            "${ACTION_OLD_TEXT[index]}" "${ACTION_NEW_TEXT[index]}" || return 1
    done
}

action_plan() {
    local id=$1 fn="rule_${1//-/_}_plan" observe="rule_${1//-/_}_observe" i
    ACTION_CONTEXT='' ACTION_REQUIREMENTS='' ACTION_ACTIVATION=''
    ACTION_TARGETS=() ACTION_BEFORE=() ACTION_DESIRED=() ACTION_OLD_TEXT=() ACTION_NEW_TEXT=()
    PLAN_REASON='' PLAN_TEXT='' PLAN_SIGNATURE=''
    "$fn" || { PLAN_REASON=${PLAN_REASON:-'could not establish native action prerequisites'}; return 1; }
    if (( ! ${#ACTION_TARGETS[@]} )); then edit_fail 'no eligible native action targets'; return; fi
    if (( DEFER )) && [[ -z $ACTION_ACTIVATION ]]; then
        edit_fail 'the native action takes effect immediately and cannot be staged with --defer-service-actions'
        return
    fi
    for i in "${!ACTION_TARGETS[@]}"; do
        if [[ $("$observe" "${ACTION_TARGETS[i]}") != "${ACTION_BEFORE[i]}" ]]; then
            edit_fail "native action state changed during review of ${ACTION_TARGETS[i]}"; return
        fi
    done
    PLAN_TEXT=$(
        action_preview_delta || exit 1
        if [[ $ACTION_REQUIREMENTS ]]; then printf 'Before applying: %s\n' "$ACTION_REQUIREMENTS"; fi
        if [[ $ACTION_ACTIVATION ]]; then printf 'Activation: %s\n' "$ACTION_ACTIVATION"; fi
        printf '%s\n' 'Recovery: restore the recorded state after checking for intervening changes.'
    ) || return 1
    PLAN_SIGNATURE=$(
        {
            printf '%s\0' "$id" "$ACTION_CONTEXT" "$ACTION_ACTIVATION" "$PLAN_TEXT"
            for i in "${!ACTION_TARGETS[@]}"; do
                printf '%s\0' "${ACTION_TARGETS[i]}" "${ACTION_BEFORE[i]}" "${ACTION_DESIRED[i]}"
            done
        } | sha256sum
    )
}

action_result_matches() {
    local fn="rule_${1//-/_}_matches"
    if declare -F "$fn" >/dev/null; then "$fn" "$2" "$3"; else [[ $2 == "$3" ]]; fi
}

apply_action_plan() {
    local id=$1 accepted=$2 fn="rule_${1//-/_}" txn i before target after
    verify_script && action_plan "$id" && [[ $PLAN_SIGNATURE == "$accepted" ]] || return 1
    prepare_backup || return 1
    txn=$BACKUP_RUN/$id.actions
    mkdir -m 0700 -- "$txn" || return 1
    for i in "${!ACTION_TARGETS[@]}"; do
        printf '%s\t%s\t%s\n' "${ACTION_TARGETS[i]}" "${ACTION_BEFORE[i]}" "${ACTION_DESIRED[i]}" ||
            return 1
    done > "$txn/operations"
    record_digest "$txn/operations" || return 1
    printf '%s\n' "$ACTION_ACTIVATION" > "$txn/activation" && record_digest "$txn/activation" || return 1
    for i in "${!ACTION_TARGETS[@]}"; do
        target=${ACTION_TARGETS[i]} before=${ACTION_BEFORE[i]}
        verify_script && verify_selection_source &&
            [[ $("${fn}_observe" "$target") == "$before" ]] || return 1
        event INFO "$id approved native action on $target" || return 1
        "${fn}_change" "$target" "$before" "${ACTION_DESIRED[i]}" || return 1
        after=$("${fn}_observe" "$target") && action_field "$after" &&
            action_result_matches "$id" "$after" "${ACTION_DESIRED[i]}" || return 1
        printf '%s\n' "$after" > "$txn/$i.post" && record_digest "$txn/$i.post" || return 1
        printf '%s changed %s (native action)\n' "$id" "$target" >> "$RUN_DIR/changes.txt" || return 1
    done
    rule_dispatch "$id"
    if [[ $ACTION_ACTIVATION ]]; then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW "Persistent change verified. $ACTION_ACTIVATION"
    fi
    return 0
}

action_read_row() {
    local extra
    IFS=$'\t' read -r ACTION_ROW_TARGET ACTION_ROW_BEFORE ACTION_ROW_DESIRED extra <<< "$1"
    [[ ! $extra ]] && action_field "$ACTION_ROW_TARGET" &&
        action_field "$ACTION_ROW_BEFORE" && action_field "$ACTION_ROW_DESIRED"
}

action_rollback_state() {
    local id=$1 txn=$2 index=$3 row=$4 observe="rule_${1//-/_}_observe"
    action_read_row "$row" && verify_digest "$txn/$index.post" &&
        IFS= read -r ACTION_ROW_POST < "$txn/$index.post" && action_field "$ACTION_ROW_POST" &&
        action_result_matches "$id" "$ACTION_ROW_POST" "$ACTION_ROW_DESIRED" &&
        [[ $("$observe" "$ACTION_ROW_TARGET") == "$ACTION_ROW_POST" ]]
}

rollback_action_plan() {
    local id=$1 old=$2 fn="rule_${1//-/_}" txn i decision
    local ACTION_ROW_TARGET ACTION_ROW_BEFORE ACTION_ROW_DESIRED ACTION_ROW_POST
    local -a action_rows=()
    txn=$old/$id.actions
    if [[ ! -e $txn && ! -L $txn ]]; then return 1; fi
    secure_directory "$txn" 0 no && verify_digest "$txn/operations" &&
        text_input_file "$txn/operations" && mapfile -t action_rows < "$txn/operations" || return 2
    (( ${#action_rows[@]} >= 1 && ${#action_rows[@]} <= 128 )) || return 2
    for i in "${!action_rows[@]}"; do
        action_rollback_state "$id" "$txn" "$i" "${action_rows[i]}" || return 2
        printf '%s restore %s (native action)\n' "$id" "$ACTION_ROW_TARGET" >&2
    done
    approve "restore-$id"; decision=$?
    case $decision in 1) return 3 ;; 2) return 4 ;; esac
    for (( i=${#action_rows[@]}-1; i>=0; i-- )); do
        verify_script && action_rollback_state "$id" "$txn" "$i" "${action_rows[i]}" || return 2
        "${fn}_restore" "$ACTION_ROW_TARGET" "$ACTION_ROW_BEFORE" "$ACTION_ROW_POST" &&
            [[ $("${fn}_observe" "$ACTION_ROW_TARGET") == "$ACTION_ROW_BEFORE" ]] || return 2
        printf '%s restored %s (native action)\n' "$id" "$ACTION_ROW_TARGET" >> "$RUN_DIR/changes.txt" || return 2
    done
    return 0
}

# 8. Rule registry and per-rule handlers

# Register a reviewed rule here with an explicit default flag. Registration
# alone must not expand the default. Metadata and quoted policy are data only.
register_rule() {
    local id=$1 category=$2 risk=$3 default=$4 kind=$5 module=$6 affected=$7
    local title=$8 revision=$9 policy=${10} check_ref=${11} fix_ref=${12}
    local check=${13} fix=${14}
    [[ $id =~ ^V-[0-9]{6}$ && ! ${TITLE[$id]+registered} ]] || return 1
    [[ $category =~ ^(I|II|III)$ && $risk =~ ^(low|medium|high)$ &&
       $default =~ ^(yes|no)$ && $kind =~ ^(assessment|evidence-review|attended-module|attended-file|attended-action)$ &&
       $revision =~ ^SV-${id#V-}r[0-9]+_rule$ && $policy =~ ^RHEL-08-[0-9]+$ &&
       $check_ref =~ ^C-[0-9]+r[0-9]+_chk$ && $fix_ref =~ ^F-[0-9]+r[0-9]+_fix$ &&
       -n $title && -n $check && -n $fix ]] || return 1
    if [[ $kind == attended-module ]]; then
        [[ $module =~ ^[a-z0-9-]+$ && -n $affected ]] || return 1
    else
        [[ -z $module ]] || return 1
    fi
    RULE_IDS+=("$id")
    CATEGORY[$id]=$category RISK[$id]=$risk DEFAULT_RULE[$id]=$default
    HANDLING[$id]=$kind AFFECTED[$id]=$affected TITLE[$id]=$title REVISION[$id]=$revision
    POLICY_NAME[$id]=$policy CHECK_REF[$id]=$check_ref FIX_REF[$id]=$fix_ref
    OFFICIAL_CHECK[$id]=$check OFFICIAL_FIX[$id]=$fix
    if [[ -n $module ]]; then MODULE[$id]=$module; fi
    return 0
}

validate_registry() {
    local id affected fn name
    local -A used=()
    for id in "${RULE_IDS[@]}"; do
        fn="rule_${id//-/_}"
        declare -F "${fn}_check" >/dev/null && declare -F "${fn}_admin" >/dev/null || return 1
        for affected in ${AFFECTED[$id]}; do known_id "$affected" || return 1; done
        if [[ ${HANDLING[$id]} == attended-module ]]; then
            name=${MODULE[$id]}
            [[ ! ${used[$name]+registered} && " ${AFFECTED[$id]} " == *" $id "* ]] || return 1
            used[$name]=1
        elif [[ ${HANDLING[$id]} == attended-file ]]; then
            declare -F "${fn}_plan" >/dev/null && [[ " ${AFFECTED[$id]} " == *" $id "* ]] || return 1
        elif [[ ${HANDLING[$id]} == attended-action ]]; then
            declare -F "${fn}_plan" "${fn}_observe" "${fn}_change" "${fn}_restore" >/dev/null &&
                [[ " ${AFFECTED[$id]} " == *" $id "* ]] || return 1
        fi
    done
}

register_rules() {
    declare -ga RULE_IDS=()
    declare -gA CATEGORY=() RISK=() DEFAULT_RULE=() HANDLING=() MODULE=() AFFECTED=()
    declare -gA TITLE=() REVISION=() POLICY_NAME=() CHECK_REF=() FIX_REF=()
    declare -gA OFFICIAL_CHECK=() OFFICIAL_FIX=()
    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230224' 'I' 'high' 'yes' 'evidence-review' '' 'V-230224' \
        'All RHEL 8 local disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at rest protection.' \
        'SV-230224r1044787_rule' 'RHEL-08-010030' 'C-32893r917863_chk' 'F-32868r567419_fix' \
        'Verify RHEL 8 prevents unauthorized disclosure or modification of all information requiring at-rest protection by using disk encryption. 

If there is a documented and approved reason for not having data-at-rest encryption at the operating system level, such as encryption provided by a hypervisor or a disk storage array in a virtualized environment, this requirement is not applicable.

Verify all system partitions are encrypted with the following command:

     $ sudo blkid

     /dev/mapper/rhel-root:  UUID="67b7d7fe-de60-6fd0-befb-e6748cf97743" TYPE="crypto_LUKS"

Every persistent disk partition present must be of type "crypto_LUKS". If any partitions other than the boot partition or pseudo file systems (such as /proc or /sys) are not type "crypto_LUKS", ask the administrator to indicate how the partitions are encrypted. 

If there is no evidence that these partitions are encrypted, this is a finding.' \
        'Configure RHEL 8 to prevent unauthorized modification of all information at rest by using disk encryption. 

Encrypting a partition in an already installed system is more difficult, because existing partitions will need to be resized and changed. To encrypt an entire partition, dedicate a partition for encryption in the partition layout.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230226' 'II' 'low' 'yes' 'attended-file' '' 'V-230226' \
        'RHEL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a graphical user logon.' \
        'SV-230226r1262183_rule' 'RHEL-08-010050' 'C-32895r1261924_chk' 'F-32870r1261925_fix' \
        'Verify RHEL 8 displays the Standard Mandatory DoW Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Check that the operating system displays the exact Standard Mandatory DoW Notice and Consent Banner text with the command:

$ sudo grep -r banner-message-text /etc/dconf/db/local.d/*

/etc/dconf/db/local.d/01-banner-message:banner-message-text='\''You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '\''

Note: The "\n " characters are for formatting only. They will not be displayed on the graphical interface.

If the banner does not match the Standard Mandatory DoW Notice and Consent Banner exactly, this is a finding.' \
        'Configure the operating system to display the Standard Mandatory DoW Notice and Consent Banner before granting access to the system.

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

banner-message-text='\''You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details. '\''

Note: The "\n " characters are for formatting only. They will not be displayed on the graphical interface.

Run the following command to update the database:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230229' 'II' 'high' 'yes' 'evidence-review' '' 'V-230229' \
        'RHEL 8, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.' \
        'SV-230229r1262186_rule' 'RHEL-08-010090' 'C-32898r1261931_chk' 'F-32873r1261932_fix' \
        'Verify RHEL 8 for PKI-based authentication has valid certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the system has a valid DoW root CA installed with the following command:

$ sudo openssl x509 -text -in /etc/sssd/pki/sssd_auth_ca_db.pem

Certificate:
   Data:
      Version: 3 (0x2)
      Serial Number: 1 (0x1)
      Signature Algorithm: sha256WithRSAEncryption
      Issuer: C = US, O = U.S. Government, OU = DoW, OU = PKI, CN = DoD Root CA 3
      Validity
         Not Before: Mar 20 18:46:41 2012 GMT
         Not After   : Dec 30 18:46:41 2029 GMT
      Subject: C = US, O = U.S. Government, OU = DoW, OU = PKI, CN = DoD Root CA 3
      Subject Public Key Info:
         Public Key Algorithm: rsaEncryption

If the root ca file is not a DoW-issued certificate with a valid date and installed in the /etc/sssd/pki/sssd_auth_ca_db.pem location, this is a finding.' \
        'Configure RHEL 8, for PKI-based authentication, to validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.

Obtain a valid copy of the DoW root CA file from the PKI CA certificate bundle at cyber.mil and copy into the following file:

/etc/sssd/pki/sssd_auth_ca_db.pem' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230233' 'II' 'medium' 'yes' 'attended-file' '' 'V-230233' \
        'The RHEL 8 shadow password suite must be configured to use a sufficient number of hashing rounds.' \
        'SV-230233r1044790_rule' 'RHEL-08-010130' 'C-32902r1044788_chk' 'F-32877r1044789_fix' \
        'Check that a minimum number of hash rounds is configured by running the following command:

     $ sudo grep -E "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "100000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "100000", this is a finding.' \
        'Configure RHEL 8 to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "100000":

SHA_CRYPT_MIN_ROUNDS 100000' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230234' 'I' 'high' 'yes' 'evidence-review' '' 'V-230234' \
        'RHEL 8 operating systems booted with United Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user mode and maintenance.' \
        'SV-230234r1262176_rule' 'RHEL-08-010140' 'C-32903r1261907_chk' 'F-32878r1261908_fix' \
        'Note: For systems that use BIOS, this is Not Applicable.

Check the unified configuration file where the grub2 password is stored:
# grep -iw "GRUB2_PASSWORD" /boot/grub2/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the "GRUB2_PASSWORD" entry exists and begins with "grub.pbkdf2.sha512", this is not a finding.

Note for legacy RHEL 8 deployments: Older versions of RHEL 8 may have stored this file in the EFI partition. If the file is not found in `/boot/grub2/`, check the legacy UEFI path:
# grep -iw GRUB2_PASSWORD /boot/efi/EFI/redhat/user.cfg

If the "GRUB2_PASSWORD" entry does not exist in either location, or does not begin with "grub.pbkdf2.sha512", this is a finding.' \
        'Configure the system to require a GRUB bootloader password for the grub superusers account.

Use the "grub2-setpassword" command, which automatically creates and sets the correct permissions for the unified "/boot/grub2/user.cfg" file using the required PBKDF2 SHA512 hashing algorithm.

Generate the encrypted GRUB 2 password with the following command:

# grub2-setpassword
Enter password: 
Confirm password: 

Note: Do not manually edit the GRUB configuration files to set this password; always use the provided utility to ensure the correct hashing algorithm is applied and the file is placed in the active configuration directory.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230243' 'II' 'medium' 'yes' 'attended-file' '' 'V-230243' \
        'A sticky bit must be set on all RHEL 8 public directories to prevent unauthorized and unintended information transferred via shared system resources.' \
        'SV-230243r1262193_rule' 'RHEL-08-010190' 'C-32912r1069197_chk' 'F-32887r567476_fix' \
        'Verify that all world-writable directories have the sticky bit set.

Check to see that all world-writable directories have the sticky bit set by running the following command:

$ sudo find / -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null -exec ls -ald {} \;

drwxrwxrwx. 14 root root 4096 Sep 13 15:13 /tmp

If any of the returned directories are world-writable and do not have the sticky bit set, this is a finding.' \
        'Configure all world-writable directories to have the sticky bit set to prevent unauthorized and unintended information transferred via shared system resources.

Set the sticky bit on all world-writable directories using the command, replace "[World-Writable Directory]" with any directory path missing the sticky bit:

$ sudo chmod 1777 [World-Writable Directory]' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230251' 'I' 'high' 'yes' 'attended-file' '' 'V-230251' \
        'The RHEL 8 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.' \
        'SV-230251r1262195_rule' 'RHEL-08-010290' 'C-32920r1155368_chk' 'F-32895r1155369_fix' \
        'Verify the RHEL 8 SSH server is configured to use only MACs employing FIPS 140-3-approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ sudo grep -i MACs /etc/crypto-policies/back-ends/opensshserver.config

-oMACs=hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If the MACs entries in the "opensshserver.config" file have any hashes other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256", or they are missing or commented out, this is a finding.' \
        'Configure the RHEL 8 SSH server to use only MACs employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230252' 'I' 'high' 'yes' 'attended-file' '' 'V-230252' \
        'The RHEL 8 SSH server must be configured to use only DoW-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.' \
        'SV-230252r1262196_rule' 'RHEL-08-010291' 'C-32921r1155362_chk' 'F-32896r1155363_fix' \
        'Verify the RHEL 8 SSH server is configured to use only ciphers employing FIPS 140-3-approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ sudo grep -i Ciphers /etc/crypto-policies/back-ends/opensshserver.config 
CRYPTO_POLICY='\''-oCiphers=aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "opensshserver.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.' \
        'Configure the RHEL 8 SSH server to use only ciphers employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230257' 'II' 'medium' 'yes' 'attended-file' '' 'V-230257' \
        'RHEL 8 system commands must have mode 755 or less permissive.' \
        'SV-230257r1017077_rule' 'RHEL-08-010300' 'C-32926r792860_chk' 'F-32901r792861_fix' \
        'Verify the system commands contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -exec ls -l {} \;

If any system commands are found to be group-writable or world-writable, this is a finding.' \
        'Configure the system commands to be protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command with a mode more permissive than "755".

$ sudo chmod 755 [FILE]' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230264' 'I' 'medium' 'yes' 'attended-file' '' 'V-230264' \
        'RHEL 8 must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.' \
        'SV-230264r1262199_rule' 'RHEL-08-010370' 'C-32933r1261949_chk' 'F-32908r880710_fix' \
        'Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.

Check that YUM verifies the signature of packages from a repository prior to install with the following command:

     $ sudo grep -E '\''^\[.*\]|gpgcheck'\'' /etc/yum.repos.d/*.repo

     /etc/yum.repos.d/appstream.repo:[appstream]
     /etc/yum.repos.d/appstream.repo:gpgcheck=1
     /etc/yum.repos.d/baseos.repo:[baseos]
     /etc/yum.repos.d/baseos.repo:gpgcheck=1

If "gpgcheck" is not set to "1", or if options are missing or commented out, ask the system administrator how the certificates for patches and other operating system components are verified.

If there is no process to validate certificates that is approved by the organization, this is a finding.' \
        'Configure the operating system to verify the signature of packages from a repository prior to install by setting the following option in the "/etc/yum.repos.d/[your_repo_name].repo" file:

     gpgcheck=1' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230274' 'II' 'high' 'yes' 'attended-file' '' 'V-230274' \
        'RHEL 8 must implement certificate status checking for multifactor authentication.' \
        'SV-230274r1262204_rule' 'RHEL-08-010400' 'C-32943r1261955_chk' 'F-32918r809280_fix' \
        'Verify the operating system implements certificate status checking for multifactor authentication.

Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Verify OCSP is enabled and using the proper digest value on the system with the following command:

$ sudo grep certificate_verification /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf | grep -v "^#"

certificate_verification = ocsp_dgst=sha1

If the certificate_verification line is missing from the [sssd] section, or is missing "ocsp_dgst=sha1", ask the administrator to indicate what type of multifactor authentication is being utilized and how the system implements certificate status checking.  If there is no evidence of certificate status checking being used, this is a finding.' \
        'Configure the operating system to implement certificate status checking for multifactor authentication.

Review the "/etc/sssd/sssd.conf" file to determine if the system is configured to prevent OCSP or certificate verification.

Add the following line to the [sssd] section of the "/etc/sssd/sssd.conf" file:

certificate_verification = ocsp_dgst=sha1

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

$ sudo systemctl restart sssd.service' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230279' 'II' 'high' 'yes' 'attended-file' '' 'V-230279' \
        'RHEL 8 must clear memory when it is freed to prevent use-after-free attacks.' \
        'SV-230279r1069286_rule' 'RHEL-08-010423' 'C-32948r1069179_chk' 'F-32923r1069180_fix' \
        'Verify that GRUB2 is configured to mitigate use-after-free vulnerabilities by employing memory poisoning.

Inspect the "GRUB_CMDLINE_LINUX" entry of /etc/default/grub as follows:
$ sudo grep -i grub_cmdline_linux /etc/default/grub
GRUB_CMDLINE_LINUX="... init_on_free=1"

If "init_on_free=1" is missing or commented out, this is a finding.' \
        'Configure RHEL 8 to enable init_on_free with the following command:
$ sudo grubby --update-kernel=ALL --args="init_on_free=1"

Regenerate the GRUB configuration:
$ sudo grub2-mkconfig -o /boot/grub2/grub.cfg

Reboot the system:
$ sudo reboot' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230287' 'II' 'high' 'yes' 'attended-file' '' 'V-230287' \
        'The RHEL 8 SSH private host key files must have mode 0600 or less permissive.' \
        'SV-230287r1208746_rule' 'RHEL-08-010490' 'C-32956r1208413_chk' 'F-32931r1208414_fix' \
        'Verify the SSH private host key files have mode "0600" or less permissive with the following command:

$ sudo ls -l /etc/ssh/ssh_host*key
-rw------- 1 root ssh_keys 668 Nov 28 06:43 ssh_host_dsa_key
-rw------- 1 root ssh_keys 582 Nov 28 06:43 ssh_host_key
-rw------- 1 root ssh_keys 887 Nov 28 06:43 ssh_host_rsa_key

If any private host key file has a mode more permissive than "0600", this is a finding.' \
        'Configure the mode of SSH private host key files under "/etc/ssh" to "0600" with the following command:

$ sudo chmod 0600 /etc/ssh/ssh_host*key

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230296' 'II' 'high' 'yes' 'attended-file' '' 'V-230296' \
        'RHEL 8 must not permit direct logons to the root account using remote access via SSH.' \
        'SV-230296r1069322_rule' 'RHEL-08-010550' 'C-32965r1069253_chk' 'F-32940r567635_fix' \
        'Verify remote access using SSH prevents users from logging on directly as "root".

Check that SSH prevents users from logging on directly as "root" with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*permitrootlogin'\''

PermitRootLogin no

If the "PermitRootLogin" keyword is set to any value other than "no", is missing, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to stop users from logging on remotely as the "root" user via SSH.

Edit the appropriate "/etc/ssh/sshd_config" file to uncomment or add the line for the "PermitRootLogin" keyword and set its value to "no":

PermitRootLogin no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230301' 'II' 'high' 'yes' 'attended-file' '' 'V-230301' \
        'RHEL 8 must prevent special devices on non-root local partitions.' \
        'SV-230301r1184262_rule' 'RHEL-08-010580' 'C-32970r1184261_chk' 'F-32945r567650_fix' \
        'Verify all nonroot local partitions are mounted with the "nodev" option with the following command:

$ sudo mount | grep '\''^/dev\S* on /\S'\'' | grep --invert-match '\''nodev'\''

If any output is produced, this is a finding.' \
        'Configure the "/etc/fstab" to use the "nodev" option on all non-root local partitions.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230302' 'II' 'high' 'yes' 'attended-file' '' 'V-230302' \
        'RHEL 8 must prevent code from being executed on file systems that contain user home directories.' \
        'SV-230302r1017112_rule' 'RHEL-08-010590' 'C-32971r567652_chk' 'F-32946r567653_fix' \
        'Verify file systems that contain user home directories are mounted with the "noexec" option.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is automatically a finding as the "noexec" option cannot be used on the "/" system.

Find the file system(s) that contain the user home directories with the following command:

$ sudo awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $1,$3,$6}'\'' /etc/passwd

smithj:1001: /home/smithj
robinst:1002: /home/robinst

Check the file systems that are mounted at boot time with the following command:

$ sudo more /etc/fstab

UUID=a411dc99-f2a1-4c87-9e05-184977be8539 /home ext4 rw,relatime,discard,data=ordered,nosuid,nodev,noexec 0 2

If a file system found in "/etc/fstab" refers to the user home directory file system and it does not have the "noexec" option set, this is a finding.' \
        'Configure the "/etc/fstab" to use the "noexec" option on file systems that contain user home directories for interactive users.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230306' 'II' 'high' 'yes' 'attended-file' '' 'V-230306' \
        'RHEL 8 must prevent code from being executed on file systems that are imported via Network File System (NFS).' \
        'SV-230306r1155386_rule' 'RHEL-08-010630' 'C-32975r1155385_chk' 'F-32950r567665_fix' \
        'Note: If no NFS mounts are configured, this requirement is Not Applicable.

Verify file systems being imported via NFS are mounted with the "noexec" option with the following command:

$ sudo grep nfs /etc/fstab | grep noexec

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "noexec" option set, this is a finding.' \
        'Configure the "/etc/fstab" to use the "noexec" option on file systems that are being imported via NFS.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230307' 'II' 'high' 'yes' 'attended-file' '' 'V-230307' \
        'RHEL 8 must prevent special devices on file systems that are imported via Network File System (NFS).' \
        'SV-230307r1155388_rule' 'RHEL-08-010640' 'C-32976r1155387_chk' 'F-32951r567668_fix' \
        'Note: If no NFS mounts are configured, this requirement is Not Applicable.

Verify file systems that are being NFS-imported are mounted with the "nodev" option with the following command:

$ sudo grep nfs /etc/fstab | grep nodev

UUID=e06097bb-cfcd-437b-9e4d-a691f5662a7d /store nfs rw,nosuid,nodev,noexec 0 0

If a file system found in "/etc/fstab" refers to NFS and it does not have the "nodev" option set, this is a finding.' \
        'Configure the "/etc/fstab" to use the "nodev" option on file systems that are being imported via NFS.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230316' 'II' 'high' 'yes' 'evidence-review' '' 'V-230316' \
        'For RHEL 8 systems using Domain Name Servers (DNS) resolution, at least two name servers must be configured.' \
        'SV-230316r1044801_rule' 'RHEL-08-010680' 'C-32985r1044800_chk' 'F-32960r567695_fix' \
        'Note: If the system is running in a cloud platform and the cloud provider gives a single, highly available IP address for DNS configuration, this is not applicable.

Determine whether the system is using local or DNS name resolution with the following command:

$ sudo grep hosts /etc/nsswitch.conf

hosts: files dns

If the DNS entry is missing from the host'\''s line in the "/etc/nsswitch.conf" file, the "/etc/resolv.conf" file must be empty.

Verify the "/etc/resolv.conf" file is empty with the following command:

$ sudo ls -al /etc/resolv.conf

-rw-r--r-- 1 root root 0 Aug 19 08:31 resolv.conf

If local host authentication is being used and the "/etc/resolv.conf" file is not empty, this is a finding.

If the DNS entry is found on the host'\''s line of the "/etc/nsswitch.conf" file, verify the operating system is configured to use two or more name servers for DNS resolution.

Determine the name servers used by the system with the following command:

$ sudo grep nameserver /etc/resolv.conf

nameserver 192.168.1.2
nameserver 192.168.1.3

If fewer than two lines are returned that are not commented out, this is a finding.' \
        'Configure the operating system to use two or more name servers for DNS resolution.

By default, "NetworkManager" on RHEL 8 dynamically updates the /etc/resolv.conf file with the DNS settings from active "NetworkManager" connection profiles. However, this feature can be disabled to allow manual configurations.

If manually configuring DNS, edit the "/etc/resolv.conf" file to uncomment or add the two or more "nameserver" option lines with the IP address of local authoritative name servers. If local host resolution is being performed, the "/etc/resolv.conf" file must be empty. An empty "/etc/resolv.conf" file can be created as follows:

$ sudo echo -n > /etc/resolv.conf' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230323' 'II' 'medium' 'yes' 'attended-action' '' 'V-230323' \
        'All RHEL 8 local interactive user home directories defined in the /etc/passwd file must exist.' \
        'SV-230323r1017134_rule' 'RHEL-08-010750' 'C-32992r567715_chk' 'F-32967r567716_fix' \
        'Verify the assigned home directory of all local interactive users on RHEL 8 exists with the following command:

$ sudo ls -ld $(awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $6}'\'' /etc/passwd)

drwxr-xr-x 2 smithj admin 4096 Jun 5 12:41 smithj

Note: This may miss interactive users that have been assigned a privileged User ID (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

$ sudo pwck -r

user '\''smithj'\'': directory '\''/home/smithj'\'' does not exist

If any home directories referenced in "/etc/passwd" are returned as not defined, this is a finding.' \
        'Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user smithj, who has a home directory of "/home/smithj", a UID of "smithj", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".

$ sudo mkdir /home/smithj 
$ sudo chown smithj /home/smithj
$ sudo chgrp users /home/smithj
$ sudo chmod 0750 /home/smithj' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230326' 'II' 'medium' 'yes' 'evidence-review' '' 'V-230326' \
        'All RHEL 8 local files and directories must have a valid owner.' \
        'SV-230326r1069284_rule' 'RHEL-08-010780' 'C-32995r1069175_chk' 'F-32970r567725_fix' \
        'Verify all local files and directories on RHEL 8 have a valid owner with the following command:

$ df --local -P | awk {'\''if (NR!=1) print $6'\''} | sudo xargs -I '\''{}'\'' find '\''{}'\'' -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding.' \
        'Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on RHEL 8 with the "chown" command:

$ sudo chown <user> <file>' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230327' 'II' 'medium' 'yes' 'evidence-review' '' 'V-230327' \
        'All RHEL 8 local files and directories must have a valid group owner.' \
        'SV-230327r1069285_rule' 'RHEL-08-010790' 'C-32996r1069177_chk' 'F-32971r567728_fix' \
        'Verify all local files and directories on RHEL 8 have a valid group with the following command:

$ df --local -P | awk {'\''if (NR!=1) print $6'\''} | sudo xargs -I '\''{}'\'' find '\''{}'\'' -xdev -nogroup

If any files on the system do not have an assigned group, this is a finding.' \
        'Either remove all files and directories from RHEL 8 that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

$ sudo chgrp <group> <file>' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230351' 'II' 'high' 'yes' 'attended-file' '' 'V-230351' \
        'RHEL 8 must be able to initiate directly a session lock for all connection types using smartcard when the smartcard is removed.' \
        'SV-230351r1017164_rule' 'RHEL-08-020050' 'C-33020r792897_chk' 'F-32995r792898_fix' \
        'Verify the operating system enables a user'\''s session lock until that user re-establishes access using established identification and authentication procedures with the following command:

This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo grep -R removal-action /etc/dconf/db/*

/etc/dconf/db/distro.d/20-authselect:removal-action='\''lock-screen'\''

If the "removal-action='\''lock-screen'\''" setting is missing or commented out from the dconf database files, this is a finding.' \
        'Configure the operating system to enable a user'\''s session lock until that user re-establishes access using established identification and authentication procedures.

Select/Create an authselect profile and incorporate the "with-smartcard-lock-on-removal" feature with the following example:

$ sudo authselect select sssd with-smartcard with-smartcard-lock-on-removal

Alternatively, the dconf settings can be edited in the /etc/dconf/db/* location.

Edit or add the "[org/gnome/settings-daemon/peripherals/smartcard]" section of the database file and add or update the following lines:

removal-action='\''lock-screen'\''

Update the system databases:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230352' 'II' 'low' 'yes' 'attended-file' '' 'V-230352' \
        'RHEL 8 must automatically lock graphical user sessions after 10 minutes of inactivity.' \
        'SV-230352r1208749_rule' 'RHEL-08-020060' 'C-33021r1208747_chk' 'F-32996r1208748_fix' \
        'Note: This requirement assumes the use of the RHEL 8 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Verify RHEL 8 initiates a session lock after a 10-minute period of inactivity for graphical user interfaces with the following command:

$ sudo gsettings get org.gnome.desktop.session idle-delay
uint32 600

If "idle-delay" is set to "0" or a value greater than "600", this is a finding.' \
        'Configure RHEL 8 to initiate a screensaver after a 10-minute period of inactivity for graphical user interfaces.

Create a database to contain the systemwide screensaver settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/00-screensaver

Edit "/etc/dconf/db/local.d/00-screensaver" and add or update the following lines:

[org/gnome/desktop/session]
# Set the lock time out to 600 seconds before the session is considered idle
idle-delay=uint32 600

Update the system databases:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230367' 'II' 'high' 'yes' 'attended-action' '' 'V-230367' \
        'RHEL 8 user account passwords must be configured so that existing passwords are restricted to a 180-day maximum lifetime.' \
        'SV-230367r1262170_rule' 'RHEL-08-020210' 'C-33036r1261895_chk' 'F-33011r1261896_fix' \
        'Check whether the maximum time period for existing passwords is restricted to 180 days with the following commands:

$ sudo awk -F: '\''$5 > 180 {print $1 " " $5}'\'' /etc/shadow

$ sudo awk -F: '\''$5 <= 0 {print $1 " " $5}'\'' /etc/shadow

If any results are returned that are not associated with a system account, this is a finding.' \
        'Configure noncompliant accounts to enforce a 180-day maximum password lifetime restriction.

$ sudo chage -M 180 [user]' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230372' 'II' 'high' 'yes' 'attended-file' '' 'V-230372' \
        'RHEL 8 must implement smart card logon for multifactor authentication for access to interactive accounts.' \
        'SV-230372r1262209_rule' 'RHEL-08-020250' 'C-33041r1261961_chk' 'F-33016r942944_fix' \
        'Verify RHEL 8 uses multifactor authentication for local access to accounts.

Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Check that the "pam_cert_auth" setting is set to "true" in the "/etc/sssd/sssd.conf" file.

Check that the "try_cert_auth" or "require_cert_auth" options are configured in both "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files with the following command:

     $ sudo grep -ir cert_auth /etc/sssd/sssd.conf /etc/sssd/conf.d/*.conf /etc/pam.d/*
     /etc/sssd/sssd.conf:pam_cert_auth = True
     /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth
     /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth

If "pam_cert_auth" is not set to "true" in "/etc/sssd/sssd.conf", this is a finding.

If "pam_sss.so" is not set to "try_cert_auth" or "require_cert_auth" in both the "/etc/pam.d/smartcard-auth" and "/etc/pam.d/system-auth" files, this is a finding.' \
        'Configure RHEL 8 to use multifactor authentication for local access to accounts.

Add or update the "pam_cert_auth" setting in the "/etc/sssd/sssd.conf" file to match the following line:

     [pam]
     pam_cert_auth = True

Add or update "pam_sss.so" with "try_cert_auth" or "require_cert_auth" in the "/etc/pam.d/system-auth" and "/etc/pam.d/smartcard-auth" files based on the following examples:

     /etc/pam.d/smartcard-auth:auth   sufficient   pam_sss.so try_cert_auth

     /etc/pam.d/system-auth:auth   [success=done authinfo_unavail=ignore ignore=ignore default=die]   pam_sss.so try_cert_auth

The "sssd" service must be restarted for the changes to take effect. To restart the "sssd" service, run the following command:

     $ sudo systemctl restart sssd.service' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230376' 'II' 'high' 'yes' 'attended-file' '' 'V-230376' \
        'RHEL 8 must prohibit the use of cached authentications after one day.' \
        'SV-230376r1069307_rule' 'RHEL-08-020290' 'C-33045r1069223_chk' 'F-33020r942947_fix' \
        'Note: If smart card authentication is not being used on the system this item is Not Applicable.

Verify that the SSSD prohibits the use of cached authentications after one day.

Check that SSSD allows cached authentications with the following command:

$ sudo grep cache_credentials /etc/sssd/sssd.conf
/etc/sssd/sssd.conf:cache_credentials = true

If "cache_credentials" is set to "false" or missing from the configuration file, this is not a finding, and no further checks are required.

If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command:

$ sudo grep offline_credentials_expiration  /etc/sssd/sssd.conf
/etc/sssd/sssd.conf:offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.' \
        'Configure the SSSD to prohibit the use of cached authentications after one day.

Add or change the following line in "/etc/sssd/sssd.conf" just below the line "[pam]".

     offline_credentials_expiration = 1' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230384' 'II' 'high' 'yes' 'attended-file' '' 'V-230384' \
        'RHEL 8 must set the umask value to 077 for all local interactive user accounts.' \
        'SV-230384r1017193_rule' 'RHEL-08-020352' 'C-33053r858731_chk' 'F-33028r567899_fix' \
        'Verify that the default umask for all local interactive users is "077".

Identify the locations of all local interactive user home directories by looking at the "/etc/passwd" file.

Check all local interactive user initialization files for interactive users with the following command:

Note: The example is for a system that is configured to create users home directories in the "/home" directory.

$ sudo grep -ir ^umask /home | grep -v '\''.bash_history'\''

If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than "077", this is a finding.' \
        'Remove the umask statement from all local interactive user'\''s initialization files. 

If the account is for an application, the requirement for a umask less restrictive than "077" can be documented with the Information System Security Officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account'\''s environment variables.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230396' 'II' 'medium' 'yes' 'attended-file' '' 'V-230396' \
        'RHEL 8 audit logs must have a mode of 0600 or less permissive to prevent unauthorized read access.' \
        'SV-230396r1017202_rule' 'RHEL-08-030070' 'C-33065r567934_chk' 'F-33040r902732_fix' \
        'Verify the audit logs have a mode of "0600" or less permissive.

First, determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, check if the audit log has a mode of "0600" or less permissive with the following command:

$ sudo stat -c "%a %n" /var/log/audit/audit.log

600 /var/log/audit/audit.log

If the audit log has a mode more permissive than "0600", this is a finding.' \
        'Configure the audit log to be protected from unauthorized read access by setting the correct permissive mode with the following command: 
 
$ sudo chmod 0600 /var/log/audit/audit.log' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230398' 'II' 'high' 'yes' 'attended-file' '' 'V-230398 V-230396 V-230400 V-230401' \
        'RHEL 8 audit logs must be group-owned by root to prevent unauthorized read access.' \
        'SV-230398r1017204_rule' 'RHEL-08-030090' 'C-33067r567940_chk' 'F-33042r567941_fix' \
        'Verify the audit logs are group-owned by "root". First determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log is group-owned by "root" using the following command:

$ sudo ls -al /var/log/audit/audit.log

rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log

If the audit log is not group-owned by "root", this is a finding.' \
        'Configure the audit log to be owned by root by configuring the log group in the /etc/audit/auditd.conf file:

log_group = root' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230400' 'II' 'medium' 'yes' 'attended-file' '' 'V-230400' \
        'RHEL 8 audit log directory must be group-owned by root to prevent unauthorized read access.' \
        'SV-230400r1017206_rule' 'RHEL-08-030110' 'C-33069r567946_chk' 'F-33044r567947_fix' \
        'Verify the audit log directory is group-owned by "root" to prevent unauthorized read access.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Determine the group owner of the audit log directory by using the output of the above command (ex: "/var/log/audit/"). Run the following command with the correct audit log directory path:

$ sudo ls -ld /var/log/audit

drw------- 2 root root 23 Jun 11 11:56 /var/log/audit

If the audit log directory is not group-owned by "root", this is a finding.' \
        'Configure the audit log to be protected from unauthorized read access by setting the correct group-owner as "root" with the following command:

$ sudo chgrp root [audit_log_directory]

Replace "[audit_log_directory]" with the correct audit log directory path, by default this location is usually "/var/log/audit".' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230401' 'II' 'medium' 'yes' 'attended-file' '' 'V-230401' \
        'RHEL 8 audit log directory must have a mode of 0700 or less permissive to prevent unauthorized read access.' \
        'SV-230401r1017207_rule' 'RHEL-08-030120' 'C-33070r567949_chk' 'F-33045r567950_fix' \
        'Verify the audit log directories have a mode of "0700" or less permissive by first determining where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log, determine the directory where the audit logs are stored (ex: "/var/log/audit"). Run the following command to determine the permissions for the audit log folder:

$ sudo stat -c "%a %n" /var/log/audit

700 /var/log/audit

If the audit log directory has a mode more permissive than "0700", this is a finding.' \
        'Configure the audit log directory to be protected from unauthorized read access by setting the correct permissive mode with the following command:

$ sudo chmod 0700 [audit_log_directory]

Replace "[audit_log_directory]" to the correct audit log directory path, by default this location is "/var/log/audit".' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230471' 'II' 'medium' 'yes' 'attended-file' '' 'V-230471' \
        'RHEL 8 must allow only the information system security manager (ISSM) (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.' \
        'SV-230471r1262175_rule' 'RHEL-08-030610' 'C-33140r1261904_chk' 'F-33115r1261905_fix' \
        'Verify that the files in the directory /etc/audit/rules.d/ have a mode of 0600 or less permissive with the following command:

$ sudo find /etc/audit/rules.d/ -type f -name "*.rules" -exec stat -c "%a %n" {} \;
600 /etc/audit/rules.d/audit.rules

Verify that the files /etc/audit/audit.rules and /etc/audit/auditd.conf have a mode of 0600 or less permissive with the following command:

$ sudo stat -c "%a %n" /etc/audit/audit.rules /etc/audit/auditd.conf
600 /etc/audit/audit.rules
600 /etc/audit/auditd.conf

If any of the audit configuration files have a mode more permissive than "0600", this is a finding.' \
        'Configure the rules files in the directory /etc/audit/rules.d/, the /etc/audit/audit.rules file, and the /etc/audit/auditd.conf file to have a mode of 0600 with the following commands:

$ sudo find /etc/audit/rules.d/ -type f -name "*.rules" -exec chmod 0600 {} +

$ sudo chmod 0600 /etc/audit/audit.rules

$ sudo chmod 0600 /etc/audit/auditd.conf' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230479' 'II' 'high' 'yes' 'evidence-review' '' 'V-230479' \
        'The RHEL 8 audit records must be off-loaded onto a different system or storage media from the system being audited.' \
        'SV-230479r958754_rule' 'RHEL-08-030690' 'C-33148r917881_chk' 'F-33123r917882_fix' \
        'Verify the audit system offloads audit records onto a different system or media from the system being audited with the following command:

     $ sudo grep @@ /etc/rsyslog.conf /etc/rsyslog.d/*.conf

     /etc/rsyslog.conf:*.* @@[logaggregationserver.example.mil]:[port]

If a remote server is not configured, or the line is commented out, ask the system administrator to indicate how the audit logs are offloaded to a different system or media. 

If there is no evidence that the audit logs are being offloaded to another system or media, this is a finding.' \
        'Configure the operating system to offload audit records onto a different system or media from the system being audited by specifying the remote logging server in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf" with the name or IP address of the log aggregation server.

For UDP:
     *.* @[logaggregationserver.example.mil]:[port]

For TCP: 
     *.* @@[logaggregationserver.example.mil]:[port]' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230484' 'II' 'medium' 'yes' 'attended-file' '' 'V-230484' \
        'RHEL 8 must securely compare internal information system clocks at least every 24 hours with a server synchronized to an authoritative time source, such as the United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoW network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).' \
        'SV-230484r1262217_rule' 'RHEL-08-030740' 'C-33153r1261971_chk' 'F-33128r568199_fix' \
        'Verify RHEL 8 is securely comparing internal information system clocks at least every 24 hours with an NTP server with the following commands:

$ sudo grep maxpoll /etc/chrony.conf

server 0.us.pool.ntp.mil iburst maxpoll 16

If the "maxpoll" option is set to a number greater than 16 or the line is commented out, this is a finding.

Verify the "chrony.conf" file is configured to an authoritative DoW time source by running the following command:

$ sudo grep -i server /etc/chrony.conf
server 0.us.pool.ntp.mil 

If the parameter "server" is not set or is not set to an authoritative DoW time source, this is a finding.' \
        'Configure the operating system to securely compare internal information system clocks at least every 24 hours with an NTP server by adding/modifying the following line in the /etc/chrony.conf file.

server [ntp.server.name] iburst maxpoll 16' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230492' 'II' 'medium' 'yes' 'attended-file' '' 'V-230492' \
        'RHEL 8 must not install packages from the Extra Packages for Enterprise Linux (EPEL) repository.' \
        'SV-230492r1184277_rule' 'RHEL-08-040010' 'C-33161r1134886_chk' 'F-33136r1134887_fix' \
        'Verify that RHEL 8 is not able to install packages from the EPEL with the following command:

$ dnf repolist
rhel-8-for-x86_64-appstream-rpms                      Red Hat Enterprise Linux 8 for x86_64 - AppStream (RPMs)
rhel-8-for-x86_64-baseos-rpms                         Red Hat Enterprise Linux 8 for x86_64 - BaseOS (RPMs)
rhel-8-for-x86_64-baseos-source-rpms                  Red Hat Enterprise Linux 8 for x86_64 - BaseOS (Source RPMs)
rhel-8-for-x86_64-supplementary-rpms                  Red Hat Enterprise Linux 8 for x86_64 - Supplementary (RPMs)
satellite-tools-6.10-for-rhel-8-x86_64-rpms           Red Hat Satellite Tools 6.10 for RHEL 8 x86_64 (RPMs)

If any repositories containing the word "epel" in the name exist, this is a finding.' \
        'The repo package can be manually removed with the following command:

$ sudo dnf remove epel-release

Configure the operating system to disable use of the EPEL repository with the following command:

$ sudo dnf config-manager --set-disabled epel' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230494' 'III' 'medium' 'yes' 'attended-module' 'atm' 'V-230494' \
        'RHEL 8 must disable the asynchronous transfer mode (ATM) protocol.' \
        'SV-230494r1069310_rule' 'RHEL-08-040021' 'C-33163r1069229_chk' 'F-33138r942917_fix' \
        'Verify the operating system disables the ability to load the ATM protocol kernel module and ensure that the ATM protocol kernel module is disabled with the following command:

$ sudo grep -r atm /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install atm /bin/false
/etc/modprobe.d/blacklist.conf:blacklist atm

If the command does not return any output, or the line is commented out, and use of the ATM protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the ATM protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install atm /bin/false
     blacklist atm

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230495' 'III' 'medium' 'yes' 'attended-module' 'can' 'V-230495' \
        'RHEL 8 must disable the controller area network (CAN) protocol.' \
        'SV-230495r1069311_rule' 'RHEL-08-040022' 'C-33164r1069231_chk' 'F-33139r942920_fix' \
        'Verify the operating system disables the ability to load the CAN protocol kernel module and ensure that the CAN protocol kernel module is disabled with the following command:

$ sudo grep -r can /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install can /bin/false
/etc/modprobe.d/blacklist.conf:blacklist can

If the command does not return any output, or the line is commented out, and use of the CAN protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the CAN protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install can /bin/false
     blacklist can

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230496' 'III' 'medium' 'yes' 'attended-module' 'sctp' 'V-230496' \
        'RHEL 8 must disable the stream control transmission protocol (SCTP).' \
        'SV-230496r1069312_rule' 'RHEL-08-040023' 'C-33165r1069233_chk' 'F-33140r942923_fix' \
        'Verify the operating system disables the ability to load the SCTP kernel module and ensure that SCTP is disabled with the following command:

$ sudo grep -r sctp /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install sctp /bin/false
/etc/modprobe.d/blacklist.conf:blacklist sctp

If the command does not return any output, or the line is commented out, and use of the SCTP is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the SCTP kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install sctp /bin/false
     blacklist sctp

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230497' 'III' 'medium' 'yes' 'attended-module' 'tipc' 'V-230497' \
        'RHEL 8 must disable the transparent inter-process communication (TIPC) protocol.' \
        'SV-230497r1069313_rule' 'RHEL-08-040024' 'C-33166r1069235_chk' 'F-33141r942926_fix' \
        'Verify the operating system disables the ability to load the TIPC protocol kernel module and ensure that TIPC is disabled with the following command:

$ sudo grep -r tipc /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install tipc /bin/false
/etc/modprobe.d/blacklist.conf:blacklist tipc

If the command does not return any output, or the line is commented out, and use of the TIPC protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the TIPC protocol kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install tipc /bin/false
     blacklist tipc

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230498' 'III' 'medium' 'yes' 'attended-module' 'cramfs' 'V-230498' \
        'RHEL 8 must disable mounting of cramfs.' \
        'SV-230498r1069314_rule' 'RHEL-08-040025' 'C-33167r1069237_chk' 'F-33142r942929_fix' \
        'Verify the operating system disables the ability to load the cramfs kernel module and ensure that the cramfs kernel module is disabled with the following command:

$ sudo grep -r cramfs /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install cramfs /bin/false
/etc/modprobe.d/blacklist.conf:blacklist cramfs

If the command does not return any output, or the line is commented out, and use of the cramfs protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the cramfs kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install cramfs /bin/false
     blacklist cramfs

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230499' 'III' 'high' 'yes' 'attended-module' 'firewire-core' 'V-230499' \
        'RHEL 8 must disable IEEE 1394 (FireWire) Support.' \
        'SV-230499r1069315_rule' 'RHEL-08-040026' 'C-33168r1069239_chk' 'F-33143r942932_fix' \
        'Verify the operating system disables the ability to load the firewire-core kernel module and ensure that the firewire-core kernel module is disabled with the following command:

$ sudo grep -r firewire-core /etc/modprobe.d/* | grep "blacklist"

/etc/modprobe.d/blacklist.conf:install firewire-core /bin/false
/etc/modprobe.d/blacklist.conf:blacklist firewire-core

If the command does not return any output, or the line is commented out, and use of the firewire-core protocol is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the firewire-core kernel module.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install firewire-core /bin/false
     blacklist firewire-core

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230503' 'II' 'high' 'yes' 'attended-module' 'usb-storage' 'V-230503' \
        'RHEL 8 must be configured to disable USB mass storage.' \
        'SV-230503r1069316_rule' 'RHEL-08-040080' 'C-33172r1069241_chk' 'F-33147r942935_fix' \
        'Verify the operating system disables the ability to load the USB Storage kernel module and ensure that the USB Storage kernel module is disabled with the following command:

$ sudo grep usb-storage /etc/modprobe.d/* | grep -i "blacklist"

/etc/modprobe.d/blacklist.conf:install usb-storage /bin/false
/etc/modprobe.d/blacklist.conf:blacklist usb-storage

If the command does not return any output, or the line is commented out, and use of USB Storage is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.' \
        'Configure the operating system to disable the ability to use the USB Storage kernel module and the ability to use USB mass storage devices.

Add or update the following lines in the file "/etc/modprobe.d/blacklist.conf":

     install usb-storage /bin/false
     blacklist usb-storage

Reboot the system for the settings to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230504' 'II' 'high' 'yes' 'attended-file' '' 'V-230504' \
        'A RHEL 8 firewall must employ a deny-all, allow-by-exception policy for allowing connections to other systems.' \
        'SV-230504r1262220_rule' 'RHEL-08-040090' 'C-33173r1261975_chk' 'F-33148r942941_fix' \
        'Verify "firewalld" is configured to employ a deny-all, allow-by-exception policy for allowing connections to other systems with the following commands:

     $ sudo  firewall-cmd --state
     running

     $ sudo firewall-cmd --get-active-zones
     [custom]
     interfaces: ens33

     $ sudo firewall-cmd --info-zone=[custom] | grep target
     target: DROP

If no zones are active on the RHEL 8 interfaces or if the target is set to a different option other than "DROP", this is a finding.

If the "firewalld" package is not installed, ask the system administrator if an alternate firewall (such as iptables) is installed and in use, and how is it configured to employ a deny-all, allow-by-exception policy. 

If the alternate firewall is not configured to employ a deny-all, allow-by-exception policy, this is a finding.

If no firewall is installed, this is a finding.' \
        'Configure the "firewalld" daemon to employ a deny-all, allow-by-exception with the following commands:

     $ sudo firewall-cmd --permanent --new-zone=[custom]

     $ sudo cp /usr/lib/firewalld/zones/drop.xml /etc/firewalld/zones/[custom].xml

This will provide a clean configuration file to work with that employs a deny-all approach. 

Note: Add the exceptions that are required for mission functionality and update the short title in the xml file to match the [custom] zone name.

Reload the firewall rules to make the new [custom] zone available to load:
     $ sudo firewall-cmd --reload 

Set the default zone to the new [custom] zone:
     $ sudo firewall-cmd --set-default-zone=[custom]

Note: This is a runtime and permanent change.
Add any interfaces to the new [custom] zone:
     $ sudo firewall-cmd --permanent --zone=[custom] --change-interface=ens33

Reload the firewall rules for changes to take effect:
     $ sudo firewall-cmd --reload' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230530' 'I' 'high' 'yes' 'attended-file' '' 'V-230530' \
        'The x86 Ctrl-Alt-Delete key sequence in RHEL 8 must be disabled if a graphical user interface is installed.' \
        'SV-230530r1069317_rule' 'RHEL-08-040171' 'C-33199r1069243_chk' 'F-33174r568337_fix' \
        'Verify RHEL 8 is not configured to reboot the system when Ctrl-Alt-Delete is pressed when using a graphical user interface with the following command:

This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo grep -r logout /etc/dconf/db/local.d/*

/etc/dconf/db/local.d/00-disable-CAD:logout='\'''\''

If the "logout" key is bound to an action, is commented out, or is missing, this is a finding.' \
        'Configure the system to disable the Ctrl-Alt-Delete sequence when using a graphical user interface by creating or editing the /etc/dconf/db/local.d/00-disable-CAD file.

Add the setting to disable the Ctrl-Alt-Delete sequence for a graphical user interface:

[org/gnome/settings-daemon/plugins/media-keys]
logout='\'''\''

Note: The value above is set to two single quotations.

Then update the dconf settings:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-230550' 'II' 'high' 'yes' 'attended-file' '' 'V-230550' \
        'RHEL 8 must be configured to prevent unrestricted mail relaying.' \
        'SV-230550r1017312_rule' 'RHEL-08-040290' 'C-33219r568396_chk' 'F-33194r568397_fix' \
        'Verify the system is configured to prevent unrestricted mail relaying.

Determine if "postfix" is installed with the following commands:

$ sudo yum list installed postfix

postfix.x86_64  2:3.3.1-9.el8 

If postfix is not installed, this is Not Applicable.

If postfix is installed, determine if it is configured to reject connections from unknown or untrusted networks with the following command:

$ sudo postconf -n smtpd_client_restrictions

smtpd_client_restrictions = permit_mynetworks, reject

If the "smtpd_client_restrictions" parameter contains any entries other than "permit_mynetworks" and "reject", this is a finding.' \
        'If "postfix" is installed, modify the "/etc/postfix/main.cf" file to restrict client connections to the local network with the following command:

$ sudo postconf -e '\''smtpd_client_restrictions = permit_mynetworks,reject'\''' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244528' 'II' 'high' 'yes' 'attended-file' '' 'V-244528' \
        'The RHEL 8 SSH daemon must not allow GSSAPI authentication, except to fulfill documented and validated mission requirements.' \
        'SV-244528r1017335_rule' 'RHEL-08-010522' 'C-47803r1017334_chk' 'F-47760r743832_fix' \
        'Verify the SSH daemon does not allow GSSAPI authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*gssapiauthentication'\''

GSSAPIAuthentication no

If the value is returned as "yes", the returned line is commented out, no output is returned, or has not been documented with the  information system security officer (ISSO), this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure the SSH daemon to not allow GSSAPI authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "no":

GSSAPIAuthentication no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244531' 'II' 'medium' 'yes' 'attended-action' '' 'V-244531' \
        'All RHEL 8 local interactive user home directory files must have mode 0750 or less permissive.' \
        'SV-244531r1017338_rule' 'RHEL-08-010731' 'C-47806r743840_chk' 'F-47763r743841_fix' \
        'Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of "0750".
Files that begin with a "." are excluded from this requirement.

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /home/smithj
-rwxr-x--- 1 smithj smithj 18 Mar 5 17:06 file1
-rwxr----- 1 smithj smithj 193 Mar 5 17:06 file2
-rw-r-x--- 1 smithj smithj 231 Mar 5 17:06 file3

If any files or directories are found with a mode more permissive than "0750", this is a finding.' \
        'Set the mode on files and directories in the local interactive user home directory with the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

$ sudo chmod 0750 /home/smithj/<file or directory>' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244532' 'II' 'medium' 'yes' 'evidence-review' '' 'V-244532' \
        'RHEL 8 must be configured so that all files and directories contained in local interactive user home directories are group-owned by a group of which the home directory owner is a member.' \
        'SV-244532r1101906_rule' 'RHEL-08-010741' 'C-47807r1101905_chk' 'F-47764r743844_fix' \
        'Verify all files and directories in a local interactive user home directory are group-owned by a group that the user is a member.

Check the group owner of all files and directories in a local interactive user'\''s home directory with the following command:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

$ sudo ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with a group owner different from the home directory user private group, check to see if the user is a member of that group with the following command:

$ sudo grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj 
smithj:x:521:smithj

If any files or directories are group owned by a group that the directory owner is not a member of verify that it is documented with the information system security officer (ISSO). If it is not, this is a finding.' \
        'Change the group of a local interactive user'\''s files and directories to a group that the interactive user is a member. To change the group owner of a local interactive user'\''s files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of "/home/smithj" and is a member of the users group.

$ sudo chgrp smithj /home/smithj/<file or directory>' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244533' 'II' 'high' 'yes' 'attended-file' '' 'V-244533' \
        'RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.' \
        'SV-244533r1069318_rule' 'RHEL-08-020025' 'C-47808r1069245_chk' 'F-47765r743847_fix' \
        'Verify the pam_faillock.so module is present and is listed before the pam.unix.so line in the "/etc/pam.d/system-auth" file:
Note: The first field in the output is the line number of the entry

$ sudo grep -E -n '\''pam_faillock.so|pam_unix.so'\'' /etc/pam.d/system-auth

7:auth required pam_faillock.so preauth silent
13:auth sufficient pam_unix.so
17:auth required pam_faillock.so authfail
21:account required pam_faillock.so
22:account required pam_unix.so
33:password sufficient pam_unix.so sha512 shadow use_authtok
42:session required pam_unix.so

If the pam_faillock.so module is not present in the "/etc/pam.d/system-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.' \
        'Configure the operating system to include the use of the pam_faillock.so module in the /etc/pam.d/system-auth file.

Add/Modify the appropriate sections of the "/etc/pam.d/system-auth" file to match the following lines:
Note: The "preauth" line must be listed before pam_unix.so.

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244534' 'II' 'high' 'yes' 'attended-file' '' 'V-244534' \
        'RHEL 8 must configure the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.' \
        'SV-244534r1069319_rule' 'RHEL-08-020026' 'C-47809r1069247_chk' 'F-47766r743850_fix' \
        'Note: This check applies to RHEL versions 8.2 or newer, if the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the pam_faillock.so module is present and is listed before the pam.unix.so line in the "/etc/pam.d/password-auth" file:
Note: The first field in the output is the line number of the entry

$ sudo grep -E -n '\''pam_faillock.so|pam_unix.so'\'' /etc/pam.d/password-auth

7:auth required pam_faillock.so preauth silent
11:auth sufficient pam_unix.so
15:auth required pam_faillock.so authfail
19:account required pam_faillock.so
20:account required pam_unix.so
31:password sufficient pam_unix.so sha512 shadow use_authtok
40:session required pam_unix.so

If the pam_faillock.so module is not present in the "/etc/pam.d/password-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.' \
        'Configure the operating system to include the use of the pam_faillock.so module in the /etc/pam.d/password-auth file.

Add/Modify the appropriate sections of the "/etc/pam.d/password-auth" file to match the following lines:
Note: The "preauth" line must be listed before pam_unix.so.

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244536' 'II' 'low' 'yes' 'attended-file' '' 'V-244536' \
        'RHEL 8 must disable the user list at logon for graphical user interfaces.' \
        'SV-244536r1017343_rule' 'RHEL-08-020032' 'C-47811r743855_chk' 'F-47768r743856_fix' \
        'Verify the operating system disables the user logon list for graphical user interfaces with the following command:
Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.login-screen disable-user-list
true

If the setting is "false", this is a finding.' \
        'Configure the operating system to disable the user list at logon for graphical user interfaces.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command: 
Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/02-login-screen

[org/gnome/login-screen]
disable-user-list=true

Update the system databases:
$ sudo dconf update' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244541' 'I' 'high' 'yes' 'attended-file' '' 'V-244541' \
        'RHEL 8 must not allow blank or null passwords in the password-auth file.' \
        'SV-244541r1017347_rule' 'RHEL-08-020332' 'C-47816r743870_chk' 'F-47773r743871_fix' \
        'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/password-auth

If output is produced, this is a finding.' \
        'Remove any instances of the "nullok" option in the "/etc/pam.d/password-auth" file to prevent logons with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244545' 'II' 'high' 'yes' 'attended-action' '' 'V-244545' \
        'The RHEL 8 fapolicy module must be enabled.' \
        'SV-244545r958804_rule' 'RHEL-08-040136' 'C-47820r743882_chk' 'F-47777r743883_fix' \
        'Verify the RHEL 8 "fapolicyd" is enabled and running with the following command:

$ sudo systemctl status fapolicyd.service

fapolicyd.service - File Access Policy Daemon
Loaded: loaded (/usr/lib/systemd/system/fapolicyd.service; enabled; vendor preset: disabled)
Active: active (running)

If fapolicyd is not enabled and running, this is a finding.' \
        'Enable "fapolicyd" using the following command:

$ sudo systemctl enable --now fapolicyd' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-244546' 'II' 'high' 'yes' 'evidence-review' '' 'V-244546' \
        'The RHEL 8 fapolicy module must be configured to employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.' \
        'SV-244546r1208752_rule' 'RHEL-08-040137' 'C-47821r1208751_chk' 'F-47778r1208394_fix' \
        'Verify the RHEL 8 "fapolicyd" employs a deny-all, permit-by-exception policy.

Check that "fapolicyd" is in enforcement mode with the following command:

$ sudo grep permissive /etc/fapolicyd/fapolicyd.conf
permissive = 0

If "fapolicyd" is not running in enforcement mode, this is a finding.

Check that "fapolicyd" employs a deny-all policy on system mounts with the following commands:

$ sudo tail /etc/fapolicyd/compiled.rules
allow exe=/usr/bin/python3.7 : ftype=text/x-python
deny_audit perm=any pattern=ld_so : all
deny perm=any all : all

If "fapolicyd" is not running with a deny-all, permit-by-exception policy, this is a finding.

Note: "deny_log" or "deny_audit" options meet the security requirements. These options will generate higher volumes of logs.' \
        'Configure RHEL 8 to employ a deny-all, permit-by-exception application allow listing policy with "fapolicyd".

With the "fapolicyd" installed and enabled, configure the daemon to function in permissive mode until the allow list is built correctly to avoid system lockout. Do this by editing the "/etc/fapolicyd/fapolicyd.conf" file with the following line:

permissive = 1

Build the allow list in a file within the "/etc/fapolicyd/rules.d" directory, ensuring the last rule implements a deny-all policy, such as "deny perm=any all : all".

Once it is determined the allow list is built correctly, set the "fapolicyd" to enforcing mode by editing the "permissive" line in the /etc/fapolicyd/fapolicyd.conf file.

permissive = 0' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-250315' 'II' 'high' 'yes' 'attended-action' '' 'V-250315' \
        'RHEL 8 systems, versions 8.2 and above, must configure SELinux context type to allow the use of a non-default faillock tally directory.' \
        'SV-250315r1017356_rule' 'RHEL-08-020027' 'C-53749r793000_chk' 'F-53703r793001_fix' \
        'If the system does not have SELinux enabled and enforcing a targeted policy, or if the pam_faillock module is not configured for use, this requirement is not applicable.

Note: This check applies to RHEL versions 8.2 or newer. If the system is RHEL version 8.0 or 8.1, this check is not applicable.

Verify the location of the non-default tally directory for the pam_faillock module with the following command:

$ sudo grep -w dir /etc/security/faillock.conf

dir = /var/log/faillock

Check the security context type of the non-default tally directory with the following command:

$ sudo ls -Zd /var/log/faillock

unconfined_u:object_r:faillog_t:s0 /var/log/faillock

If the security context type of the non-default tally directory is not "faillog_t", this is a finding.' \
        'Configure RHEL 8 to allow the use of a non-default faillock tally directory while SELinux enforces a targeted policy.

Create a non-default faillock tally directory (if it does not already exist) with the following example:

$ sudo mkdir /var/log/faillock

Update the /etc/selinux/targeted/contexts/files/file_contexts.local with "faillog_t" context type for the non-default faillock tally directory with the following command:

$ sudo semanage fcontext -a -t faillog_t "/var/log/faillock(/.*)?" 

Next, update the context type of the non-default faillock directory/subdirectories and files with the following command:	

$ sudo restorecon -R -v /var/log/faillock' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-251710' 'II' 'medium' 'yes' 'evidence-review' '' 'V-251710' \
        'The RHEL 8 operating system must use a file integrity tool to verify correct operation of all security functions.' \
        'SV-251710r958944_rule' 'RHEL-08-010359' 'C-55147r880728_chk' 'F-55101r880729_fix' \
        'Verify that Advanced Intrusion Detection Environment (AIDE) is installed and verifies the correct operation of all security functions.

Check that the AIDE package is installed with the following command:
     $ sudo rpm -q aide

     aide-0.16-14.el8_5.1.x86_64

If AIDE is not installed, ask the System Administrator how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:
     $ sudo /usr/sbin/aide --check

If the output is "Couldn'\''t open file /var/lib/aide/aide.db.gz for reading", this is a finding.' \
        'Install AIDE, initialize it, and perform a manual check.

Install AIDE:
     $ sudo yum install aide

Initialize it:
     $ sudo /usr/sbin/aide --init

Example output:
     Number of entries:      48623

     ---------------------------------------------------
     The attributes of the (uncompressed) database(s):
     ---------------------------------------------------

     /var/lib/aide/aide.db.new.gz
       SHA1     : LTAVQ8tFJthsrf4m9gfRpnf1vyc=
       SHA256   : NJ9+uzRQKSwmLQ8A6IpKNvYjVKGbhSjt
                  BeJBVcmOVrI=
       SHA512   : 7d8I/F6A1b07E4ZuGeilZjefRgJJ/F20
                  eC2xoag1OsOVpctt3Mi7Jjjf3vFW4xoY
                  5mdS6/ImQpm0xtlTLOPeQQ==

     End timestamp: 2022-10-20 10:50:52 -0700 (run time: 0m 46s)

The new database will need to be renamed to be read by AIDE:
     $ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Perform a manual check:
     $ sudo /usr/sbin/aide --check

Example output:
     Start timestamp: 2022-10-20 11:03:16 -0700 (AIDE 0.16)
     AIDE found differences between database and filesystem!!
     ...
	 
Done.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-251713' 'II' 'high' 'yes' 'attended-file' '' 'V-251713' \
        'RHEL 8 must ensure the password complexity module is enabled in the system-auth file.' \
        'SV-251713r1262179_rule' 'RHEL-08-020101' 'C-55150r1261916_chk' 'F-55104r1261917_fix' \
        'Verify the operating system uses "pwquality" to enforce the password complexity rules. 

Check for the use of "pwquality" in the system-auth file with the following command:

$ sudo cat /etc/pam.d/system-auth | grep pam_pwquality
password required pam_pwquality.so

If the command does not return a line containing the value "pam_pwquality.so" as shown, or the line is commented out, this is a finding.' \
        'Configure the operating system to use "pwquality" to enforce password complexity rules.

Add the following line to the "/etc/pam.d/system-auth" file (or modify the line to have the required value):

password required pam_pwquality.so' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-251718' 'II' 'high' 'yes' 'evidence-review' '' 'V-251718' \
        'The graphical display manager must not be the default target on RHEL 8 unless approved.' \
        'SV-251718r1017371_rule' 'RHEL-08-040321' 'C-55155r809376_chk' 'F-55109r809377_fix' \
        'Verify that the system is configured to boot to the command line:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target" and the Information System Security Officer (ISSO) lacks a documented requirement for a graphical user interface, this is a finding.' \
        'Document the requirement for a graphical user interface with the ISSO or reinstall the operating system without the graphical user interface. If reinstallation is not feasible, then continue with the following procedure:

Open an SSH session and enter the following commands:

$ sudo systemctl set-default multi-user.target

A reboot is required for the changes to take effect.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-257258' 'II' 'high' 'yes' 'attended-file' '' 'V-257258' \
        'RHEL 8.7 and higher must terminate idle user sessions.' \
        'SV-257258r1069328_rule' 'RHEL-08-020035' 'C-60942r1069265_chk' 'F-60884r1014792_fix' \
        'Note: This requirement applies to RHEL versions 8.7 and higher. If the system is not RHEL version 8.7 or newer, this requirement is not applicable.

Note: For cloud hosted systems where "ClientAliveInterval" (V-244525) is configured, this setting is not applicable.

Verify that RHEL 8 logs out sessions that are idle for 10 minutes with the following command:

$ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

StopIdleSessionSec=600

If "StopIdleSessionSec" is not configured to "600" seconds, this is a finding.' \
        'Configure RHEL 8 to log out idle sessions after 10 minutes by editing the /etc/systemd/logind.conf file with the following line:

StopIdleSessionSec=600

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

$ sudo systemctl restart systemd-logind' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-268322' 'I' 'high' 'yes' 'attended-file' '' 'V-268322' \
        'RHEL 8 must not allow blank or null passwords in the system-auth file.' \
        'SV-268322r1017568_rule' 'RHEL-08-020331' 'C-72343r1017566_chk' 'F-72246r1017567_fix' \
        'To verify that null passwords cannot be used, run the following command:

$ sudo grep -i nullok /etc/pam.d/system-auth

If output is produced, this is a finding.' \
        'Remove any instances of the "nullok" option in the "/etc/pam.d/system-auth" file to prevent logons with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-272482' 'I' 'high' 'yes' 'attended-file' '' 'V-272482' \
        'The RHEL 8 SSH client must be configured to use only DoW-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.' \
        'SV-272482r1262197_rule' 'RHEL-08-010296' 'C-76536r1208396_chk' 'F-76442r1208397_fix' \
        'Verify the RHEL 8 SSH client is configured to use only MACs employing FIPS 140-3-approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ grep -i MACs /etc/crypto-policies/back-ends/openssh.config
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

If the MACs entries in the "openssh.config" file have any hashes other than "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256", or they are missing or commented out, this is a finding.' \
        'Configure the RHEL 8 SSH client to use only MACs employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS
Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-272483' 'I' 'high' 'yes' 'attended-file' '' 'V-272483' \
        'The RHEL 8 SSH client must be configured to use only DoW-approved encryption ciphers employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.' \
        'SV-272483r1262198_rule' 'RHEL-08-010297' 'C-76537r1155359_chk' 'F-76443r1155360_fix' \
        'Verify the RHEL 8 SSH client is configured to use only ciphers employing FIPS 140-3-approved algorithms.

To verify the ciphers in the systemwide SSH configuration file, use the following command:

$ grep -i Ciphers /etc/crypto-policies/back-ends/openssh.config 

Ciphers aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr

If the cipher entries in the "openssh.config" file have any ciphers other than "aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr", or they are missing or commented out, this is a finding.' \
        'Configure the RHEL 8 SSH client to use only ciphers employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS

Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-272484' 'II' 'high' 'yes' 'evidence-review' '' 'V-272484' \
        'RHEL 8 must elevate the SELinux context when an administrator calls the sudo command.' \
        'SV-272484r1134875_rule' 'RHEL-08-010455' 'C-76538r1134873_chk' 'F-76444r1134874_fix' \
        'Verify the operating system elevates the SELinux context when an administrator calls the sudo command with the following command:

This command must be run as root:

# grep -r sysadm_r /etc/sudoers /etc/sudoers.d
/etc/sudoers.d/admins:<username> ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

If conflicting results are returned, this is a finding.

If a designated sudoers administrator group or account(s) is not configured to elevate the SELinux type and role to "sysadm_t" and "sysadm_r" with the use of the sudo command, this is a finding.' \
        'Configure the operating system to elevate the SELinux context when an administrator calls the sudo command.

Edit a file in the "/etc/sudoers.d" directory with the following command:

$ sudo visudo -f /etc/sudoers.d/<customfile>

Use the following example to build the <customfile> in the /etc/sudoers.d directory to allow any administrator belonging to a designated sudoers admin group to elevate their SELinux context with the use of the sudo command:

{designated_group_or_user_name} ALL=(ALL) TYPE=sysadm_t ROLE=sysadm_r ALL

Remove any configurations that conflict with the above from the following locations:
 
/etc/sudoers
/etc/sudoers.d/' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-274877' 'II' 'high' 'yes' 'attended-file' '' 'V-274877' \
        'RHEL 8 must audit any script or executable called by cron as root or by any privileged user.' \
        'SV-274877r1155381_rule' 'RHEL-08-030655' 'C-78978r1106147_chk' 'F-78883r1155380_fix' \
        'Verify RHEL 8 is configured to audit the execution of any system call made by cron as root or as any privileged user.

$ sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.' \
        'Configure RHEL 8 to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":
-w /etc/cron.d/ -p wa -k cronjobs
-w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

$ sudo augenrules --load' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-279929' 'II' 'medium' 'yes' 'attended-file' '' 'V-279929' \
        'RHEL 8 must automatically exit interactive command shell user sessions after 10 minutes of inactivity.' \
        'SV-279929r1156340_rule' 'RHEL-08-020360' 'C-84489r1156338_chk' 'F-84394r1156339_fix' \
        'Verify RHEL 8 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh

/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'\''profile.d/ directory, is missing or is commented out, this is a finding.' \
        'Configure RHEL 8 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-288829' 'I' 'high' 'yes' 'attended-file' '' 'V-288829' \
        'RHEL 8 must implement DoW-approved encryption in the OpenSSL package.' \
        'SV-288829r1261888_rule' 'RHEL-08-010293' 'C-93518r1261886_chk' 'F-93423r1261887_fix' \
        'Verify the RHEL 8 OpenSSL library is configured to use only ciphers employing FIPS 140-3-approved algorithms with the following command:

$ grep -i opensslcnf.config /etc/pki/tls/openssl.cnf
.include = /etc/crypto-policies/back-ends/opensslcnf.config

If the "opensslcnf.config" is not defined in the "/etc/pki/tls/openssl.cnf" file, this is a finding.' \
        'Configure the RHEL 8 OpenSSL library to use the systemwide cryptographic policy.

Edit the "/etc/pki/tls/openssl.cnf" and add or modify the following line:

.include = /etc/crypto-policies/back-ends/opensslcnf.config' || return 1

    # shellcheck disable=SC2016 # DISA command examples are literal reference text.
    register_rule 'V-288831' 'II' 'high' 'yes' 'attended-file' '' 'V-288831' \
        'OS must generate an audit record for all successful and unsuccessful uses of the useradd command.' \
        'SV-288831r1261903_rule' 'RHEL-08-030565' 'C-93520r1261901_chk' 'F-93425r1261902_fix' \
        'Verify OS generates an audit record for any successful and unsuccessful use of the "useradd" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":
  
$ grep -w useradd /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure OS to generate an audit event for any successful and unsuccessful uses of the "useradd" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd

The audit daemon must be restarted for the changes to take effect.

$ service auditd restart' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230227' 'II' 'medium' 'yes' 'attended-file' '' 'V-230227' \
        'RHEL 8 must display the Standard Mandatory DoW Notice and Consent Banner before granting local or remote access to the system via a command line user logon.' \
        'SV-230227r1262184_rule' 'RHEL-08-010060' 'C-32896r1261927_chk' 'F-32871r1261928_fix' \
        'Verify RHEL 8 displays the Standard Mandatory DoW Notice and Consent Banner before granting access to the operating system via a command line user logon.

Check that RHEL 8 displays a banner at the command line login screen with the following command:

$ sudo cat /etc/issue

If the banner is set correctly it will return the following text:

“You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.”

If the banner text does not match the Standard Mandatory DoW Notice and Consent Banner exactly, this is a finding.' \
        'Configure RHEL 8 to display the Standard Mandatory DoW Notice and Consent Banner before granting access to the system via command line logon.

Edit the "/etc/issue" file to replace the default text with the Standard Mandatory DoW Notice and Consent Banner. The DoW-required text is:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests -- not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230244' 'II' 'high' 'yes' 'attended-file' '' 'V-230244' \
        'RHEL 8 must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.' \
        'SV-230244r1069300_rule' 'RHEL-08-010200' 'C-32913r1069209_chk' 'F-32888r917866_fix' \
        'Verify the SSH server automatically terminates a user session after the SSH client has become unresponsive.

Check that the "ClientAliveCountMax" is set to "1" by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*clientalivecountmax'\''

/etc/ssh/sshd_config:ClientAliveCountMax 1

If "ClientAliveCountMax" do not exist, is not set to a value of "1" in "/etc/ssh/sshd_config", or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Note: This setting must be applied in conjunction with RHEL-08-010201 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has become unresponsive.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveCountMax 1

For the changes to take effect, the SSH daemon must be restarted:

     $ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230245' 'II' 'medium' 'yes' 'attended-file' '' 'V-230245' \
        'The RHEL 8 /var/log/messages file must have mode 0640 or less permissive.' \
        'SV-230245r1017063_rule' 'RHEL-08-010210' 'C-32914r567481_chk' 'F-32889r567482_fix' \
        'Verify that the "/var/log/messages" file has mode "0640" or less permissive with the following command:

$ sudo stat -c "%a %n" /var/log/messages

640 /var/log/messages

If a value of "0640" or less permissive is not returned, this is a finding.' \
        'Change the permissions of the file "/var/log/messages" to "0640" by running the following command:

$ sudo chmod 0640 /var/log/messages' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230246' 'II' 'high' 'yes' 'attended-action' '' 'V-230246' \
        'The RHEL 8 /var/log/messages file must be owned by root.' \
        'SV-230246r1017064_rule' 'RHEL-08-010220' 'C-32915r567484_chk' 'F-32890r567485_fix' \
        'Verify that the /var/log/messages file is owned by root with the following command:

$ sudo stat -c "%U" /var/log/messages

root

If "root" is not returned as a result, this is a finding.' \
        'Change the owner of the file /var/log/messages to root by running the following command:

$ sudo chown root /var/log/messages' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230247' 'II' 'medium' 'yes' 'attended-file' '' 'V-230247' \
        'The RHEL 8 /var/log/messages file must be group-owned by root.' \
        'SV-230247r1017065_rule' 'RHEL-08-010230' 'C-32916r567487_chk' 'F-32891r567488_fix' \
        'Verify the "/var/log/messages" file is group-owned by root with the following command:

$ sudo stat -c "%G" /var/log/messages

root

If "root" is not returned as a result, this is a finding.' \
        'Change the group of the file "/var/log/messages" to "root" by running the following command:

$ sudo chgrp root /var/log/messages' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230248' 'II' 'medium' 'yes' 'attended-file' '' 'V-230248' \
        'The RHEL 8 /var/log directory must have mode 0755 or less permissive.' \
        'SV-230248r1069291_rule' 'RHEL-08-010240' 'C-32917r1069191_chk' 'F-32892r567491_fix' \
        'Verify that the "/var/log" directory has a mode of "0755" or less with the following command:

$ sudo stat -c "%a %n" /var/log

755 /var/log

If a value of "0755" or less permissive is not returned, this is a finding.' \
        'Change the permissions of the directory "/var/log" to "0755" by running the following command:

$ sudo chmod 0755 /var/log' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230250' 'II' 'medium' 'yes' 'attended-file' '' 'V-230250' \
        'The RHEL 8 /var/log directory must be group-owned by root.' \
        'SV-230250r1017068_rule' 'RHEL-08-010260' 'C-32919r567496_chk' 'F-32894r567497_fix' \
        'Verify the "/var/log" directory is group-owned by root with the following command:

$ sudo stat -c "%G" /var/log

root

If "root" is not returned as a result, this is a finding.' \
        'Change the group of the directory "/var/log" to "root" by running the following command:

$ sudo chgrp root /var/log' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230267' 'II' 'medium' 'yes' 'attended-file' '' 'V-230267' \
        'RHEL 8 must enable kernel parameters to enforce discretionary access control on symlinks.' \
        'SV-230267r1184249_rule' 'RHEL-08-010373' 'C-32936r1184247_chk' 'F-32911r1184248_fix' \
        'Verify RHEL 8 is configured to enable DAC on symlinks.

Check the status of the "fs.protected_symlinks" kernel parameter with the following command:

$ sudo sysctl fs.protected_symlinks
fs.protected_symlinks = 1

If "fs.protected_symlinks" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to enable DAC on symlinks with the following:

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-fs_protected_symlinks.conf

Add the following to the file:
fs.protected_symlinks = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230268' 'II' 'medium' 'yes' 'attended-file' '' 'V-230268' \
        'RHEL 8 must enable kernel parameters to enforce discretionary access control on hardlinks.' \
        'SV-230268r1184252_rule' 'RHEL-08-010374' 'C-32937r1184250_chk' 'F-32912r1184251_fix' \
        'Verify RHEL 8 is configured to enable DAC on hardlinks.

Check the status of the "fs.protected_hardlinks" kernel parameter with the following command:

$ sudo sysctl fs.protected_hardlinks
fs.protected_hardlinks = 1

If "fs.protected_hardlinks" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to enable DAC on hardlinks.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-fs_protected_hardlinks.conf

Add the following to the file:
fs.protected_hardlinks = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230269' 'III' 'medium' 'yes' 'attended-file' '' 'V-230269' \
        'RHEL 8 must restrict access to the kernel message buffer.' \
        'SV-230269r1262201_rule' 'RHEL-08-010375' 'C-32938r1184253_chk' 'F-32913r1184254_fix' \
        'Verify RHEL 8 is configured to restrict access to the kernel message buffer.

Check the status of the "kernel.dmesg_restrict" kernel parameter with the following command:

$ sudo sysctl kernel.dmesg_restrict
kernel.dmesg_restrict = 1

If "kernel.dmesg_restrict" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to restrict access to the kernel message buffer.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-dmesg_restrict.conf

Add the following to the file:
kernel.dmesg_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230270' 'III' 'medium' 'yes' 'attended-file' '' 'V-230270' \
        'RHEL 8 must prevent kernel profiling by unprivileged users.' \
        'SV-230270r1262202_rule' 'RHEL-08-010376' 'C-32939r1184256_chk' 'F-32914r1184257_fix' \
        'Verify RHEL 8 is configured to prevent kernel profiling by nonprivileged users.

Check the status of the "kernel.perf_event_paranoid" kernel parameter.

$ sudo sysctl kernel.perf_event_paranoid
kernel.perf_event_paranoid = 2

If "kernel.perf_event_paranoid" is not set to "2" or is missing, this is a finding.' \
        'Configure RHEL 8 to prevent kernel profiling by nonprivileged users.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_perf_event_paranoid.conf

Add the following to the file:
kernel.perf_event_paranoid = 2

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230280' 'II' 'medium' 'yes' 'attended-file' '' 'V-230280' \
        'RHEL 8 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.' \
        'SV-230280r1208745_rule' 'RHEL-08-010430' 'C-32949r1208743_chk' 'F-32924r1208744_fix' \
        'Verify RHEL 8 implements ASLR with the following command:

$ sudo sysctl kernel.randomize_va_space
kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", this is a finding.

Check that the configuration files are present to enable this kernel parameter.

$ sudo grep -rs kernel.randomize_va_space /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf
/etc/sysctl.d/99-kernel_randomize_va_space.conf:kernel.randomize_va_space = 2

If "kernel.randomize_va_space" is not set to "2", or is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to implement virtual address space randomization.

$ echo '\''kernel.randomize_va_space = 2'\'' | sudo tee /etc/sysctl.d/99-kernel_randomize_va_space.conf

Remove any configurations that conflict with the above from the following locations:

/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Issue the following command to make the changes take effect:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230281' 'III' 'medium' 'yes' 'attended-file' '' 'V-230281' \
        'YUM must remove all software components after updated versions have been installed on RHEL 8.' \
        'SV-230281r958936_rule' 'RHEL-08-010440' 'C-32950r567589_chk' 'F-32925r567590_fix' \
        'Verify the operating system removes all software components after updated versions have been installed.

Check if YUM is configured to remove unneeded packages with the following command:

$ sudo grep -i clean_requirements_on_remove /etc/dnf/dnf.conf

clean_requirements_on_remove=True

If "clean_requirements_on_remove" is not set to either "1", "True", or "yes", commented out, or is missing from "/etc/dnf/dnf.conf", this is a finding.' \
        'Configure the operating system to remove all software components after updated versions have been installed.

Set the "clean_requirements_on_remove" option to "True" in the "/etc/dnf/dnf.conf" file:

clean_requirements_on_remove=True' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230286' 'II' 'high' 'yes' 'attended-file' '' 'V-230286' \
        'The RHEL 8 SSH public host key files must have mode 0644 or less permissive.' \
        'SV-230286r1017097_rule' 'RHEL-08-010480' 'C-32955r567604_chk' 'F-32930r567605_fix' \
        'Verify the SSH public host key files have mode "0644" or less permissive with the following command:

$ sudo ls -l /etc/ssh/*.pub

-rw-r--r-- 1 root root 618 Nov 28 06:43 ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 347 Nov 28 06:43 ssh_host_key.pub
-rw-r--r-- 1 root root 238 Nov 28 06:43 ssh_host_rsa_key.pub

If any key.pub file has a mode more permissive than "0644", this is a finding.

Note: SSH public key files may be found in other directories on the system depending on the installation.' \
        'Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

$ sudo chmod 0644 /etc/ssh/*key.pub

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230288' 'II' 'high' 'yes' 'attended-file' '' 'V-230288' \
        'The RHEL 8 SSH daemon must perform strict mode checking of home directory configuration files.' \
        'SV-230288r1069301_rule' 'RHEL-08-010500' 'C-32957r1069211_chk' 'F-32932r567611_fix' \
        'Verify the SSH daemon performs strict mode checking of home directory configuration files with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*strictmodes'\''

/etc/ssh/sshd_config:StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure SSH to perform strict mode checking of home directory configuration files. Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes":

StrictModes yes

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230290' 'II' 'high' 'yes' 'attended-file' '' 'V-230290' \
        'The RHEL 8 SSH daemon must not allow authentication using known host’s authentication.' \
        'SV-230290r1069302_rule' 'RHEL-08-010520' 'C-32959r1069213_chk' 'F-32934r567617_fix' \
        'Verify the SSH daemon does not allow authentication using known host’s authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*ignoreuserknownhosts'\''

/etc/ssh/sshd_config:IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure the SSH daemon to not allow authentication using known host’s authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreUserKnownHosts yes

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230321' 'II' 'high' 'yes' 'attended-action' '' 'V-230321' \
        'All RHEL 8 local interactive user home directories must have mode 0750 or less permissive.' \
        'SV-230321r1017132_rule' 'RHEL-08-010730' 'C-32990r567709_chk' 'F-32965r567710_fix' \
        'Verify the assigned home directory of all local interactive users has a mode of "0750" or less permissive with the following command:

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

$ sudo ls -ld $(awk -F: '\''($3>=1000)&&($7 !~ /nologin/){print $6}'\'' /etc/passwd)

drwxr-x--- 2 smithj admin 4096 Jun 5 12:41 smithj

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.' \
        'Change the mode of interactive user’s home directories to "0750". To change the mode of a local interactive user’s home directory, use the following command:

Note: The example will be for the user "smithj".

$ sudo chmod 0750 /home/smithj' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230324' 'II' 'high' 'yes' 'attended-file' '' 'V-230324' \
        'All RHEL 8 local interactive user accounts must be assigned a home directory upon creation.' \
        'SV-230324r1017135_rule' 'RHEL-08-010760' 'C-32993r567718_chk' 'F-32968r567719_fix' \
        'Verify all local interactive users on RHEL 8 are assigned a home directory upon creation with the following command:

$ sudo grep -i create_home /etc/login.defs

CREATE_HOME yes

If the value for "CREATE_HOME" parameter is not set to "yes", the line is missing, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to assign home directories to all new local interactive users by setting the "CREATE_HOME" parameter in "/etc/login.defs" to "yes" as follows.

CREATE_HOME yes' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230325' 'II' 'high' 'yes' 'attended-action' '' 'V-230325' \
        'All RHEL 8 local initialization files must have mode 0740 or less permissive.' \
        'SV-230325r1017136_rule' 'RHEL-08-010770' 'C-32994r917877_chk' 'F-32969r917878_fix' \
        'Verify that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "smithj" user, who has a home directory of "/home/smithj".

     $ sudo ls -al /home/smithj/.[^.]* | more

     -rw-------. 1 smithj users 2984 Apr 27 19:02 .bash_history
     -rw-r--r--. 1 smithj users   18 Aug 21  2019 .bash_logout
     -rw-r--r--. 1 smithj users  193 Aug 21  2019 .bash_profile

If any local initialization files have a mode more permissive than "0740", this is a finding.' \
        'Set the mode of the local initialization files to "0740" with the following command:

Note: The example will be for the smithj user, who has a home directory of "/home/smithj".

     $ sudo chmod 0740 /home/smithj/.<INIT_FILE>' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230330' 'II' 'high' 'yes' 'attended-file' '' 'V-230330' \
        'RHEL 8 must not allow users to override SSH environment variables.' \
        'SV-230330r1069305_rule' 'RHEL-08-010830' 'C-32999r1069219_chk' 'F-32974r567737_fix' \
        'Verify that unattended or automatic logon via ssh is disabled with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*permituserenvironment'\''

/etc/ssh/sshd_config:PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to allow the SSH daemon to not allow unattended or automatic logon to the system.

Add or edit the following line in the "/etc/ssh/sshd_config" file:

PermitUserEnvironment no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230347' 'II' 'medium' 'yes' 'attended-file' '' 'V-230347' \
        'RHEL 8 must enable a user session lock until that user re-establishes access using established identification and authentication procedures for graphical user sessions.' \
        'SV-230347r1017160_rule' 'RHEL-08-020030' 'C-33016r567787_chk' 'F-32991r567788_fix' \
        'Verify the operating system enables a user'\''s session lock until that user re-establishes access using established identification and authentication procedures with the following command:

$ sudo gsettings get org.gnome.desktop.screensaver lock-enabled

true

If the setting is "false", this is a finding.

Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.' \
        'Configure the operating system to enable a user'\''s session lock until that user re-establishes access using established identification and authentication procedures.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following example:

$ sudo vi /etc/dconf/db/local.d/00-screensaver

Edit the "[org/gnome/desktop/screensaver]" section of the database file and add or update the following lines:

# Set this to true to lock the screen when the screensaver activates
lock-enabled=true

Update the system databases:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230357' 'II' 'high' 'yes' 'attended-file' '' 'V-230357' \
        'RHEL 8 must enforce password complexity by requiring that at least one uppercase character be used.' \
        'SV-230357r1017169_rule' 'RHEL-08-020110' 'C-33026r833312_chk' 'F-33001r858770_fix' \
        'Verify the value for "ucredit" with the following command:

$ sudo grep -r ucredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ucredit = -1

If the value of "ucredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to enforce password complexity by requiring that at least one uppercase character be used by setting the "ucredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ucredit = -1

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230358' 'II' 'high' 'yes' 'attended-file' '' 'V-230358' \
        'RHEL 8 must enforce password complexity by requiring that at least one lower-case character be used.' \
        'SV-230358r1017170_rule' 'RHEL-08-020120' 'C-33027r833314_chk' 'F-33002r858772_fix' \
        'Verify the value for "lcredit" with the following command:

$ sudo grep -r lcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:lcredit = -1

If the value of "lcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to enforce password complexity by requiring that at least one lower-case character be used by setting the "lcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

lcredit = -1

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230359' 'II' 'high' 'yes' 'attended-file' '' 'V-230359' \
        'RHEL 8 must enforce password complexity by requiring that at least one numeric character be used.' \
        'SV-230359r1017171_rule' 'RHEL-08-020130' 'C-33028r833316_chk' 'F-33003r858774_fix' \
        'Verify the value for "dcredit" with the following command:

$ sudo grep -r dcredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dcredit = -1

If the value of "dcredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

dcredit = -1

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230360' 'II' 'high' 'yes' 'attended-file' '' 'V-230360' \
        'RHEL 8 must require the maximum number of repeating characters of the same character class be limited to four when passwords are changed.' \
        'SV-230360r1017172_rule' 'RHEL-08-020140' 'C-33029r833318_chk' 'F-33004r858776_fix' \
        'Check for the value of the "maxclassrepeat" option with the following command:

$ sudo grep -r maxclassrepeat /etc/security/pwquality.conf*

/etc/security/pwquality.conf:maxclassrepeat = 4

If the value of "maxclassrepeat" is set to "0", more than "4" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to require the change of the number of repeating characters of the same character class when passwords are changed by setting the "maxclassrepeat" option.

Add the following line to "/etc/security/pwquality.conf" conf (or modify the line to have the required value):

maxclassrepeat = 4

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230361' 'II' 'high' 'yes' 'attended-file' '' 'V-230361' \
        'RHEL 8 must require the maximum number of repeating characters be limited to three when passwords are changed.' \
        'SV-230361r1017173_rule' 'RHEL-08-020150' 'C-33030r833320_chk' 'F-33005r858778_fix' \
        'Check for the value of the "maxrepeat" option with the following command:

$ sudo grep -r maxrepeat /etc/security/pwquality.conf*

/etc/security/pwquality.conf:maxrepeat = 3

If the value of "maxrepeat" is set to more than "3" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

maxrepeat = 3

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230362' 'II' 'high' 'yes' 'attended-file' '' 'V-230362' \
        'RHEL 8 must require the change of at least four character classes when passwords are changed.' \
        'SV-230362r1017174_rule' 'RHEL-08-020160' 'C-33031r833322_chk' 'F-33006r858780_fix' \
        'Verify the value of the "minclass" option with the following command:

$ sudo grep -r minclass /etc/security/pwquality.conf*

/etc/security/pwquality.conf:minclass = 4

If the value of "minclass" is set to less than "4" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

minclass = 4

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230363' 'II' 'high' 'yes' 'attended-file' '' 'V-230363' \
        'RHEL 8 must require the change of at least 8 characters when passwords are changed.' \
        'SV-230363r1017175_rule' 'RHEL-08-020170' 'C-33032r833324_chk' 'F-33007r858782_fix' \
        'Verify the value of the "difok" option with the following command:

$ sudo grep -r difok /etc/security/pwquality.conf*

/etc/security/pwquality.conf:difok = 8

If the value of "difok" is set to less than "8" or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

difok = 8

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230365' 'II' 'high' 'yes' 'attended-file' '' 'V-230365' \
        'RHEL 8 passwords for new users or password changes must have a 24 hours/1 day minimum password lifetime restriction in /etc/login.defs.' \
        'SV-230365r1017177_rule' 'RHEL-08-020190' 'C-33034r567841_chk' 'F-33009r567842_fix' \
        'Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.

Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command:

$ sudo grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater, or is commented out, this is a finding.' \
        'Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MIN_DAYS 1' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230366' 'II' 'high' 'yes' 'attended-file' '' 'V-230366' \
        'RHEL 8 user account passwords must have a 180-day maximum password lifetime restriction.' \
        'SV-230366r1262169_rule' 'RHEL-08-020200' 'C-33035r1261892_chk' 'F-33010r1261893_fix' \
        'Verify that RHEL 8 enforces a 180-day maximum password lifetime for new user accounts by running the following command:

$ sudo grep -i pass_max_days /etc/login.defs
PASS_MAX_DAYS 180

If the "PASS_MAX_DAYS" parameter value is greater than "180", or commented out, this is a finding.' \
        'Configure RHEL 8 to enforce a 180-day maximum password lifetime.

Add, or modify the following line in the "/etc/login.defs" file:

PASS_MAX_DAYS 180' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230369' 'II' 'high' 'yes' 'attended-file' '' 'V-230369' \
        'RHEL 8 passwords must have a minimum of 15 characters.' \
        'SV-230369r1262207_rule' 'RHEL-08-020230' 'C-33038r833326_chk' 'F-33013r858784_fix' \
        'Verify the operating system enforces a minimum 15-character password length. The "minlen" option sets the minimum number of characters in a new password.

Check for the value of the "minlen" option with the following command:

$ sudo grep -r minlen /etc/security/pwquality.conf*

/etc/security/pwquality.conf:minlen = 15

If the command does not return a "minlen" value of 15 or greater, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure operating system to enforce a minimum 15-character password length.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

minlen = 15

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230375' 'II' 'high' 'yes' 'attended-file' '' 'V-230375' \
        'All RHEL 8 passwords must contain at least one special character.' \
        'SV-230375r1017187_rule' 'RHEL-08-020280' 'C-33044r833328_chk' 'F-33019r858786_fix' \
        'Verify the value for "ocredit" with the following command:

$ sudo grep -r ocredit /etc/security/pwquality.conf*

/etc/security/pwquality.conf:ocredit = -1

If the value of "ocredit" is a positive number or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure the operating system to enforce password complexity by requiring that at least one special character be used by setting the "ocredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

ocredit = -1

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230377' 'II' 'high' 'yes' 'attended-file' '' 'V-230377' \
        'RHEL 8 must prevent the use of dictionary words for passwords.' \
        'SV-230377r1017188_rule' 'RHEL-08-020300' 'C-33046r833330_chk' 'F-33021r858788_fix' \
        'Verify RHEL 8 prevents the use of dictionary words for passwords.

Determine if the field "dictcheck" is set with the following command:

$ sudo grep -r dictcheck /etc/security/pwquality.conf*

/etc/security/pwquality.conf:dictcheck=1

If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding.
If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the /etc/pwquality.conf.d/ directory to contain the "dictcheck" parameter:

dictcheck=1

Remove any configurations that conflict with the above value.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230378' 'II' 'high' 'yes' 'attended-file' '' 'V-230378' \
        'RHEL 8 must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.' \
        'SV-230378r1262211_rule' 'RHEL-08-020310' 'C-33047r567880_chk' 'F-33022r567881_fix' \
        'Verify the operating system enforces a delay of at least four seconds between console logon prompts following a failed logon attempt with the following command:

$ sudo grep -i fail_delay /etc/login.defs

FAIL_DELAY 4

If the value of "FAIL_DELAY" is not set to "4" or greater, or the line is commented out, this is a finding.' \
        'Configure the operating system to enforce a delay of at least four seconds between logon prompts following a failed console logon attempt.

Modify the "/etc/login.defs" file to set the "FAIL_DELAY" parameter to "4" or greater:

FAIL_DELAY 4' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230382' 'II' 'high' 'yes' 'attended-file' '' 'V-230382' \
        'RHEL 8 must display the date and time of the last successful account logon upon an SSH logon.' \
        'SV-230382r1069309_rule' 'RHEL-08-020350' 'C-33051r1069227_chk' 'F-33026r567893_fix' \
        'Verify SSH provides users with feedback on when account accesses last occurred with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*printlastlog'\''

/etc/ssh/sshd_config:PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure SSH to provide users with feedback on when account accesses last occurred by setting the required configuration options in "/etc/pam.d/sshd" or in the "sshd_config" file used by the system ("/etc/ssh/sshd_config" will be used in the example) (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

Modify the "PrintLastLog" line in "/etc/ssh/sshd_config" to match the following:

PrintLastLog yes

The SSH service must be restarted for changes to "sshd_config" to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230383' 'II' 'high' 'yes' 'attended-file' '' 'V-230383' \
        'RHEL 8 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.' \
        'SV-230383r1017192_rule' 'RHEL-08-020351' 'C-33052r567895_chk' 'F-33027r567896_fix' \
        'Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Check for the value of the "UMASK" parameter in "/etc/login.defs" file with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs

UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.' \
        'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the line for the "UMASK" parameter in "/etc/login.defs" file to "077":

UMASK 077' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230393' 'II' 'medium' 'yes' 'attended-file' '' 'V-230393' \
        'The RHEL 8 audit system must audit local events.' \
        'SV-230393r1017200_rule' 'RHEL-08-030061' 'C-33062r567925_chk' 'F-33037r567926_fix' \
        'Verify the RHEL 8 Audit Daemon is configured to include local events, with the following command:

$ sudo grep local_events /etc/audit/auditd.conf

local_events = yes

If the value of the "local_events" option is not set to "yes", or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to audit local events on the system.

Add or update the following line in "/etc/audit/auditd.conf" file:

local_events = yes' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230395' 'III' 'medium' 'yes' 'attended-file' '' 'V-230395' \
        'RHEL 8 must resolve audit information before writing to disk.' \
        'SV-230395r1017201_rule' 'RHEL-08-030063' 'C-33064r567931_chk' 'F-33039r567932_fix' \
        'Verify the RHEL 8 Audit Daemon is configured to resolve audit information before writing to disk, with the following command:

$ sudo grep "log_format" /etc/audit/auditd.conf

log_format = ENRICHED

If the "log_format" option is not "ENRICHED", or the line is commented out, this is a finding.' \
        'Edit the /etc/audit/auditd.conf file and add or update the "log_format" option:

log_format = ENRICHED

The audit daemon must be restarted for changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230397' 'II' 'high' 'yes' 'attended-action' '' 'V-230397' \
        'RHEL 8 audit logs must be owned by root to prevent unauthorized read access.' \
        'SV-230397r1017203_rule' 'RHEL-08-030080' 'C-33066r567937_chk' 'F-33041r567938_fix' \
        'Verify the audit logs are owned by "root". First, determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Using the location of the audit log file, determine if the audit log is owned by "root" using the following command:

$ sudo ls -al /var/log/audit/audit.log

rw------- 2 root root 23 Jun 11 11:56 /var/log/audit/audit.log

If the audit log is not owned by "root", this is a finding.' \
        'Configure the audit log to be protected from unauthorized read access, by setting the correct owner as "root" with the following command:

$ sudo chown root [audit_log_file]

Replace "[audit_log_file]" to the correct audit log path, by default this location is "/var/log/audit/audit.log".' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230399' 'II' 'high' 'yes' 'attended-action' '' 'V-230399' \
        'RHEL 8 audit log directory must be owned by root to prevent unauthorized read access.' \
        'SV-230399r1017205_rule' 'RHEL-08-030100' 'C-33068r567943_chk' 'F-33043r567944_fix' \
        'Verify the audit log directory is owned by "root" to prevent unauthorized read access.

Determine where the audit logs are stored with the following command:

$ sudo grep -iw log_file /etc/audit/auditd.conf

log_file = /var/log/audit/audit.log

Determine the owner of the audit log directory by using the output of the above command (ex: "/var/log/audit/"). Run the following command with the correct audit log directory path:

$ sudo ls -ld /var/log/audit

drw------- 2 root root 23 Jun 11 11:56 /var/log/audit

If the audit log directory is not owned by "root", this is a finding.' \
        'Configure the audit log to be protected from unauthorized read access, by setting the correct owner as "root" with the following command:

$ sudo chown root [audit_log_directory]

Replace "[audit_log_directory]" with the correct audit log directory path, by default this location is usually "/var/log/audit".' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230404' 'II' 'medium' 'yes' 'attended-file' '' 'V-230404' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.' \
        'SV-230404r1017210_rule' 'RHEL-08-030130' 'C-33073r567958_chk' 'F-33048r567959_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/shadow /etc/audit/audit.rules

-w /etc/shadow -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/shadow".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/shadow -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230405' 'II' 'medium' 'yes' 'attended-file' '' 'V-230405' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/security/opasswd.' \
        'SV-230405r1017211_rule' 'RHEL-08-030140' 'C-33074r567961_chk' 'F-33049r567962_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/security/opasswd /etc/audit/audit.rules

-w /etc/security/opasswd -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/security/opasswd".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/security/opasswd -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230406' 'II' 'medium' 'yes' 'attended-file' '' 'V-230406' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.' \
        'SV-230406r1017212_rule' 'RHEL-08-030150' 'C-33075r567964_chk' 'F-33050r567965_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/passwd /etc/audit/audit.rules

-w /etc/passwd -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/passwd".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/passwd -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230407' 'II' 'medium' 'yes' 'attended-file' '' 'V-230407' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.' \
        'SV-230407r1017213_rule' 'RHEL-08-030160' 'C-33076r567967_chk' 'F-33051r567968_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/gshadow /etc/audit/audit.rules

-w /etc/gshadow -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/gshadow".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/gshadow -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230408' 'II' 'medium' 'yes' 'attended-file' '' 'V-230408' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.' \
        'SV-230408r1017214_rule' 'RHEL-08-030170' 'C-33077r567970_chk' 'F-33052r567971_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/group".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/group /etc/audit/audit.rules

-w /etc/group -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/group".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/group -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230409' 'II' 'medium' 'yes' 'attended-file' '' 'V-230409' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.' \
        'SV-230409r1017215_rule' 'RHEL-08-030171' 'C-33078r567973_chk' 'F-33053r567974_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/sudoers /etc/audit/audit.rules

-w /etc/sudoers -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/sudoers -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230410' 'II' 'medium' 'yes' 'attended-file' '' 'V-230410' \
        'RHEL 8 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.d/.' \
        'SV-230410r1017216_rule' 'RHEL-08-030172' 'C-33079r567976_chk' 'F-33054r567977_fix' \
        'Verify RHEL 8 generates audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers.d/".

Check the auditing rules in "/etc/audit/audit.rules" with the following command:

$ sudo grep /etc/sudoers.d/ /etc/audit/audit.rules

-w /etc/sudoers.d/ -p wa -k identity

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records for all account creations, modifications, disabling, and termination events that affect "/etc/sudoers.d/".

Add or update the following file system rule to "/etc/audit/rules.d/audit.rules":

-w /etc/sudoers.d/ -p wa -k identity

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230412' 'II' 'medium' 'yes' 'attended-file' '' 'V-230412' \
        'Successful/unsuccessful uses of the su command in RHEL 8 must generate an audit record.' \
        'SV-230412r1017218_rule' 'RHEL-08-030190' 'C-33081r567982_chk' 'F-33056r567983_fix' \
        'Verify RHEL 8 generates audit records when successful/unsuccessful attempts to use the "su" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w /usr/bin/su /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to generate audit records when successful/unsuccessful attempts to use the "su" command occur by adding or updating the following rule in "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged-priv_change

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230418' 'II' 'medium' 'yes' 'attended-file' '' 'V-230418' \
        'Successful/unsuccessful uses of the chage command in RHEL 8 must generate an audit record.' \
        'SV-230418r1017220_rule' 'RHEL-08-030250' 'C-33087r568000_chk' 'F-33062r568001_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "chage" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w chage /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "chage" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-chage

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230419' 'II' 'medium' 'yes' 'attended-file' '' 'V-230419' \
        'Successful/unsuccessful uses of the chcon command in RHEL 8 must generate an audit record.' \
        'SV-230419r1017221_rule' 'RHEL-08-030260' 'C-33088r568003_chk' 'F-33063r568004_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "chcon" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w chcon /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chcon" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230421' 'II' 'medium' 'yes' 'attended-file' '' 'V-230421' \
        'Successful/unsuccessful uses of the ssh-agent in RHEL 8 must generate an audit record.' \
        'SV-230421r1017222_rule' 'RHEL-08-030280' 'C-33090r568009_chk' 'F-33065r568010_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "ssh-agent" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep ssh-agent /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-agent" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/ssh-agent -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230422' 'II' 'medium' 'yes' 'attended-file' '' 'V-230422' \
        'Successful/unsuccessful uses of the passwd command in RHEL 8 must generate an audit record.' \
        'SV-230422r1017223_rule' 'RHEL-08-030290' 'C-33091r568012_chk' 'F-33066r568013_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "passwd" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w passwd /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "passwd" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-passwd

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230423' 'II' 'medium' 'yes' 'attended-file' '' 'V-230423' \
        'Successful/unsuccessful uses of the mount command in RHEL 8 must generate an audit record.' \
        'SV-230423r1017224_rule' 'RHEL-08-030300' 'C-33092r568015_chk' 'F-33067r568016_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "mount" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w /usr/bin/mount /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "mount" command by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/mount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230424' 'II' 'medium' 'yes' 'attended-file' '' 'V-230424' \
        'Successful/unsuccessful uses of the umount command in RHEL 8 must generate an audit record.' \
        'SV-230424r1017225_rule' 'RHEL-08-030301' 'C-33093r568018_chk' 'F-33068r568019_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "umount" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w /usr/bin/umount /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "umount" command by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=unset -k privileged-mount

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230426' 'II' 'medium' 'yes' 'attended-file' '' 'V-230426' \
        'Successful/unsuccessful uses of the unix_update in RHEL 8 must generate an audit record.' \
        'SV-230426r1017227_rule' 'RHEL-08-030310' 'C-33095r568024_chk' 'F-33070r568025_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "unix_update" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "unix_update" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "unix_update" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/unix_update -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230427' 'II' 'medium' 'yes' 'attended-file' '' 'V-230427' \
        'Successful/unsuccessful uses of postdrop in RHEL 8 must generate an audit record.' \
        'SV-230427r1017228_rule' 'RHEL-08-030311' 'C-33096r568027_chk' 'F-33071r568028_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "postdrop" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "postdrop" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "postdrop" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230428' 'II' 'medium' 'yes' 'attended-file' '' 'V-230428' \
        'Successful/unsuccessful uses of postqueue in RHEL 8 must generate an audit record.' \
        'SV-230428r1017229_rule' 'RHEL-08-030312' 'C-33097r568030_chk' 'F-33072r568031_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "postqueue" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "postqueue" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "postqueue" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230429' 'II' 'medium' 'yes' 'attended-file' '' 'V-230429' \
        'Successful/unsuccessful uses of semanage in RHEL 8 must generate an audit record.' \
        'SV-230429r1017230_rule' 'RHEL-08-030313' 'C-33098r568033_chk' 'F-33073r568034_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "semanage" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "semanage" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "semanage" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230430' 'II' 'medium' 'yes' 'attended-file' '' 'V-230430' \
        'Successful/unsuccessful uses of setfiles in RHEL 8 must generate an audit record.' \
        'SV-230430r1017231_rule' 'RHEL-08-030314' 'C-33099r568036_chk' 'F-33074r568037_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "setfiles" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "setfiles" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "setfiles" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230431' 'II' 'medium' 'yes' 'attended-file' '' 'V-230431' \
        'Successful/unsuccessful uses of userhelper in RHEL 8 must generate an audit record.' \
        'SV-230431r1017232_rule' 'RHEL-08-030315' 'C-33100r568039_chk' 'F-33075r568040_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "userhelper" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "userhelper" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "userhelper" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230432' 'II' 'medium' 'yes' 'attended-file' '' 'V-230432' \
        'Successful/unsuccessful uses of setsebool in RHEL 8 must generate an audit record.' \
        'SV-230432r1017233_rule' 'RHEL-08-030316' 'C-33101r568042_chk' 'F-33076r568043_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "setsebool" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "setsebool" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "setsebool" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230433' 'II' 'medium' 'yes' 'attended-file' '' 'V-230433' \
        'Successful/unsuccessful uses of unix_chkpwd in RHEL 8 must generate an audit record.' \
        'SV-230433r1017234_rule' 'RHEL-08-030317' 'C-33102r568045_chk' 'F-33077r568046_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of "unix_chkpwd" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w "unix_chkpwd" /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "unix_chkpwd" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-unix-update

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230434' 'II' 'medium' 'yes' 'attended-file' '' 'V-230434' \
        'Successful/unsuccessful uses of the ssh-keysign in RHEL 8 must generate an audit record.' \
        'SV-230434r1017235_rule' 'RHEL-08-030320' 'C-33103r568048_chk' 'F-33078r744001_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "ssh-keysign" by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep ssh-keysign /etc/audit/audit.rules

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "ssh-keysign" by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=unset -k privileged-ssh

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230435' 'II' 'medium' 'yes' 'attended-file' '' 'V-230435' \
        'Successful/unsuccessful uses of the setfacl command in RHEL 8 must generate an audit record.' \
        'SV-230435r1017236_rule' 'RHEL-08-030330' 'C-33104r568051_chk' 'F-33079r568052_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "setfacl" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w setfacl /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "setfacl" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230436' 'II' 'medium' 'yes' 'attended-file' '' 'V-230436' \
        'Successful/unsuccessful uses of the pam_timestamp_check command in RHEL 8 must generate an audit record.' \
        'SV-230436r1017237_rule' 'RHEL-08-030340' 'C-33105r568054_chk' 'F-33080r568055_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "pam_timestamp_check" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w pam_timestamp_check /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "pam_timestamp_check" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=unset -k privileged-pam_timestamp_check

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230437' 'II' 'medium' 'yes' 'attended-file' '' 'V-230437' \
        'Successful/unsuccessful uses of the newgrp command in RHEL 8 must generate an audit record.' \
        'SV-230437r1017238_rule' 'RHEL-08-030350' 'C-33106r568057_chk' 'F-33081r568058_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "newgrp" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w newgrp /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "newgrp" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230444' 'II' 'medium' 'yes' 'attended-file' '' 'V-230444' \
        'Successful/unsuccessful uses of the gpasswd command in RHEL 8 must generate an audit record.' \
        'SV-230444r1017244_rule' 'RHEL-08-030370' 'C-33113r568078_chk' 'F-33088r568079_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "gpasswd" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w gpasswd /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "gpasswd" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-gpasswd

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230447' 'II' 'medium' 'yes' 'attended-file' '' 'V-230447' \
        'Successful/unsuccessful uses of the crontab command in RHEL 8 must generate an audit record.' \
        'SV-230447r1017246_rule' 'RHEL-08-030400' 'C-33116r568087_chk' 'F-33091r568088_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "crontab" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w crontab /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "crontab" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=unset -k privileged-crontab

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230448' 'II' 'medium' 'yes' 'attended-file' '' 'V-230448' \
        'Successful/unsuccessful uses of the chsh command in RHEL 8 must generate an audit record.' \
        'SV-230448r1017247_rule' 'RHEL-08-030410' 'C-33117r568090_chk' 'F-33092r568091_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "chsh" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w chsh /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chsh" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230462' 'II' 'medium' 'yes' 'attended-file' '' 'V-230462' \
        'Successful/unsuccessful uses of the sudo command in RHEL 8 must generate an audit record.' \
        'SV-230462r1017254_rule' 'RHEL-08-030550' 'C-33131r568132_chk' 'F-33106r568133_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "sudo" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w sudo /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "sudo" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k priv_cmd

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230463' 'II' 'medium' 'yes' 'attended-file' '' 'V-230463' \
        'Successful/unsuccessful uses of the usermod command in RHEL 8 must generate an audit record.' \
        'SV-230463r1017255_rule' 'RHEL-08-030560' 'C-33132r568135_chk' 'F-33107r568136_fix' \
        'Verify that an audit event is generated for any successful/unsuccessful use of the "usermod" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w usermod /etc/audit/audit.rules

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful uses of the "usermod" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/sbin/usermod -F perm=x -F auid>=1000 -F auid!=unset -k privileged-usermod

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230464' 'II' 'medium' 'yes' 'attended-file' '' 'V-230464' \
        'Successful/unsuccessful uses of the chacl command in RHEL 8 must generate an audit record.' \
        'SV-230464r1017256_rule' 'RHEL-08-030570' 'C-33133r568138_chk' 'F-33108r568139_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful attempts to use the "chacl" command by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w chacl /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful use of the "chacl" command by adding or updating the following rule in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/usr/bin/chacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_mod

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230465' 'II' 'medium' 'yes' 'attended-file' '' 'V-230465' \
        'Successful/unsuccessful uses of the kmod command in RHEL 8 must generate an audit record.' \
        'SV-230465r1262212_rule' 'RHEL-08-030580' 'C-33134r568141_chk' 'F-33109r568142_fix' \
        'Verify if RHEL 8 is configured to audit the execution of the module management program "kmod", by running the following command:

$ sudo grep "/usr/bin/kmod" /etc/audit/audit.rules

-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure RHEL 8 to audit the execution of the module management program "kmod" by adding or updating the following line to "/etc/audit/rules.d/audit.rules":

-a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k modules

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230467' 'II' 'medium' 'yes' 'attended-file' '' 'V-230467' \
        'Successful/unsuccessful modifications to the lastlog file in RHEL 8 must generate an audit record.' \
        'SV-230467r1262214_rule' 'RHEL-08-030600' 'C-33136r568147_chk' 'F-33111r568148_fix' \
        'Verify RHEL 8 generates an audit record when successful/unsuccessful modifications to the "lastlog" file by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -w lastlog /etc/audit/audit.rules

-w /var/log/lastlog -p wa -k logins

If the command does not return a line, or the line is commented out, this is a finding.' \
        'Configure the audit system to generate an audit event for any successful/unsuccessful modifications to the "lastlog" file by adding or updating the following rules in the "/etc/audit/rules.d/audit.rules" file:

-w /var/log/lastlog -p wa -k logins

The audit daemon must be restarted for the changes to take effect.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230472' 'II' 'medium' 'yes' 'attended-file' '' 'V-230472' \
        'RHEL 8 audit tools must have a mode of 0755 or less permissive.' \
        'SV-230472r1017263_rule' 'RHEL-08-030620' 'C-33141r568162_chk' 'F-33116r568163_fix' \
        'Verify the audit tools are protected from unauthorized access, deletion, or modification by checking the permissive mode.

Check the octal permission of each audit tool by running the following command:

$ sudo stat -c "%a %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

755 /sbin/auditctl
755 /sbin/aureport
755 /sbin/ausearch
750 /sbin/autrace
755 /sbin/auditd
755 /sbin/rsyslogd
755 /sbin/augenrules

If any of the audit tools has a mode more permissive than "0755", this is a finding.' \
        'Configure the audit tools to be protected from unauthorized access by setting the correct permissive mode using the following command:

$ sudo chmod 0755 [audit_tool]

Replace "[audit_tool]" with the audit tool that does not have the correct permissive mode.' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230474' 'II' 'medium' 'yes' 'attended-file' '' 'V-230474' \
        'RHEL 8 audit tools must be group-owned by root.' \
        'SV-230474r1017265_rule' 'RHEL-08-030640' 'C-33143r568168_chk' 'F-33118r568169_fix' \
        'Verify the audit tools are group-owned by "root" to prevent any unauthorized access, deletion, or modification.

Check the owner of each audit tool by running the following commands:

$ sudo stat -c "%G %n" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/rsyslogd /sbin/augenrules

root /sbin/auditctl
root /sbin/aureport
root /sbin/ausearch
root /sbin/autrace
root /sbin/auditd
root /sbin/rsyslogd
root /sbin/augenrules

If any of the audit tools are not group-owned by "root", this is a finding.' \
        'Configure the audit tools to be group-owned by "root", by running the following command:

$ sudo chgrp root [audit_tool]

Replace "[audit_tool]" with each audit tool not group-owned by "root".' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230531' 'I' 'high' 'yes' 'attended-file' '' 'V-230531' \
        'The systemd Ctrl-Alt-Delete burst key sequence in RHEL 8 must be disabled.' \
        'SV-230531r1262161_rule' 'RHEL-08-040172' 'C-33200r1208753_chk' 'F-33175r1261882_fix' \
        'Verify RHEL 8 is configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ sudo grep -iR CtrlAltDelBurstAction /etc/systemd/system*
/etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf:CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", is commented out, or is missing, this is a finding.' \
        'Configure RHEL 8 to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:

If no drop file exists, create one with the following command:

$ sudo mkdir -p /etc/systemd/system.conf.d && sudo vi /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf

Edit the file to contain the setting by adding the following text:

[Manager]
CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect.

$ sudo systemctl daemon-reload' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230535' 'II' 'medium' 'yes' 'attended-file' '' 'V-230535' \
        'RHEL 8 must prevent IPv6 Internet Control Message Protocol (ICMP) redirect messages from being accepted.' \
        'SV-230535r1017297_rule' 'RHEL-08-040210' 'C-33204r833339_chk' 'F-33179r858792_fix' \
        'Verify RHEL 8 will not accept IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_redirects

net.ipv6.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.default.accept_redirects = 0

If "net.ipv6.conf.default.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to prevent IPv6 ICMP redirect messages from being accepted.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230536' 'II' 'medium' 'yes' 'attended-file' '' 'V-230536' \
        'RHEL 8 must not allow IPv4 ICMP redirect messages.' \
        'SV-230536r1208868_rule' 'RHEL-08-040220' 'C-33205r1208411_chk' 'F-33180r858794_fix' \
        'Verify RHEL 8 does not IPv4 ICMP redirect messages.

Check the value of the "all send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.send_redirects
net.ipv4.conf.all.send_redirects = 0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.send_redirects = 0

If "net.ipv4.conf.all.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not allow interfaces to perform IPv4 ICMP redirects.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.send_redirects=0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230537' 'II' 'medium' 'yes' 'attended-file' '' 'V-230537' \
        'RHEL 8 must not respond to Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.' \
        'SV-230537r1017299_rule' 'RHEL-08-040230' 'C-33206r833343_chk' 'F-33181r858796_fix' \
        'Verify RHEL 8 does not respond to ICMP echoes sent to a broadcast address.

Check the value of the "icmp_echo_ignore_broadcasts" variable with the following command:

$ sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts = 1

If the returned line does not have a value of "1", a line is not returned, or the retuned line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.icmp_echo_ignore_broadcasts /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.icmp_echo_ignore_broadcasts = 1

If "net.ipv4.icmp_echo_ignore_broadcasts" is not set to "1", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not respond to IPv4 ICMP echoes sent to a broadcast address.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.icmp_echo_ignore_broadcasts=1

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230538' 'II' 'medium' 'yes' 'attended-file' '' 'V-230538' \
        'RHEL 8 must not forward IPv6 source-routed packets.' \
        'SV-230538r1017300_rule' 'RHEL-08-040240' 'C-33207r833345_chk' 'F-33182r858800_fix' \
        'Verify RHEL 8 does not accept IPv6 source-routed packets.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_source_route

net.ipv6.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_source_route = 0

If "net.ipv6.conf.all.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not forward IPv6 source-routed packets.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_source_route=0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230539' 'II' 'medium' 'yes' 'attended-file' '' 'V-230539' \
        'RHEL 8 must not forward IPv6 source-routed packets by default.' \
        'SV-230539r1017301_rule' 'RHEL-08-040250' 'C-33208r861084_chk' 'F-33183r858805_fix' \
        'Verify RHEL 8 does not accept IPv6 source-routed packets by default.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv6.conf.default.accept_source_route

net.ipv6.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.default.accept_source_route = 0

If "net.ipv6.conf.default.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not forward IPv6 source-routed packets by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.default.accept_source_route=0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230543' 'II' 'medium' 'yes' 'attended-file' '' 'V-230543' \
        'RHEL 8 must not allow interfaces to perform Internet Control Message Protocol (ICMP) redirects by default.' \
        'SV-230543r1017305_rule' 'RHEL-08-040270' 'C-33212r833354_chk' 'F-33187r858815_fix' \
        'Verify RHEL 8 does not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Check the value of the "default send_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.send_redirects

net.ipv4.conf.default.send_redirects=0

If the returned line does not have a value of "0", or a line is not returned, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.send_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.send_redirects = 0

If "net.ipv4.conf.default.send_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not allow interfaces to perform Internet Protocol version 4 (IPv4) ICMP redirects by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.send_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230544' 'II' 'medium' 'yes' 'attended-file' '' 'V-230544' \
        'RHEL 8 must ignore IPv6 Internet Control Message Protocol (ICMP) redirect messages.' \
        'SV-230544r1017306_rule' 'RHEL-08-040280' 'C-33213r833356_chk' 'F-33188r858819_fix' \
        'Verify RHEL 8 ignores IPv6 ICMP redirect messages.

Note: If IPv6 is disabled on the system, this requirement is Not Applicable.

Check the value of the "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv6.conf.all.accept_redirects

net.ipv6.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv6.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv6.conf.all.accept_redirects = 0

If "net.ipv6.conf.all.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to ignore IPv6 ICMP redirect messages.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv6.conf.all.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230547' 'II' 'medium' 'yes' 'attended-file' '' 'V-230547' \
        'RHEL 8 must restrict exposed kernel pointer addresses access.' \
        'SV-230547r1184283_rule' 'RHEL-08-040283' 'C-33216r1184281_chk' 'F-33191r1184282_fix' \
        'Verify RHEL 8 is configured to restrict exposed kernel pointer address access.

Verify the runtime status of the "kernel.kptr_restrict" kernel parameter with the following command:

$ sudo sysctl kernel.kptr_restrict
kernel.kptr_restrict = 1

If "kernel.kptr_restrict" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to restrict exposed kernel pointer addresses access.

Create a drop-in if it does not already exist:

$ sudo vi /etc/sysctl.d/99-kernel_kptr_restrict.conf

Add the following to the file:
kernel.kptr_restrict = 1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-230556' 'II' 'high' 'yes' 'attended-file' '' 'V-230556' \
        'The RHEL 8 SSH daemon must prevent remote hosts from connecting to the proxy display.' \
        'SV-230556r1017318_rule' 'RHEL-08-040341' 'C-33225r951619_chk' 'F-33200r568415_fix' \
        'Verify the SSH daemon prevents remote hosts from connecting to the proxy display.

Check the SSH X11UseLocalhost setting with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*x11uselocalhost'\''

X11UseLocalhost yes

If the "X11UseLocalhost" keyword is set to "no", is missing, or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure the SSH daemon to prevent remote hosts from connecting to the proxy display.

Edit the "/etc/ssh/sshd_config" file to uncomment or add the line for the "X11UseLocalhost" keyword and set its value to "yes" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

X11UseLocalhost yes' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244519' 'II' 'medium' 'yes' 'attended-file' '' 'V-244519' \
        'RHEL 8 must display a banner before granting local or remote access to the system via a graphical user logon.' \
        'SV-244519r1017326_rule' 'RHEL-08-010049' 'C-47794r743804_chk' 'F-47751r743805_fix' \
        'Verify RHEL 8 displays a banner before granting access to the operating system via a graphical user logon.

Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

Check to see if the operating system displays a banner at the logon screen with the following command:

$ sudo grep banner-message-enable /etc/dconf/db/local.d/*

banner-message-enable=true

If "banner-message-enable" is set to "false" or is missing, this is a finding.' \
        'Configure the operating system to display a banner before granting access to the system.

Note: If the system does not have a graphical user interface installed, this requirement is Not Applicable.

Create a database to contain the system-wide graphical user logon settings (if it does not already exist) with the following command:

$ sudo touch /etc/dconf/db/local.d/01-banner-message

Add the following lines to the [org/gnome/login-screen] section of the "/etc/dconf/db/local.d/01-banner-message":

[org/gnome/login-screen]

banner-message-enable=true

Run the following command to update the database:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244525' 'II' 'high' 'yes' 'attended-file' '' 'V-244525' \
        'RHEL 8 must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.' \
        'SV-244525r1017331_rule' 'RHEL-08-010201' 'C-47800r951595_chk' 'F-47757r917885_fix' \
        'Verify the SSH server automatically terminates a user session after the SSH client has been unresponsive for 10 minutes.

Check that the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '\''/filename/ {print $4}'\'' | tr -d '\''\r'\'' | tr '\''\n'\'' '\'' '\'' | xargs sudo grep -iH '\''^\s*clientaliveinterval'\''

ClientAliveInterval 600

If "ClientAliveInterval" does not exist, does not have a value of "600" or less in "/etc/ssh/sshd_config", or is commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Note: This setting must be applied in conjunction with RHEL-08-010200 to function correctly.

Configure the SSH server to terminate a user session automatically after the SSH client has been unresponsive for 10 minutes.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

     ClientAliveInterval 600

For the changes to take effect, the SSH daemon must be restarted.

     $ sudo systemctl restart sshd.service' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244535' 'II' 'medium' 'yes' 'attended-file' '' 'V-244535' \
        'RHEL 8 must initiate a session lock for graphical user interfaces when the screensaver is activated.' \
        'SV-244535r1017342_rule' 'RHEL-08-020031' 'C-47810r743852_chk' 'F-47767r743853_fix' \
        'Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated with the following command:

Note: This requirement assumes the use of the RHEL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable.

$ sudo gsettings get org.gnome.desktop.screensaver lock-delay

uint32 5

If the "uint32" setting is missing, or is not set to "5" or less, this is a finding.' \
        'Configure the operating system to initiate a session lock for graphical user interfaces when a screensaver is activated.

Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:

Note: The example below is using the database "local" for the system, so if the system is using another database in "/etc/dconf/profile/user", the file should be created under the appropriate subdirectory.

$ sudo touch /etc/dconf/db/local.d/00-screensaver

[org/gnome/desktop/screensaver]
lock-delay=uint32 5

The "uint32" must be included along with the integer key values as shown.

Update the system databases:

$ sudo dconf update' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244550' 'II' 'medium' 'yes' 'attended-file' '' 'V-244550' \
        'RHEL 8 must prevent IPv4 Internet Control Message Protocol (ICMP) redirect messages from being accepted.' \
        'SV-244550r1017350_rule' 'RHEL-08-040209' 'C-47825r833372_chk' 'F-47782r858790_fix' \
        'Verify RHEL 8 will not accept IPv4 ICMP redirect messages.

Check the value of the default "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_redirects

net.ipv4.conf.default.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.accept_redirects = 0

If "net.ipv4.conf.default.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to prevent IPv4 ICMP redirect messages from being accepted.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244551' 'II' 'medium' 'yes' 'attended-file' '' 'V-244551' \
        'RHEL 8 must not forward IPv4 source-routed packets.' \
        'SV-244551r1017351_rule' 'RHEL-08-040239' 'C-47826r833374_chk' 'F-47783r858798_fix' \
        'Verify RHEL 8 does not accept IPv4 source-routed packets.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_source_route

net.ipv4.conf.all.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_source_route = 0

If "net.ipv4.conf.all.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not forward IPv4 source-routed packets.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_source_route=0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244552' 'II' 'medium' 'yes' 'attended-file' '' 'V-244552' \
        'RHEL 8 must not forward IPv4 source-routed packets by default.' \
        'SV-244552r1017352_rule' 'RHEL-08-040249' 'C-47827r833376_chk' 'F-47784r858802_fix' \
        'Verify RHEL 8 does not accept IPv4 source-routed packets by default.

Check the value of the accept source route variable with the following command:

$ sudo sysctl net.ipv4.conf.default.accept_source_route

net.ipv4.conf.default.accept_source_route = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.default.accept_source_route /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.default.accept_source_route = 0

If "net.ipv4.conf.default.accept_source_route" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to not forward IPv4 source-routed packets by default.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.default.accept_source_route=0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-244553' 'II' 'medium' 'yes' 'attended-file' '' 'V-244553' \
        'RHEL 8 must ignore IPv4 Internet Control Message Protocol (ICMP) redirect messages.' \
        'SV-244553r1017353_rule' 'RHEL-08-040279' 'C-47828r833378_chk' 'F-47785r858817_fix' \
        'Verify RHEL 8 ignores IPv4 ICMP redirect messages.

Check the value of the "accept_redirects" variables with the following command:

$ sudo sysctl net.ipv4.conf.all.accept_redirects

net.ipv4.conf.all.accept_redirects = 0

If the returned line does not have a value of "0", a line is not returned, or the line is commented out, this is a finding.

Check that the configuration files are present to enable this network parameter.

$ sudo grep -r net.ipv4.conf.all.accept_redirects /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf /etc/sysctl.d/*.conf

/etc/sysctl.d/99-sysctl.conf: net.ipv4.conf.all.accept_redirects = 0

If "net.ipv4.conf.all.accept_redirects" is not set to "0", is missing or commented out, this is a finding.

If conflicting results are returned, this is a finding.' \
        'Configure RHEL 8 to ignore IPv4 ICMP redirect messages.

Add or edit the following line in a system configuration file, in the "/etc/sysctl.d/" directory:

net.ipv4.conf.all.accept_redirects = 0

Remove any configurations that conflict with the above from the following locations:
/run/sysctl.d/*.conf
/usr/local/lib/sysctl.d/*.conf
/usr/lib/sysctl.d/*.conf
/lib/sysctl.d/*.conf
/etc/sysctl.conf
/etc/sysctl.d/*.conf

Load settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-251716' 'II' 'high' 'yes' 'attended-file' '' 'V-251716' \
        'RHEL 8 systems, version 8.4 and above, must ensure the password complexity module is configured for three retries or less.' \
        'SV-251716r1069329_rule' 'RHEL-08-020104' 'C-55153r1069267_chk' 'F-55107r1069268_fix' \
        'Note: This requirement applies to RHEL versions 8.4 or newer. If the system is RHEL below version 8.4, this requirement is not applicable.

Verify RHEL 8 is configured to limit the "pwquality" retry option to "3".

Check for the use of the retry option in the security directory with the following command:

$ grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf

retry = 3

If the value of "retry" is set to "0" or greater than "3", or is missing, this is a finding.' \
        'Configure RHEL 8 to limit the "pwquality" retry option to "3".

Add or update the following line in the "/etc/security/pwquality.conf" file or a file in the "/etc/security/pwquality.conf.d/" directory to contain the "retry" parameter:

retry = 3' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-284948' 'II' 'medium' 'yes' 'attended-file' '' 'V-284948' \
        'RHEL 8 must log IPv4 packets with impossible addresses.' \
        'SV-284948r1262225_rule' 'RHEL-08-040221' 'C-89517r1208427_chk' 'F-89422r1208756_fix' \
        'Verify RHEL 8 logs IPv4 martian packets.

Check the value of the "log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.all.log_martians
net.ipv4.conf.all.log_martians = 1

If "net.ipv4.conf.all.log_martians" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to log martian packets on IPv4 interfaces.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.all.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    # shellcheck disable=SC2016,SC1112 # DISA references are quoted verbatim.
    register_rule 'V-284949' 'II' 'medium' 'yes' 'attended-file' '' 'V-284949' \
        'RHEL 8 must log IPv4 packets with impossible addresses by default.' \
        'SV-284949r1262226_rule' 'RHEL-08-040222' 'C-89518r1208430_chk' 'F-89423r1208758_fix' \
        'Verify RHEL 8 logs IPv4 martian packets by default.

Check the value of the "default.log_martians" variable with the following command:

$ sudo sysctl net.ipv4.conf.default.log_martians
net.ipv4.conf.default.log_martians = 1

If "net.ipv4.conf.default.log_martians" is not set to "1" or is missing, this is a finding.' \
        'Configure RHEL 8 to log martian packets on IPv4 interfaces by default.

Create a configuration file if it does not already exist:

$ sudo vi /etc/sysctl.d/ipv4_log_martians.conf

Add the following line to the file:

net.ipv4.conf.default.log_martians=1

Reload settings from all system configuration files with the following command:

$ sudo sysctl --system' || return 1

    mapfile -t RULE_IDS < <(printf '%s\n' "${RULE_IDS[@]}" | LC_ALL=C sort)
    validate_registry
}


# Local boot, SSH key, repository, module, and audit checks.

rule_V_230279_check() {
    local defaults persistent installed active status=0
    if [[ ! -r /etc/default/grub || ! -r /proc/cmdline ]]; then
        rule_result NEEDS_REVIEW 'GRUB settings or the running kernel command line is unreadable'; return
    fi
    defaults=$(boot_defaults_args /etc/default/grub) || status=$?
    case $status in
        1) rule_result FAIL 'GRUB_CMDLINE_LINUX lacks the required init_on_free=1'; return ;;
        2) rule_result NEEDS_REVIEW 'GRUB_CMDLINE_LINUX is nonliteral or has duplicate assignments'; return ;;
        0) ;;
        *) rule_result ERROR 'GRUB defaults parse failed'; return ;;
    esac
    persistent=$(boot_poison_state <<< "$defaults") || { rule_result ERROR 'GRUB defaults parse failed'; return; }
    case $persistent in
        ambiguous) rule_result NEEDS_REVIEW 'GRUB_CMDLINE_LINUX has conflicting or noncanonical init_on_free arguments'; return ;;
        absent|disabled) rule_result FAIL 'GRUB_CMDLINE_LINUX lacks the required init_on_free=1'; return ;;
    esac
    if ! have_tools grubby || ! installed=$(timeout 10 grubby --info=ALL 2>/dev/null | boot_grubby_state); then
        rule_result NEEDS_REVIEW 'GRUB defaults have init_on_free=1. Effective installed boot entries could not be verified'; return
    fi
    if [[ $installed != enabled ]]; then
        rule_result FAIL 'GRUB defaults have init_on_free=1, but one or more installed boot entries do not'; return
    fi
    active=$(boot_poison_state < /proc/cmdline) || { rule_result ERROR 'kernel command-line parse failed'; return; }
    if [[ $active == enabled ]]; then
        rule_result PASS 'GRUB defaults, installed boot entries and running kernel use init_on_free=1'
    else
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW 'installed boot entries use init_on_free=1. The running kernel needs approved reboot and verification'
    fi
}

rule_V_230279_admin() {
    printf '%s\n' \
        '1. Boot administrator: capture current kernel entries and back up the boot configuration.' \
        '2. Identify the boot mode, BLS entries and the active grub.cfg path. Review grubby output for every installed kernel.' \
        '3. For a defaults-only stage, run grubby --update-kernel=ALL --args=init_on_free=1 and regenerate the verified active menu with grub2-mkconfig. A staged shared GRUB environment already supplies the argument to its BLS entries.' \
        '4. Schedule console recovery and a maintenance reboot. Confirm grubby --info=ALL, /etc/default/grub and /proc/cmdline.'
}

rule_V_230287_check() {
    local file mode effective default_count=0
    local -a keys=()
    if [[ ! -d /etc/ssh || ! -r /etc/ssh || ! -x /etc/ssh ]]; then
        rule_result NEEDS_REVIEW 'SSH key directory is unavailable or unreadable'; return
    fi
    for file in /etc/ssh/ssh_host*key; do
        if [[ ! -e $file && ! -L $file ]]; then continue; fi
        if [[ -L $file || ! -f $file ]]; then
            rule_result NEEDS_REVIEW 'an SSH host key path uses a symlink or a nonregular file'; return
        fi
        keys+=("$file")
    done
    for file in "${keys[@]}"; do
        mode=$(stat -c '%a' -- "$file" 2>/dev/null) || { rule_result ERROR 'SSH host key mode query failed'; return; }
        if [[ ! $mode =~ ^[0-7]{1,4}$ ]]; then rule_result ERROR 'invalid SSH host key mode'; return; fi
        if (( 8#$mode & 07177 )); then
            rule_result FAIL "at least one default SSH host key has mode $mode; allowed bits are 0600"; return
        fi
    done
    if (( ! ${#keys[@]} )) || ! have_tools sshd; then
        rule_result NEEDS_REVIEW 'no default host keys or SSH daemon found; applicability needs review'; return
    fi
    if ! expanded_sshd_invocation >/dev/null; then
        rule_result NEEDS_REVIEW 'default key modes meet the limit, but the running SSH invocation could not be verified'; return
    fi
    effective=$(timeout 10 sshd -T 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'the SSH daemon could not report effective HostKey paths'; return;
    }
    while IFS= read -r file; do
        [[ $file == hostkey\ * ]] || continue
        file=${file#hostkey }
        if [[ $file != /etc/ssh/ssh_host*key || ${file#/etc/ssh/} == */* ]]; then
            rule_result NEEDS_REVIEW 'a custom effective HostKey path needs review'; return
        fi
        if [[ -f $file ]]; then (( default_count += 1 )); fi
    done <<< "$effective"
    if (( ! default_count )); then
        rule_result NEEDS_REVIEW 'no usable key was found at an effective default HostKey path'; return
    fi
    rule_result PASS "checked mode only for ${#keys[@]} default SSH host key paths; allowed bits are 0600"
}

rule_V_230287_admin() {
    printf '%s\n' \
        '1. SSH administrator: identify every effective private HostKey path, including unit overrides.' \
        '2. Preserve metadata and restrict each affected regular key to 0600 or narrower as required.' \
        '3. Validate with sshd -t and retain the current connection and console access.' \
        '4. Activate the approved change in a maintenance window. Test an independent new SSH login.'
}

rule_V_230492_check() {
    local repos
    if ! have_tools dnf; then rule_result NEEDS_REVIEW 'DNF binary unavailable'; return; fi
    repos=$(timeout 25 dnf --cacheonly --noplugins -q --setopt=logfilelevel=0 repolist --enabled 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'cache-only DNF could not enumerate enabled repositories'; return;
    }
    if printf '%s\n' "$repos" | grep -qi 'epel'; then
        rule_result FAIL 'cache-only DNF listed an enabled repository with an EPEL identifier or name'
    else
        rule_result NEEDS_REVIEW 'cache-only DNF without plugins found no EPEL name; verify site/plugin repository sources'
    fi
}

rule_V_230492_admin() {
    printf '%s\n' \
        '1. Repository administrator: review enabled repo IDs and names, including managed DNF plugins.' \
        '2. Identify the authoritative source for each EPEL definition. Obtain application-owner review for dependencies.' \
        '3. Disable each enabled EPEL repository in its source, using actual IDs when invoking config-manager.' \
        '4. Preview any separate package transaction and repeat the effective enabled repository check.'
}

rule_V_230494_check() { check_module V-230494; }
rule_V_230495_check() { check_module V-230495; }
rule_V_230496_check() { check_module V-230496; }
rule_V_230497_check() { check_module V-230497; }
rule_V_230498_check() { check_module V-230498; }
rule_V_230499_check() { check_module V-230499; }
rule_V_230503_check() { check_module V-230503; }

rule_V_230494_admin() { module_admin V-230494; }
rule_V_230495_admin() { module_admin V-230495; }
rule_V_230496_admin() { module_admin V-230496; }
rule_V_230497_admin() { module_admin V-230497; }
rule_V_230498_admin() { module_admin V-230498; }
rule_V_230499_admin() { module_admin V-230499; }
rule_V_230503_admin() { module_admin V-230503; }

audit_has_rule() {
    local mode=$1
    awk -v mode="$mode" '
        function field(value) {return value in token}
        /^[[:space:]]*#/ {next}
        {
            delete token; extras=0;
            for (i=1; i<=NF; i++) {
                if ($i ~ /^#/) break;
                if ($i == "-S" && $(i+1) == "all") {i++; continue}
                if ($i ~ /^-(a|A|F|k|p|w)$/ && i<NF) {
                    arg=$(i+1);
                    if ($i == "-w") sub(/\/$/,"",arg);
                    if ($i == "-p" && arg == "aw") arg="wa";
                    if ($i == "-F" && arg ~ /^auid!=(-1|4294967295)$/) arg="auid!=unset";
                    if ($i == "-F" && arg ~ /^key=/) {
                        sub(/^key=/,"",arg); token["-k " arg]=1; i++; continue
                    }
                    flag=$i; if (flag == "-A") flag="-a";
                    if (flag == "-a" && arg == "exit,always") arg="always,exit";
                    if (flag == "-a" && arg == "task,never") arg="never,task";
                    token[flag " " arg]=1; i++;
                } else extras++;
            }
            if (field("-a never,task")) ignore=1;
            if (field("-a never,exit") || field("-a exit,never") ||
                field("-a never,exclude") || field("-a exclude,never")) suppress=1;
            if (!extras && field("-k cronjobs") && field("-p wa")) {
                if (field("-w /etc/cron.d")) etc=1;
                if (field("-w /var/spool/cron")) spool=1;
            }
            if (!extras && field("-a always,exit") && field("-F path=/usr/sbin/useradd") && field("-F perm=x") &&
                field("-F auid>=1000") && field("-F auid!=unset") && field("-k privileged-useradd")) {
                n=0; for (f in token) if (f ~ /^-F /) n++;
                if (n == 4 && !field("-a never,exit")) useradd=1;
            }
        }
        END {print ignore ? "disabled" :
            (mode == "cron" ? etc && spool : useradd) ? (suppress ? "suppression-review" : "present") : "missing"}
    '
}

active_audit_rules() {
    local settings
    settings=$(timeout 10 auditctl -s 2>/dev/null) || return 1
    local enabled
    enabled=$(printf '%s\n' "$settings" | awk '$1 == "enabled" && $2 ~ /^[012]$/ {print $2}') || return 1
    case $enabled in 0) return 2 ;; 1|2) ;; *) return 1 ;; esac
    timeout 10 auditctl -l 2>/dev/null || return 1
}

rule_V_274877_check() {
    local current stored result
    if ! have_tools auditctl; then rule_result NEEDS_REVIEW 'auditctl unavailable'; return; fi
    current=$(active_audit_rules)
    case $? in
        2) rule_result FAIL 'kernel auditing is explicitly disabled'; return ;;
        1) rule_result NEEDS_REVIEW 'active audit rules are unavailable'; return ;;
    esac
    result=$(audit_has_rule cron <<< "$current") || { rule_result ERROR 'active cron rules parse failed'; return; }
    case $result in
        suppression-review) rule_result NEEDS_REVIEW 'active watches are present alongside audit suppression rules'; return ;;
        present) ;;
        *) rule_result FAIL 'active audit policy lacks one or both required cron watch rules'; return ;;
    esac
    if [[ ! -r /etc/audit/audit.rules ]]; then
        rule_result NEEDS_REVIEW 'active cron watches present; generated persistent rules are unreadable'; return
    fi
    stored=$(audit_has_rule cron < /etc/audit/audit.rules) || { rule_result ERROR 'persistent rules parse failed'; return; }
    case $stored in
        present) rule_result PASS 'both required cron watch rules are present in active and generated audit policy' ;;
        suppression-review) rule_result NEEDS_REVIEW 'persistent watches are present alongside audit suppression rules' ;;
        *) rule_result FAIL 'active watches would not be preserved by the observed generated audit rules' ;;
    esac
}

rule_V_274877_admin() {
    printf '%s\n' \
        '1. Audit administrator: identify the authoritative audit rules source and immutable audit state.' \
        '2. In the managed rules source, place the required wa watches and cronjobs key for /etc/cron.d and /var/spool/cron.' \
        '3. Review the whole pending policy and approve activation. For immutable audit, use an authorized maintenance reboot.' \
        '4. Verify both the generated rules and the active output of auditctl -l.'
}

rule_V_288831_check() {
    local current stored result
    if [[ ! -r /etc/audit/audit.rules ]]; then rule_result NEEDS_REVIEW 'generated audit rules unreadable'; return; fi
    stored=$(audit_has_rule useradd < /etc/audit/audit.rules) || { rule_result ERROR 'persistent rules parse failed'; return; }
    case $stored in
        suppression-review) rule_result NEEDS_REVIEW 'persistent useradd rule is present alongside audit suppression rules'; return ;;
        present) ;;
        *) rule_result FAIL 'generated audit rules lack the required privileged-useradd rule'; return ;;
    esac
    if ! have_tools auditctl; then rule_result NEEDS_REVIEW 'persistent rule present; auditctl unavailable'; return; fi
    current=$(active_audit_rules)
    case $? in
        2) rule_result FAIL 'kernel auditing is explicitly disabled'; return ;;
        1) rule_result NEEDS_REVIEW 'persistent rule present; active audit state unavailable'; return ;;
    esac
    result=$(audit_has_rule useradd <<< "$current") || { rule_result ERROR 'active useradd rules parse failed'; return; }
    case $result in
        present) rule_result PASS 'required useradd execution rule is present in generated and active audit policy' ;;
        suppression-review) rule_result NEEDS_REVIEW 'active useradd rule is present alongside audit suppression rules' ;;
        *) rule_result FAIL 'persistent useradd execution rule is missing from active audit policy' ;;
    esac
}

rule_V_288831_admin() {
    printf '%s\n' \
        '1. Audit administrator: confirm /usr/sbin/useradd and identify the authoritative rules source.' \
        '2. Add or correct the path/execute/auid rule and privileged-useradd key specified in --explain V-288831.' \
        '3. Review all pending audit rules before any service action. Account for immutable audit state and scheduled reboot.' \
        '4. Verify the generated file and active audit policy. Test event capture in an isolated guest.'
}

# Storage, SSH policy, identity, and network evidence. Read-only functions.

rule_V_230224_check() {
    local devices luks_count
    if ! have_tools lsblk awk timeout; then
        rule_result UNKNOWN 'lsblk, awk and timeout are required for the block-device inventory.'
        return
    fi
    if ! devices=$(timeout 15 lsblk -e 7 -nr -o TYPE,FSTYPE 2>/dev/null); then
        rule_result ERROR 'Block-device inventory failed or timed out.'
        return
    fi
    luks_count=$(awk '$2 == "crypto_LUKS" { count++ } END { print count + 0 }' <<< "$devices")
    rule_result NEEDS_REVIEW \
        "Inventory found $luks_count LUKS entries. Trace all covered storage and verify any approved exceptions."
}

rule_V_230224_admin() {
    cat <<'EOF'
1. Storage owner: inventory local storage with lsblk -e 7 -o PATH,TYPE,FSTYPE,PKNAME,MOUNTPOINT.
2. Trace each persistent data and swap volume to its underlying encryption layer. Review unmounted
   partitions as well. Obtain the documented approval and evidence for any external encryption.
3. Where protection is missing, plan encrypted storage or a migration with verified backups, key
   escrow, a maintenance window and console recovery. Verify the volume layout and recovery boot.
EOF
}

rule_V_230229_check() {
    local bundle=/etc/sssd/pki/sssd_auth_ca_db.pem
    if ! have_tools openssl timeout; then
        rule_result UNKNOWN 'OpenSSL and timeout are required to inspect SSSD trust material.'
    elif [[ ! -e $bundle ]]; then
        rule_result NEEDS_REVIEW 'SSSD trust file was not observed. Confirm alternate MFA approval or supply the trust anchor.'
    elif [[ ! -f $bundle || ! -r $bundle ]]; then
        rule_result ERROR 'The expected SSSD trust file is unreadable or is not a regular file.'
    elif timeout 10 openssl x509 -in "$bundle" -noout -checkend 0 >/dev/null 2>&1; then
        rule_result NEEDS_REVIEW \
            'The first certificate parses and is unexpired. Verify the trusted root fingerprint, full date window and effective validation.'
    else
        rule_result NEEDS_REVIEW \
            'The first certificate could not be confirmed parseable and unexpired. Review the bundle or alternate MFA evidence.'
    fi
}

rule_V_230229_admin() {
    cat <<'EOF'
1. Identity owner: establish the active MFA method and provide its approval if relying on an alternate.
2. For the smart-card path, have the PKI team authenticate the DoW root bundle against a trusted
   fingerprint source. Inspect the first certificate with the following command.
   openssl x509 -in /etc/sssd/pki/sssd_auth_ca_db.pem -noout -dates -sha256 -fingerprint
   Inspect every PEM
   certificate separately if the file is a bundle. Verify the current date lies in the validity window.
3. Use the managed SSSD trust configuration and an approved maintenance window if replacing the trust
   material. Test the chain and revocation handling with approved test credentials and a recovery login.
EOF
}

# Exact sets from V2R9 C-32920, C-32921, C-76536 and C-76537. An approved nonempty subset is valid.
readonly SSH_MACS_V2R9='hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256'
readonly SSH_CIPHERS_V2R9='aes256-gcm@openssh.com,aes256-ctr,aes128-gcm@openssh.com,aes128-ctr'

check_ssh_backend() {
    local role=$1 directive=$2 permitted=$3 path code
    if ! have_tools awk; then
        rule_result UNKNOWN 'awk is required to inspect the generated OpenSSH backend.'
        return
    fi
    case $role in
        server) path=/etc/crypto-policies/back-ends/opensshserver.config ;;
        client) path=/etc/crypto-policies/back-ends/openssh.config ;;
        *) rule_result ERROR 'Unsupported OpenSSH backend role.'; return ;;
    esac
    if [[ -n ${4-} ]]; then path=$4; fi
    if [[ ! -e $path ]]; then
        if [[ -x /etc/crypto-policies/back-ends || ! -e /etc/crypto-policies ]]; then
            rule_result FAIL "The $role crypto-policy backend was not found."
        else
            rule_result UNKNOWN "The $role crypto-policy backend directory is unavailable."
        fi
        return
    fi
    if [[ ! -f $path || ! -r $path ]]; then
        rule_result ERROR "The $role crypto-policy backend is not a readable regular file."
        return
    fi

    # Read only known generated formats. In particular, never source opensshserver.config.
    if awk -v role="$role" -v name="$directive" -v values="$permitted" '
        BEGIN {
            wanted = tolower(name)
            entries = split(values, tokens, /,/)
            for (i = 1; i <= entries; i++) allowed[tokens[i]] = 1
            quote = sprintf("%c", 39)
        }
        /^[[:space:]]*($|#)/ { next }
        {
            if (role == "client") {
                keyword = tolower($1)
                if (keyword == "include" || keyword == "host" || keyword == "match") {
                    ambiguous = 1
                }
                if (keyword == wanted) {
                    if (NF != 2 && $3 !~ /^#/) ambiguous = 1
                    lists[++count] = $2
                } else if (keyword ~ ("^" wanted "=")) {
                    ambiguous = 1
                }
                next
            }
            line = $0
            sub(/^[[:space:]]*/, "", line)
            if (index(line, "CRYPTO_POLICY=" quote) != 1) {
                ambiguous = 1
                next
            }
            sub(/^CRYPTO_POLICY=/, "", line)
            tail = substr(line, 2)
            closing = index(tail, quote)
            if (closing == 0 || substr(tail, closing + 1) !~ /^[[:space:]]*(#.*)?$/) {
                ambiguous = 1
                next
            }
            assignments++
            arguments = split(substr(tail, 1, closing - 1), words, /[[:space:]]+/)
            prefix = "-o" wanted "="
            for (i = 1; i <= arguments; i++) {
                word = tolower(words[i])
                if (index(word, prefix) == 1) {
                    lists[++count] = substr(words[i], length(prefix) + 1)
                } else if (word == "-o" wanted) {
                    ambiguous = 1
                }
            }
        }
        END {
            if (ambiguous || assignments > 1 || count > 1) exit 4
            if (!count || lists[1] == "") exit 5
            n = split(lists[1], ciphers, /,/)
            for (i = 1; i <= n; i++) if (!(ciphers[i] in allowed)) exit 6
        }
    ' "$path" 2>/dev/null; then
        if [[ -n ${4-} ]]; then
            rule_result PASS "The generated $role backend $directive list contains only approved algorithms."
        else
            rule_result NEEDS_REVIEW \
                "The $role backend $directive list contains only approved algorithms. Confirm effective policy and activation."
        fi
        return
    else
        code=$?
    fi
    case $code in
        4) rule_result NEEDS_REVIEW "The $role backend has ambiguous syntax for $directive." ;;
        5) rule_result FAIL "The $role backend has no active $directive list." ;;
        6) rule_result FAIL "The $role backend $directive list contains an unapproved algorithm." ;;
        *) rule_result ERROR "The $role backend could not be assessed." ;;
    esac
}

ssh_policy_admin() {
    cat <<'EOF'
1. Security and SSH owners: review update-crypto-policies --show, both OpenSSH backends, and
   the applicable client configuration, sshd unit and overrides, including /etc/sysconfig/sshd.
2. Confirm effective algorithms for each relevant SSH client and server context, including application
   compatibility and overrides. Review configuration before running client diagnostics, since an SSH
   Match exec can execute local code. Confirm the actual running server uses the expected policy.
3. If changing the systemwide policy, coordinate all affected crypto consumers and approved package
   sources. Use the approved Red Hat policy procedure, then validate activation in a maintenance
   window with console access and a successful new SSH session. Retain the earlier policy and configs
   for tested recovery. Obtain broader scope approval for the shared crypto changes.
EOF
}

rule_V_230251_admin() { ssh_policy_admin; }
rule_V_230252_admin() { ssh_policy_admin; }
rule_V_272482_admin() { ssh_policy_admin; }
rule_V_272483_admin() { ssh_policy_admin; }

# Stream normalized SSSD assignments as section<TAB>key<TAB>value. No values go to reports.
# Only simple INI syntax is interpreted. A conflicting assignment remains under review.
read_sensitive_sssd() {
    local base=/etc/sssd/sssd.conf snippets=/etc/sssd/conf.d file
    local -a files=()
    if [[ -e $base || -L $base ]]; then files+=("$base"); fi
    if [[ -d $snippets ]]; then
        [[ -r $snippets && -x $snippets ]] || return 2
        for file in "$snippets"/*.conf; do
            if [[ -e $file || -L $file ]]; then files+=("$file"); fi
        done
    elif [[ -e $snippets || -L $snippets ]]; then
        return 2
    fi
    ((${#files[@]})) || return 1
    for file in "${files[@]}"; do
        [[ -f $file && -r $file ]] || return 2
    done
    parse_sensitive_sssd_assignments "${files[@]}"
}

parse_sensitive_sssd_assignments() {
    (( $# )) || return 0
    awk '
        FNR == 1 { section = "" }
        /^[[:space:]]*([#;]|$)/ { next }
        {
            if (index($0, "\r") || $0 ~ /\\[[:space:]]*$/) exit 3
            line = $0
            sub(/^[[:space:]]+/, "", line)
            sub(/[[:space:]]+$/, "", line)
            if (line ~ /^\[[^][]+\]$/) {
                section = substr(line, 2, length(line) - 2)
                next
            }
            equals = index(line, "=")
            if (section == "" || !equals) exit 3
            key = substr(line, 1, equals - 1)
            sub(/[[:space:]]+$/, "", key)
            value = substr(line, equals + 1)
            sub(/^[[:space:]]+/, "", value)
            if (section ~ /[[:cntrl:]]/ || key !~ /^[[:alnum:]_]+$/ || value ~ /[[:cntrl:]]/) exit 3
            print section "\t" key "\t" value
        }
    ' "$@" 2>/dev/null
}

get_sensitive_sssd() {
    local destination=$1 parsed read_rc
    if ! have_tools awk; then
        rule_result UNKNOWN 'awk is required to inspect SSSD configuration.'
        return 1
    fi
    if [[ ! -x /etc/sssd && -e /etc/sssd ]]; then
        rule_result UNKNOWN 'The SSSD directory cannot be traversed with current privileges.'
        return 1
    fi
    if parsed=$(read_sensitive_sssd); then
        printf -v "$destination" '%s' "$parsed"
        return
    else
        read_rc=$?
    fi
    case $read_rc in
        1) rule_result NEEDS_REVIEW 'No readable SSSD configuration was identified. Confirm site MFA and SSSD applicability.' ;;
        3) rule_result NEEDS_REVIEW 'SSSD configuration has syntax outside the supported evidence parser.' ;;
        *) rule_result ERROR 'SSSD configuration could not be inspected.' ;;
    esac
    return 1
}

rule_V_230274_check() {
    local assignments result
    get_sensitive_sssd assignments || return
    result=$(awk -F '\t' '
        $1 == "sssd" && $2 == "certificate_verification" {
            if (seen && prior != $3) conflict = 1
            seen = 1
            prior = $3
        }
        END {
            if (conflict) { print "conflict"; exit }
            n = split(prior, opts, /[[:space:]]*,[[:space:]]*/)
            for (i = 1; i <= n; i++) {
                if (opts[i] == "ocsp_dgst=sha1") required++
                else if (opts[i] ~ /^ocsp_dgst=/ || opts[i] == "no_ocsp" ||
                    opts[i] == "no_verification" || opts[i] == "soft_ocsp") bypass = 1
            }
            if (required == 1 && !bypass) print "candidate"
            else print "missing"
        }
    ' <<< "$assignments") || { rule_result ERROR 'SSSD OCSP evidence parsing failed.'; return; }
    case $result in
        candidate) rule_result NEEDS_REVIEW 'The expected OCSP digest is configured. Confirm live status checking or approved alternate MFA.' ;;
        conflict) rule_result NEEDS_REVIEW 'SSSD files disagree on certificate_verification.' ;;
        *)
            CHECK_PLAN_CANDIDATE=1
            rule_result NEEDS_REVIEW 'The expected OCSP setup was not established. Verify the approved MFA and certificate-status method.' ;;
    esac
}

rule_V_230274_admin() {
    cat <<'EOF'
1. Identity owner: establish the deployed MFA mechanism and document approval for any alternate.
2. For SSSD certificate checking, reconcile the [sssd] certificate_verification directives in the
   managed base configuration and snippets. Confirm certificate status checking with the PKI owner,
   including responder, digest, and failure behavior. Validate the configuration with sssctl config-check.
3. Use a maintenance window, a known-good privileged console, and approved valid and revoked test
   credentials to verify behavior after restarting SSSD. Keep the prior managed config for recovery.
EOF
}

check_sensitive_pam_cert() {
    [[ -f $1 && -r $1 ]] || return 2
    awk '
        /^[[:space:]]*($|#)/ { next }
        {
            sub(/[[:space:]]+#.*/, "")
            if ($1 != "auth" && $1 != "-auth") next
            if ($0 ~ /\\[[:space:]]*$/) { unsupported = 1; next }
            for (i = 3; i < NF; i++) {
                if ($i !~ /(^|\/)pam_sss\.so$/) continue
                for (j = i + 1; j <= NF; j++) {
                    if ($j == "try_cert_auth" || $j == "require_cert_auth") matched = 1
                }
            }
        }
        END { if (unsupported) exit 3; if (!matched) exit 4 }
    ' "$1" 2>/dev/null
}

rule_V_230372_check() {
    local assignments output base_output path check_rc
    local -a missing=()
    get_sensitive_sssd assignments || return
    output=$(awk -F '\t' '
        $1 == "pam" && $2 == "pam_cert_auth" {
            seen++
            if (tolower($3) != "true") contradiction = 1
        }
        END { if (seen && !contradiction) print "true" }
    ' <<< "$assignments") || { rule_result ERROR 'SSSD smart-card evidence parsing failed.'; return; }
    if [[ -f /etc/sssd/sssd.conf && -r /etc/sssd/sssd.conf ]]; then
        base_output=$(awk '
            /^[[:space:]]*\[/ { in_pam = $0 ~ /^[[:space:]]*\[pam\][[:space:]]*$/ }
            in_pam && tolower($0) ~ /^[[:space:]]*pam_cert_auth[[:space:]]*=[[:space:]]*true[[:space:]]*$/ {
                found = 1
            }
            END { if (found) print "true" }
        ' /etc/sssd/sssd.conf 2>/dev/null) || { rule_result ERROR 'SSSD base file could not be read.'; return; }
    fi
    if [[ $output != true || ${base_output:-} != true ]]; then missing+=('SSSD pam_cert_auth'); fi
    for path in /etc/pam.d/system-auth /etc/pam.d/smartcard-auth; do
        if check_sensitive_pam_cert "$path"; then continue; else check_rc=$?; fi
        case $check_rc in
            2|3|4) missing+=("${path##*/}") ;;
            *) rule_result ERROR 'A required PAM stack could not be inspected.'; return ;;
        esac
    done
    if ((${#missing[@]})); then
        CHECK_PLAN_CANDIDATE=1
        rule_result NEEDS_REVIEW \
            "Smart-card configuration not established in ${missing[*]}. Confirm approved alternate MFA or correct the configuration."
    else
        rule_result NEEDS_REVIEW 'Expected smart-card directives present. Verify active PAM paths and a new interactive smart-card login.'
    fi
}

rule_V_230372_admin() {
    cat <<'EOF'
1. Identity owner: document an approved alternate or identify the effective smart-card login paths.
2. Review sssctl config-check and, on authselect-managed systems, authselect current and authselect
   check. Correct SSSD and the relevant authselect profile or authoritative PAM source. Use the actual
   PAM control flow to validate both required stacks, including how fallback is permitted by policy.
3. During an approved maintenance window, hold console recovery, activate the configuration and
   verify a new interactive login with authorized test credentials. Keep a known-good profile/config.
EOF
}

rule_V_230376_check() {
    local assignments result
    get_sensitive_sssd assignments || return
    result=$(awk -F '\t' '
        $1 ~ /^domain\// && $2 == "cache_credentials" {
            if (tolower($3) == "true") enabled = 1
            else if (tolower($3) != "false") unrecognized = 1
        }
        $1 == "pam" && $2 == "offline_credentials_expiration" {
            seen = 1
            if ($3 != "1") invalid = 1
        }
        END {
            if (unrecognized) print "ambiguous"
            else if (!enabled) print "disabled"
            else if (seen && !invalid) print "daily"
            else print "longer"
        }
    ' <<< "$assignments") || { rule_result ERROR 'SSSD offline-cache evidence parsing failed.'; return; }
    case $result in
        disabled) rule_result NEEDS_REVIEW 'No caching enabled in the parsed SSSD domain settings. Confirm smart-card applicability and effective settings.' ;;
        daily) rule_result NEEDS_REVIEW 'SSSD caching is enabled and the configured expiration is one day. Confirm smart-card use and active configuration.' ;;
        longer)
            CHECK_PLAN_CANDIDATE=1
            rule_result NEEDS_REVIEW 'SSSD caching is enabled without verified one-day expiration. Confirm smart-card use before making the finding.' ;;
        *) rule_result NEEDS_REVIEW 'SSSD contains an unrecognized cache_credentials value. Confirm effective domain settings and smart-card use.' ;;
    esac
}

rule_V_230376_admin() {
    cat <<'EOF'
1. Identity owner: verify whether smart-card authentication is used. Document the observed login
   configuration and approved environment; unused smart cards make this control inapplicable.
2. If applicable, review cache_credentials in each effective SSSD domain. If caching is enabled,
   configure offline_credentials_expiration = 1 in the authoritative [pam] configuration.
3. Validate with sssctl config-check. In a maintenance window with console access, activate and
   verify both approved online and offline login behavior and the one-day cache expiry policy.
EOF
}

rule_V_230471_check() {
    local base=/etc/audit dir=/etc/audit/rules.d file mode dev root_dev metadata type
    local checked=0 broader=0 incomplete=0
    if ! have_tools stat find timeout; then
        rule_result UNKNOWN 'stat, find and timeout are required for the audit configuration mode check.'
        return
    fi
    if [[ -L $base || -L $dir || ! -d $dir || ! -x $dir || ! -r $dir ]]; then
        rule_result UNKNOWN 'Audit rule directory is absent, linked, or inaccessible.'
        return
    fi
    for file in "$base/audit.rules" "$base/auditd.conf"; do
        if [[ -L $file || ! -f $file ]]; then incomplete=1; continue; fi
        if ! mode=$(stat -c '%a' -- "$file" 2>/dev/null) || [[ ! $mode =~ ^[0-7]{1,4}$ ]]; then
            incomplete=1
            continue
        fi
        checked=$((checked + 1))
        if (( (8#$mode & 07177) != 0 )); then broader=$((broader + 1)); fi
    done
    if ! root_dev=$(stat -c '%d' -- "$dir" 2>/dev/null) ||
        ! metadata=$(timeout 15 find -P "$dir" -xdev \
            \( -type d -o -type l -o \( -type f -name '*.rules' \) \) \
            -printf '%y %m %D\n' 2>/dev/null); then
        rule_result ERROR 'Audit rule inventory failed or timed out.'
        return
    fi
    while read -r type mode dev; do
        if [[ $dev != "$root_dev" || $type == l ]]; then
            incomplete=1
        elif [[ $type == f ]]; then
            if [[ ! $mode =~ ^[0-7]{1,4}$ ]]; then incomplete=1; continue; fi
            checked=$((checked + 1))
            if (( (8#$mode & 07177) != 0 )); then broader=$((broader + 1)); fi
        fi
    done <<< "$metadata"
    if ((broader)); then
        rule_result FAIL "$broader of $checked checked audit configuration files grant access outside mode 0600."
    elif ((incomplete)); then
        rule_result NEEDS_REVIEW 'No excessive mode found on checked files. Missing, linked, or mounted paths prevent a complete check.'
    else
        rule_result PASS "All $checked required audit configuration files have mode 0600 or stricter."
    fi
}

rule_V_230471_admin() {
    cat <<'EOF'
1. Audit owner: inventory effective rules with find -P /etc/audit/rules.d -xdev -type f -name
   '*.rules' -exec stat -c '%a %n' {} + and check the mode of /etc/audit/{audit.rules,auditd.conf}.
   Resolve inaccessible paths, linked sources, or mount boundaries before concluding compliance.
2. Where needed, remove only excessive permissions through the authoritative configuration source.
   Review ACLs and ownership. Retain original metadata and confirm only approved roles can edit rules.
3. Verify with stat that every required regular file is mode 0600 or stricter. A mode change alone
   does not require reloading audit rules.
EOF
}

rule_V_230479_check() {
    local path active=0 inaccessible=0 grep_rc
    if ! have_tools grep; then
        rule_result UNKNOWN 'grep is required to collect local rsyslog forwarding evidence.'
        return
    fi
    if [[ -d /etc/rsyslog.d && ( ! -r /etc/rsyslog.d || ! -x /etc/rsyslog.d ) ]]; then
        inaccessible=1
    fi
    for path in /etc/rsyslog.conf /etc/rsyslog.d/*.conf; do
        [[ -e $path || -L $path ]] || continue
        if [[ ! -f $path || ! -r $path ]]; then inaccessible=1; continue; fi
        if grep -Eiq '^[[:space:]]*[^#[:space:]].*([[:space:]]@@?[^[:space:]]|omfwd)' \
            "$path" 2>/dev/null; then
            active=1
        else
            grep_rc=$?
            if ((grep_rc != 1)); then inaccessible=1; fi
        fi
    done
    if ((active)); then
        rule_result NEEDS_REVIEW 'Local rsyslog forwarding indicators present. Confirm the effective route and verify audit events at the collector.'
    elif ((inaccessible)); then
        rule_result NEEDS_REVIEW 'Some rsyslog configuration could not be read. Review the effective audit offload path.'
    else
        rule_result NEEDS_REVIEW 'No forwarding indicator found in standard rsyslog files. Verify alternate audit offload or document the finding.'
    fi
}

rule_V_230479_admin() {
    cat <<'EOF'
1. Audit and logging owners: identify the authoritative audit route, transport, approved destination,
   and how the collector distinguishes audit records from ordinary syslog messages.
2. If rsyslog is used, review its loaded includes, audit input/dispatch and forwarding. Validate
   with rsyslogd -N1 after reviewing the configuration. Preserve known-good audit and rsyslog configs.
3. Correlate an approved, benign test audit event by time and audit event ID at both endpoints.
   Obtain comparable delivery evidence for a different system or medium if an alternate route is used.
EOF
}

chrony_valid_approved_server() {
    local LC_ALL=C value=${1%.} label first
    local -a labels=()
    [[ -n $value && ${#value} -le 253 && $value != *..* &&
       $value != .* && $value != *. && $value =~ ^[A-Za-z0-9.-]+$ ]] || return 1
    [[ ${value,,} != localhost && ${value,,} != *.localhost ]] || return 1
    IFS=. read -r -a labels <<< "$value"
    if [[ $value =~ ^[0-9.]+$ ]]; then
        [[ $1 == "$value" ]] && (( ${#labels[@]} == 4 )) || return 1
        for label in "${labels[@]}"; do
            [[ $label =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( label <= 255 )) || return 1
        done
        first=${labels[0]}
        (( first > 0 && first != 127 && first < 224 ))
        return
    fi
    for label in "${labels[@]}"; do
        [[ $label =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || return 1
    done
}

chrony_effective_approved_server() {
    printf '%s\n' "${CHRONY_RUN_SERVER:-${CHRONY_APPROVED_SERVER-}}"
}

chrony_config_summary() {
    LC_ALL=C awk -v approved="$2" '
        function canonical(name) { sub(/[.]$/, "", name); return tolower(name) }
        /^[[:space:]]*($|[#;!%])/ { next }
        tolower($1) == "include" || tolower($1) == "confdir" || tolower($1) == "sourcedir" { includes = 1 }
        tolower($1) ~ /^(pool|peer|refclock|local|manual|authselectmode)$/ { other = 1 }
        tolower($1) == "minsources" && $2 != "1" { other = 1 }
        tolower($1) == "server" {
            if (NF < 2 || $2 ~ /^[#;!%]/) { ambiguous = 1; next }
            servers++
            matched = (approved != "" && canonical($2) == canonical(approved))
            if (matched) matching++
            bounded = 0
            seen = 0
            for (i = 3; i <= NF; i++) {
                if ($i ~ /^[#;!%]/) break
                if (tolower($i) == "maxpoll") {
                    if (++seen > 1 || $(i + 1) !~ /^-?[0-9]{1,3}$/) ambiguous = 1
                    else if ($(i + 1) + 0 > 16) excessive = 1
                    else bounded = 1
                    i++
                }
            }
            if (matched && bounded) matching_bounded++
        }
        END {
            print servers + 0, includes + 0, ambiguous + 0, excessive + 0,
                  other + 0, matching + 0, matching_bounded + 0
        }
    ' "$1" 2>/dev/null
}

rule_V_230484_check() {
    local path=/etc/chrony.conf result approved
    local servers includes ambiguous excessive other matching matching_bounded
    if ! have_tools awk; then
        rule_result UNKNOWN 'awk is required to inspect the chrony configuration.'
        return
    fi
    if [[ ! -e $path && ! -L $path ]]; then
        rule_result FAIL 'The required /etc/chrony.conf file was not found.'
        return
    fi
    if ! text_input_file "$path"; then
        rule_result UNKNOWN 'The chrony configuration is not a readable regular text file.'
        return
    fi
    approved=$(chrony_effective_approved_server)
    result=$(chrony_config_summary "$path" "$approved") ||
        { rule_result ERROR 'chrony configuration parsing failed.'; return; }
    read -r servers includes ambiguous excessive other matching matching_bounded <<< "$result"
    if ((excessive)); then
        rule_result FAIL 'An active server in /etc/chrony.conf specifies maxpoll greater than 16.'
    elif ((ambiguous || includes)); then
        rule_result NEEDS_REVIEW 'chrony includes or ambiguous server options require an effective configuration and time-source review.'
    elif (( ! servers )); then
        if (( other )); then
            rule_result FAIL 'No active server directive was found. Alternate time sources or selection policies require review.'
        elif [[ $approved ]]; then
            rule_result FAIL 'No active server directive was found. The supplied approved time source can be considered in the plan.'
        else
            rule_result FAIL 'No active server directive was found. Supply the approved time source to review adding it.'
        fi
    elif [[ $approved ]] && (( matching == 0 )); then
        rule_result NEEDS_REVIEW 'The supplied approved server does not match the existing server entries. Review the authoritative time configuration.'
    elif [[ $approved ]] && (( ! other && servers == 1 && matching_bounded == 1 )); then
        if chrony_verify_live "$path" "$approved"; then
            rule_result PASS 'The supplied approved server matches the sole configured source and the running chrony source. Synchronization and a recent poll within the required limit were observed.'
        else
            rule_result NEEDS_REVIEW 'The approved source and poll limit are present in the file. A current synchronized source could not be verified. Check activation and the selected source.'
        fi
    else
        rule_result NEEDS_REVIEW \
            "$servers configured server entries were inspected. Confirm the approved authoritative source and live synchronization."
    fi
}

rule_V_230484_admin() {
    cat <<'EOF'
1. Time-service owner: confirm which authoritative DoW time sources the site approves. Review the
   effective chrony file and includes, poll interval and source-authentication requirements.
2. Use the approved configuration source for chrony. For the DISA example, configure a server line
   for the actual approved site value with iburst and maxpoll no greater than 16. Coordinate the
   change with dependent applications, since restoring configuration cannot undo clock adjustments.
   To propose adding a server where no existing or alternate source is configured, supply one site-
   approved name or address as CHRONY_APPROVED_SERVER or through the approved time-source input.
3. After controlled activation, use chronyc -n tracking and chronyc -n sources to verify root delay,
   synchronization, selected source and poll interval against approved evidence.
EOF
}

# Identify active interface zones without including local interface names in reports.
rule_V_230504_check() {
    local state zones zone kind attributes status targets permanent count=0 interface_zone=0
    local no_drop=0 permanent_no_drop=0
    if ! have_tools firewall-cmd timeout awk; then
        rule_result NEEDS_REVIEW 'firewalld runtime inspection unavailable. Verify whether an alternate firewall enforces the required policy.'
        return
    fi
    if state=$(timeout 12 firewall-cmd --state 2>/dev/null); then
        if [[ $state != running ]]; then
            rule_result NEEDS_REVIEW 'firewalld returned an unexpected state. Verify the active firewall implementation.'
            return
        fi
    else
        status=$?
        if ((status == 124)); then
            rule_result ERROR 'firewalld state check timed out.'
        else
            rule_result NEEDS_REVIEW 'A running firewalld service could not be verified. Check privileges and alternate firewall use.'
        fi
        return
    fi
    if ! zones=$(timeout 12 firewall-cmd --get-active-zones 2>/dev/null); then
        rule_result ERROR 'The active firewalld zones could not be inspected.'
        return
    fi
    count=0
    zone=
    while IFS= read -r attributes; do
        [[ -n $attributes ]] || continue
        if [[ $attributes =~ ^[A-Za-z0-9_-]+$ ]]; then
            zone=$attributes
            count=$((count + 1))
            if ! targets=$(timeout 12 firewall-cmd "--zone=$zone" --list-all 2>/dev/null) ||
                ! permanent=$(timeout 12 firewall-cmd --permanent "--zone=$zone" --list-all 2>/dev/null); then
                rule_result NEEDS_REVIEW 'An active firewalld zone could not be verified in both runtime and permanent state.'
                return
            fi
            if ! awk '$1 == "target:" { n++; target = $2 } END { exit !(n == 1 && target == "DROP") }' \
                <<< "$targets"; then
                no_drop=1
            fi
            if ! awk '$1 == "target:" { n++; target = $2 } END { exit !(n == 1 && target == "DROP") }' \
                <<< "$permanent"; then
                permanent_no_drop=1
            fi
        elif [[ $attributes =~ ^[[:space:]]+([a-z]+):[[:space:]]+[^[:space:]] ]]; then
            kind=${BASH_REMATCH[1]}
            if [[ -z $zone || ( $kind != interfaces && $kind != sources ) ]]; then
                rule_result NEEDS_REVIEW 'Active firewalld zone output was not recognized.'
                return
            fi
            if [[ $kind == interfaces ]]; then interface_zone=1; fi
        else
            rule_result NEEDS_REVIEW 'Active firewalld zone output was not recognized.'
            return
        fi
    done <<< "$zones"
    if ((!interface_zone)); then
        rule_result FAIL 'firewalld has no active interface-associated zone.'
    elif ((no_drop)); then
        rule_result FAIL 'An active firewalld zone did not have the required runtime DROP target.'
    elif ((permanent_no_drop)); then
        rule_result NEEDS_REVIEW 'Runtime zones have DROP targets. Verify why the permanent state differs before claiming persistence.'
    else
        rule_result NEEDS_REVIEW \
            "$count active zones have DROP targets. Verify coverage and confirm every accepted exception with the network owner."
    fi
}

rule_V_230504_admin() {
    cat <<'EOF'
1. Network owner: identify the active firewall, interface and source assignments, traffic paths and
   approved exceptions. For firewalld, use firewall-cmd --get-active-zones, then list every applicable
   zone in runtime and permanent state. Review forwarding, outbound policy, direct rules and exceptions.
2. Stage changes with an authorized management exception, console recovery, prior firewall and
   NetworkManager profiles, and a maintenance window. Include any alternate firewall in the same review.
3. Verify a new administrative connection and required application flows, representative blocked
   flows, and persistence before concluding that the policy is enforced.
EOF
}

# Read-only checks for mounts, PAM, and access policy.

access_nodev_check() {
    local mountinfo=$1 summary
    if [[ ! -r $mountinfo ]] || ! have_tools awk; then
        rule_result UNKNOWN 'Mount namespace data or awk is unavailable.'
        return
    fi
    if ! summary=$(awk '
        {
            separator = 7
            while (separator <= NF && $separator != "-") separator++
            if (NF < 10 || separator + 3 != NF || $5 !~ /^\//) invalid = 1
            if ($5 != "/" && $(separator + 2) ~ /^\/dev\//) {
                local_count++
                if ($6 !~ /(^|,)nodev(,|$)/) missing++
            }
        }
        END {
            if (NR == 0 || invalid) exit 2
            printf "%d %d\n", local_count, missing
        }
    ' "$mountinfo" 2>/dev/null); then
        rule_result ERROR 'Unable to interpret the current mount namespace.'
        return
    fi
    local count missing
    read -r count missing <<< "$summary"
    if (( missing > 0 )); then
        rule_result FAIL "$missing of $count device-backed non-root mounts lack nodev."
    else
        rule_result PASS "All $count device-backed non-root mounts have nodev in this mount namespace."
    fi
}

rule_V_230301_check() { access_nodev_check /proc/self/mountinfo; }

rule_V_230301_admin() {
    printf '%s\n' \
        '1. Storage administrator: run findmnt --kernel -o SOURCE,TARGET,FSTYPE,OPTIONS and identify each non-root local device mount missing nodev.' \
        '2. Identify each mount owner and persistent source. For fstab-managed mounts, add nodev to the existing option field. Review systemd units or mount management when those own the mount.' \
        '3. Validate with findmnt --verify. Arrange a maintenance window and a rollback path before targeted remount or reboot. Rerun the scoped status check in the target namespace.'
}

access_owner_admin() {
    local predicate=$1 operation=$2 principal=$3
    printf '%s\n' \
        '1. Storage and identity administrators: enumerate mounted local filesystems with df --local -P. Review mount boundaries, automounts, and NSS or directory-service availability before the scan.' \
        "2. For each confirmed local mount, use find '<MOUNTPOINT>' -xdev $predicate -print during an approved window. <MOUNTPOINT> is the verified local filesystem root." \
        "3. Confirm the intended $principal from inventory or the application owner. Record previous metadata and review hard links or special files. Use $operation only on reviewed individual paths. Rescan each local filesystem."
}

rule_V_230326_check() {
    rule_result NEEDS_REVIEW 'A complete local-filesystem ownership sweep and authoritative NSS lookup are required.'
}

rule_V_230326_admin() { access_owner_admin -nouser chown owner; }

rule_V_230327_check() {
    rule_result NEEDS_REVIEW 'A complete local-filesystem group ownership sweep and authoritative NSS lookup are required.'
}

rule_V_230327_admin() { access_owner_admin -nogroup chgrp group; }

rule_V_244531_admin() {
    printf '%s\n' \
        '1. System administrator: identify local interactive accounts and their actual home directories. Check that homes and nested filesystems are local and identify symlink and bind-mount boundaries.' \
        '2. Examine applicable entries for group write, any other-user bit, and special mode bits. Review hidden entries and initialization file exclusions against the official check.' \
        '3. With the account or application owner, remove only excess bits from reviewed paths. Verify ACL mask changes, links, and required access. Repeat the complete inventory and mode check.'
}

rule_V_244532_check() {
    rule_result NEEDS_REVIEW 'The home directory inventory, authoritative group memberships, and ISSO exception evidence are required.'
}

rule_V_244532_admin() {
    printf '%s\n' \
        '1. System and identity administrators: identify each local interactive home and examine its contained files and directories within reviewed mount/link boundaries.' \
        '2. Verify every file group against the primary and supplementary memberships of the home owner. Refer mismatches to the ISSO and record applicable evidence.' \
        '3. For unexplained mismatches, agree on an authorized group with the file owner, preserve original metadata, and use chgrp only on reviewed paths. Repeat the inventory to verify.'
}

access_pam_check() {
    local file=$1 test=$2 outcome
    if [[ ! -f $file || ! -r $file ]] || ! have_tools awk; then
        rule_result UNKNOWN 'The live PAM stack or awk is unavailable.'
        return
    fi
    outcome=$(awk -v test="$test" '
        {
            if (test == "nullok" && tolower($0) ~ /nullok/) literal_nullok = 1
            sub(/#.*/, "")
            if (NF == 0) next
            active++
            type = $1
            sub(/^-/, "", type)
            if (type != "auth" && type != "account" && type != "password" &&
                type != "session") ambiguous = 1
            if ($0 ~ /\\[[:space:]]*$/) ambiguous = 1
            control = $2
            if (!branch[type] && (control == "sufficient" || control ~ /^\[/))
                branch[type] = NR
            module_index = 3
            if (control ~ /^\[/) {
                module_index = 2
                while (module_index <= NF && $module_index !~ /\]$/) module_index++
                module_index++
                if (module_index > NF) ambiguous = 1
            } else if (control !~ /^(required|requisite|sufficient|optional|include|substack)$/) {
                ambiguous = 1
            }
            if (module_index > NF || control == "include" || control == "substack") {
                if (test == "nullok" || type == "auth" || type == "account" ||
                    type == "password") ambiguous = 1
            }
            module = $module_index
            sub(/^\/usr\/lib64\/security\//, "", module)
            for (i = module_index + 1; i <= NF; i++) {
                if (tolower($i) == "nullok") nullok++
            }
            if (module == "pam_unix.so") {
                if (type == "auth" && !auth_unix) auth_unix = NR
                if (type == "account" && !account_unix) account_unix = NR
                if (type == "password" && !password_unix) password_unix = NR
            }
            if (module ~ /pam_unix\.so$/ && module != "pam_unix.so") ambiguous = 1
            if (module == "pam_faillock.so" && (type == "auth" || type == "account")) {
                if (control != "required") custom_faillock = 1
                if (type == "auth") {
                    for (i = module_index + 1; i <= NF; i++) {
                        if ($i == "preauth") { preauth++; preauth_line = NR }
                        if ($i == "authfail") { authfail++; authfail_line = NR }
                    }
                }
                if (type == "account") { account++; account_line = NR }
            } else if (module ~ /pam_faillock\.so$/) {
                custom_faillock = 1
            }
            if (module == "pam_pwquality.so" && type == "password") {
                pwquality++
                pwquality_line = NR
                if (control != "required") custom_pwquality = 1
            } else if (module ~ /pam_pwquality\.so$/) {
                custom_pwquality = 1
            }
        }
        END {
            if (test == "nullok" && nullok) print "NULL_OK"
            else if (test == "nullok" && literal_nullok) print "NULL_OK_LITERAL"
            else if (!active || ambiguous) print "AMBIGUOUS"
            else if (test == "nullok") print "PASS"
            else if (test == "faillock") {
                if (custom_faillock || preauth > 1 || authfail > 1 || account > 1)
                    print "AMBIGUOUS"
                else if (!preauth || (auth_unix && preauth_line >= auth_unix)) print "FAILLOCK"
                else if (!auth_unix || !authfail || !account || authfail_line <= auth_unix ||
                    (branch["auth"] && branch["auth"] < preauth_line) ||
                    (account_unix && account_line >= account_unix)) print "AMBIGUOUS"
                else print "PASS"
            } else if (test == "pwquality") {
                if (custom_pwquality || pwquality > 1) print "AMBIGUOUS"
                else if (!pwquality || (password_unix && pwquality_line >= password_unix))
                    print "PWQUALITY"
                else if (!password_unix ||
                    (branch["password"] && branch["password"] < pwquality_line)) print "AMBIGUOUS"
                else print "PASS"
            } else exit 2
        }
    ' "$file" 2>/dev/null) || {
        rule_result ERROR 'The PAM stack could not be read and evaluated.'
        return
    }
    case $outcome in
        PASS)
            case $test in
                nullok) rule_result PASS "No match for the official nullok check in $file." ;;
                faillock) rule_result PASS "Required faillock entries and pam_unix ordering found in $file." ;;
                pwquality) rule_result PASS "The required pam_pwquality.so entry precedes pam_unix in $file." ;;
            esac ;;
        AMBIGUOUS) rule_result NEEDS_REVIEW "Review included, custom, or conditional PAM policy affecting $file." ;;
        NULL_OK) rule_result FAIL "An active nullok argument is present in $file." ;;
        NULL_OK_LITERAL) rule_result FAIL "The official grep check matches nullok text in $file. No direct active nullok argument was identified." ;;
        FAILLOCK) rule_result FAIL "The faillock preauth entry is missing or occurs after pam_unix in $file." ;;
        PWQUALITY) rule_result FAIL "The required pam_pwquality.so line is missing or misplaced in $file." ;;
        *) rule_result ERROR 'Unexpected PAM assessment result.' ;;
    esac
}

rule_V_244541_check() { access_pam_check /etc/pam.d/password-auth nullok; }
rule_V_251713_check() { access_pam_check /etc/pam.d/system-auth pwquality; }
rule_V_268322_check() { access_pam_check /etc/pam.d/system-auth nullok; }

access_pam_admin() {
    local stack=$1 requirement=$2
    printf '%s\n' \
        '1. Authentication administrator: retain a recovery console and a working privileged session. Run authselect current and authselect check. Identify the profile/template or configuration management owner.' \
        "2. Review the effective $stack PAM stack and its branch/include behavior. $requirement" \
        '3. For an authselect-managed profile, preview the supported feature or edit the approved custom PAM template. Preserve existing features and review all regenerated stacks and their shared effects before activation.' \
        '4. Verify the resulting stack and both approved and rejected logins in fresh sessions before releasing the console. Repeat the scoped status check.'
}

rule_V_244533_admin() {
    access_pam_admin system-auth 'Ensure pam_faillock preauth before pam_unix, authfail after it, and the required account entry. Review with-faillock availability.'
}

rule_V_244534_admin() {
    access_pam_admin password-auth 'Ensure pam_faillock preauth before pam_unix, authfail after it, and the required account entry. Review with-faillock availability.'
}

rule_V_244541_admin() {
    access_pam_admin password-auth 'Review whether the installed profile can suppress blank-password support. Remove nullok occurrences from the generated stack, including comments matched by the DISA check.'
}

rule_V_251713_admin() {
    access_pam_admin system-auth 'Ensure the password stack uses required pam_pwquality.so before pam_unix. Confirm local and delegated password-change paths.'
}

rule_V_268322_admin() {
    access_pam_admin system-auth 'Review whether the installed profile can suppress blank-password support. Remove nullok occurrences from the generated stack, including comments matched by the DISA check.'
}

rule_V_244546_check() {
    local state permissive tail_rule
    if ! have_tools timeout systemctl awk; then
        rule_result UNKNOWN 'systemctl, timeout, or awk is unavailable.'
        return
    fi
    if ! state=$(timeout 8s systemctl show fapolicyd.service -p ActiveState --value 2>/dev/null); then
        rule_result UNKNOWN 'Could not determine the fapolicyd service state.'
        return
    fi
    case $state in
        inactive|failed)
            rule_result FAIL 'The fapolicyd service is not running in enforcement mode.'
            return ;;
        active) ;;
        *)
            rule_result NEEDS_REVIEW 'The fapolicyd service is not in a stable active state.'
            return ;;
    esac
    # Keep awk field references literal when invoking it through timeout.
    # shellcheck disable=SC2016
    if [[ ! -f /etc/fapolicyd/fapolicyd.conf ]] || ! permissive=$(timeout 8s awk '
        { sub(/#.*/, "") }
        /^[[:space:]]*permissive[[:space:]]*=/ {
            n++
            sub(/^[^=]*=[[:space:]]*/, "")
            sub(/[[:space:]]+$/, "")
            value = $0
        }
        END {
            if (n != 1 || value !~ /^[01]$/) print "unknown"
            else print value
        }
    ' /etc/fapolicyd/fapolicyd.conf 2>/dev/null); then
        rule_result UNKNOWN 'The fapolicyd configuration is unavailable.'
        return
    fi
    if [[ $permissive == 1 ]]; then
        rule_result FAIL 'fapolicyd is configured for permissive mode.'
        return
    fi
    if [[ $permissive != 0 ]]; then
        rule_result NEEDS_REVIEW 'fapolicyd permissive configuration is missing or ambiguous.'
        return
    fi
    # shellcheck disable=SC2016
    if [[ ! -f /etc/fapolicyd/compiled.rules ]] || ! tail_rule=$(timeout 8s awk '
        BEGIN {
            decision = "[[:space:]]+perm=any[[:space:]]+all[[:space:]]*:[[:space:]]*all[[:space:]]*$"
            allow = "^[[:space:]]*allow(_audit|_log|_syslog)?" decision
            deny = "^[[:space:]]*deny(_audit|_log|_syslog)?" decision
        }
        {
            sub(/#.*/, "")
            if (NF) {
                last = $0
                if (!first_catchall && ($0 ~ allow || $0 ~ deny))
                    first_catchall = ($0 ~ allow ? "allow" : "deny")
            }
        }
        END {
            if (first_catchall == "allow") print "ALLOW_ALL"
            else if (last ~ deny) print "DENY_ALL"
            else print "MISSING"
        }
    ' /etc/fapolicyd/compiled.rules 2>/dev/null); then
        rule_result UNKNOWN 'The compiled fapolicyd policy is unavailable.'
        return
    fi
    case $tail_rule in
        ALLOW_ALL) rule_result NEEDS_REVIEW 'An unconditional allow precedes any catch-all denial in the compiled policy. Determine whether unmatched execution can proceed.' ;;
        MISSING) rule_result FAIL 'The final compiled fapolicyd rule lacks a recognized catch-all denial.' ;;
        DENY_ALL) rule_result NEEDS_REVIEW 'Service is active and configuration ends in deny-all. Verify the daemon loaded this policy, mount coverage, and scope of earlier allows.' ;;
        *) rule_result ERROR 'Unexpected fapolicyd assessment result.' ;;
    esac
}

rule_V_244546_admin() {
    printf '%s\n' \
        '1. System and application owners: inventory required executables, trust sources, watched mounts, and recovery access.' \
        '2. Review ordered rules with fapolicyd-cli --list and mount coverage with fapolicyd-cli --check-watch_fs, if supported. Validate the planned allowlist on a representative isolated host before enforcing.' \
        '3. Manage components under /etc/fapolicyd/rules.d, then rebuild and load through the installed fagenrules workflow. Confirm catch-all deny and effective enforcement with approved test programs and a recovery session.'
}

rule_V_251710_check() {
    local package status=0
    if ! have_tools timeout rpm; then
        rule_result UNKNOWN 'rpm or timeout is unavailable.'
        return
    fi
    package=$(timeout 10s rpm -q --qf '%{NAME}' aide 2>&1) || status=$?
    if (( status == 0 )) && [[ $package == aide ]]; then
        rule_result NEEDS_REVIEW 'AIDE is installed. Verify its trusted database, integrity check execution and security-function coverage.'
    elif (( status == 1 )) && [[ $package == 'package aide is not installed' ]]; then
        rule_result NEEDS_REVIEW 'AIDE is absent. Identify and verify an approved alternative integrity tool, or record a finding if none exists.'
    else
        rule_result UNKNOWN 'The rpm query did not reliably determine AIDE installation.'
    fi
}

rule_V_251710_admin() {
    printf '%s\n' \
        '1. Integrity administrator: identify the installed integrity tool and documented coverage of security functions. If using AIDE, determine its configured input database and the approved baseline provenance.' \
        '2. If no approved integrity application is deployed, plan an authorized installation and initialize from a trusted system state. Inspect the generated database before promoting it to the configured input path.' \
        '3. Open Resolve to run the bounded AIDE evidence check for a verified default configuration. For a customized configuration or an alternative tool, review the approved integrity-check result and documented coverage with the security owner.'
}

rule_V_257258_check() {
    local runtime value evidence='Runtime idle threshold could not be confirmed.'
    if ! logind_257258_scope >/dev/null; then
        rule_result NEEDS_REVIEW 'Confirm whether the cloud SSH idle-session exception applies.'; return
    fi
    if ! text_input_file /etc/systemd/logind.conf || ! logind_257258_source ||
       ! value=$(logind_257258_idle /etc/systemd/logind.conf check); then
        rule_result NEEDS_REVIEW 'The authoritative logind section and effective configuration could not be verified.'; return
    fi
    if [[ $value != 600 ]]; then
        rule_result FAIL 'StopIdleSessionSec is absent or different from the required literal 600 in the authoritative [Login] section.'; return
    fi
    if have_tools busctl timeout; then
        runtime=$(timeout 5s busctl --system --no-pager --auto-start=no get-property \
            org.freedesktop.login1 /org/freedesktop/login1 \
            org.freedesktop.login1.Manager StopIdleSessionUSec 2>/dev/null) || runtime=
        if [[ $runtime == 't 600000000' ]]; then
            rule_result PASS 'persistent and reported runtime logind idle thresholds are 600 seconds'; return
        elif [[ $runtime =~ ^t\ [0-9]+$ ]]; then
            evidence='logind reports a runtime idle threshold other than 600 seconds.'
        fi
    fi
    rule_result NEEDS_REVIEW "$evidence StopIdleSessionSec is staged as 600. Verify a fresh supported session terminates after ten idle minutes."
}

rule_V_257258_admin() {
    printf '%s\n' \
        '1. Operations: establish whether this is a cloud host and whether the approved alternative covered by V-244525 is configured. Document both facts before applying the exception.' \
        '2. If applicable, inspect /etc/systemd/logind.conf and installed-version drop-in precedence. Set StopIdleSessionSec=600 in the effective [Login] section and verify that no higher precedence setting overrides it.' \
        '3. Arrange a console and maintenance window before restarting systemd-logind. Start a fresh supported session and verify termination after the configured idle interval.'
}

rule_V_272484_check() {
    local state
    if ! have_tools timeout getenforce; then
        rule_result UNKNOWN 'SELinux status tooling is unavailable.'
        return
    fi
    if ! state=$(timeout 5s getenforce 2>/dev/null); then
        rule_result UNKNOWN 'Unable to determine SELinux status.'
    elif [[ $state == Disabled ]]; then
        rule_result FAIL 'SELinux is disabled, so sudo cannot transition into the required SELinux context.'
    elif (( EUID != 0 )); then
        rule_result UNKNOWN 'The official sudoers check requires root.'
    elif ! have_tools visudo; then
        rule_result UNKNOWN 'sudoers validation tooling is unavailable.'
    elif ! timeout 10s visudo -c -q >/dev/null 2>&1; then
        rule_result NEEDS_REVIEW 'sudoers validation did not succeed or timed out. Review locally as root.'
    else
        rule_result NEEDS_REVIEW 'sudoers passed syntax validation. Review designated administrators, effective role/type, and conflicting permissions.'
    fi
}

rule_V_272484_admin() {
    printf '%s\n' \
        '1. System and SELinux administrators: obtain the designated administrator identities and approved SELinux user mappings. Retain a recovery console and a current privileged session.' \
        '2. Review included sudoers rules and effective permissions for each designated administrator. Use visudo to validate the proposed group or account rule with TYPE=sysadm_t and ROLE=sysadm_r and resolve conflicting entries.' \
        '3. Validate with visudo -c. Use a fresh approved administrator login to perform sudo id -Z and confirm the intended type and role before releasing recovery access.'
}


# Local account, SSH, desktop and crypto-policy checks added in the expanded scope.

expanded_rounds() {
    awk '
        /^[[:space:]]*#/ {next}
        $1 == "SHA_CRYPT_MIN_ROUNDS" || $1 == "SHA_CRYPT_MAX_ROUNDS" {
            if (++seen[$1] != 1 || $2 !~ /^[0-9]+$/ || length($2) > 9 ||
                (NF > 2 && $3 !~ /^#/)) bad=1;
            if (($2 + 0) > maximum) maximum=$2+0;
        }
        END {print bad ? "ambiguous" : maximum >= 100000 ? "pass" : "fail"}
    ' "$1"
}

rule_V_230233_check() {
    local result
    if [[ ! -r /etc/login.defs ]]; then rule_result NEEDS_REVIEW 'login.defs is unreadable'; return; fi
    result=$(expanded_rounds /etc/login.defs) || { rule_result ERROR 'could not read login.defs'; return; }
    case $result in
        pass) rule_result PASS 'the highest configured SHA crypt rounds value is at least 100000' ;;
        fail) rule_result FAIL 'login.defs has no SHA crypt rounds value of at least 100000' ;;
        *) rule_result NEEDS_REVIEW 'login.defs contains duplicate or ambiguous SHA crypt settings' ;;
    esac
}

rule_V_230233_admin() {
    printf '%s\n' \
        '1. Identity administrator: review SHA_CRYPT_MIN_ROUNDS and SHA_CRYPT_MAX_ROUNDS in /etc/login.defs.' \
        '2. Preview the scoped plan. A new minimum does not change existing password hashes or PAM hashing options.' \
        '3. Rerun the check and revise separate PAM settings through their authoritative source if required.'
}

expanded_rounds_render() {
    awk '
        /^[[:space:]]*SHA_CRYPT_MIN_ROUNDS[[:space:]]+/ {
            match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH);
            print indent "# rhel8-stig V-230233 original: " substr($0,RLENGTH+1);
            print indent "SHA_CRYPT_MIN_ROUNDS 100000"; found=1; next;
        }
        {print}
        END {if (!found) {
            print ""; print "# rhel8-stig V-230233"; print "SHA_CRYPT_MIN_ROUNDS 100000";
        }}
    ' "$1"
}

expanded_rounds_validate() { [[ $(expanded_rounds "$1") == pass ]]; }

rule_V_230233_plan() {
    local path=/etc/login.defs new="$EDIT_TEMP/V-230233.conf" current description
    if [[ $(expanded_rounds "$path") != fail ]]; then
        PLAN_REASON='the authoritative login.defs SHA crypt directives are ambiguous or already compliant'
        return 1
    fi
    current=$(awk '$1 == "SHA_CRYPT_MIN_ROUNDS" {print $2}' "$path") || return 1
    expanded_rounds_render "$path" > "$new" && expanded_rounds_validate "$new" || return 1
    description="Add SHA_CRYPT_MIN_ROUNDS 100000 to /etc/login.defs. Existing password hashes stay unchanged."
    if [[ -n $current ]]; then
        description="Comment SHA_CRYPT_MIN_ROUNDS $current in place and put SHA_CRYPT_MIN_ROUNDS 100000 directly underneath. Existing password hashes stay unchanged."
    fi
    edit_content "$path" keep "$description" expanded_rounds_validate < "$new"
}

# sshd -T tests parser-effective settings without binding a listening socket.
# Match and Include can produce per-context values and require a separate source review.
expanded_ssh_topology() {
    awk '
        /^[[:space:]]*#/ {next}
        {key=tolower($1); sub(/=.*/,"",key)}
        key == "include" || key == "match" {complex=1}
        END {print complex ? "scoped" : "plain"}
    ' "$1"
}

expanded_ssh_values() {
    awk -v directive="$2" '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/^[[:space:]]*/,"",line); sub(/[[:space:]]*$/,"",line);
            n=split(line,fields,/[[:space:]=]+/);
            if (tolower(fields[1]) == tolower(directive)) {
                if (n < 2 || (n > 2 && fields[3] !~ /^#/)) print "ambiguous";
                else print tolower(fields[2]);
            }
        }
    ' "$1"
}

expanded_sshd_invocation() {
    local output source=unit
    have_tools systemctl || return 1
    output=$(timeout 8 systemctl show sshd.service --no-pager --all \
        -p LoadState -p FragmentPath -p DropInPaths -p ExecStart 2>/dev/null) || return 1
    # Inspect the service contract, then hash it for plan staleness without logging options.
    if ! awk '
        /^LoadState=loaded$/ {loaded=1}
        /^FragmentPath=\/usr\/lib\/systemd\/system\/sshd.service$/ {unit=1}
        /^DropInPaths=$/ {drop=1}
        /^ExecStart=/ {
            if (index($0,"argv[]=/usr/sbin/sshd -D") == 0) next;
            start=substr($0,index($0,"argv[]=")+7); sub(/[[:space:]]*;.*/,"",start);
            args=split(start,tokens,/[[:space:]]+/);
            if (tokens[1] != "/usr/sbin/sshd" || tokens[2] != "-D") next;
            for (i=3; i<=args; i++) if (tokens[i] != "$OPTIONS" && tokens[i] != "$CRYPTO_POLICY") next;
            exec=1;
        }
        END {exit !(loaded && unit && drop && exec)}
    ' <<< "$output"; then return 1; fi
    if [[ -e /etc/sysconfig/sshd || -L /etc/sysconfig/sshd ]]; then
        [[ -f /etc/sysconfig/sshd && ! -L /etc/sysconfig/sshd && -r /etc/sysconfig/sshd ]] || return 1
        if ! awk '
            /^[[:space:]]*($|#)/ {next}
            {
                line=$0; sub(/^[[:space:]]*/,"",line); sub(/[[:space:]]*$/,"",line);
                if (line !~ /^(OPTIONS|CRYPTO_POLICY)=(""|\047\047)?$/ &&
                    line !~ /^SSH_USE_STRONG_RNG=[0-9]+$/) exit 1;
            }
        ' /etc/sysconfig/sshd; then return 1; fi
        source=$(sha256_file /etc/sysconfig/sshd) || return 1
    fi
    printf '%s\n%s\n' "$output" "$source" | sha256sum
}

expanded_ssh_effective() {
    local output
    output=$(timeout 12 sshd -T -f "$1" 2>/dev/null) || return 1
    awk -v directive="$2" 'tolower($1) == tolower(directive) {print tolower($2)}' <<< "$output"
}

expanded_ssh_loaded_state() {
    local output started conf_seconds start_seconds
    output=$(timeout 8 systemctl show sshd.service --no-pager -p ActiveState -p ExecMainStartTimestamp 2>/dev/null) || return 1
    if grep -qx 'ActiveState=inactive' <<< "$output"; then printf 'inactive\n'; return; fi
    grep -qx 'ActiveState=active' <<< "$output" || return 1
    started=$(awk '/^ExecMainStartTimestamp=/ {sub(/^[^=]*=/, ""); print}' <<< "$output") || return 1
    [[ -n $started ]] || return 1
    conf_seconds=$(stat -c %Y -- "$1") && start_seconds=$(date -d "$started" +%s) || return 1
    [[ $conf_seconds =~ ^[0-9]+$ && $start_seconds =~ ^[0-9]+$ ]] || return 1
    if (( conf_seconds >= start_seconds )); then printf 'pending\n'; else printf 'started\n'; fi
}

expanded_ssh_check() {
    local path=$1 directive=$2 topology values effective invocation state
    if ! have_tools sshd || [[ ! -r $path ]]; then
        rule_result NEEDS_REVIEW 'OpenSSH server tools or readable configuration are unavailable'; return
    fi
    topology=$(expanded_ssh_topology "$path") || { rule_result ERROR 'could not read OpenSSH configuration'; return; }
    values=$(expanded_ssh_values "$path" "$directive") || { rule_result ERROR 'could not parse OpenSSH directive'; return; }
    effective=$(expanded_ssh_effective "$path" "$directive") || {
        rule_result NEEDS_REVIEW 'sshd could not resolve its effective configuration under current privileges'; return;
    }
    if [[ $topology == scoped ]]; then
        rule_result NEEDS_REVIEW "global $directive is ${effective:-unresolved}; review Include and Match contexts"
        return
    fi
    if [[ $values == *ambiguous* ]]; then
        rule_result NEEDS_REVIEW "ambiguous $directive syntax requires authoritative source review"; return
    fi
    if [[ -z $values || $effective != no || $(sort -u <<< "$values") != no ]]; then
        rule_result FAIL "$directive is missing, conflicting, or effectively permits the prohibited authentication"
        return
    fi
    invocation=$(expanded_sshd_invocation) || {
        rule_result NEEDS_REVIEW "configured $directive is no; the systemd service invocation needs review"; return;
    }
    state=$(expanded_ssh_loaded_state "$path") || {
        rule_result NEEDS_REVIEW "configured $directive is no; activation state needs review"; return;
    }
    case $state in
        pending)
            CHECK_PENDING=1
            rule_result NEEDS_REVIEW "configured $directive is no; the active listener started before the current file. Complete SSH activation and verify a fresh login." ;;
        started|inactive)
            if [[ -n $invocation ]]; then rule_result PASS "OpenSSH evaluates explicit $directive no in the reviewed service configuration"; fi ;;
    esac
}

rule_V_230296_check() { expanded_ssh_check /etc/ssh/sshd_config PermitRootLogin; }
rule_V_244528_check() { expanded_ssh_check /etc/ssh/sshd_config GSSAPIAuthentication; }

expanded_ssh_admin() {
    printf '%s\n' \
        "1. SSH administrator: verify $1 in every included file, Match context, and sshd service override." \
        '2. Before activation, keep an administrative session and console available. Validate with sshd -t.' \
        '3. Use the approved SSH maintenance procedure to restart sshd. Confirm an independent new administrative login.'
}

rule_V_230296_admin() { expanded_ssh_admin PermitRootLogin; }
rule_V_244528_admin() {
    expanded_ssh_admin GSSAPIAuthentication
    printf '%s\n' '4. Have the ISSO review any documented GSSAPI mission exception before changing the policy.'
}

expanded_ssh_render() {
    awk -v selector="$2" -v id="$3" '
        !/^[[:space:]]*#/ {
            line=$0; sub(/^[[:space:]]*/,"",line); split(line,fields,/[[:space:]=]+/);
            if (tolower(fields[1]) == tolower(selector)) {
                match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH);
                print indent "# rhel8-stig " id " original: " line;
                print indent selector " no"; found=1; next;
            }
        }
        {print}
        END {if (!found) {print ""; print "# rhel8-stig " id; print selector " no"}}
    ' "$1"
}

expanded_ssh_validate() {
    local path=$1 directive=$2 current
    if [[ -n ${EDIT_CONTEXT-} ]]; then
        current=$(expanded_sshd_invocation) || return 1
        [[ $current == "$EDIT_CONTEXT" ]] || return 1
    fi
    [[ $(expanded_ssh_topology "$path") == plain && $(expanded_ssh_values "$path" "$directive") == no ]] &&
        timeout 12 sshd -t -f "$path" >/dev/null 2>&1 && [[ $(expanded_ssh_effective "$path" "$directive") == no ]]
}

expanded_permit_root_validate() { expanded_ssh_validate "$1" PermitRootLogin; }
expanded_gssapi_validate() { expanded_ssh_validate "$1" GSSAPIAuthentication; }
expanded_both_ssh_validate() {
    expanded_permit_root_validate "$1" && [[ $(expanded_ssh_values "$1" GSSAPIAuthentication) == no ]] &&
        [[ $(expanded_ssh_effective "$1" GSSAPIAuthentication) == no ]]
}

expanded_ssh_change_description() {
    local directive=$1 previous=$2 id=$3
    if [[ -z $previous ]]; then
        printf '+ # rhel8-stig %s\n+ %s no\n' "$id" "$directive"
    else
        printf -- '- %s %s\n+ # rhel8-stig %s original: %s %s\n+ %s no\n' \
            "$directive" "$previous" "$id" "$directive" "$previous" "$directive"
    fi
}

expanded_ssh_plan() {
    local id=$1 directive=$2 validator=$3 path=/etc/ssh/sshd_config
    local new="$EDIT_TEMP/$id.conf" previous description alt alt_description
    if ! edit_safe_path "$path" || [[ $(expanded_ssh_topology "$path") != plain ]]; then
        PLAN_REASON='SSH Include or Match has ambiguous precedence for this edit'; return 1
    fi
    if ! EDIT_CONTEXT=$(expanded_sshd_invocation); then
        PLAN_REASON='SSH staging requires the Red Hat sshd unit and reviewed invocation without overrides'; return 1
    fi
    previous=$(expanded_ssh_values "$path" "$directive") || return 1
    if [[ -n $previous && ! $previous =~ ^(yes|no|prohibit-password|without-password|forced-commands-only)$ ]]; then
        PLAN_REASON='conflicting or noncanonical active SSH options require review'; return 1
    fi
    if ! expanded_ssh_render "$path" "$directive" "$id" > "$new"; then
        PLAN_REASON='the primary SSH candidate could not be rendered'; return 1
    fi
    description=$(expanded_ssh_change_description "$directive" "$previous" "$id") || return 1
    # When both controls were selected, stage one reviewed file and one recovery
    # record. Skipping GSSAPI leaves that directive byte-for-byte unchanged.
    if [[ $id == V-230296 && ${EFFECTIVE[V-244528]+selected} ]]; then
        alt=$(expanded_ssh_values "$path" GSSAPIAuthentication) || return 1
        if [[ -z $alt || $alt == yes ]]; then
            expanded_ssh_render "$new" GSSAPIAuthentication V-244528 > "$new.combined" || return 1
            new=$new.combined validator=expanded_both_ssh_validate
            EDIT_RELATED=V-244528 EDIT_GROUPED=V-244528
            alt_description=$(expanded_ssh_change_description GSSAPIAuthentication "$alt" V-244528) || return 1
            description=$description$'\n'$alt_description
        fi
    fi
    if ! "$validator" "$new"; then
        PLAN_REASON='the candidate SSH configuration did not pass sshd -t and effective settings validation'; return 1
    fi
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Validate with sshd -t. Keep console and an administrative session available. Activate in the maintenance window using systemctl restart sshd.service, then verify a fresh authorized administrative login.'
    EDIT_REQUIREMENTS='Confirm this policy is locally managed, an independent non-root administrative login works, no approved exception or SSH reliance is affected, and console recovery is available.'
    edit_content "$path" keep "$description" "$validator" < "$new"
}

rule_V_230296_plan() { expanded_ssh_plan V-230296 PermitRootLogin expanded_permit_root_validate; }
rule_V_244528_plan() { expanded_ssh_plan V-244528 GSSAPIAuthentication expanded_gssapi_validate; }

expanded_gui_state() {
    local status pkg item
    local -a packages=(gnome-shell gdm plasma-workspace mate-session-manager xfce4-session
        cinnamon-session lxqt-session xorg-x11-server-Xorg)
    if ! have_tools rpm; then printf 'unknown\n'; return; fi
    status=$(timeout 6 rpm -q --qf '%{NAME}\n' "${packages[@]}" 2>/dev/null)
    case $? in 0|1) ;; *) printf 'unknown\n'; return ;; esac
    if grep -qxE 'gnome-shell|gdm' <<< "$status"; then printf 'gnome\n'; return; fi
    for pkg in "${packages[@]:2}"; do
        if grep -qxF "$pkg" <<< "$status"; then printf 'other\n'; return; fi
    done
    if (( $(grep -c '^package .* is not installed$' <<< "$status") != ${#packages[@]} )); then
        printf 'unknown\n'; return
    fi
    for item in /usr/share/xsessions/*.desktop /usr/share/wayland-sessions/*.desktop \
                /etc/systemd/system/display-manager.service /usr/lib/systemd/system/display-manager.service; do
        if [[ -e $item || -L $item ]]; then printf 'other\n'; return; fi
    done
    if have_tools systemctl && timeout 6 systemctl is-active --quiet display-manager.service; then
        printf 'other\n'; return
    fi
    printf 'absent\n'
}

expanded_gnome_applicable() {
    case $(expanded_gui_state) in
        gnome) return 0 ;;
        absent) rule_result NOT_APPLICABLE 'no installed graphical login or desktop session was found' ;;
        other) rule_result NEEDS_REVIEW 'a nonstandard graphical environment needs its own effective check' ;;
        *) rule_result NEEDS_REVIEW 'could not establish whether a graphical environment is installed' ;;
    esac
    return 1
}

# Read literal keyfile assignments and retain contradictory definitions for review.
expanded_dconf_extract() {
    local section=$1 key=$2
    shift 2
    awk -v section="$section" -v key="$key" '
        FNR == 1 {current=""}
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*\[/ {
            current=$0; sub(/^[[:space:]]*\[/,"",current); sub(/\][[:space:]]*$/,"",current); next;
        }
        current == section {
            code=$0; sub(/^[[:space:]]*/,"",code);
            if (sub("^" key "[[:space:]]*=[[:space:]]*","",code)) print code;
        }
    ' "$@"
}

expanded_dconf_values() {
    local section=$1 key=$2 dir file
    local -a files=()
    for dir in /etc/dconf/db/*.d; do
        [[ -e $dir || -L $dir ]] || continue
        [[ -d $dir && ! -L $dir && -r $dir && -x $dir ]] || return 1
        for file in "$dir"/*; do
            [[ -e $file || -L $file ]] || continue
            if [[ -d $file && ! -L $file && ${file##*/} == locks ]]; then continue; fi
            small_regular_file "$file" || return 1
            files+=("$file")
            (( ${#files[@]} <= 128 )) || return 1
        done
    done
    if (( ${#files[@]} )); then expanded_dconf_extract "$section" "$key" "${files[@]}"; fi
}

rule_V_230226_check() {
    local expected banner enabled
    expanded_gnome_applicable || return 0
    expected=$(awk '/^banner-message-text=/ {sub(/^banner-message-text=/,""); print; exit}' <<< "${OFFICIAL_FIX[V-230226]}")
    if [[ -z $expected ]]; then rule_result ERROR 'pinned banner constant is missing'; return; fi
    if ! banner=$(expanded_dconf_values org/gnome/login-screen banner-message-text) ||
       ! enabled=$(expanded_dconf_values org/gnome/login-screen banner-message-enable); then
        rule_result NEEDS_REVIEW 'GDM dconf source could not be fully read'; return
    fi
    if [[ -z $banner || $enabled == false ]]; then
        rule_result FAIL 'the standard GDM notice is missing or explicitly disabled'; return
    fi
    if [[ $banner == *$'\n'* || $enabled == *$'\n'* ]]; then
        rule_result NEEDS_REVIEW 'multiple GDM banner definitions require profile precedence review'; return
    fi
    if [[ $banner != "$expected" ]]; then
        rule_result FAIL 'the local GDM banner text differs from the exact pinned notice'; return
    fi
    if [[ ! $enabled ]]; then CHECK_PLAN_CANDIDATE=1; fi
    rule_result NEEDS_REVIEW 'pinned notice text is present; verify the compiled GDM profile displays the enabled notice before login'
}

rule_V_230226_admin() {
    printf '%s\n' \
        '1. Desktop administrator: identify the active GDM dconf profile and source database.' \
        '2. Use the exact pinned notice shown by --explain V-230226 and enable the banner for the GDM profile.' \
        '3. Review all pending dconf source edits before dconf update. Verify the actual pre-login screen at the console.'
}

rule_V_230351_check() {
    local values lock="'lock-screen'"
    expanded_gnome_applicable || return 0
    values=$(expanded_dconf_values org/gnome/settings-daemon/peripherals/smartcard removal-action) || {
        rule_result NEEDS_REVIEW 'smart-card dconf source could not be fully read'; return;
    }
    if [[ -z $values || $(sort -u <<< "$values") != "$lock" ]]; then
        if [[ $values == *$'\n'* ]]; then
            rule_result NEEDS_REVIEW 'conflicting removal actions require authselect and dconf precedence review'
        else
            rule_result FAIL 'local dconf lacks the required smart-card lock-screen removal action'
        fi
        return
    fi
    rule_result NEEDS_REVIEW 'local lock-screen removal action exists; verify effective profile and real card-removal lock behavior'
}

rule_V_230351_admin() {
    printf '%s\n' \
        '1. Identity and desktop administrators: record active authselect features and the GNOME dconf profile.' \
        '2. Review the supported smartcard-lock-on-removal feature or set the authoritative removal-action key.' \
        '3. Stage alongside any approved related authselect changes. Test actual card removal and fresh login with recovery access.'
}

rule_V_230352_check() {
    local effective source seconds
    expanded_gnome_applicable || return 0
    if ! have_tools gsettings || (( EUID == 0 )) || [[ -z ${DBUS_SESSION_BUS_ADDRESS-} ]]; then
        source=$(expanded_dconf_values org/gnome/desktop/session idle-delay) || source='unresolved'
        if [[ $source =~ ^uint32\ ([0-9]{1,10})$ ]]; then
            seconds=${BASH_REMATCH[1]}
            if (( 10#$seconds <= 4294967295 && (10#$seconds == 0 || 10#$seconds > 600) )); then
                CHECK_PLAN_CANDIDATE=1
                rule_result NEEDS_REVIEW 'the literal source idle delay is disabled or over 600 seconds. Active session behavior still needs verification.'
                return
            fi
        fi
        rule_result NEEDS_REVIEW 'the effective graphical user session is unavailable. Verify its gsettings idle-delay.'
        return
    fi
    effective=$(timeout 8 gsettings get org.gnome.desktop.session idle-delay 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'gsettings could not resolve the current session idle-delay'; return;
    }
    if [[ ! $effective =~ ^uint32\ ([0-9]{1,10})$ ]]; then
        rule_result ERROR 'gsettings returned an unrecognized idle-delay'; return
    fi
    if (( 10#${BASH_REMATCH[1]} == 0 || 10#${BASH_REMATCH[1]} > 600 )); then
        rule_result FAIL 'this active graphical session has idle delay disabled or greater than 600 seconds'
    else
        rule_result NEEDS_REVIEW 'tested session meets the 600-second limit; check all relevant user profiles and overrides'
    fi
}

rule_V_230352_admin() {
    printf '%s\n' \
        '1. Desktop administrator: identify all applicable GNOME user profiles and session overrides.' \
        '2. Review the authoritative dconf idle-delay policy. Set uint32 600 or a shorter nonzero delay.' \
        '3. Verify gsettings get org.gnome.desktop.session idle-delay and observe a fresh session lock.'
}

rule_V_244536_check() {
    local values
    expanded_gnome_applicable || return 0
    values=$(expanded_dconf_values org/gnome/login-screen disable-user-list) || {
        rule_result NEEDS_REVIEW 'GDM dconf source could not be fully read'; return;
    }
    if [[ $values == false ]]; then
        rule_result FAIL 'local GDM configuration explicitly keeps the graphical login user list enabled'; return
    fi
    rule_result NEEDS_REVIEW 'verify disable-user-list in the compiled GDM profile and at the graphical greeter'
}

rule_V_244536_admin() {
    printf '%s\n' \
        '1. Desktop administrator: confirm the dconf database used by the GDM greeter.' \
        '2. Set disable-user-list=true in the authoritative org/gnome/login-screen section.' \
        '3. Review pending dconf sources and apply the site maintenance procedure. Verify the actual greeter omits names.'
}

rule_V_251718_check() {
    local target
    if ! have_tools systemctl; then rule_result NEEDS_REVIEW 'systemctl is unavailable'; return; fi
    target=$(timeout 10 systemctl get-default 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'could not resolve the configured default boot target'; return;
    }
    if [[ $target == multi-user.target ]]; then
        rule_result PASS 'the configured default target is multi-user.target'
    elif [[ $target == graphical.target ]]; then
        rule_result NEEDS_REVIEW 'graphical.target is the default; confirm documented ISSO approval or change the default'
    else
        rule_result NEEDS_REVIEW 'nonstandard boot target requires unit and ISSO applicability review'
    fi
}

rule_V_251718_admin() {
    printf '%s\n' \
        '1. System administrator: confirm whether the ISSO approved the graphical default and whether console recovery works.' \
        '2. If the GUI default is unapproved, plan systemctl set-default multi-user.target without changing the running target.' \
        '3. Verify systemctl get-default. Schedule the reboot separately and verify administrative access.'
}

expanded_uid_min() {
    awk '
        /^[[:space:]]*#/ {next}
        $1 == "UID_MIN" {if (++n != 1 || $2 !~ /^[0-9]+$/ || length($2) > 6) bad=1; else value=$2}
        END {if (bad) exit 1; print n ? value : 1000}
    ' "$1"
}

expanded_password_age() {
    awk -F: -v minimum="$3" '
        FNR==NR {
            if (NF != 7 || $3 !~ /^[0-9]+$/) bad=1;
            else if ($3 >= minimum && $3 != 65534 && $7 !~ /(^|\/)(nologin|false|sync|halt|shutdown)$/) local[$1]=1;
            next;
        }
        NF == 9 && $1 in local {
            if (found[$1]++ || ($5 != "" && $5 !~ /^-?[0-9]+$/)) bad=1;
            if ($5+0 <= 0 || $5+0 > 180) failing++;
        }
        END {
            for (account in local) if (!(account in found)) missing++;
            if (bad || missing) print "ambiguous";
            else print failing+0;
        }
    ' "$1" "$2"
}

rule_V_230367_check() {
    local minimum verdict
    if [[ ! -r /etc/shadow || ! -r /etc/passwd || ! -r /etc/login.defs ]]; then
        rule_result NEEDS_REVIEW 'privileges to read local account policy and shadow aging are required'; return
    fi
    if ! minimum=$(expanded_uid_min /etc/login.defs) ||
       ! verdict=$(expanded_password_age /etc/passwd /etc/shadow "$minimum"); then
        rule_result ERROR 'could not read local account aging policy'; return
    fi
    if [[ $verdict == ambiguous ]]; then
        rule_result NEEDS_REVIEW 'some local accounts or shadow aging data could not be classified'; return
    fi
    if (( verdict > 0 )); then
        rule_result FAIL "$verdict local interactive account records have a missing, zero or greater-than-180 day maximum"
    else
        rule_result PASS 'selected local interactive account records satisfy the 180-day password maximum'
    fi
}

rule_V_230367_admin() {
    printf '%s\n' \
        '1. Identity administrator: review local shadow maximum-age records and identify exempt system accounts.' \
        '2. Review the last password change and expiry before applying chage -M 180 to each approved username.' \
        '3. Be prepared for an immediate password-expiry prompt for older passwords. Verify each account with chage -l.'
}

# Read only named startup files for simple local Bash home layouts. Mountinfo is
# checked before looking at paths so auto-mounted and network homes stay untouched.
expanded_home_path_safe() {
    local home=$1
    [[ $home =~ ^/home/[a-zA-Z0-9_.@-]+$ && $home != /home/. && $home != /home/.. ]] || return 1
    awk -v home="$home" '
        {for(i=7;i<=NF;i++) if($i=="-") {fs=$(i+1); break}}
        ($5=="/" || home==$5 || index(home,$5 "/")==1) && length($5) > length(point) {point=$5; seen=fs}
        END {exit !(point && seen ~ /^(xfs|ext[234]|btrfs)$/)}
    ' /proc/self/mountinfo && [[ -d /home && ! -L /home && -d $home && ! -L $home && -x $home ]]
}

expanded_literal_umask() {
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*umask([[:space:]]|$)/ {
            if ($2 !~ /^[0-7]{1,4}$/ || (NF > 2 && $3 !~ /^#/)) unknown++;
            else {
                bits=$2; sub(/^0+/,"",bits);
                if (length(bits) < 2 || substr(bits,length(bits)-1) != "77") bad++;
                else strict++;
            }
        }
        END {print bad+0,unknown+0,strict+0}
    ' "$@"
}

rule_V_230384_check() {
    local names minimum home shell file state bad unknown gaps=0 violations=0
    local -a files=()
    if [[ ! -r /etc/passwd || ! -r /etc/login.defs || ! -r /proc/self/mountinfo ]]; then
        rule_result NEEDS_REVIEW 'could not read local interactive account and mount evidence'; return
    fi
    if ! minimum=$(expanded_uid_min /etc/login.defs) || ! names=$(awk -F: -v low="$minimum" '
        NF != 7 || $3 !~ /^[0-9]+$/ {bad=1}
        ($3 >= low && $3 != 65534) && $7 !~ /(^|\/)(nologin|false|sync|halt|shutdown)$/ {
            if ($6 ~ /[[:space:]]/ || $7 ~ /[[:space:]]/) bad=1;
            else print $6 " " $7;
        }
        END {if (bad) exit 1}
    ' /etc/passwd); then
        rule_result NEEDS_REVIEW 'interactive accounts could not be classified'; return
    fi
    if [[ -z $names ]]; then rule_result NEEDS_REVIEW 'no local interactive home paths could be verified'; return; fi
    while read -r home shell; do
        if [[ $shell != /bin/bash && $shell != /usr/bin/bash ]] || ! expanded_home_path_safe "$home"; then
            (( gaps += 1 )); continue
        fi
        for file in "$home"/{.bash_profile,.bash_login,.profile,.bashrc}; do
            [[ -e $file || -L $file ]] || continue
            if ! small_regular_file "$file" || (( ${#files[@]} >= 256 )); then
                (( gaps += 1 )); continue
            fi
            files+=("$file")
        done
    done <<< "$names"
    if (( ${#files[@]} )); then
        state=$(expanded_literal_umask "${files[@]}") || { rule_result ERROR 'user startup inventory read failed'; return; }
        read -r bad unknown _ <<< "$state"
        violations=$(( bad + 0 ))
        gaps=$(( gaps + unknown ))
    fi
    if (( violations )); then
        rule_result FAIL "$violations literal user startup umask declarations grant group or other permissions"
    else
        rule_result NEEDS_REVIEW "bounded Bash home scan found no literal loosened mask; verify effective default and $gaps uncertain paths or directives"
    fi
}

rule_V_230384_admin() {
    printf '%s\n' \
        '1. Identity administrator: inventory local interactive shells, homes, and system or user startup sources.' \
        '2. Confirm the effective default mask is 077 for a fresh login. Review application exceptions with the ISSO.' \
        '3. Remove or correct reviewed user startup overrides through their authoritative source and test new sessions.'
}

expanded_faillock_dir() {
    awk '
        /^[[:space:]]*#/ {next}
        /^[[:space:]]*dir[[:space:]]*=/ {
            if (++n != 1) bad=1;
            sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*$/, ""); value=$0;
            if (value !~ /^\/([a-zA-Z0-9_.-]+\/)*[a-zA-Z0-9_.-]+$/ ||
                value ~ /(^|\/)\.\.?($|\/)/) bad=1;
        }
        END {if (bad) exit 1; print value}
    ' "$1"
}

rule_V_250315_check() {
    local status directory label expected='' pamdata
    if ! have_tools sestatus stat; then rule_result NEEDS_REVIEW 'SELinux policy tools are unavailable'; return; fi
    status=$(timeout 8 sestatus 2>/dev/null) || { rule_result NEEDS_REVIEW 'SELinux state unavailable'; return; }
    if grep -Eq '^SELinux status:[[:space:]]+disabled|^Current mode:[[:space:]]+permissive|^Loaded policy name:[[:space:]]+(minimum|mls)$' <<< "$status"; then
        rule_result NOT_APPLICABLE 'SELinux targeted policy is not enforcing'; return
    fi
    if ! grep -Eq '^Current mode:[[:space:]]+enforcing$' <<< "$status" ||
       ! grep -Eq '^Loaded policy name:[[:space:]]+targeted$' <<< "$status"; then
        rule_result NEEDS_REVIEW 'effective targeted SELinux enforcement is unresolved'; return
    fi
    if [[ ! -r /etc/pam.d/system-auth || ! -r /etc/pam.d/password-auth ]]; then
        rule_result NEEDS_REVIEW 'cannot read local PAM stacks for faillock applicability'; return
    fi
    pamdata=$(awk '!/^[[:space:]]*#/ && /(^|[[:space:]\/])pam_faillock\.so([[:space:]]|$)/ {print}' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth) || {
        rule_result NEEDS_REVIEW 'could not inspect canonical PAM stacks'; return;
    }
    if [[ -z $pamdata || $pamdata =~ [[:space:]]dir= ]]; then
        rule_result NEEDS_REVIEW 'faillock use or per-service tally directory requires PAM context review'; return
    fi
    if [[ ! -r /etc/security/faillock.conf ]] || ! directory=$(expanded_faillock_dir /etc/security/faillock.conf); then
        rule_result NEEDS_REVIEW 'cannot resolve the authoritative faillock directory'; return
    fi
    if [[ -z $directory || $directory == /run/faillock || $directory == /var/run/faillock ]]; then
        rule_result NEEDS_REVIEW 'no non-default tally directory is configured for the targeted-policy check'; return
    fi
    if [[ ! -d $directory || -L $directory ]]; then
        rule_result NEEDS_REVIEW 'configured faillock tally directory is missing or a symlink'; return
    fi
    label=$(stat -c '%C' -- "$directory" 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'the tally directory context could not be read'; return;
    }
    if have_tools matchpathcon; then
        expected=$(timeout 8 matchpathcon -n "$directory" 2>/dev/null) || expected=''
    fi
    if [[ $label != *:faillog_t:* ]]; then
        if [[ $expected == *:faillog_t:* ]]; then
            CHECK_PENDING=1
            rule_result NEEDS_REVIEW 'persistent faillog_t policy is already in place. Review the restorecon preview and complete activation.'
        else
            rule_result FAIL 'the configured non-default tally directory lacks the faillog_t type'
        fi
    elif [[ $expected == *:faillog_t:* ]]; then
        rule_result PASS 'the configured non-default tally directory and persistent policy use faillog_t'
    else
        if [[ -n $expected ]]; then CHECK_PLAN_CANDIDATE=1; fi
        rule_result NEEDS_REVIEW 'the current tally directory has faillog_t; verify the persistent file context rule'
    fi
}

rule_V_250315_admin() {
    printf '%s\n' \
        '1. SELinux administrator: confirm targeted enforcement, the effective faillock path and any PAM overrides.' \
        '2. Inventory non-default tally directory contents and coordinate persistent faillog_t labeling with the identity team.' \
        '3. Preview the expected context with matchpathcon and verify the observed label. Test lockout and recovery with a lab account.'
}

expanded_tmout_value() {
    local mode=$1
    shift
    awk -v mode="$mode" '
        /^[[:space:]]*#/ {next}
        /(^|[^[:alnum:]_])TMOUT([^[:alnum:]_]|$)/ {
            seen++;
            if ((mode == "system" && FILENAME !~ /profile\.d\/[^/]+\.sh$/) ||
                $0 !~ /^[[:space:]]*declare[[:space:]]+-(xr|rx)[[:space:]]+TMOUT=[0-9]{1,4}[[:space:]]*$/) {
                bad=1; next;
            }
            choice=$0; sub(/^.*TMOUT=/,"",choice); sub(/[[:space:]]*$/,"",choice);
        }
        END {
            if (bad || seen > 1) print "ambiguous";
            else if (!seen) print "absent";
            else if ((choice+0) == 0 || (choice+0) > 600) print "weak";
            else print "pass";
        }
    ' "$@"
}

expanded_tmout_inventory() {
    local file signature=${1-}
    local -a files=(/etc/profile /etc/bashrc)
    for file in /etc/profile.d/*.sh; do
        [[ -e $file || -L $file ]] || continue
        files+=("$file")
    done
    for file in "${files[@]}"; do small_regular_file "$file" || return 1; done
    if [[ $signature == digest ]]; then
        {
            for file in "${files[@]}"; do
                printf '%s\t' "$file"
                sha256_file "$file" || return 1
            done
        } | sha256sum
    else
        expanded_tmout_value system "${files[@]}"
    fi
}

rule_V_279929_check() {
    local value
    value=$(expanded_tmout_inventory) || { rule_result NEEDS_REVIEW 'system Bash startup sources are incomplete or unreadable'; return; }
    case $value in
        pass) rule_result PASS 'the reviewed system Bash startup sources set a readonly idle timeout within 600 seconds' ;;
        absent|weak) rule_result FAIL 'the reviewed Bash startup sources lack a nonzero readonly TMOUT at or below 600 seconds' ;;
        *) rule_result NEEDS_REVIEW 'conflicting or nonliteral TMOUT references need precedence and fresh interactive-shell review' ;;
    esac
}

rule_V_279929_admin() {
    printf '%s\n' \
        '1. System administrator: check the system Bash startup order and any existing TMOUT definitions.' \
        '2. Use a single readonly exported TMOUT of 600 or a shorter nonzero value in the authoritative startup path.' \
        '3. Start a fresh interactive shell and verify declare -p TMOUT and automatic exit after the configured idle period.'
}

expanded_tmout_validate() {
    bash -n "$1" && [[ $(expanded_tmout_value candidate "$1") == pass ]]
}

rule_V_279929_plan() {
    local path=/etc/profile.d/99-rhel8-stig-tmout.sh disposition file new="$EDIT_TEMP/V-279929.bash"
    if ! grep -Eq '^[[:space:]]*for[[:space:]].* /etc/profile\.d/\*\.sh' /etc/profile; then
        PLAN_REASON='the system /etc/profile does not demonstrate the expected profile.d sourcing path'; return 1
    fi
    EDIT_CONTEXT=$(expanded_tmout_inventory digest) || return 1
    EDIT_REQUIREMENTS='Confirm the Bash timeout is locally managed and that the approved idle limit can affect administrator and automation sessions.'
    disposition=$(expanded_tmout_inventory) || return 1
    if [[ $disposition == absent && ! -e $path && ! -L $path ]]; then
        edit_content "$path" 0644 'Create /etc/profile.d/99-rhel8-stig-tmout.sh with declare -xr TMOUT=600. Effective for new Bash sessions that load system startup files.' \
            expanded_tmout_validate < <(printf '# rhel8-stig V-279929\ndeclare -xr TMOUT=600\n')
        return
    fi
    if [[ $disposition == weak ]]; then
        for file in /etc/profile.d/*.sh; do
            [[ $(expanded_tmout_value system "$file") == weak ]] || continue
            awk '
                /^[[:space:]]*declare[[:space:]]+-(xr|rx)[[:space:]]+TMOUT=[0-9]{1,4}[[:space:]]*$/ {
                    match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH);
                    print indent "# rhel8-stig V-279929 original: " substr($0,RLENGTH+1);
                    print indent "declare -xr TMOUT=600"; next;
                }
                {print}
            ' "$file" > "$new" || return 1
            edit_content "$file" keep 'Comment the single existing literal readonly TMOUT in place and set declare -xr TMOUT=600 directly underneath. Applies to new sessions.' \
                expanded_tmout_validate < "$new"
            return
        done
    fi
    PLAN_REASON='existing or ambiguous TMOUT needs authoritative startup-file review'; return 1
}

expanded_openssl_layout() {
    awk '
        /^[[:space:]]*($|#)/ {next}
        /^[[:space:]]*\[/ {
            section=$0; sub(/^[[:space:]]*\[[[:space:]]*/,"",section);
            sub(/[[:space:]]*\][[:space:]]*(#.*)?$/,"",section);
            sections[section]++; next;
        }
        {
            line=$0; sub(/^[[:space:]]*/,"",line); sub(/[[:space:]]*(#.*)?$/,"",line);
            if (line ~ /^\.include([[:space:]]|=)/) {
                if (line ~ /^\.include[[:space:]]*(=[[:space:]]*)?\/etc\/crypto-policies\/back-ends\/opensslcnf\.config$/) {
                    pinned++; if (section=="crypto_policy") selected++;
                } else other++;
            } else if (section=="crypto_policy") directives++;
            if (section=="" && line ~ /^openssl_conf[[:space:]]*=[[:space:]]*default_modules$/) entry++;
            if (section=="default_modules" && line ~ /^ssl_conf[[:space:]]*=[[:space:]]*ssl_module$/) ssl++;
            if (section=="ssl_module" && line ~ /^system_default[[:space:]]*=[[:space:]]*crypto_policy$/) policy++;
            if (section=="default_modules" && line !~ /^ssl_conf[[:space:]]*=[[:space:]]*ssl_module$/) custom++;
            if (section=="ssl_module" && line !~ /^system_default[[:space:]]*=[[:space:]]*crypto_policy$/) custom++;
            if (section=="" && line ~ /^openssl_conf([[:space:]]|=)/ && line !~ /^openssl_conf[[:space:]]*=[[:space:]]*default_modules$/) custom++;
        }
        END {
            if (!pinned && !other && !directives && !custom && entry==1 && ssl==1 && policy==1 &&
                sections["crypto_policy"]==1 && sections["ssl_module"]==1 && sections["default_modules"]==1) print "canonical-missing";
            else if (pinned==1 && selected==1 && !other && !directives && !custom && entry==1 && ssl==1 && policy==1 &&
                sections["crypto_policy"]==1 && sections["ssl_module"]==1 && sections["default_modules"]==1) print "canonical-pass";
            else if (!pinned) print "missing";
            else print "noncanonical";
        }
    ' "$1"
}

expanded_openssl_backend() {
    local path=/etc/crypto-policies/back-ends/opensslcnf.config resolved
    resolved=$(realpath -e -- "$path") || return 1
    case $resolved in /etc/crypto-policies/*|/usr/share/crypto-policies/*) ;; *) return 1 ;; esac
    small_regular_file "$resolved" || return 1
    # Do not let a custom backend load other configs or modules during staged validation.
    awk '
        /^[[:space:]]*($|#)/ {next}
        /^[[:space:]]*(CipherString|Ciphersuites|SignatureAlgorithms|Groups|Options|(TLS\.|DTLS\.)?(MinProtocol|MaxProtocol))[[:space:]]*=[[:space:]]*[-A-Za-z0-9_:.+!@=, ]+$/ {n++; next}
        {bad=1}
        END {exit !(n && !bad)}
    ' "$resolved" || return 1
    sha256_file "$resolved"
}

rule_V_288829_check() {
    local path=/etc/pki/tls/openssl.cnf layout
    [[ -r $path ]] || { rule_result NEEDS_REVIEW 'OpenSSL system configuration is unreadable'; return; }
    layout=$(expanded_openssl_layout "$path") || { rule_result ERROR 'could not parse OpenSSL system configuration'; return; }
    case $layout in
        canonical-missing|missing) rule_result FAIL 'the required OpenSSL system crypto-policy backend is not included' ;;
        canonical-pass)
            if expanded_openssl_backend >/dev/null 2>&1; then
                rule_result PASS 'the system-default OpenSSL section includes the readable crypto-policy backend'
            else
                rule_result NEEDS_REVIEW 'OpenSSL declares the system backend; backend contents or resolution require review'
            fi ;;
        *) rule_result NEEDS_REVIEW 'the backend reference exists in an ambiguous OpenSSL initialization layout' ;;
    esac
}

rule_V_288829_admin() {
    printf '%s\n' \
        '1. Crypto administrator: trace the OpenSSL system-default SSL section and its generated backend.' \
        '2. Review dependent TLS consumers before adding the backend reference to the active policy section.' \
        '3. Validate with a new process that uses the system profile. Coordinate approved consumer restart or reconnect tests as applicable.'
}

expanded_openssl_validate() {
    local backend
    backend=$(expanded_openssl_backend) || return 1
    if [[ -n ${EDIT_CONTEXT-} && $backend != "$EDIT_CONTEXT" ]]; then return 1; fi
    [[ $(expanded_openssl_layout "$1") == canonical-pass ]] &&
        timeout 12 env -u OPENSSL_ENGINES -u OPENSSL_CONF_INCLUDE OPENSSL_CONF="$1" openssl ciphers -s DEFAULT >/dev/null 2>&1
}

rule_V_288829_plan() {
    local path=/etc/pki/tls/openssl.cnf new="$EDIT_TEMP/V-288829.cnf"
    if ! have_tools openssl env || ! edit_safe_path "$path" ||
        [[ $(expanded_openssl_layout "$path") != canonical-missing ]]; then
        PLAN_REASON='the installed OpenSSL initialization and policy section differ from the eligible canonical empty section'; return 1
    fi
    if ! EDIT_CONTEXT=$(expanded_openssl_backend); then
        PLAN_REASON='the generated system crypto backend is missing, untrusted, or outside the supported layout'; return 1
    fi
    if ! awk '
        {print}
        /^[[:space:]]*\[[[:space:]]*crypto_policy[[:space:]]*\][[:space:]]*(#.*)?$/ {
            print ".include = /etc/crypto-policies/back-ends/opensslcnf.config";
        }
    ' "$path" > "$new" || ! expanded_openssl_validate "$new"; then
        PLAN_REASON='the staged OpenSSL system configuration did not validate'; return 1
    fi
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Test fresh application processes and representative TLS connections. Coordinate consumer reload or restart with application owners where needed.'
    EDIT_REQUIREMENTS='Confirm local file ownership, dependent TLS compatibility and a tested recovery route with the crypto and application administrators.'
    edit_content "$path" keep 'Insert .include = /etc/crypto-policies/back-ends/opensslcnf.config directly under the existing empty [crypto_policy] section.' \
        expanded_openssl_validate < "$new"
}

expanded_auth_select_raw() {
    local raw
    have_tools authselect || return 1
    timeout 10 authselect check >/dev/null 2>&1 || return 1
    raw=$(timeout 10 authselect current -r 2>/dev/null) || return 1
    [[ $raw =~ ^custom/[A-Za-z0-9_][A-Za-z0-9_.-]*([\ ][A-Za-z0-9_][A-Za-z0-9_-]*)*$ ]] || return 1
    printf '%s\n' "$raw"
}

expanded_auth_select_render() {
    local raw=$1 stack=$2
    local -a words
    read -r -a words <<< "$raw"
    [[ $stack == system-auth || $stack == password-auth ]] || return 1
    timeout 10 authselect test "${words[0]}" "--$stack" "${words[@]:1}" 2>/dev/null
}

expanded_pam_active_lines() {
    awk '/^[[:space:]]*-?(auth|account|password|session)[[:space:]]+/ {
        line=$0; sub(/^[[:space:]]*/,"",line); sub(/[[:space:]]*$/,"",line); print line
    }'
}

expanded_pam_template_render() {
    local path=$1 mode=$2 id=$3
    awk -v mode="$mode" -v id="$id" '
        mode == "nullok" && tolower($0) ~ /nullok/ {
            # A comment retaining this exact token would also fail the DISA check.
            if ($0 !~ /^[[:space:]]*(auth|password)[[:space:]]+(required|requisite|sufficient|optional)[[:space:]]+pam_unix\.so[[:space:]]+/) {bad=1; next}
            if (!match($0,/[[:blank:]]+\{if not "without-nullok":nullok\}([[:blank:]]|$)/) &&
                !match($0,/[[:blank:]]+nullok([[:blank:]]|$)/)) {bad=1; next}
            start=RSTART; end=RSTART+RLENGTH-1;
            if (substr($0,end,1) ~ /[[:blank:]]/) end--;
            revised=substr($0,1,start-1) substr($0,end+1);
            if (tolower(revised) ~ /nullok/) {bad=1; next}
            print "# rhel8-stig " id " removed the empty-password option from the following line";
            print revised; changed++; next;
        }
        mode == "pwquality" && $0 !~ /^[[:space:]]*#/ && /pam_pwquality\.so/ {
            if (!match($0,/^[[:space:]]*password[[:space:]]+requisite[[:space:]]+pam_pwquality\.so([[:space:]]|$)/) || $0 ~ /[{}]/) {bad=1; next}
            revised=$0; match(revised,/^[[:space:]]*password[[:space:]]+/);
            prefix=substr(revised,1,RLENGTH); rest=substr(revised,RLENGTH+1);
            sub(/^requisite/,"required",rest);
            print "# rhel8-stig " id " original: " $0;
            print prefix rest; changed++; next;
        }
        {print}
        END {if (bad || (mode == "nullok" && !changed) || (mode == "pwquality" && changed != 1)) exit 1}
    ' "$path"
}

expanded_pam_validate_stream() {
    local mode=$1
    awk -v mode="$mode" '
        tolower($0) ~ /nullok/ {null=1}
        /^[[:space:]]*-?(auth|password)[[:space:]]+/ {stack++}
        /^[[:space:]]*password[[:space:]]+required[[:space:]]+pam_pwquality\.so([[:space:]]|$)/ {quality++}
        END {exit (mode == "nullok" ? (!stack || null) : quality != 1)}
    '
}

expanded_pam_template_validate() {
    local path=$1 stack=$2 mode=$3 active rendered
    expanded_pam_validate_stream "$mode" < "$path" || return 1
    # Authselect can render the installed template without touching its generated PAM files.
    if [[ ${path##*/} == "$stack" && $path == /etc/authselect/custom/* ]]; then
        active=$(expanded_auth_select_raw) || return 1
        rendered=$(expanded_auth_select_render "$active" "$stack") || return 1
        expanded_pam_validate_stream "$mode" <<< "$rendered"
    fi
}

expanded_pam_password_null_validate() { expanded_pam_template_validate "$1" password-auth nullok; }
expanded_pam_system_null_validate() { expanded_pam_template_validate "$1" system-auth nullok; }
expanded_pam_pwquality_validate() { expanded_pam_template_validate "$1" system-auth pwquality; }

expanded_pam_without_nullok_proof() {
    local raw=$1 stack=$2 active=$3 candidate expected
    candidate=$(expanded_auth_select_render "$raw without-nullok" "$stack") &&
        expanded_pam_validate_stream nullok <<< "$candidate" || return 1
    candidate=$(expanded_pam_active_lines <<< "$candidate" | awk '{$1=$1; print}') || return 1
    expected=$(awk '{
        separator=""
        for (i=1; i<=NF; i++) if ($i != "nullok") {
            printf "%s%s", separator, $i
            separator=" "
        }
        print ""
    }' <<< "$active") || return 1
    [[ $expected && $candidate == "$expected" ]]
}

attended_optional_peer_ready() {
    local id=$1 peer=$2
    local PLAN_REASON ASSESSMENT EVIDENCE CHECK_PENDING CHECK_PLAN_CANDIDATE
    if (( REVIEW_EACH )) ||
       [[ ${SKIPPED[$peer]+excluded} || ${PREVIEW_KEY[$peer]+planned} ||
          ( ${PLANNED_BY[$peer]+grouped} && ${PLANNED_BY[$peer]} != "$id" ) ]] ||
       ! allow_rule_plan "$id" "$peer"; then
        return 1
    fi
    rule_dispatch "$peer" && check_supports_plan "$peer"
}

expanded_pam_template_edit() {
    local id=$1 stack=$2 mode=$3 validator=$4 raw=$5 profile path rendered active fingerprint
    local new="$EDIT_TEMP/$id.pam" description option_count
    profile=${raw%% *}
    path=/etc/authselect/$profile/$stack
    if [[ ${EDIT_TOUCHED[$path]+changed} ]]; then
        edit_fail "an earlier rule changed $path. Reassess it in a separate run for independent recovery"; return
    fi
    if ! small_regular_file "$path" || ! [[ -r /etc/pam.d/$stack ]]; then
        PLAN_REASON='active authselect source is linked, unreadable or outside the supported custom profile'; return 1
    fi
    rendered=$(expanded_auth_select_render "$raw" "$stack") || return 1
    active=$(expanded_pam_active_lines < "/etc/pam.d/$stack") || return 1
    if [[ -z $active || $(expanded_pam_active_lines <<< "$rendered") != "$active" ]]; then
        PLAN_REASON='the custom profile already has unactivated PAM source changes; review them separately'; return 1
    fi
    if ! expanded_pam_template_render "$path" "$mode" "$id" > "$new" || ! "$validator" "$new"; then
        PLAN_REASON='the required PAM directive is conditional, ambiguous or outside the supported direct template form'; return 1
    fi
    if [[ $mode == nullok ]] && grep -Fq '{if not "without-nullok":nullok}' "$path" &&
        ! expanded_pam_without_nullok_proof "$raw" "$stack" "$active"; then
        PLAN_REASON='authselect did not prove that the vendor without-nullok feature changes only the expected options'; return 1
    fi
    fingerprint=$(printf '%s\n%s' "$raw" "$active" | sha256sum) || return 1
    if [[ $mode == nullok ]]; then
        option_count=$(grep -c '^# rhel8-stig .*removed the empty-password option' "$new") || return 1
        description="Remove the nullok option from $option_count canonical pam_unix lines in the $stack custom template. The generated PAM stack requires activation."
    else
        description='Comment the original pam_pwquality requisite line and place the required control directly beneath it in the system-auth custom template. The generated PAM stack requires activation.'
    fi
    edit_content "$path" keep "$description" "$validator" < "$new" || return 1
    EDIT_CONTEXT+="${EDIT_CONTEXT:+$'\n'}$fingerprint"
}

expanded_pam_template_include() {
    local id=$1 raw=$2 peer stack validator
    local PLAN_REASON
    case $id in
        V-244541) peer=V-268322 stack=system-auth validator=expanded_pam_system_null_validate ;;
        V-268322) peer=V-244541 stack=password-auth validator=expanded_pam_password_null_validate ;;
        *) return 1 ;;
    esac
    attended_optional_peer_ready "$id" "$peer" &&
        expanded_pam_template_edit "$peer" "$stack" nullok "$validator" "$raw" || return 1
    EDIT_RELATED=$peer EDIT_GROUPED=$peer
}

expanded_pam_template_plan() {
    local id=$1 stack=$2 mode=$3 validator=$4 raw
    if ! raw=$(expanded_auth_select_raw); then
        PLAN_REASON='a valid locally copied active authselect custom profile is required for source-only staging'; return 1
    fi
    expanded_pam_template_edit "$id" "$stack" "$mode" "$validator" "$raw" || return 1
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Compare authselect test output for the active profile and features to its generated files. Keep console recovery and an administrative login. After review, use authselect apply-changes -b, then test a fresh relevant login and authselect check.'
    EDIT_REQUIREMENTS='Confirm the profile is locally managed and a tested independent administrative access route is available. Authselect activation may regenerate PAM, NSS and dconf artifacts, so review all queued differences before activation.'
    if [[ $mode == nullok ]]; then expanded_pam_template_include "$id" "$raw" || true; fi
}

rule_V_244541_plan() { expanded_pam_template_plan V-244541 password-auth nullok expanded_pam_password_null_validate; }
rule_V_268322_plan() { expanded_pam_template_plan V-268322 system-auth nullok expanded_pam_system_null_validate; }
rule_V_251713_plan() { expanded_pam_template_plan V-251713 system-auth pwquality expanded_pam_pwquality_validate; }


# Audit file and directory checks. Use auditd's explicit configured path. Never
# read audit record contents to check their permissions or ownership.

audit_setting() {
    local key=$1
    awk -v key="$key" '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/^[[:space:]]*/, "", line)
            if (tolower(line) !~ ("^" key "([[:space:]]|=|$)")) next
            found++
            if (tolower(line) !~ ("^" key "[[:blank:]]+=[[:blank:]]+")) {bad=1; next}
            sub(/^[^=]*=[[:blank:]]+/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (line !~ /^[a-zA-Z0-9_./+@-]+$/) bad=1
            value=line
        }
        END {
            if (bad || found>1) exit 2
            if (!found) exit 1
            print value
        }'
}

audit_read_setting() {
    local key=$1 config=/etc/audit/auditd.conf
    if [[ ! -d /etc/audit || -L /etc/audit ]] || ! text_input_file "$config"; then
        return 2
    fi
    audit_setting "$key" < "$config"
}

audit_log_object() {
    local kind=$1 path canonical
    path=$(audit_read_setting log_file) || return 1
    [[ $path == /*/* && $path != */ && $path != *//* ]] || return 1
    if [[ $kind == directory ]]; then path=${path%/*}; fi
    canonical=$(realpath -e -- "$path" 2>/dev/null) || return 1
    [[ $path == "$canonical" && ! -L $path ]] || return 1
    case $kind in
        file) [[ -f $path ]] || return 1 ;;
        directory) [[ -d $path && $path != / ]] || return 1 ;;
        *) return 1 ;;
    esac
    printf '%s\n' "$path"
}

audit_check_permissions() {
    local kind=$1 field=$2 max_mode=$3 path mode gid removed
    if ! have_tools stat realpath awk; then
        rule_result UNKNOWN 'Audit path evidence requires awk, realpath and stat.'; return
    fi
    if ! path=$(audit_log_object "$kind"); then
        rule_result NEEDS_REVIEW 'The audit log_file setting or its associated object is missing, linked, ambiguous or inaccessible.'; return
    fi
    if ! read -r mode gid < <(stat -c '%a %g' -- "$path" 2>/dev/null) ||
       [[ ! $mode =~ ^[0-7]{1,4}$ || ! $gid =~ ^[0-9]+$ ]]; then
        rule_result ERROR 'The owner and mode of the configured audit object could not be read.'; return
    fi
    if [[ $field == group ]]; then
        if [[ $gid == 0 ]]; then rule_result PASS "The configured audit $kind belongs to the root group."
        else rule_result FAIL "The configured audit $kind has group ID $gid. The requirement is group ID 0 (root)."; fi
    else
        removed=$(( 8#$mode & ~8#$max_mode ))
        if (( removed )); then rule_result FAIL "The configured audit $kind has mode $mode. The permitted maximum is $max_mode."
        else rule_result PASS "The configured audit $kind has mode $mode. It is within the permitted mask $max_mode."; fi
    fi
}

rule_V_230396_check() { audit_check_permissions file mode 0600; }
rule_V_230400_check() { audit_check_permissions directory group 0700; }
rule_V_230401_check() { audit_check_permissions directory mode 0700; }

rule_V_230398_check() {
    local group read_rc
    audit_check_permissions file group 0600
    [[ $ASSESSMENT == PASS || $ASSESSMENT == FAIL ]] || return 0
    group=$(audit_read_setting log_group)
    read_rc=$?
    case $read_rc in
        0)
            if [[ $group != root && ! $group =~ ^0+$ ]]; then
                rule_result FAIL "$EVIDENCE The persistent log_group setting also needs to be root."
            fi ;;
        1) ;; # The auditd default log group is root.
        *)
            if [[ $ASSESSMENT == PASS ]]; then
                rule_result NEEDS_REVIEW 'The current log group is root, but the persistent log_group setting is ambiguous.'
            fi ;;
    esac
}

rule_V_230396_admin() {
    cat <<'EOF'
1. Resolve the active log_file entry in /etc/audit/auditd.conf and confirm the daemon
   uses that file. Review any group-based audit readers and managed-file ownership.
2. Restrict the active log's mode to 0600 or stricter, retaining more restrictive owner
   permissions. Check the file by stat and verify the mode after audit log rotation.
EOF
}

rule_V_230398_admin() {
    cat <<'EOF'
1. Check the numeric group on the configured audit log and the log_group value in
   /etc/audit/auditd.conf. Review audit readers that depend on the current group.
2. Use log_group = root in the authoritative auditd configuration. Set the group on
   the current log to root if needed. Coordinate any auditd reload with its owner.
3. Verify the configured file and the replacement log after rotation with stat.
EOF
}

rule_V_230400_admin() {
    cat <<'EOF'
1. Resolve the parent directory from the effective auditd log_file setting. Review
   group access, mount boundaries, and audit consumers before changing ownership.
2. Set the verified directory's group to root. Recheck it with stat and verify the
   daemon continues recording events to its configured log.
EOF
}

rule_V_230401_admin() {
    cat <<'EOF'
1. Resolve the parent directory from the effective auditd log_file setting. Review
   group and other access needed by audit collectors or backup software.
2. Restrict that directory to 0700 or stricter while preserving necessary owner access.
   Verify its mode with stat and verify auditd still records events.
EOF
}

audit_writer_context() {
    local path=$1 pid exe arg fd fd_target flags access_mode uid config_hash
    local -a runtime_args=()
    pid=$(timeout 8 systemctl show auditd.service -p MainPID --value 2>/dev/null) || return 1
    [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
    uid=$(stat -c '%u' -- "/proc/$pid" 2>/dev/null) || return 1
    exe=$(readlink -- "/proc/$pid/exe" 2>/dev/null) || return 1
    [[ $uid == 0 && ( $exe == /usr/sbin/auditd || $exe == /sbin/auditd ) ]] || return 1
    mapfile -d '' -t runtime_args < "/proc/$pid/cmdline" || return 1
    (( ${#runtime_args[@]} )) || return 1
    for arg in "${runtime_args[@]:1}"; do
        [[ $arg != -c* && $arg != --config* ]] || return 1
    done
    for fd in "/proc/$pid/fd/"*; do
        fd_target=$(readlink -- "$fd" 2>/dev/null) || continue
        if [[ $fd_target == "$path" ]]; then
            flags=$(awk '$1 == "flags:" {print $2}' "/proc/$pid/fdinfo/${fd##*/}" 2>/dev/null) || continue
            [[ $flags =~ ^[0-7]+$ ]] || continue
            access_mode=$(( 8#$flags & 3 ))
            (( access_mode == 1 || access_mode == 2 )) || continue
            config_hash=$(sha256_file /etc/audit/auditd.conf) || return 1
            printf 'auditd-pid=%s %s\n' "$pid" "$config_hash"
            return 0
        fi
    done
    return 1
}

audit_log_plan_context() {
    local path
    path=$(audit_log_object file) || { PLAN_REASON='Cannot identify the configured audit log file.'; return 1; }
    EDIT_CONTEXT=$(audit_writer_context "$path") || {
        PLAN_REASON='Cannot confirm that the running auditd uses the standard configuration and has the configured log open.'
        return 1
    }
    EDIT_REQUIREMENTS='Confirm audit collectors and authorized readers can tolerate the access change.'
}

audit_narrow_mode() {
    local path=$1 max=$2 mode next
    mode=$(stat -c '%a' -- "$path" 2>/dev/null) || { PLAN_REASON='Cannot read the current audit mode.'; return 1; }
    [[ $mode =~ ^[0-7]{1,4}$ ]] || { PLAN_REASON='Unexpected numeric audit mode.'; return 1; }
    printf -v next '%04o' "$(( 8#$mode & 8#$max ))"
    if (( 8#$mode != 8#$next )); then
        edit_metadata "$path" "$next" keep "Mode $mode -> $next. Existing owner permissions are preserved." || return
    fi
}

rule_V_230396_plan() {
    local path
    audit_log_plan_context || return
    path=$(audit_log_object file) || return 1
    audit_narrow_mode "$path" 0600
}

rule_V_230400_plan() {
    local path gid
    audit_log_plan_context || return
    path=$(audit_log_object directory) || return 1
    gid=$(stat -c '%g' -- "$path" 2>/dev/null) || return 1
    [[ $gid =~ ^[0-9]+$ && $gid != 0 ]] || return 1
    edit_metadata "$path" keep 0 "Group ID $gid -> 0 (root) on the audit log directory."
}

rule_V_230401_plan() {
    local path
    audit_log_plan_context || return
    path=$(audit_log_object directory) || return 1
    audit_narrow_mode "$path" 0700
}

audit_log_group_rewrite() {
    local source=$1
    awk '
        /^[[:space:]]*#/ {print; next}
        {lower=tolower($0)}
        lower ~ /^[[:space:]]*log_group[[:space:]]*=/ {
            match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH)
            print indent "# Previous V-230398 setting: " substr($0,RLENGTH+1)
            print indent "log_group = root"
            next
        }
        {print}
    ' "$source"
}

audit_log_group_validate() {
    local candidate=$1 original=$2 old_path new_path group
    old_path=$(audit_setting log_file < "$original") || return 1
    new_path=$(audit_setting log_file < "$candidate") || return 1
    group=$(audit_setting log_group < "$candidate") || return 1
    [[ $old_path == "$new_path" && $group == root ]]
}

rule_V_230398_plan() {
    local path gid configured cfg_rc
    audit_log_plan_context || return
    path=$(audit_log_object file) || return 1
    gid=$(stat -c '%g' -- "$path" 2>/dev/null) || return 1
    [[ $gid =~ ^[0-9]+$ ]] || return 1
    configured=$(audit_read_setting log_group)
    cfg_rc=$?
    if (( cfg_rc > 1 )); then
        PLAN_REASON='Resolve the duplicate, malformed, or inaccessible auditd log_group setting.'
        return 1
    fi
    if [[ $gid != 0 ]]; then
        edit_metadata "$path" keep 0 "Group ID $gid -> 0 (root) on the current audit log file." || return
    fi
    if (( cfg_rc == 0 )) && [[ $configured != root && ! $configured =~ ^0+$ ]]; then
        edit_content /etc/audit/auditd.conf keep \
            "log_group = $configured -> log_group = root. Comment the original line immediately above the replacement." \
            audit_log_group_validate < <(audit_log_group_rewrite /etc/audit/auditd.conf) || return
        EDIT_DISPOSITION=pending
        EDIT_ACTIVATION='Coordinate a supported service auditd reload with the audit owner. Review all pending auditd.conf edits before activation. Verify the active and rotated log group and reassess V-230396, V-230400, and V-230401.'
    fi
}

audit_config_mode_inventory() {
    local target=/etc/audit/rules.d entry dev kind name output top_dev
    [[ -d /etc/audit && ! -L /etc/audit && -d $target && ! -L $target ]] || return 1
    top_dev=$(stat -c '%d' -- "$target" 2>/dev/null) || return 1
    output=$(timeout 15 find -P "$target" -xdev \
        \( -type d -o -type l -o \( -type f -name '*.rules' \) \) \
        -printf '%D %y %p\n' 2>/dev/null) || return 1
    printf '/etc/audit/audit.rules\n/etc/audit/auditd.conf\n'
    while IFS= read -r entry; do
        dev=${entry%% *}
        entry=${entry#* }
        kind=${entry%% *}
        name=${entry#* }
        [[ $dev == "$top_dev" && $kind != l && $name == "$target"* ]] || return 1
        [[ $name =~ ^[-/a-zA-Z0-9_.]+$ ]] || return 1
        if [[ $kind == f ]]; then printf '%s\n' "$name"; fi
    done <<< "$output"
}

rule_V_230471_plan() {
    local paths path
    paths=$(audit_config_mode_inventory) || {
        PLAN_REASON='Audit configuration includes a mount, link or ambiguous rules path. Resolve the inventory first.'
        return 1
    }
    EDIT_CONTEXT=$(printf '%s\n' "$paths" | LC_ALL=C sort | sha256sum) || return 1
    EDIT_REQUIREMENTS='Confirm audit readers and configuration management can use the resulting owner-only audit configuration.'
    while IFS= read -r path; do
        [[ ! -L $path && -f $path ]] || { PLAN_REASON='An audit configuration file is missing or linked.'; return 1; }
        audit_narrow_mode "$path" 0600 || return
    done <<< "$paths"
}

audit_rule_source_inventory() {
    local source dir=/etc/audit/rules.d metadata owner mode size total=0
    [[ -d /etc/audit && ! -L /etc/audit && -d $dir && ! -L $dir && -r $dir && -x $dir ]] || return 1
    for source in "$dir"/*.rules; do
        [[ -e $source || -L $source ]] || continue
        [[ -f $source && ! -L $source && -r $source && $source =~ ^[-/a-zA-Z0-9_.]+$ ]] || return 1
        metadata=$(stat -c '%u %a %s' -- "$source" 2>/dev/null) || return 1
        read -r owner mode size <<< "$metadata"
        [[ $owner == 0 && $mode =~ ^[0-7]{1,4}$ && $size =~ ^[0-9]{1,6}$ ]] &&
            (( (8#$mode & 022) == 0 )) || return 1
        total=$((total + size))
        ((total <= 524288)) || return 1
        printf '%s\n' "$source"
    done
}

audit_rule_source_contents() {
    local source
    while IFS= read -r source; do
        [[ -n $source ]] || continue
        cat -- "$source" || return 1
        printf '\n'
    done
}

audit_rule_dropin_payload() {
    local profile=$1 existing=$2 detail via_check
    if [[ $profile == useradd ]]; then
        via_check=$(audit_has_rule useradd <<< "$existing") || return 1
        case $via_check in
            present) return 2 ;;
            disabled|suppression-review) return 1 ;;
        esac
        detail=$(awk '
            /^[[:space:]]*#/ {next}
            {line=$0; sub(/[[:space:]]+#.*/,"",line)}
            line ~ /(^|[[:space:]])(path=|exe=)?\/usr\/sbin\/useradd([[:space:]]|$)/ ||
                line ~ /(^|[[:space:]])(key=)?privileged-useradd([[:space:]]|$)/ {found=1}
            END {print found ? "overlap" : "clear"}
        ' <<< "$existing") || return 1
        [[ $detail == clear ]] || return 1
        printf '%s\n' '-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd'
        return 0
    fi

    local path result
    local -a additions=()
    for path in /etc/cron.d /var/spool/cron; do
        result=$(awk -v path="$path" '
            /^[[:space:]]*#/ {next}
            {line=$0; sub(/[[:space:]]+#.*/, "", line); sub(/^[[:space:]]+/,"",line); sub(/[[:space:]]+$/,"",line)}
            {
                n=split(line, a, /[[:space:]]+/); path_seen=0; watch=0; mode=0; key=0
                for (i=1; i<=n; i++) {
                    s=a[i]; sub(/^(path|dir)=/, "", s); sub(/\/$/,"",s)
                    if (s == path) {
                        path_seen=1
                        if (i>1 && a[i-1] == "-w") watch=1
                    }
                    if (a[i] == "-p" && i<n && a[i+1] ~ /^(wa|aw)$/) mode=1
                    if (a[i] == "-k" && i<n && a[i+1] == "cronjobs") key=1
                    if (a[i] == "-F" && i<n && a[i+1] == "key=cronjobs") key=1
                }
                if (n == 6 && path_seen && watch && mode && key) good=1
                else if (path_seen) other=1
            }
            END {print other ? "overlap" : (good ? "present" : "missing")}
        ' <<< "$existing") || return 1
        case $result in
            missing) additions+=("-w $path/ -p wa -k cronjobs") ;;
            overlap) return 1 ;;
        esac
    done
    if (( ${#additions[@]} )); then printf '%s\n' "${additions[@]}"; fi
}

audit_rule_dropin_validate() {
    local candidate=$1 target=$2 line found=0
    local -A checked=()
    while IFS= read -r line; do
        [[ -n $line && ! ${checked[$line]+present} ]] || return 1
        checked[$line]=1
        case ${target##*/}:$line in
            '90-rhel8-stig-v274877.rules:-w /etc/cron.d/ -p wa -k cronjobs'|\
            '90-rhel8-stig-v274877.rules:-w /var/spool/cron/ -p wa -k cronjobs'|\
            '90-rhel8-stig-v288831.rules:-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd')
                found=$((found + 1)) ;;
            *) return 1 ;;
        esac
    done < "$candidate"
    (( found ))
}

audit_rule_dropin_edit() {
    local id=$1 existing=$2 profile target payload payload_rc=0
    case $id in
        V-274877)
            profile=cron
            if [[ ! -d /etc/cron.d || ! -d /var/spool/cron || -L /etc/cron.d || -L /var/spool/cron ]]; then
                PLAN_REASON='Both standard cron paths must exist as ordinary directories to stage the watches.'; return 1
            fi ;;
        V-288831)
            profile=useradd
            if [[ ! -f /usr/sbin/useradd || ! -x /usr/sbin/useradd || -L /usr/sbin/useradd ]]; then
                PLAN_REASON='The standard useradd executable must be a regular, executable file.'; return 1
            fi ;;
        *) return 1 ;;
    esac
    target=/etc/audit/rules.d/90-rhel8-stig-v${id#V-}.rules
    payload=$(audit_rule_dropin_payload "$profile" "$existing") || payload_rc=$?
    if (( payload_rc == 2 )) || [[ -z $payload && $payload_rc == 0 ]]; then
        PLAN_REASON='The required source rules already exist. Only audit policy activation and verification remain.'; return 1
    fi
    if (( payload_rc != 0 )); then
        PLAN_REASON='A source rule overlaps the controlled paths or key. Review and preserve its existing policy purpose.'; return 1
    fi
    if [[ -e $target || -L $target || ${EDIT_TOUCHED[$target]+changed} ]]; then
        PLAN_REASON='The proposed dedicated audit rules file already exists or was changed in this run.'; return 1
    fi
    edit_content "$target" 0600 "$payload" audit_rule_dropin_validate <<< "$payload"
}

audit_rule_dropin_include() {
    local id=$1 peer=$2 existing=$3
    local PLAN_REASON
    attended_optional_peer_ready "$id" "$peer" &&
        audit_rule_dropin_edit "$peer" "$existing" || return 1
    EDIT_RELATED=$peer EDIT_GROUPED=$peer
}

audit_rule_dropin_plan() {
    local id=$1 peer=$2 unit sources existing settings enabled
    local loader='argv\[\]=(/usr)?/sbin/augenrules[[:space:]]+--load([[:space:]]|;|$)'
    if ! have_tools systemctl auditctl augenrules sha256sum; then
        PLAN_REASON='The standard auditd, auditctl and augenrules tools are required to stage audit rules.'; return 1
    fi
    unit=$(timeout 8 systemctl show auditd.service -p ExecStartPost --value 2>/dev/null) || return 1
    if [[ ! $unit =~ $loader ]]; then
        PLAN_REASON='The auditd unit does not have an identifiable augenrules --load start action.'; return 1
    fi
    settings=$(timeout 8 auditctl -s 2>/dev/null) || return 1
    enabled=$(awk '$1 == "enabled" && $2 ~ /^[012]$/ {print $2}' <<< "$settings") || return 1
    if [[ $enabled != 1 && $enabled != 2 ]]; then
        PLAN_REASON='Kernel auditing is disabled or its enablement cannot be read.'; return 1
    fi
    sources=$(audit_rule_source_inventory) || {
        PLAN_REASON='An audit rules source is inaccessible, linked, untrusted or has an ambiguous filename.'; return 1;
    }
    existing=$(audit_rule_source_contents <<< "$sources") || return 1
    if grep -Eq '^[[:space:]]*-(a|A)[[:space:]]+(never,(task|exit|exclude)|(task|exit|exclude),never)\b' <<< "$existing"; then
        PLAN_REASON='Audit suppression is present. Review whether it would override the proposed rule.'; return 1
    fi
    audit_rule_dropin_edit "$id" "$existing" || return 1
    EDIT_CONTEXT=$(printf '%s\n' "$unit" "$enabled" "$sources" "$existing" | sha256sum) || return 1
    EDIT_DISPOSITION=pending
    if [[ $enabled == 2 ]]; then
        EDIT_ACTIVATION='The kernel audit policy is immutable. Review every queued augenrules change, schedule an authorized reboot, then verify auditctl -l and the reported rule.'
    else
        EDIT_ACTIVATION='Review every queued augenrules change before the audit owner runs augenrules --load in an approved window. Check auditctl -l and the reported rule.'
    fi
    EDIT_REQUIREMENTS='Confirm this audit rules source is locally managed and the added audit events are authorized.'
    audit_rule_dropin_include "$id" "$peer" "$existing" || true
}

rule_V_274877_plan() { audit_rule_dropin_plan V-274877 V-288831; }
rule_V_288831_plan() { audit_rule_dropin_plan V-288831 V-274877; }

# Only the standard temporary directories are eligible. Other public paths may
# intentionally support cooperative ownership and deletion workflows.
rule_V_230243_plan() {
    local path owner mode next planned=0
    for path in /tmp /var/tmp; do
        [[ -e $path || -L $path ]] || continue
        if [[ -L $path || ! -d $path ]] || ! local_filesystem "$path"; then
            PLAN_REASON="$path is linked, non-directory, or outside a supported local filesystem."
            return 1
        fi
        if ! read -r owner mode < <(stat -c '%u %a' -- "$path" 2>/dev/null) ||
           [[ ! $mode =~ ^[0-7]{1,4}$ ]]; then
            PLAN_REASON="Cannot read the current owner and mode of $path."
            return 1
        fi
        if (( ! (8#$mode & 2) || (8#$mode & 01000) )); then continue; fi
        if [[ $owner != 0 ]]; then
            PLAN_REASON="$path is not owned by root. Review the management and directory policy."
            return 1
        fi
        printf -v next '0%03o' "$(( 8#$mode | 01000 ))"
        edit_metadata "$path" "$next" keep "Mode $mode -> $next. Add only the sticky bit." || return
        planned=$((planned + 1))
    done
    if (( ! planned )); then
        PLAN_REASON='No missing sticky bit was found on eligible standard temporary directories. Review other public paths from all applicable mounts.'
        return 1
    fi
    EDIT_REQUIREMENTS='Confirm workloads can tolerate losing permission to rename or remove entries owned by other users. Verify shared workloads and all applicable mounts afterward.'
}

# Additional boot, filesystem, repository, network, mail, and desktop rules.

rule_V_230234_check() {
    local path state
    case ${BOOT_MODE-} in
        BIOS) rule_result NOT_APPLICABLE 'the host is using BIOS'; return ;;
        UEFI) ;;
        *) rule_result NEEDS_REVIEW 'boot firmware mode was not established'; return ;;
    esac
    for path in /boot/grub2/user.cfg /boot/efi/EFI/redhat/user.cfg; do
        [[ -e $path || -L $path ]] || continue
        if [[ -L $path || ! -f $path || ! -r $path ]]; then
            rule_result NEEDS_REVIEW 'the selected GRUB authentication file is linked, unreadable or unsupported'
            return
        fi
        state=$(awk '
            /^[[:space:]]*GRUB2_PASSWORD[[:space:]]*=/ {
                n++; sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*$/, "");
                if ($0 ~ /^grub\.pbkdf2\.sha512\.[^[:space:]]+$/) valid++
            }
            END {
                if (n > 1) print "ambiguous"
                else if (n == 1 && valid == 1) print "present"
                else print "missing"
            }
        ' "$path") || { rule_result ERROR 'GRUB authentication file could not be parsed'; return; }
        case $state in
            present) rule_result PASS 'selected UEFI GRUB authentication file has one PBKDF2 SHA-512 entry' ;;
            ambiguous) rule_result NEEDS_REVIEW 'selected UEFI GRUB authentication file has duplicate definitions' ;;
            missing) rule_result FAIL 'the selected UEFI GRUB authentication file lacks the required hash type' ;;
        esac
        return
    done
    if [[ ! -x /boot || ! -d /boot/grub2 || ! -x /boot/grub2 ]]; then
        rule_result NEEDS_REVIEW 'the UEFI GRUB storage path cannot be inspected'; return
    fi
    rule_result FAIL 'no GRUB authentication file was found at the unified or legacy UEFI path'
}

rule_V_230234_admin() {
    printf '%s\n' \
        '1. Boot administrator: identify the active UEFI boot configuration and confirm physical console and recovery access.' \
        '2. Use grub2-setpassword interactively with an approved secret and escrow procedure. Keep the secret out of reports.' \
        '3. Verify the active user.cfg hash type and test maintenance entry in the disposable guest before rolling out.'
}

rule_V_230243_check() {
    local directory mode result code
    for directory in /tmp /var/tmp; do
        [[ -d $directory && ! -L $directory ]] || continue
        mode=$(stat -c %a -- "$directory" 2>/dev/null) || continue
        if [[ $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 0002) != 0 && (8#$mode & 01000) == 0 )); then
            rule_result FAIL "the standard public directory $directory is world-writable without a sticky bit"
            return
        fi
    done
    if ! have_tools find; then rule_result NEEDS_REVIEW 'find is not available'; return; fi
    # Mountpoint traversal is deliberately bounded. The original check spans all mounted filesystems.
    result=$(timeout 15 find / -xdev -type d -perm -0002 ! -perm -1000 -printf . 2>/dev/null)
    code=$?
    if [[ -n $result ]]; then
        rule_result FAIL "found ${#result} world-writable directories without a sticky bit in the root filesystem scan"
    elif (( code != 0 )); then
        rule_result NEEDS_REVIEW 'the bounded root filesystem scan could not finish'
    else
        rule_result NEEDS_REVIEW 'no finding in the root filesystem scan; all relevant additional mounts need coverage'
    fi
}

rule_V_230243_admin() {
    printf '%s\n' \
        '1. Storage administrator: review root and additional mounted local and shared filesystems for world-writable directories.' \
        '2. Use a bounded find per approved mount. Review directory owner, ACLs, applications and deliberate exception paths.' \
        '3. On reviewed directories add the sticky bit with chmod +t. Preserve all existing permission bits.' \
        '4. Repeat the scan and verify shared application behavior.'
}

system_command_scan() {
    local root path duplicate
    local -a directories=()
    for root in /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin; do
        if [[ ! -e $root && ! -L $root ]]; then continue; fi
        [[ -d $root && -r $root && -x $root ]] || return 1
        path=$(realpath -e -- "$root") || return 1
        duplicate=0
        local saved
        for saved in "${directories[@]}"; do [[ $saved != "$path" ]] || duplicate=1; done
        if (( ! duplicate )); then directories+=("$path"); fi
    done
    (( ${#directories[@]} > 0 )) || return 1
    timeout 15 find -L "${directories[@]}" -xdev -type f -perm /022 -printf '%m\t%p\0'
}

rule_V_230257_check() {
    local result code count
    if ! have_tools find; then rule_result NEEDS_REVIEW 'find is not available'; return; fi
    result=$(system_command_scan 2>/dev/null | tr -dc '\000' | wc -c)
    code=$?
    count=${result//[[:space:]]/}
    if [[ $count =~ ^[1-9][0-9]*$ ]]; then
        rule_result FAIL "found $count regular command paths with group or other write bits in standard command directories"
    elif (( code != 0 )); then
        rule_result NEEDS_REVIEW 'the bounded standard command scan could not finish'
    else
        rule_result PASS 'no scanned regular command path in the standard directories is group- or world-writable'
    fi
}

rule_V_230257_plan() {
    local row old new path canonical owner links
    if ! have_tools find; then PLAN_REASON='find is required for a complete command scan'; return 1; fi
    if ! system_command_scan > "$EDIT_TEMP/system-command-candidates" 2>/dev/null; then
        PLAN_REASON='complete command scan is required for a permission plan'; return 1
    fi
    while IFS= read -r -d '' row; do
        old=${row%%$'\t'*}
        path=${row#*$'\t'}
        case $path in
            /usr/bin/*|/usr/sbin/*|/usr/local/bin/*|/usr/local/sbin/*|/bin/*|/sbin/*) ;;
            *) PLAN_REASON='a command resolves outside the reviewed standard paths'; return 1 ;;
        esac
        if [[ ! $old =~ ^[0-7]{3,4}$ || $path == *[![:print:]]* || -L $path || ! -f $path ]]; then
            PLAN_REASON='a candidate command is linked, nonregular or ambiguous'; return 1
        fi
        canonical=$(realpath -e -- "$path") || return 1
        if [[ $canonical != "$path" ]]; then
            PLAN_REASON='a candidate command passes through a symbolic link'; return 1
        fi
        read -r owner links < <(stat -c '%u %h' -- "$path") || return 1
        if [[ $owner != 0 || $links != 1 ]] || (( (8#$old & 07000) != 0 )); then
            PLAN_REASON='a candidate command has non-root ownership, multiple links or special permission bits'; return 1
        fi
        printf -v new '%04o' "$((8#$old & ~022))"
        edit_metadata "$path" "$new" keep "$path mode $old -> $new (remove group and other write bits)" || return 1
    done < "$EDIT_TEMP/system-command-candidates"
}

rule_V_230257_admin() {
    printf '%s\n' \
        '1. System administrator: reproduce the standard command permission scan and confirm each affected owner and package.' \
        '2. Check deliberate writable directories, ACLs, linked commands and package restoration before changing permissions.' \
        '3. Remove group and other write permission from reviewed command files. Confirm package integrity if unauthorized writes were possible.'
}

rule_V_230264_check() {
    local file observation total=0 unsigned=0 alternate=0
    local -a files=()
    [[ -d /etc/yum.repos.d && -r /etc/yum.repos.d && -x /etc/yum.repos.d ]] || {
        rule_result NEEDS_REVIEW 'repository configuration directory cannot be inspected'; return;
    }
    for file in /etc/yum.repos.d/*.repo; do
        [[ -e $file || -L $file ]] || continue
        [[ -f $file && -r $file ]] || { rule_result NEEDS_REVIEW 'an on-disk repository file is unreadable'; return; }
        files+=("$file")
    done
    if (( ! ${#files[@]} )); then
        rule_result NEEDS_REVIEW 'no local .repo files were found; check plugin-managed sources and approved process'; return
    fi
    observation=$(awk -v alternatives="${GPGCHECK_ALTERNATE_REPOS-}" '
        BEGIN {split(alternatives, ids, ","); for (i in ids) alternate[ids[i]]=1}
        FNR == 1 {finish()}
        function finish() {
            if (section && enabled !~ /^(0|no|false)$/) {
                n++;
                if (gpg != "1") {if (id in alternate) a++; else u++}
            }
            section=0; enabled=""; gpg=""
        }
        /^[[:space:]]*\[/ {
            finish(); section=1; id=$0; sub(/^[[:space:]]*\[/, "", id); sub(/\].*$/, "", id); next
        }
        tolower($0) ~ /^[[:space:]]*(enabled|gpgcheck)[[:space:]]*=/ {
            v=$0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*$/, "", v);
            if (tolower($0) ~ /^[[:space:]]*enabled/) enabled=tolower(v); else gpg=v;
        }
        END {finish(); print n+0, u+0, a+0}
    ' "${files[@]}") || { rule_result ERROR 'on-disk repository parse failed'; return; }
    read -r total unsigned alternate <<< "$observation"
    if (( unsigned > 0 )); then CHECK_PLAN_CANDIDATE=1; fi
    rule_result NEEDS_REVIEW "$unsigned of $total on-disk enabled repository sections lack explicit gpgcheck=1 without a declared alternate. $alternate other sections have a declared alternate. Verify approved keys and other effective repo sources."
}

rule_V_230264_admin() {
    printf '%s\n' \
        '1. Package administrator: identify effective DNF repositories, inherited defaults and enabled plugins.' \
        '2. Confirm organization-approved signing keys and any documented alternate verification process.' \
        '3. Review the candidate for locally managed definitions with installed matching keys. Set gpgcheck=1 in the authoritative source for any additional unprotected repositories.' \
        '4. Verify signature enforcement using approved local packages and repository metadata. Keep repositories using an approved alternate out of the plan with GPGCHECK_ALTERNATE_REPOS.'
}

# Columns are the encoded mountpoint and 0/1 for the required explicit option.
scope_fstab_nfs() {
    awk -v opt="$2" '
        function has(opts, desired,    n,i,items,last) {
            n=split(opts,items,","); last=0;
            for (i=1;i<=n;i++) {if (items[i] == desired) last=1;
                if (items[i] == substr(desired,3)) last=0}
            return last
        }
        /^[[:space:]]*($|#)/ {next}
        {sub(/[[:space:]]+#.*/, ""); if (NF<4 || NF>6) {bad=1; next}}
        {if (++seen[$2] > 1) bad=1}
        $3 ~ /^nfs4?$/ {print $2 "\t" has($4,opt)}
        END {if (bad) exit 2}
    ' "$1"
}

scope_active_nfs() {
    awk -v opt="$2" '
        {sep=0; for(i=7;i<=NF;i++) if ($i=="-") {sep=i; break}
         if (!sep || sep+3>NF) {bad=1; next}
         if ($(sep+1) !~ /^nfs4?$/) next;
         if (++seen[$5]>1) bad=1;
         print $5 "\t" ($6 ~ ("(^|,)" opt "(,|$)")) + 0}
        END {if (bad) exit 2}
    ' "$1"
}

scope_extra_mount_manager() {
    local unit
    if have_tools systemctl &&
       { timeout 5 systemctl is-active --quiet autofs.service 2>/dev/null ||
         timeout 5 systemctl is-enabled --quiet autofs.service 2>/dev/null; }; then return 0; fi
    for unit in /etc/systemd/system/*.mount /etc/systemd/system/*.automount; do
        [[ -e $unit || -L $unit ]] || continue
        [[ $unit != *.automount && -f $unit && -r $unit ]] || return 0
        if grep -qiE '^[[:space:]]*Type[[:space:]]*=[[:space:]]*nfs4?([[:space:]]|$)' "$unit"; then return 0; fi
    done
    return 1
}

scope_check_nfs() {
    local opt=$1 persistent active path present bad_persistent=0 bad_active=0 alternative=0
    local -A sources=()
    if [[ ! -r /etc/fstab || ! -r /proc/self/mountinfo ]]; then
        rule_result NEEDS_REVIEW 'persistent or active mount configuration is unreadable'; return
    fi
    if ! persistent=$(scope_fstab_nfs /etc/fstab "$opt") || ! active=$(scope_active_nfs /proc/self/mountinfo "$opt"); then
        rule_result NEEDS_REVIEW 'mount configuration has unreadable, duplicate or ambiguous entries'; return;
    fi
    while IFS=$'\t' read -r path present; do
        [[ $path ]] || continue
        sources[$path]=1
        if [[ $present == 0 ]]; then ((bad_persistent += 1)); fi
    done <<< "$persistent"
    while IFS=$'\t' read -r path present; do
        [[ $path ]] || continue
        if [[ $present == 0 ]]; then ((bad_active += 1)); fi
        if [[ ! ${sources[$path]+exists} ]]; then ((alternative += 1)); fi
    done <<< "$active"
    if (( bad_persistent || bad_active )); then
        rule_result FAIL "NFS mounts missing $opt: $bad_persistent persistent and $bad_active active"
    elif (( alternative )) || scope_extra_mount_manager; then
        rule_result NEEDS_REVIEW 'an alternative NFS mount manager or runtime-only mount requires source verification'
    elif [[ -z $persistent && -z $active ]]; then
        rule_result NOT_APPLICABLE 'no configured or active NFS mount was found'
    else
        rule_result PASS "persistent NFS entries and their active mounts use $opt"
    fi
}

rule_V_230306_check() { scope_check_nfs noexec; }
rule_V_230307_check() { scope_check_nfs nodev; }

scope_validate_fstab() {
    timeout 10 findmnt --verify --tab-file "$1" >/dev/null 2>&1
}

# Replace an option token, or append the option to the existing options field. Preserve the line layout.
scope_fstab_transform() {
    awk -v opt="$2" -v diff="$3" -v companion="${4-}" '
        function set_option(opts, desired, target,    n,a,i,result,change,selected) {
            n=split(opts,a,",");
            for (i=1;i<=n;i++) if (a[i]==desired || a[i]==substr(desired,3)) {
                if (change) bad=1;
                change=i; selected=a[i];
            }
            if (selected==desired) return opts;
            # The source and other options stay private. Only literal target paths go in plan text.
            if (target !~ /^\/[a-zA-Z0-9_./-]+$/ || target ~ /(^|\/)\.\.?($|\/)/) bad=1;
            if (change) {
                a[change]=desired; result=a[1]; for(i=2;i<=n;i++) result=result "," a[i];
            } else result=opts "," desired;
            if (selected=="") selected="(absent)";
            print target ": " selected " -> " desired > diff;
            modifications++;
            return result;
        }
        /^[[:space:]]*($|#)/ {print; next}
        {raw=$0; tmp=raw; sub(/[[:space:]]+#.*/, "", tmp); $0=tmp;
         if (NF<4 || NF>6 || ++seen[$2]>1) {bad=1; print raw; next}}
        $3 ~ /^nfs4?$/ {
            old=$4; target=$2; nextopt=set_option(old,opt,target);
            if (companion!="") nextopt=set_option(nextopt,companion,target);
            if (nextopt==old) {print raw; next}
            tags=opt; if (companion!="") tags=tags "," companion;
            rest=raw; split_at=0;
            for(i=1;i<=3;i++) {match(rest,/^[[:space:]]*[^[:space:]]+/); split_at+=RLENGTH; rest=substr(rest,RLENGTH+1)}
            match(rest,/^[[:space:]]+/); split_at+=RLENGTH;
            print "# rhel8-stig " tags " recorded prior NFS mount entry: " raw;
            print substr(raw,1,split_at) nextopt substr(raw,split_at + length(old) + 1);
            next
        }
        {print raw}
        END {if (bad || !modifications) exit 2}
    ' "$1"
}

scope_nfs_home_related() {
    local persistent=$1
    [[ -r /etc/passwd ]] || return 0
    awk -F: '
        FILENAME==ARGV[1] {split($0,t,"\t"); if (t[2]==0 && t[1]!="") changing[t[1]]=1; next}
        NF==7 && $3 ~ /^[0-9]+$/ && ($3>=1000 || $3==0) && $7 !~ /nologin/ {
            if ($6 !~ /^\/[a-zA-Z0-9_./-]+$/ || $6 ~ /(^|\/)\.\.?($|\/)/) found=1;
            for (p in changing) if ($6==p || index($6,p "/")==1) found=1
        }
        NF!=7 {found=1}
        END {exit !found}
    ' - /etc/passwd <<< "$persistent"
}

scope_plan_nfs() {
    local opt=$1 diff active persistent mount present nodev_persistent nodev_active companion=''
    local -A managed=()
    if ! have_tools findmnt || [[ ! -f /etc/fstab || -L /etc/fstab ]]; then
        PLAN_REASON='a regular system fstab and findmnt are required'; return 1
    fi
    if scope_extra_mount_manager; then
        PLAN_REASON='another mount manager needs verification before staging fstab'; return 1
    fi
    if ! persistent=$(scope_fstab_nfs /etc/fstab "$opt") || ! active=$(scope_active_nfs /proc/self/mountinfo "$opt"); then
        PLAN_REASON='mount configuration could not be parsed without ambiguity'; return 1;
    fi
    while IFS=$'\t' read -r mount present; do
        if [[ -n $mount ]]; then managed[$mount]=1; fi
    done <<< "$persistent"
    while IFS=$'\t' read -r mount present; do
        if [[ -n $mount && ! ${managed[$mount]+known} ]]; then
            PLAN_REASON='an active NFS mount is not managed by fstab'; return 1
        fi
    done <<< "$active"
    if [[ $opt == noexec && ${EFFECTIVE[V-230307]+eligible} ]] &&
       grep -q $'\t0$' <<< "$persistent" &&
       nodev_persistent=$(scope_fstab_nfs /etc/fstab nodev) && grep -q $'\t0$' <<< "$nodev_persistent" &&
       nodev_active=$(scope_active_nfs /proc/self/mountinfo nodev); then
        companion=nodev
    fi
    if ! scope_fstab_transform /etc/fstab "$opt" "$EDIT_TEMP/scope-nfs-diff" "$companion" > "$EDIT_TEMP/scope-nfs"; then
        if [[ -z $companion ]] ||
           ! scope_fstab_transform /etc/fstab "$opt" "$EDIT_TEMP/scope-nfs-diff" > "$EDIT_TEMP/scope-nfs"; then
            PLAN_REASON='no unambiguous persistent edit is available. Review the active mount and any existing options.'; return 1
        fi
        companion=''
    fi
    if [[ $opt == noexec ]] && scope_nfs_home_related "$persistent"; then EDIT_RELATED='V-230302'; fi
    if [[ $companion ]]; then
        EDIT_RELATED="${EDIT_RELATED:+$EDIT_RELATED }V-230307"
        EDIT_GROUPED='V-230307'
        active+=$'\n'
        active+=$nodev_active
    fi
    diff=$(< "$EDIT_TEMP/scope-nfs-diff")
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Review open users and use an approved targeted remount or planned reboot. Verify effective flags in the target mount namespace.'
    EDIT_REQUIREMENTS='Confirm the fstab source and workload access needs with storage and application administrators before approving persistence.'
    EDIT_CONTEXT=$active
    edit_content /etc/fstab keep "$diff" scope_validate_fstab < "$EDIT_TEMP/scope-nfs"
}

rule_V_230306_plan() { scope_plan_nfs noexec; }
rule_V_230307_plan() { scope_plan_nfs nodev; }

rule_V_230306_admin() {
    printf '%s\n' \
        '1. Storage administrator: confirm the fstab or managed source for each affected NFS mount and check application execution dependencies.' \
        '2. Preview the persistent noexec edit. Activate only after coordinating handles and sessions that depend on the mount.' \
        '3. Verify active VFS noexec flags with findmnt and rerun the rule.'
}

rule_V_230307_admin() {
    printf '%s\n' \
        '1. Storage administrator: confirm the fstab or managed source for each affected NFS mount and review special-device dependencies.' \
        '2. Preview the persistent nodev edit. Activate through an approved targeted remount or maintenance reboot.' \
        '3. Verify active VFS nodev flags with findmnt and rerun the rule.'
}

rule_V_230302_check() {
    local homes inventory
    if [[ ! -r /etc/passwd || ! -r /proc/self/mountinfo || ! -r /etc/fstab ]]; then
        rule_result NEEDS_REVIEW 'local account, active mount, or fstab evidence is unreadable'; return
    fi
    homes=$(awk -F: 'NF==7 && $3 ~ /^[0-9]+$/ && $3>=1000 && $7 !~ /nologin/ {print $6}' /etc/passwd) || {
        rule_result ERROR 'local account parse failed'; return;
    }
    if [[ -z $homes ]]; then
        rule_result NEEDS_REVIEW 'no home paths were found for the checked account class; review interactive accounts'; return
    fi
    inventory=$(awk '
        FILENAME == ARGV[1] {
            sep=0; for(i=7;i<=NF;i++) if($i=="-") {sep=i; break};
            if(!sep || sep+3>NF) {err=1; next}; active[$5]=$6; next
        }
        FILENAME == ARGV[2] {
            if ($0 ~ /^[[:space:]]*($|#)/) next;
            sub(/[[:space:]]+#.*/, ""); if (NF<4 || NF>6 || ++number[$2]>1) {err=1; next}; fstab[$2]=$4; next
        }
        function noexec(opts,    n,i,a,last) {n=split(opts,a,","); last=0;
            for(i=1;i<=n;i++){if(a[i]=="noexec") last=1; if(a[i]=="exec") last=0}; return last}
        {if ($0 !~ /^\/[a-zA-Z0-9_./-]+$/ || $0 ~ /(^|\/)\.\.?($|\/)/) {unknown++; next}
         home=$0; best="/";
         for(mp in active) if ((home==mp || index(home,mp "/")==1) && length(mp)>length(best)) best=mp;
         if(best=="/" || !noexec(active[best])) bad++;
         else if (!(best in fstab)) unknown++;
         else if (!noexec(fstab[best])) bad++;
         else complete++}
        END {if(err) exit 2; print bad+0, unknown+0, complete+0}
    ' /proc/self/mountinfo /etc/fstab - <<< "$homes") || {
        rule_result NEEDS_REVIEW 'home mount configuration is ambiguous'; return;
    }
    local bad unknown complete
    read -r bad unknown complete <<< "$inventory"
    if (( bad > 0 )); then
        rule_result FAIL "$bad lexical local-account home paths map to root or lack active or persistent noexec; review redirected homes"
    elif (( unknown > 0 || complete == 0 )); then
        rule_result NEEDS_REVIEW 'some local home paths lack an unambiguous active and fstab mapping'
    else
        rule_result NEEDS_REVIEW "$complete local home paths map lexically to noexec mounts; confirm symlink, mount-manager and interactive-account coverage"
    fi
}

rule_V_230302_admin() {
    printf '%s\n' \
        '1. Storage administrator: verify each local interactive account and resolve its actual home filesystem.' \
        '2. Establish a separate home mount if any account uses the root filesystem and coordinate a recovery path.' \
        '3. Add noexec through the authoritative mount configuration and activate in an approved window.' \
        '4. Verify persistent and active options and test user applications.'
}

rule_V_230316_check() {
    local mode count
    if [[ ! -r /etc/nsswitch.conf || ! -r /etc/resolv.conf ]]; then
        rule_result NEEDS_REVIEW 'name-service switch or resolver configuration is unreadable'; return
    fi
    mode=$(awk '
        /^[[:space:]]*hosts[[:space:]]*:/ {n++; sub(/#.*/, ""); sub(/^[^:]*:/, "");
           for(i=1;i<=NF;i++) if($i=="dns") found=1}
        END {print n==1 ? found ? "dns" : "local" : "unknown"}
    ' /etc/nsswitch.conf) || { rule_result ERROR 'name-service switch could not be parsed'; return; }
    case $mode in
        local)
            if [[ -s /etc/resolv.conf ]]; then
                rule_result FAIL 'NSS hosts lacks dns while resolver configuration is nonempty'
            else
                rule_result PASS 'NSS hosts lacks dns and resolver configuration is empty'
            fi
            ;;
        dns)
            count=$(awk '
                function ipv4(s,    i,a) {
                    if (split(s,a,".")!=4) return "";
                    for (i=1;i<=4;i++) if (a[i] !~ /^(0|[1-9][0-9]{0,2})$/ || a[i]+0>255) return "";
                    return a[1] "." a[2] "." a[3] "." a[4]
                }
                /^[[:space:]]*nameserver[[:space:]]/ {ip=ipv4($2); if (ip) server[ip]=1}
                END {for(s in server) n++; print n+0}
            ' /etc/resolv.conf) || { rule_result ERROR 'resolver configuration could not be parsed'; return; }
            if (( count >= 2 )); then
                rule_result PASS "$count unique IPv4 nameserver entries were found for NSS DNS resolution"
            else
                rule_result NEEDS_REVIEW "$count unique IPv4 nameserver entries were found; review IPv6 settings or the cloud provider exception"
            fi
            ;;
        *) rule_result NEEDS_REVIEW 'NSS hosts configuration is missing or ambiguous' ;;
    esac
}

rule_V_230316_admin() {
    printf '%s\n' \
        '1. Network administrator: verify approved DNS addresses and any documented highly available cloud resolver exception.' \
        '2. Identify NetworkManager, a resolver service or a static file as the source before altering configuration.' \
        '3. Add the second approved nameserver through that source and test resolution from a fresh session.'
}

rule_V_230323_check() {
    local report count code
    if (( EUID != 0 )) || ! have_tools pwck; then
        rule_result NEEDS_REVIEW 'root and pwck are required to verify local home directories'; return
    fi
    report=$(timeout 12 pwck -r 2>&1)
    code=$?
    count=$(awk '/directory .* does not exist/ {n++} END {print n+0}' <<< "$report") || return 1
    if (( count > 0 )); then
        rule_result FAIL "pwck reported $count nonexistent referenced home directories; verify interactive account applicability"
    elif (( code == 0 )); then
        rule_result PASS 'pwck -r reported no local account database or home path findings'
    elif (( code == 2 )); then
        rule_result NEEDS_REVIEW 'pwck reports other account database issues that need review'
    else
        rule_result NEEDS_REVIEW 'read-only pwck could not finish'
    fi
}

rule_V_230323_admin() {
    printf '%s\n' \
        '1. Account administrator: run pwck -r and identify each missing home belonging to a local interactive account.' \
        '2. Verify the expected path, filesystem, owner, primary group, permissions and SELinux file context.' \
        '3. Create or restore only the approved home directories. Verify with pwck -r and the affected account login.'
}

scope_postfix_evidence() {
    local path=${1:-/etc/postfix} restrictions overrides alternate networks
    restrictions=$(timeout 10 postconf -c "$path" -h smtpd_client_restrictions 2>/dev/null) || return 1
    overrides=$(timeout 10 postconf -c "$path" -P 2>/dev/null) || return 1
    alternate=$(timeout 10 postconf -c "$path" -h multi_instance_directories 2>/dev/null) || return 1
    networks=$(timeout 10 postconf -c "$path" -h mynetworks 2>/dev/null) || return 1
    if [[ -n $alternate ]] || grep -qE '/(smtpd_(client|relay)_restrictions|mynetworks)[[:space:]]*=' <<< "$overrides"; then
        printf 'review\n'; return
    fi
    if grep -Eq '(^|[[:space:],])(0\.0\.0\.0/0|\[::\]/0|::/0)([[:space:],]|$)' <<< "$networks"; then
        printf 'unsafe-network\n'; return
    fi
    restrictions=${restrictions//[[:space:],]/ }
    # Bash split is intentional after normalizing the separators. Globs are data to compare.
    local -a tokens=()
    read -r -a tokens <<< "$restrictions"
    if [[ ${tokens[*]} == 'permit_mynetworks reject' || ${tokens[*]} == reject ]]; then
        printf 'restricted\n'
    else
        printf 'noncompliant\n'
    fi
}

rule_V_230550_check() {
    local installed state
    installed=$(timeout 10 rpm -q postfix 2>/dev/null)
    case $? in
        0) ;;
        1) if [[ $installed == 'package postfix is not installed' ]]; then
               rule_result NOT_APPLICABLE 'RPM reports Postfix is not installed'; return
           fi
           rule_result NEEDS_REVIEW 'Postfix RPM status is unavailable'; return ;;
        *) rule_result NEEDS_REVIEW 'Postfix RPM status is unavailable'; return ;;
    esac
    if ! have_tools postconf; then rule_result NEEDS_REVIEW 'Postfix is installed but postconf is unavailable'; return; fi
    state=$(scope_postfix_evidence) || { rule_result NEEDS_REVIEW 'Postfix site configuration could not be evaluated'; return; }
    case $state in
        restricted) rule_result PASS 'Postfix client restrictions use only the required deny-by-default ordering' ;;
        noncompliant) rule_result FAIL 'Postfix client restrictions lack the required deny-by-default ordering' ;;
        unsafe-network) rule_result FAIL 'Postfix mynetworks includes unrestricted network scope' ;;
        review) rule_result NEEDS_REVIEW 'Postfix service overrides or other active instances need review' ;;
    esac
}

scope_validate_postfix() {
    local stage=$1 directory result
    if [[ $stage == /etc/postfix/main.cf ]]; then
        result=$(scope_postfix_evidence) && [[ $result == restricted ]]; return
    fi
    directory=$(mktemp -d -- "$EDIT_TEMP/postfix.XXXXXXXX") || return 1
    cp -- "$stage" "$directory/main.cf" && cp -- /etc/postfix/master.cf "$directory/master.cf" || return 1
    result=$(scope_postfix_evidence "$directory") && [[ $result == restricted ]]
}

scope_postfix_transform() {
    awk '
        {if (prior && /^[[:blank:]]+[^[:blank:]#]/) conflict=1; prior=0}
        /^smtpd_client_restrictions[[:blank:]]*=/ {
            if (++seen>1) conflict=1;
            print "# rhel8-stig recorded prior smtpd_client_restrictions: " $0;
            print "smtpd_client_restrictions = permit_mynetworks, reject";
            prior=1; next
        }
        {print}
        END {if(conflict) exit 2; if(!seen) print "smtpd_client_restrictions = permit_mynetworks, reject"}
    ' "$1"
}

rule_V_230550_plan() {
    local state context
    if ! have_tools postconf cp || [[ ! -f /etc/postfix/main.cf || -L /etc/postfix/main.cf ||
                                   ! -f /etc/postfix/master.cf || -L /etc/postfix/master.cf ]]; then
        PLAN_REASON='canonical Postfix main.cf and master.cf plus postconf are required'; return 1
    fi
    state=$(scope_postfix_evidence) || { PLAN_REASON='canonical Postfix scope could not be established'; return 1; }
    if [[ $state != noncompliant ]]; then
        PLAN_REASON='Postfix overrides, instance layout or trusted network scope requires separate review'; return 1
    fi
    if ! scope_postfix_transform /etc/postfix/main.cf > "$EDIT_TEMP/scope-postfix-main"; then
        PLAN_REASON='client restrictions are duplicated or span multiple lines'; return 1
    fi
    context=$(sha256_file /etc/postfix/master.cf) || return 1
    EDIT_CONTEXT=$context
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Review trusted mynetworks and application routing. Reload an approved running instance with systemctl reload postfix and verify trusted and untrusted clients; otherwise verify on its next approved start.'
    edit_content /etc/postfix/main.cf keep \
        'smtpd_client_restrictions -> permit_mynetworks, reject (prior value recorded in place without exposing site policy in reports)' \
        scope_validate_postfix < "$EDIT_TEMP/scope-postfix-main"
}

rule_V_230550_admin() {
    printf '%s\n' \
        '1. Mail administrator: inspect mynetworks, service overrides, trusted clients, and alternate Postfix instances.' \
        '2. Apply deny-by-default client restrictions through the authoritative mail configuration source.' \
        '3. Validate the configuration, reload in an approved window, and verify both permitted mail and rejection of untrusted relay.'
}

rule_V_244545_check() {
    local service
    if ! have_tools systemctl; then rule_result NEEDS_REVIEW 'systemctl unavailable'; return; fi
    service=$(timeout 8 systemctl show --property=LoadState,UnitFileState,ActiveState,SubState fapolicyd.service 2>/dev/null) || {
        rule_result NEEDS_REVIEW 'fapolicyd service state is unavailable'; return;
    }
    if grep -qx 'LoadState=not-found' <<< "$service"; then
        rule_result FAIL 'fapolicyd service is not installed'; return
    fi
    if grep -qx 'LoadState=loaded' <<< "$service" && grep -qx 'UnitFileState=enabled' <<< "$service" &&
       grep -qx 'ActiveState=active' <<< "$service" && grep -qx 'SubState=running' <<< "$service"; then
        rule_result PASS 'fapolicyd service is enabled and running'
    else
        rule_result FAIL 'fapolicyd service is not both enabled and running'
    fi
}

rule_V_244545_admin() {
    printf '%s\n' \
        '1. Application and security administrators: review package availability and trusted fapolicyd policy with V-244546.' \
        '2. Inventory executable and application dependencies in an isolated guest. Validate the approved compiled policy.' \
        '3. Enable and start fapolicyd with console recovery and application verification in the approved window.'
}

rule_V_230530_check() {
    local state file result
    local -a files=()
    if [[ ${ARCH-} != x86_64 ]]; then rule_result NEEDS_REVIEW 'x86 applicability is unconfirmed'; return; fi
    state=$(expanded_gui_state) || { rule_result NEEDS_REVIEW 'GUI applicability could not be established'; return; }
    case $state in
        absent) rule_result NOT_APPLICABLE 'no GUI installation was detected'; return ;;
        gnome) ;;
        *) rule_result NEEDS_REVIEW 'custom or indeterminate GUI settings require review'; return ;;
    esac
    for file in /etc/dconf/db/local.d/*; do
        [[ -e $file || -L $file ]] || continue
        if [[ -d $file && ! -L $file ]]; then continue; fi
        [[ -r $file && -f $file && ! -L $file ]] || {
            rule_result NEEDS_REVIEW 'a GNOME local keyfile is linked or unreadable'; return;
        }
        files+=("$file")
    done
    if (( ! ${#files[@]} )); then rule_result FAIL 'GNOME local database has no inspectable keyfiles'; return; fi
    result=$(awk -v empty="''" '
        FNR==1 {active=0}
        /^[[:space:]]*\[/ {line=$0; gsub(/[[:space:]]/, "", line);
            active=line=="[org/gnome/settings-daemon/plugins/media-keys]"}
        active && /^[[:space:]]*logout[[:space:]]*=/ {
            n++; line=$0; sub(/^[^=]*=[[:space:]]*/, "",line); sub(/[[:space:]]*$/, "",line); if(line==empty) valid++
        }
        END {
            if (n > 1) print "ambiguous"
            else if (n == 1 && valid == 1) print "present"
            else print "missing"
        }
    ' "${files[@]}") || { rule_result ERROR 'GNOME local keyfile parse failed'; return; }
    case $result in
        present) rule_result NEEDS_REVIEW 'the GNOME local keyfile disables logout binding; confirm the loaded database and graphical session' ;;
        ambiguous) rule_result NEEDS_REVIEW 'multiple GNOME logout definitions require profile and precedence review' ;;
        missing) rule_result FAIL 'the GNOME local policy lacks the required empty logout binding' ;;
    esac
}

rule_V_230530_admin() {
    printf '%s\n' \
        '1. Desktop administrator: verify the GNOME dconf profile and effective media-keys logout binding.' \
        '2. Set logout to the empty string in the authoritative dconf database and update it with dconf update.' \
        '3. Test the setting in an isolated graphical session and ensure no local override restores the key binding.'
}


# Narrow firewalld staging for clear existing local zone definitions. The
# operator retains control of the reload and verifies the management path.

firewall_preview_zones() {
    awk '
        /^[[:space:]]*$/ {next}
        /^[a-zA-Z0-9_-]+$/ {if (name != "" && !bound) bad=1; name=$0; bound=0; next}
        /^[[:blank:]]+interfaces:[[:blank:]]+[^[:space:]]/ {if (!bound && name != "") print name; bound=1; next}
        /^[[:blank:]]+sources:[[:blank:]]+[^[:space:]]/ {next}
        {bad=1}
        END {if (bad || (name != "" && !bound)) exit 1}
    '
}

firewall_stage_zone() {
    /usr/libexec/platform-python - "$@" <<'PYTHON'
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

path, expected = sys.argv[1:3]
data = Path(path).read_bytes()
if re.search(br'<!\s*(DOCTYPE|ENTITY)\b', data, re.I):
    sys.exit(1)

try:
    root = ET.fromstring(data)
except ET.ParseError:
    sys.exit(1)
if root.tag != 'zone' or root.get('target', 'default') != expected:
    sys.exit(1)

zones = list(re.finditer(br'(?m)^[ \t]*<zone(?=[ \t>])[^<>\r\n]*>', data))
if len(zones) != 1:
    sys.exit(1)
zone = zones[0]
tag = zone.group()
target = re.compile(br'([ \t]+target[ \t]*=[ \t]*)([\x22\x27])([^\x22\x27]*)\2')
if expected == 'default' and not target.search(tag):
    result = tag[:-1] + b' target="DROP">'
else:
    result, changes = target.subn(lambda m: m[1] + m[2] + b'DROP' + m[2], tag)
    if changes != 1:
        sys.exit(1)
updated = data[:zone.start()] + result + data[zone.end():]
expected_attrs = dict(root.attrib, target='DROP')
root.attrib.clear()
root.attrib.update(expected_attrs)
if ET.tostring(ET.fromstring(updated)) != ET.tostring(root):
    # Attribute ordering is preserved even when the original target was first.
    check = ET.fromstring(updated)
    if check.attrib != expected_attrs:
        sys.exit(1)
    check.attrib.clear()
    check.attrib.update(expected_attrs)
    if ET.tostring(check) != ET.tostring(root):
        sys.exit(1)
sys.stdout.buffer.write(updated)
PYTHON
}

firewall_validate_zone() {
    local candidate=$1 target=$2 sandbox="$EDIT_TEMP/firewalld-check" zone=${2##*/}
    local -a settings
    [[ $zone =~ ^[A-Za-z0-9_-]+\.xml$ && -f $candidate ]] || return 1
    if [[ $candidate == "$target" ]]; then
        # The installed data is checked as read-only after staging.
        timeout 20 firewall-offline-cmd --check-config >/dev/null 2>&1
        return
    fi
    if [[ ! -d $sandbox/zones ]]; then
        local file relative
        mkdir -- "$sandbox" || return 1
        while IFS= read -r -d '' file; do
            [[ $file == /etc/firewalld ]] && continue
            relative=${file#/etc/firewalld/}
            if [[ -L $file ]]; then return 1; fi
            if [[ -d $file ]]; then
                mkdir -p -- "$sandbox/$relative" || return 1
            else
                text_input_file "$file" && mkdir -p -- "$(dirname -- "$sandbox/$relative")" &&
                    cp -- "$file" "$sandbox/$relative" || return 1
            fi
        done < "$EDIT_TEMP/firewalld-paths"
    fi
    [[ -d $sandbox/zones && ! -L $sandbox/zones && ! -L $sandbox/zones/$zone ]] || return 1
    cp -- "$candidate" "$sandbox/zones/$zone" || return 1
    settings=(--system-config "$sandbox" --check-config)
    timeout 20 firewall-offline-cmd "${settings[@]}" >/dev/null 2>&1
}

firewall_tree_fingerprint() {
    local list=$1 file digest records=0
    [[ -d /etc/firewalld && ! -L /etc/firewalld && $(stat -c '%u:%g' /etc/firewalld) == 0:0 ]] || return 1
    timeout 8 find -P /etc/firewalld -xdev -print0 | sort -z > "$list" || return 1
    while IFS= read -r -d '' file; do
        (( records += 1 )); (( records <= 200 )) || return 1
        [[ ! -L $file && $file != *[[:cntrl:]]* ]] || return 1
        if [[ -f $file ]] && text_input_file "$file"; then
            digest=$(sha256_file "$file") || return 1
            printf '%s %s\n' "$file" "$digest" || return 1
        elif [[ ! -d $file ]]; then
            return 1
        fi
    done < "$list"
}

rule_V_230504_plan() {
    local active zones zone current target file candidate tree runtime permanent
    if ! have_tools firewall-cmd firewall-offline-cmd find sort || [[ ! -x /usr/libexec/platform-python ]]; then
        edit_fail 'firewalld commands and the RHEL platform Python XML parser are required'; return
    fi
    active=$(timeout 10 firewall-cmd --get-active-zones 2>/dev/null) &&
        zones=$(firewall_preview_zones <<< "$active") && [[ $zones ]] || {
        edit_fail 'active interface zones are missing or include source-only or unrecognized assignments'; return;
    }
    tree=$(firewall_tree_fingerprint "$EDIT_TEMP/firewalld-paths") || {
        edit_fail 'custom firewalld configuration contains unsupported paths or unreadable content'; return;
    }
    if ! runtime=$(timeout 15 firewall-cmd --list-all-zones 2>/dev/null) ||
       ! permanent=$(timeout 15 firewall-cmd --permanent --list-all-zones 2>/dev/null); then
        edit_fail 'runtime and permanent firewall state could not both be inspected'; return
    fi
    while IFS= read -r zone; do
        current=$(timeout 8 firewall-cmd --permanent "--zone=$zone" --list-all 2>/dev/null) || return 1
        target=$(awk '$1 == "target:" {n++; value=$2} END {if (n==1) print value; else exit 1}' <<< "$current") || return 1
        case $target in DROP) continue ;; default|ACCEPT|REJECT|'%%REJECT%%') ;; *) return 1 ;; esac
        file=/etc/firewalld/zones/$zone.xml
        if ! text_input_file "$file"; then
            edit_fail "zone $zone needs a reviewed local XML definition before staging"; return
        fi
        candidate="$EDIT_TEMP/next-firewall-$zone"
        if ! firewall_stage_zone "$file" "$target" > "$candidate"; then
            edit_fail "zone $zone XML is outside the supported source format"; return
        fi
        edit_content "$file" keep "- zone $zone target=$target
+ zone $zone target=DROP" firewall_validate_zone < "$candidate" || return
    done <<< "$zones"
    EDIT_CONTEXT=$(printf '%s\n' "$active" "$tree" "$runtime" "$permanent" | sha256sum) || return 1
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Review the existing required services and exceptions, confirm console recovery, and approve every change a full firewalld reload would activate.'
    EDIT_ACTIVATION='In the approved maintenance window, validate the full permanent policy and run firewall-cmd --reload from the console. Test a fresh management connection and required traffic, then recheck the active targets and approved exceptions.'
}


# V-230287 stages SSH private key mode changes using metadata only. OpenSSH
# validates and reloads its own keys during the separately approved activation.
standard_ssh_host_key_path() {
    case $1 in
        /etc/ssh/ssh_host_key|/etc/ssh/ssh_host_rsa_key|/etc/ssh/ssh_host_dsa_key|\
        /etc/ssh/ssh_host_ecdsa_key|/etc/ssh/ssh_host_ed25519_key) return 0 ;;
        *) return 1 ;;
    esac
}

standard_ssh_configured_key_paths() {
    local config=$1 paths path
    [[ $(expanded_ssh_topology "$config") == plain ]] || return 1
    paths=$(awk '
        /^[[:space:]]*#/ {next}
        {
            line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
            n=split(line, tokens, /[[:space:]=]+/); keyword=tolower(tokens[1]);
            if (keyword == "hostkeyagent" && (n != 2 || tokens[2] != "none")) bad=1;
            if (keyword == "hostkey") {
                if (n < 2 || (n > 2 && tokens[3] !~ /^#/)) bad=1;
                else print tokens[2];
            }
        }
        END {exit bad}
    ' "$config") || return 1
    if [[ ! $paths ]]; then
        printf '%s\n' /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ed25519_key
        return
    fi
    while IFS= read -r path; do standard_ssh_host_key_path "$path" || return 1; done <<< "$paths"
    printf '%s\n' "$paths"
}

rule_V_230287_plan() {
    local config=/etc/ssh/sshd_config invocation configured service key mode owner links size next config_hash
    local usable=0 candidates=0 active_state
    if ! edit_safe_path "$config" || ! text_input_file "$config" || ! edit_target_metadata "$config" ||
        (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
        PLAN_REASON='The SSH configuration must be the trusted, root-controlled regular file.'; return 1
    fi
    invocation=$(expanded_sshd_invocation) || {
        PLAN_REASON='The packaged SSH unit or standard service arguments could not be verified.'; return 1;
    }
    configured=$(standard_ssh_configured_key_paths "$config") || {
        PLAN_REASON='SSH includes, conditional settings, custom keys, or a key agent need authoritative review.'; return 1;
    }
    while IFS= read -r key; do
        [[ -e $key || -L $key ]] || continue
        if ! edit_safe_path "$key" || [[ ! -f $key || -L $key ]]; then
            PLAN_REASON='A configured host key is linked, nonregular or outside the reviewed layout.'; return 1
        fi
        read -r mode owner links size < <(stat -c '%a %u %h %s' -- "$key" 2>/dev/null) || return 1
        if [[ ! $mode =~ ^[0-7]{1,4}$ || $owner != 0 || $links != 1 || ! $size =~ ^[1-9][0-9]*$ ]] ||
            (( (8#$mode & 0400) == 0 )); then
            PLAN_REASON='A configured key lacks trusted ownership, a single link, owner-read mode or plausible size.'; return 1
        fi
        usable=$((usable + 1))
    done <<< "$configured"
    if (( ! usable )); then PLAN_REASON='No eligible existing default SSH host key was identified.'; return 1; fi

    service=$(timeout 8 systemctl show sshd.service --no-pager -p ActiveState -p MainPID 2>/dev/null) || return 1
    active_state=$(awk -F= '$1 == "ActiveState" {print $2}' <<< "$service") || return 1
    case $active_state in
        active|inactive|failed) ;;
        *) PLAN_REASON='SSH service state is changing or could not be identified.'; return 1 ;;
    esac
    for key in /etc/ssh/ssh_host*key; do
        [[ -e $key || -L $key ]] || continue
        mode=$(stat -c '%a' -- "$key" 2>/dev/null) || return 1
        [[ $mode =~ ^[0-7]{1,4}$ ]] || return 1
        if (( (8#$mode & 07177) == 0 )); then continue; fi
        if ! standard_ssh_host_key_path "$key" || ! edit_safe_path "$key" ||
            [[ ! -f $key || -L $key ]] || (( (8#$mode & 0400) == 0 )); then
            PLAN_REASON='A noncompliant key has a custom path, unsafe file kind, or lacks owner-read mode.'; return 1
        fi
        printf -v next '%04o' "$((8#$mode & 0600))"
        edit_metadata "$key" "$next" keep "Mode $mode -> $next. Preserve existing owner permissions." || return
        candidates=$((candidates + 1))
    done
    if (( ! candidates )); then PLAN_REASON='No standard host key needs mode tightening.'; return 1; fi
    config_hash=$(sha256_file "$config") || return 1
    EDIT_CONTEXT=$(printf '%s\n%s\n%s\n' "$invocation" "$service" "$config_hash" | sha256sum) || return 1
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Permissions change on disk immediately. Confirm privileged console recovery and dependencies on group access to the host keys. Keep the current privileged session open.'
    if [[ $active_state == active ]]; then
        EDIT_ACTIVATION='At the console, validate with sshd -t. Restart sshd.service in an approved window as specified by DISA. Verify service health and a separate new login using the expected host identity.'
    else
        EDIT_ACTIVATION='Keep the current SSH service state. Validate with sshd -t before the next approved start and verify service health and a separate new login if the service is used.'
    fi
}

# Attended edits for static repository and authoritative clock configuration.

repo_platform_python() { /usr/libexec/platform-python "$@"; }

repo_ini() {
    repo_platform_python - "$@" <<'PY'
import configparser
import re
import sys

mode, path = sys.argv[1:3]
requested = set(sys.argv[3:])
section_line = re.compile(r"^[ \t]*\[([A-Za-z0-9_.:-]+)\][ \t]*(?:\r?\n)?$")
enable_line = re.compile(r"^([ \t]*)(?i:enabled)[ \t]*=[ \t]*([01])[ \t]*(\r?\n|$)")


def config(text):
    parser = configparser.ConfigParser(interpolation=None, strict=True, empty_lines_in_values=False)
    parser.read_string(text)
    if parser.defaults() or 'DEFAULT' in parser.sections():
        raise ValueError('repository sections cannot inherit DEFAULT')
    return parser


try:
    with open(path, 'rb') as source:
        text = source.read().decode('utf-8')
    parsed = config(text)
    lines = text.splitlines(True)
    headings = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith('['):
            header = section_line.fullmatch(line)
            if not header:
                raise ValueError('unsupported repository section header')
            headings.append((header.group(1), index))
    if [name for name, _ in headings] != parsed.sections():
        raise ValueError('repository sections do not match parsed source')
    if mode == 'inventory':
        for name, _ in headings:
            print(name)
        sys.exit(0)

    def identifies_epel(section):
        return 'epel' in (section + '\n' + parsed[section].get('name', '')).lower()

    if mode == 'validate':
        if any(identifies_epel(name) and parsed[name].get('enabled') != '0' for name, _ in headings):
            raise ValueError('an EPEL definition remains enabled in the staged file')
        for name, _ in headings:
            if identifies_epel(name):
                print(name)
        sys.exit(0)
    if mode != 'render' or not requested or not requested.issubset(parsed.sections()):
        raise ValueError('repository selection does not match the local source')
    end = len(lines)
    for name, start in reversed(headings):
        if name in requested:
            if not identifies_epel(name):
                raise ValueError('repository name is dynamic or inconsistent with DNF evidence')
            value = parsed[name].get('enabled')
            if value not in (None, '1'):
                raise ValueError('unsupported enabled option or inconsistent DNF evidence')
            target = None
            if value == '1':
                for index in range(start + 1, end):
                    candidate = enable_line.fullmatch(lines[index])
                    if candidate:
                        if target is not None or candidate.group(2) != '1':
                            raise ValueError('ambiguous enabled option')
                        target = index
                if target is None:
                    raise ValueError('active enabled option is not a standalone literal')
            if target is None:
                eol = '\r\n' if lines[start].endswith('\r\n') else '\n'
                if not lines[start].endswith('\n'):
                    lines[start] += eol
                lines.insert(start + 1, 'enabled=0' + eol)
            else:
                original = lines[target]
                candidate = enable_line.fullmatch(original)
                indentation, _, eol = candidate.groups()
                eol = eol or '\n'
                lines[target:target + 1] = [
                    indentation + '# rhel8-stig V-230492 original: ' + original.rstrip('\r\n').lstrip() + eol,
                    indentation + 'enabled=0' + eol,
                ]
        end = start
    updated = ''.join(lines)
    validated = config(updated)
    if any(validated[name].get('enabled') != '0' for name in requested):
        raise ValueError('transformed enabled values were not parsed correctly')
    sys.stdout.buffer.write(updated.encode('utf-8'))
except (OSError, UnicodeError, configparser.Error, ValueError):
    sys.exit(2)
PY
}

repo_epel_rows() {
    local mode=$1 raw
    shift
    raw=$(LC_ALL=C timeout 25 dnf --cacheonly --noplugins -q --setopt=logfilelevel=0 \
        "--setopt=logdir=$EDIT_TEMP" "--setopt=cachedir=$EDIT_TEMP" "--setopt=persistdir=$EDIT_TEMP" \
        "$@" repolist "--$mode" 2>/dev/null) || return 1
    awk -v mode="$mode" '
        tolower($0) ~ /epel/ {
            if ($1 !~ /^[a-zA-Z0-9_.:-]+$/ || ++seen[$1] > 1) bad=1;
            else if (mode == "all" && $NF != "disabled") bad=1;
            else print $1;
        }
        END {if (bad) exit 2}
    ' <<< "$raw"
}

repo_validate_epel() {
    local directory staged expected
    expected=$(repo_ini validate "$1" | LC_ALL=C sort) && [[ -n $expected ]] || return 1
    directory=$(mktemp -d -- "$EDIT_TEMP/repo-validation.XXXXXXXX") || return 1
    cp -- "$1" "$directory/staged.repo" || return 1
    staged=$(repo_epel_rows all "--setopt=reposdir=$directory" | LC_ALL=C sort) && [[ $staged == "$expected" ]]
}

repo_local_layout() {
    local names alternate
    text_input_file /etc/dnf/dnf.conf || return 1
    names=$(repo_ini inventory /etc/dnf/dnf.conf) && [[ $names == main ]] || return 1
    if grep -qiE '^[[:space:]]*(include|reposdir)[[:space:]]*=' /etc/dnf/dnf.conf; then return 1; fi
    for alternate in /etc/yum/repos.d/*.repo /etc/distro.repos.d/*.repo; do
        if [[ -e $alternate || -L $alternate ]]; then return 1; fi
    done
}

rule_V_230492_plan() {
    local repo file result names diff fingerprint i=0 candidate
    local -a repo_paths=() wanted=() next=()
    local -A target=() owner=()
    if ! have_tools dnf || [[ ! -x /usr/libexec/platform-python ]]; then
        edit_fail 'the RHEL DNF command and platform Python are required for safe repository staging'; return
    fi
    if ! repo_local_layout; then
        edit_fail 'DNF uses a noncanonical global configuration or additional repository directories'; return
    fi
    if ! result=$(repo_epel_rows enabled) || [[ -z $result ]]; then
        edit_fail 'cache-only DNF did not identify any definite enabled EPEL repository'; return
    fi
    mapfile -t wanted <<< "$result"
    for repo in "${wanted[@]}"; do target[$repo]=1; done
    for file in /etc/yum.repos.d/*.repo; do
        [[ -e $file || -L $file ]] || continue
        if ! text_input_file "$file" || ! names=$(repo_ini inventory "$file"); then
            edit_fail 'a repository file is unreadable, linked, duplicated or outside the supported INI syntax'; return
        fi
        repo_paths+=("$file")
        while IFS= read -r repo; do
            [[ -n $repo && ${target[$repo]+matching} ]] || continue
            if [[ ${owner[$repo]+found} ]]; then edit_fail "repository ID $repo is duplicated"; return; fi
            owner[$repo]=$file
        done <<< "$names"
    done
    for repo in "${wanted[@]}"; do
        if [[ ! ${owner[$repo]+found} ]]; then edit_fail "enabled repository $repo lacks a supported local source"; return; fi
    done
    fingerprint=$(for file in /etc/dnf/dnf.conf "${repo_paths[@]}"; do sha256_file "$file" || exit; done) || return 1
    EDIT_CONTEXT=$(printf '%s\n%s' "$result" "$fingerprint" | sha256sum) || return 1
    EDIT_REQUIREMENTS='Confirm the EPEL definitions are locally controlled and applications can continue receiving approved updates after these repositories are disabled.'
    for file in "${repo_paths[@]}"; do
        next=()
        diff=''
        for repo in "${wanted[@]}"; do
            [[ ${owner[$repo]} == "$file" ]] || continue
            next+=("$repo")
            diff+="[$repo]: set enabled=0 in this section"
            diff+=$'\n'
        done
        (( ${#next[@]} )) || continue
        candidate="$EDIT_TEMP/repo-$i"
        if ! repo_ini render "$file" "${next[@]}" > "$candidate"; then
            edit_fail 'an EPEL definition has unsupported names, option values or continuation syntax'; return
        fi
        edit_content "$file" keep "${diff%$'\n'}" repo_validate_epel < "$candidate" || return 1
        ((i += 1))
    done
}

chrony_poll_transform() {
    awk -v mode="$2" -v preview="${3-}" '
        /^[[:space:]]*($|[#;!%])/ {if (mode=="render") print; next}
        tolower($1) ~ /^(include|confdir|sourcedir)$/ {bad=1}
        tolower($1) == "server" {
            if (NF<2) bad=1;
            rest=$0; offset=0; count=0; options=0;
            while (match(rest,/[^[:space:]]+/)) {
                token=substr(rest,RSTART,RLENGTH);
                if(token ~ /^[#;!%]/) break;
                count++; start[count]=offset+RSTART; width[count]=RLENGTH; tokens[count]=token;
                offset+=RSTART+RLENGTH-1; rest=substr(rest,RSTART+RLENGTH);
            }
            for (i=3;i<=count;i++) if (tolower(tokens[i])=="maxpoll") {
                if (++options>1 || i==count || tokens[i+1] !~ /^-?[0-9]{1,3}$/) {bad=1; continue}
                if (tokens[i+1]+0>16) {
                    ++changes;
                    if (mode=="render") {
                        if (options!=1) bad=1;
                        print "server directive at line " FNR ": maxpoll " tokens[i+1] " -> 16" > preview;
                        revised=substr($0,1,start[i+1]-1) "16" substr($0,start[i+1]+width[i+1]);
                    }
                }
                i++;
            }
            if (mode=="render" && revised!="") {
                print "# rhel8-stig V-230484 original: " $0;
                print revised; revised=""; next;
            }
        }
        mode == "render" {print}
        END {if (bad || (mode=="render" ? changes==0 : changes!=0)) exit 2}
    ' "$1"
}

chrony_authority() {
    local unit details state
    unit=$(timeout 10 systemctl show --property=FragmentPath,DropInPaths,EnvironmentFiles,Environment,ExecStart \
        chronyd.service 2>/dev/null) || return 1
    grep -Fxq 'FragmentPath=/usr/lib/systemd/system/chronyd.service' <<< "$unit" &&
        grep -Fxq 'DropInPaths=' <<< "$unit" && grep -Fxq 'Environment=' <<< "$unit" || return 1
    details=$(awk '
        /^ExecStart=/ {
            if (!match($0,/argv\[\]=[^;]*/)) exit 2;
            text=substr($0,RSTART+7,RLENGTH-7); sub(/[[:space:]]+$/, "",text); print text;
        }
        /^EnvironmentFiles=/ {print}
    ' <<< "$unit") || return 1
    # The literal $OPTIONS is expanded by systemd. The file providing it is checked below.
    # shellcheck disable=SC2016
    grep -Eq '^/usr/sbin/chronyd( -n)?( -u chrony)?( -f /etc/chrony\.conf)? \$OPTIONS$' <<< "$details" &&
        grep -Fxq 'EnvironmentFiles=/etc/sysconfig/chronyd (ignore_errors=yes)' <<< "$details" || return 1
    if [[ -e /etc/sysconfig/chronyd || -L /etc/sysconfig/chronyd ]]; then
        text_input_file /etc/sysconfig/chronyd || return 1
        state=$(awk '
            /^[[:space:]]*($|#)/ {next}
            /^[[:space:]]*OPTIONS[[:space:]]*=/ {
                if (++n>1) bad=1;
                sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]*$/, "");
                if ($0 !~ /^"(-[46]|-F[[:space:]]+[012])?"$/ && $0 !~ /^$/) bad=1;
                next
            }
            {bad=1}
            END {if(bad) exit 2; print "canonical"}
        ' /etc/sysconfig/chronyd) || return 1
        [[ $state == canonical ]] || return 1
        state=$(sha256_file /etc/sysconfig/chronyd) || return 1
    fi
    printf '%s\n%s\n' "$unit" "${state-}" | sha256sum
}

chrony_poll_validate() {
    chrony_poll_transform "$1" validate && timeout 12 chronyd -p -f "$1" >/dev/null 2>&1
}

chrony_verify_live() {
    local path=$1 approved=$2 service started conf_seconds start_seconds sources tracking
    have_tools chronyd chronyc systemctl date stat &&
        attended_policy_source "$path" && chrony_authority >/dev/null &&
        timeout 12 chronyd -p -f "$path" >/dev/null 2>&1 || return 1
    service=$(LC_ALL=C timeout 8 systemctl show chronyd.service --no-pager -p ActiveState \
        -p ExecMainStartTimestamp 2>/dev/null) || return 1
    grep -qx 'ActiveState=active' <<< "$service" || return 1
    started=$(awk '/^ExecMainStartTimestamp=/ {sub(/^[^=]*=/, ""); print}' <<< "$service") || return 1
    [[ $started ]] || return 1
    conf_seconds=$(stat -c %Y -- "$path") && start_seconds=$(LC_ALL=C date -d "$started" +%s) || return 1
    [[ $conf_seconds =~ ^[0-9]+$ && $start_seconds =~ ^[0-9]+$ ]] &&
        (( conf_seconds < start_seconds )) || return 1
    # -N retains the originally configured name and -c avoids DNS and truncation.
    sources=$(LC_ALL=C timeout 8 chronyc -c -N sources -a 2>/dev/null) || return 1
    LC_ALL=C awk -F, -v approved="$approved" '
        function canonical(name) { sub(/[.]$/, "", name); return tolower(name) }
        NF == 10 && $1 == "^" && $2 == "*" && canonical($3) == canonical(approved) &&
            $4 ~ /^[0-9]{1,2}$/ && $4 + 0 > 0 && $4 + 0 < 16 &&
            $5 ~ /^-?[0-9]{1,2}$/ && $5 + 0 <= 16 &&
            $6 ~ /^[0-7]{1,3}$/ && $6 + 0 > 0 &&
            $7 ~ /^[0-9]{1,5}$/ && $7 + 0 <= 86400 { verified++ }
        END { exit !(NR == 1 && verified == 1) }
    ' <<< "$sources" || return 1
    tracking=$(LC_ALL=C timeout 8 chronyc -n tracking 2>/dev/null) || return 1
    grep -Eq '^Leap status[[:space:]]+:[[:space:]]*Normal$' <<< "$tracking"
}

chrony_no_live_alternative() {
    local state activity
    state=$(LC_ALL=C timeout 8 systemctl show chronyd.service -p ActiveState --value 2>/dev/null) || return 1
    case $state in
        inactive) return 0 ;;
        active)
            have_tools chronyc || return 1
            activity=$(LC_ALL=C timeout 8 chronyc -c activity 2>/dev/null) || return 1
            [[ $activity == 0,0,0,0,0 ]] ;;
        *) return 1 ;;
    esac
}

chrony_render_approved_source() {
    cat -- "$1" && printf '\nserver %s iburst maxpoll 16\n' "$2"
}

chrony_approved_source_validate() {
    local candidate=$1 target=$2 approved summary expected actual
    approved=$(chrony_effective_approved_server)
    chrony_valid_approved_server "$approved" || return 1
    summary=$(chrony_config_summary "$candidate" "$approved") || return 1
    [[ $summary == '1 0 0 0 0 1 1' ]] &&
        timeout 12 chronyd -p -f "$candidate" >/dev/null 2>&1 || return 1
    if [[ $candidate == "$target" ]]; then return 0; fi
    # Before installation, bind the new directive to the unmodified target bytes.
    [[ $(chrony_config_summary "$target" "$approved") == '0 0 0 0 0 0 0' ]] &&
        chrony_no_live_alternative || return 1
    expected=$(chrony_render_approved_source "$target" "$approved" | sha256sum) &&
        actual=$(sha256sum < "$candidate") && [[ $expected == "$actual" ]]
}

rule_V_230484_plan() {
    local path=/etc/chrony.conf diff approved result validator
    local servers includes ambiguous excessive other matching matching_bounded
    if ! have_tools chronyd systemctl || ! attended_policy_source "$path" || ! EDIT_CONTEXT=$(chrony_authority); then
        edit_fail 'an authoritative vendor chronyd service and trusted regular chrony.conf are required'; return
    fi
    approved=$(chrony_effective_approved_server)
    result=$(chrony_config_summary "$path" "$approved") || {
        edit_fail 'the chrony configuration could not be inspected'; return;
    }
    read -r servers includes ambiguous excessive other matching matching_bounded <<< "$result"
    if ! timeout 12 chronyd -p -f "$path" >/dev/null 2>&1; then
        edit_fail 'the native chronyd parser rejected the existing configuration'; return
    fi
    EDIT_CONTEXT+=" approved time source=${approved:-unsupplied}"
    if (( excessive )); then
        if ! chrony_poll_transform "$path" render "$EDIT_TEMP/chrony-poll-diff" > "$EDIT_TEMP/chrony-poll"; then
            edit_fail 'chrony includes or server options do not support a verified maxpoll-only edit'; return
        fi
        diff=$(< "$EDIT_TEMP/chrony-poll-diff")
        validator=chrony_poll_validate
        EDIT_REQUIREMENTS='Confirm the current time sources are approved and coordinate with the time-service owner. This edit reduces only excessive maxpoll values.'
    else
        if (( servers || includes || ambiguous || other )); then
            edit_fail 'existing or alternate sources, includes, or source policies require review before adding an approved server'; return
        fi
        if ! chrony_valid_approved_server "$approved"; then
            edit_fail 'supply one approved time server name or address to prepare this plan'; return
        fi
        if grep -qiE '^[[:blank:]]*[#;].*(do not edit|automatically generated|managed by|ansible managed)' "$path"; then
            edit_fail 'the chrony configuration appears to be externally managed'; return
        fi
        if ! chrony_no_live_alternative; then
            edit_fail 'existing live time sources or an unverified chronyd service state require review'; return
        fi
        chrony_render_approved_source "$path" "$approved" > "$EDIT_TEMP/chrony-poll" || return 1
        diff="+ server $approved iburst maxpoll 16"
        validator=chrony_approved_source_validate
        EDIT_REQUIREMENTS='Confirm the supplied source is approved for this host and accepts this NTP configuration. Review any site authentication requirements and coordinate activation with the time-service owner.'
    fi
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Activate chronyd in the approved window. Confirm the approved authoritative source, synchronization and poll behavior with chronyc tracking and chronyc sources.'
    edit_content "$path" keep "$diff" "$validator" < "$EDIT_TEMP/chrony-poll"
}


# These handlers stage settings in a verified GNOME dconf source database.
# Compilation here uses a private copy. The administrator controls activation
# because dconf update can publish other pending source changes on the host.

desktop_profile_database() {
    local name=$1 file=$2
    awk -v profile="$name" '
        /^[[:space:]]*(#|$)/ {next}
        $0 == "user-db:user" {user++; next}
        $0 == "system-db:local" || (profile == "gdm" && $0 == "system-db:gdm") {
            if (!user) bad=1;
            system_sources++; sub(/^system-db:/, ""); database=$0; next;
        }
        profile == "gdm" && $0 == "file-db:/usr/share/gdm/greeter-dconf-defaults" {
            if (system_sources != 1) bad=1; vendor++; next;
        }
        {bad=1}
        END {if (bad || user!=1 || system_sources!=1 || vendor>1) exit 1; print database}
    ' "$file"
}

desktop_controlled_source() {
    edit_safe_path "$1" && text_input_file "$1" && edit_target_metadata "$1" &&
        (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 ))
}

desktop_source_snapshot() {
    local profile=$1 item lock name digest
    local path=/etc/dconf/profile/$profile
    if ! have_tools dconf awk cp || ! desktop_controlled_source "$path"; then
        edit_fail 'the dconf command or the root-controlled profile is unavailable'; return
    fi
    DESKTOP_DATABASE=$(desktop_profile_database "$profile" "$path") || {
        edit_fail 'the active dconf profile uses an unsupported database layout or precedence'; return;
    }
    DESKTOP_DIRECTORY=/etc/dconf/db/$DESKTOP_DATABASE.d
    if [[ ! -d $DESKTOP_DIRECTORY ]] || ! edit_safe_path "$DESKTOP_DIRECTORY" ||
       ! edit_target_metadata "$DESKTOP_DIRECTORY" || (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
        edit_fail 'the dconf source directory must already exist and be root-controlled'; return
    fi
    DESKTOP_SNAPSHOT=$EDIT_TEMP/dconf-input
    mkdir -m 0700 -- "$DESKTOP_SNAPSHOT" || return 1
    DESKTOP_FILES=()
    digest=$(sha256_file "$path") || return 1
    EDIT_CONTEXT="$DESKTOP_DATABASE $digest"
    for item in "$DESKTOP_DIRECTORY"/.[!.]* "$DESKTOP_DIRECTORY"/..?*; do
        if [[ -e $item || -L $item ]]; then
            edit_fail 'hidden dconf sources need precedence review'; return
        fi
    done
    for item in "$DESKTOP_DIRECTORY"/*; do
        [[ -e $item || -L $item ]] || continue
        name=${item##*/}
        if [[ $name == locks ]]; then
            if [[ ! -d $item ]] || ! edit_safe_path "$item" || ! edit_target_metadata "$item" ||
               (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
                edit_fail 'the dconf locks directory is outside the supported layout'; return
            fi
            mkdir -m 0700 -- "$DESKTOP_SNAPSHOT/locks" || return 1
            for lock in "$item"/*; do
                [[ -e $lock || -L $lock ]] || continue
                if ! desktop_copy_source "$lock" "locks/${lock##*/}"; then
                    edit_fail 'an unreadable, linked or excessive dconf lock source prevents validation'; return
                fi
            done
            continue
        fi
        if ! desktop_copy_source "$item" "$name"; then
            edit_fail 'an unreadable, linked or excessive dconf keyfile prevents validation'; return
        fi
        DESKTOP_FILES+=("$item")
    done
}

desktop_copy_source() {
    local path=$1 relative=$2 digest
    [[ $relative =~ ^(locks/)?[A-Za-z0-9_-][A-Za-z0-9_.-]*$ ]] &&
        (( ${#EDIT_CONTEXT} < 24000 )) && desktop_controlled_source "$path" || return 1
    digest=$(sha256_file "$path") && cp -- "$path" "$DESKTOP_SNAPSHOT/$relative" || return 1
    [[ $(sha256_file "$DESKTOP_SNAPSHOT/$relative") == "$digest" ]] || return 1
    EDIT_CONTEXT+=$'\n'"$relative $digest"
}

desktop_key_owner() {
    local section=$1 key=$2 file result
    DESKTOP_OWNER='' DESKTOP_VALUE=''
    for file in "${DESKTOP_FILES[@]}"; do
        # Keep trailing newlines so empty and duplicate assignments remain visible.
        result=$(expanded_dconf_extract "$section" "$key" "$file" && printf '.') || return 1
        result=${result%.}
        if [[ $result ]]; then
            result=${result%$'\n'}
            if [[ $DESKTOP_OWNER || $result == *$'\n'* ]]; then return 1; fi
            DESKTOP_OWNER=$file DESKTOP_VALUE=$result
        fi
    done
}

desktop_render_key() {
    local source=$1 section=$2 key=$3 value=$4 id=$5
    DESKTOP_RENDER_VALUE=$value awk -v section="$section" -v key="$key" -v id="$id" '
        function finish() {if (group==section && !found) {print key "=" value; found=1}}
        BEGIN {value=ENVIRON["DESKTOP_RENDER_VALUE"]}
        /^[[:space:]]*\[/ {
            finish(); group=$0; sub(/^[[:space:]]*\[/,"",group); sub(/\][[:space:]]*$/,"",group);
            if (group==section) sections++;
        }
        group==section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (found) {bad=1; next}
            found=1; old=$0; sub(/^[^=]*=[[:space:]]*/, "", old);
            if (old!=value) {
                match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH);
                print indent "# rhel8-stig " id " original: " substr($0,RLENGTH+1);
                print indent key "=" value; next;
            }
        }
        {print}
        END {
            finish(); if (bad || sections>1) exit 1;
            if (!sections) {if (NR) print ""; print "[" section "]"; print key "=" value}
        }
    ' "$source"
}

desktop_validate_source() {
    local staged=$1 target=$2 name=${2##*/}
    [[ $target == "$DESKTOP_DIRECTORY/$name" && $name =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*$ ]] || return 1
    cp -- "$staged" "$DESKTOP_SNAPSHOT/$name" &&
        timeout 15 dconf compile "$EDIT_TEMP/compiled.dconf" "$DESKTOP_SNAPSHOT" \
            >/dev/null 2> "$EDIT_TEMP/dconf-diagnostics" &&
        [[ -s $EDIT_TEMP/compiled.dconf && ! -s $EDIT_TEMP/dconf-diagnostics ]]
}

desktop_source_target() {
    local id=$1 hint=$2
    DESKTOP_TARGET=$hint DESKTOP_MODE=keep DESKTOP_INPUT=$hint
    if [[ ! $hint ]]; then
        DESKTOP_TARGET=$DESKTOP_DIRECTORY/90-rhel8-stig-${id,,}
        if [[ -e $DESKTOP_TARGET || -L $DESKTOP_TARGET ]]; then
            edit_fail 'the proposed dedicated dconf file already exists and has no matching setting'; return
        fi
        DESKTOP_INPUT=/dev/null DESKTOP_MODE=0644
    elif grep -q $'\r' -- "$hint"; then
        edit_fail 'the controlling dconf file uses unsupported non-LF line endings'; return
    fi
}

desktop_stage_activation() {
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm the dconf source is locally managed. Review all changes the next database update would publish.'
    EDIT_ACTIVATION=$1
}

rule_V_230226_plan() {
    local section=org/gnome/login-screen source previous expected draft enabled enabled_owner preview candidate
    desktop_source_snapshot gdm || return
    if [[ $DESKTOP_DATABASE != local ]]; then
        edit_fail 'the pinned banner check requires local.d and the active GDM profile must consume that database'; return
    fi
    expected=$(awk '/^banner-message-text=/ {sub(/^banner-message-text=/,""); print; exit}' <<< "${OFFICIAL_FIX[V-230226]}")
    [[ $expected ]] || return 1
    desktop_key_owner "$section" banner-message-text || {
        edit_fail 'multiple active banner text assignments need precedence review'; return;
    }
    source=$DESKTOP_OWNER previous=$DESKTOP_VALUE
    desktop_key_owner "$section" banner-message-enable || {
        edit_fail 'multiple active banner enable assignments need precedence review'; return;
    }
    enabled=$DESKTOP_VALUE enabled_owner=$DESKTOP_OWNER
    if [[ $source && $enabled_owner && $source != "$enabled_owner" ]]; then
        edit_fail 'banner text and enablement live in two files and need precedence review'; return
    fi
    if [[ $previous == "$expected" && $enabled == true ]]; then return 1; fi
    desktop_source_target V-230226 "${source:-$enabled_owner}" || return
    draft=$EDIT_TEMP/banner-text
    desktop_render_key "$DESKTOP_INPUT" "$section" banner-message-text "$expected" V-230226 > "$draft" &&
        desktop_render_key "$draft" "$section" banner-message-enable true V-230226 > "$draft.enabled" || return 1
    candidate=$draft.enabled
    preview=$'+ banner-message-text = exact pinned DoW consent text (see --explain V-230226)\n+ banner-message-enable=true'
    desktop_stage_activation 'After reviewing all pending desktop changes, run dconf update. Verify the exact banner is visible before a fresh graphical login.'
    if [[ ${EFFECTIVE[V-244536]+selected} ]] && desktop_key_owner "$section" disable-user-list &&
       [[ $DESKTOP_OWNER == "$DESKTOP_TARGET" && $DESKTOP_VALUE == false ]]; then
        desktop_render_key "$candidate" "$section" disable-user-list true V-244536 > "$draft.group" || return 1
        candidate=$draft.group
        preview+=$'\n- disable-user-list=false\n+ disable-user-list=true'
        EDIT_RELATED=V-244536 EDIT_GROUPED=V-244536
        EDIT_ACTIVATION+=' Confirm the greeter hides names and an authorized user can sign in by typing their username.'
    fi
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" "$preview" desktop_validate_source < "$candidate"
}

rule_V_244536_plan() {
    local section=org/gnome/login-screen
    desktop_source_snapshot gdm || return
    desktop_key_owner "$section" disable-user-list || {
        edit_fail 'multiple active login user-list assignments need precedence review'; return;
    }
    if [[ $DESKTOP_VALUE != false || ! $DESKTOP_OWNER ]]; then
        edit_fail 'no explicit false user-list policy was found in the verified GDM database'; return
    fi
    desktop_source_target V-244536 "$DESKTOP_OWNER" || return
    desktop_render_key "$DESKTOP_INPUT" "$section" disable-user-list true V-244536 > "$EDIT_TEMP/hide-users" || return 1
    desktop_stage_activation 'After reviewing pending desktop changes, run dconf update. Confirm the greeter hides names and an authorized user can still sign in by typing their username.'
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" $'- disable-user-list=false\n+ disable-user-list=true' \
        desktop_validate_source < "$EDIT_TEMP/hide-users"
}

rule_V_230352_plan() {
    local section=org/gnome/desktop/session previous seconds
    desktop_source_snapshot user || return
    desktop_key_owner "$section" idle-delay || {
        edit_fail 'multiple active GNOME idle-delay assignments need precedence review'; return;
    }
    previous=$DESKTOP_VALUE
    if [[ ! $DESKTOP_OWNER || ! $previous =~ ^uint32\ ([0-9]{1,10})$ ]]; then
        edit_fail 'this edit needs an explicit numeric idle-delay in the verified user dconf database'; return
    fi
    seconds=${BASH_REMATCH[1]}
    if (( 10#$seconds > 4294967295 || (10#$seconds && 10#$seconds <= 600) )); then
        edit_fail 'the source value is outside a valid noncompliant uint32 case'; return
    fi
    desktop_source_target V-230352 "$DESKTOP_OWNER" || return
    desktop_render_key "$DESKTOP_INPUT" "$section" idle-delay 'uint32 600' V-230352 > "$EDIT_TEMP/idle-delay" || return 1
    desktop_stage_activation 'Review pending desktop changes and run dconf update. In a fresh GNOME session, verify gsettings get org.gnome.desktop.session idle-delay and observe actual locking. Check for user overrides.'
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" "- idle-delay=$previous
+ idle-delay=uint32 600" desktop_validate_source < "$EDIT_TEMP/idle-delay"
}

# Attended signature enforcement for static DNF repositories (V-230264).

repo_gpg_ini() {
    repo_platform_python - "$@" <<'PY'
import configparser
import re
import sys

action, path = sys.argv[1:3]
wanted = set(sys.argv[3:])
section_line = re.compile(r"^[ \t]*\[([A-Za-z0-9_.:-]+)\][ \t]*(?:\r?\n)?$")
setting_line = re.compile(r"^([ \t]*)(?i:gpgcheck)[ \t]*=[ \t]*(0|1|true|false|yes|no)[ \t]*(\r?\n|$)", re.I)


def parse(source):
    parser = configparser.ConfigParser(interpolation=None, strict=True, delimiters=('=',))
    parser.read_string(source)
    if parser.defaults() or any('include' in parser[name] for name in parser.sections()):
        raise ValueError('inherited or included options')
    return parser


try:
    with open(path, 'rb') as original:
        source = original.read().decode('utf-8')
    config = parse(source)
    lines = source.splitlines(True)
    starts = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith('['):
            heading = section_line.fullmatch(line)
            if not heading:
                raise ValueError('noncanonical section heading')
            starts.append((heading.group(1), index))
    if [name for name, _ in starts] != config.sections() or not starts:
        raise ValueError('repository section mismatch')
    if action == 'inspect':
        for name, _ in starts:
            value = config[name].get('gpgcheck', '-')
            if value.lower() not in ('-', '0', '1', 'true', 'false', 'yes', 'no'):
                raise ValueError('ambiguous gpgcheck option')
            print('{}\t{}'.format(name, value))
        sys.exit(0)
    if action != 'render' or not wanted or not wanted.issubset(config.sections()):
        raise ValueError('invalid repository selection')

    end = len(lines)
    for name, index in reversed(starts):
        if name in wanted:
            previous = config[name].get('gpgcheck')
            matches = [row for row in range(index + 1, end) if setting_line.fullmatch(lines[row])]
            if previous is None:
                if matches:
                    raise ValueError('a physical gpgcheck option was parsed as a continuation')
                newline = '\r\n' if lines[index].endswith('\r\n') else '\n'
                if not lines[index].endswith('\n'):
                    lines[index] += newline
                lines.insert(index + 1, 'gpgcheck=1' + newline)
            else:
                if len(matches) != 1:
                    raise ValueError('gpgcheck is not a standalone setting')
                row = matches[0]
                indentation, value, newline = setting_line.fullmatch(lines[row]).groups()
                if value != previous or value == '1':
                    raise ValueError('unexpected gpgcheck value')
                newline = newline or '\n'
                lines[row:row + 1] = [
                    indentation + '# rhel8-stig V-230264 original: ' + lines[row].strip() + newline,
                    indentation + 'gpgcheck=1' + newline,
                ]
        end = index

    staged = ''.join(lines)
    parsed = parse(staged)
    if config.sections() != parsed.sections():
        raise ValueError('unexpected changed sections')
    for name in config.sections():
        expected = dict(config[name])
        if name in wanted:
            expected['gpgcheck'] = '1'
        if dict(parsed[name]) != expected:
            raise ValueError('unexpected changed settings')
    sys.stdout.buffer.write(staged.encode('utf-8'))
except (OSError, UnicodeError, configparser.Error, ValueError):
    sys.exit(2)
PY
}

repo_gpg_dnf() {
    repo_platform_python - "$@" <<'PY' 2>/dev/null
import re
import sys
import dnf

directory, scratch = sys.argv[1:3]
repo_id = re.compile(r'[A-Za-z0-9_.:-]+')
local_key = re.compile(r'file:///etc/pki/rpm-gpg/[A-Za-z0-9_.-]+')
with dnf.Base() as base:
    base.conf.read()
    base.conf.plugins = False
    base.conf.cacheonly = True
    base.conf.cachedir = scratch
    base.conf.persistdir = scratch
    base.conf.logdir = scratch
    base.conf.reposdir = [directory]
    # Read configuration only. Loading the sack may consult repository metadata.
    base.read_all_repos()
    for repo in sorted(base.repos.values(), key=lambda item: item.id):
        if not repo_id.fullmatch(repo.id):
            sys.exit(2)
        keys = list(repo.gpgkey)
        trusted_source = keys and all(local_key.fullmatch(key) for key in keys)
        local_paths = ','.join(key[7:] for key in keys) if trusted_source else '-'
        print('{}\t{}\t{}\t{}'.format(repo.id, int(repo.enabled), int(repo.gpgcheck), local_paths))
PY
}

repo_gpg_alternate() {
    [[ ,${GPGCHECK_ALTERNATE_REPOS-}, == *",$1,"* ]]
}

repo_gpg_fingerprints() {
    local file=$1 strict=$2 records home now
    home=$(mktemp -d -- "$EDIT_TEMP/gnupg.XXXXXXXX") && now=$(date +%s) || return 1
    if ! records=$(LC_ALL=C timeout 20 gpg --no-options --homedir "$home" --batch --no-tty \
        --no-auto-key-retrieve --with-colons --with-fingerprint --show-keys -- "$file" 2>/dev/null); then
        return 1
    fi
    awk -F: -v strict="$strict" -v now="$now" '
        $1 == "pub" {
            if (await) bad=1;
            await=1; unusable=($2 ~ /[redi]/ || ($7 != "" && $7 != "0" && $7+0 <= now)); next
        }
        $1 == "fpr" && await {
            await=0;
            if ($10 !~ /^[A-F0-9]+$/ || length($10) != 40) {bad=1; next}
            if (unusable) {if (strict) bad=1; next}
            print $10; found=1
        }
        END {if (bad || await || !found) exit 1}
    ' <<< "$records" | LC_ALL=C sort -u
}

repo_gpg_installed_keys() {
    local export_file
    export_file=$(mktemp -- "$EDIT_TEMP/installed-rpm-keys.XXXXXXXX") || return 1
    timeout 20 rpm -qa gpg-pubkey --qf '%{DESCRIPTION}\n' > "$export_file" || return 1
    repo_gpg_fingerprints "$export_file" 0
}

repo_gpg_key_evidence() {
    local key=$1 seen fingerprint owner mode
    [[ $key =~ ^/etc/pki/rpm-gpg/[a-zA-Z0-9_.-]+$ ]] && edit_safe_path "$key" && small_regular_file "$key" || return 1
    read -r owner mode < <(stat -c '%u %a' -- "$key") || return 1
    [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
    seen=$(repo_gpg_fingerprints "$key" 1) || return 1
    while IFS= read -r fingerprint; do
        grep -Fqx -- "$fingerprint" <<< "$GPGCHECK_RPM_KEYS" || return 1
    done <<< "$seen"
    printf '%s %s\n' "$key" "${seen//$'\n'/,}"
}

repo_gpg_validate_stage() {
    local path=$1 original=$2 check_directory actual record current GPGCHECK_RPM_KEYS
    check_directory=$(mktemp -d -- "$EDIT_TEMP/gpgcheck-validation.XXXXXXXX") || return 1
    cp -- "$path" "$check_directory/staged.repo" || return 1
    actual=$(repo_gpg_dnf "$check_directory" "$EDIT_TEMP") || return 1
    [[ -n $actual && $actual == "${GPGCHECK_EXPECTED[$original]-}" ]] || return 1
    GPGCHECK_RPM_KEYS=$(repo_gpg_installed_keys) || return 1
    while IFS= read -r record; do
        current=$(repo_gpg_key_evidence "${record%% *}") && [[ $current == "$record" ]] || return 1
    done <<< "${GPGCHECK_EXPECTED_KEYS[$original]-}"
}

rule_V_230264_plan() {
    local folder=/etc/yum.repos.d file id rows old key keys verified n=0
    local dnf_rows local_rows expected diff candidate fingerprint records file_keys repo_keys
    local -a files=() missing=() targets=() local_keys=()
    local -A src=() states=() dnf_key=() configuration=() active=()
    declare -gA GPGCHECK_EXPECTED=() GPGCHECK_EXPECTED_KEYS=()
    local GPGCHECK_RPM_KEYS

    if ! have_tools rpm gpg timeout || [[ ! -x /usr/libexec/platform-python ]]; then
        edit_fail 'installed RPM, GnuPG and the RHEL platform Python DNF library are needed to verify existing local keys'; return
    fi
    repo_local_layout || { edit_fail 'DNF uses an unresolved repository layout or alternative repo directory'; return; }
    dnf_rows=$(repo_gpg_dnf "$folder" "$EDIT_TEMP") && [[ -n $dnf_rows ]] || {
        edit_fail 'the local DNF library did not identify any effective repository definitions'; return;
    }
    while IFS=$'\t' read -r id old rows keys; do
        if [[ ! $id =~ ^[A-Za-z0-9_.:-]+$ || ! $old =~ ^[01]$ || ! $rows =~ ^[01]$ || ! $keys || ${states[$id]+used} ]]; then
            edit_fail 'an effective DNF repository definition is ambiguous'; return
        fi
        states[$id]=$rows dnf_key[$id]=$keys active[$id]=$old
    done <<< "$dnf_rows"

    for file in "$folder"/*.repo; do
        [[ -e $file || -L $file ]] || continue
        if ! text_input_file "$file" || ! local_rows=$(repo_gpg_ini inspect "$file"); then
            edit_fail 'a repository file could not be inspected for duplicate IDs and standalone options'; return
        fi
        files+=("$file")
        configuration[$file]=$local_rows
        while IFS=$'\t' read -r id old; do
            if [[ ! ${states[$id]+present} || ${src[$id]+duplicate} ]]; then
                edit_fail "repository $id is duplicated or its effective source does not match DNF"; return
            fi
            src[$id]=$file
        done <<< "$local_rows"
    done
    for id in "${!states[@]}"; do
        if [[ ! ${src[$id]+found} ]]; then edit_fail "repository $id lacks an authoritative static source"; return; fi
    done

    if ! GPGCHECK_RPM_KEYS=$(repo_gpg_installed_keys); then
        edit_fail 'the installed RPM signing keys could not be verified by full fingerprint'; return
    fi
    records=$(for file in /etc/dnf/dnf.conf "${files[@]}"; do sha256_file "$file" || exit 1; done) || return 1
    fingerprint=$(printf '%s\n%s\n%s' "$dnf_rows" "$records" "$GPGCHECK_RPM_KEYS" | sha256sum) || return 1
    EDIT_CONTEXT=$fingerprint

    for file in "${files[@]}"; do
        targets=() diff='' expected='' file_keys=''
        while IFS=$'\t' read -r id old; do
            rows=${states[$id]}
            if [[ ${active[$id]} == 1 && $old != 1 ]] && ! repo_gpg_alternate "$id"; then
                verified='' repo_keys=''
                if [[ ${file##*/} != redhat.repo && ${dnf_key[$id]} != - ]] &&
                   ! grep -qiE '^[[:blank:]]*[#;].*(do not edit|automatically generated|managed by)' "$file"; then
                    IFS=, read -r -a local_keys <<< "${dnf_key[$id]}"
                    for key in "${local_keys[@]}"; do
                        if ! keys=$(repo_gpg_key_evidence "$key"); then verified=''; break; fi
                        verified+="${verified:+ / }$keys"
                        repo_keys+="$keys"$'\n'
                    done
                fi
                if [[ $verified ]]; then
                    targets+=("$id")
                    diff+="[$id] gpgcheck ${old/-/(missing)} -> 1 (effective DNF value $rows -> 1); existing RPM key $verified"$'\n'
                    EDIT_CONTEXT+=$'\n'$id:$verified
                    file_keys+=$repo_keys
                    rows=1
                else
                    missing+=("$id")
                fi
            fi
            expected+="$id"$'\t'"${active[$id]}"$'\t'"$rows"$'\t'"${dnf_key[$id]}"$'\n'
        done <<< "${configuration[$file]}"
        (( ${#targets[@]} )) || continue
        candidate=$EDIT_TEMP/gpgcheck-$n
        if ! repo_gpg_ini render "$file" "${targets[@]}" > "$candidate"; then
            edit_fail "the reviewed gpgcheck settings in ${file##*/} could not be replaced independently"; return
        fi
        GPGCHECK_EXPECTED[$file]=$(LC_ALL=C sort <<< "${expected%$'\n'}") || return 1
        GPGCHECK_EXPECTED_KEYS[$file]=$(LC_ALL=C sort -u <<< "${file_keys%$'\n'}") || return 1
        edit_content "$file" keep "${diff%$'\n'}" repo_gpg_validate_stage < "$candidate" || return 1
        (( n += 1 ))
    done
    if (( ! n )); then
        edit_fail "no enabled repository needs an eligible local signature edit${missing[*]:+ (review ${missing[*]})}"; return
    fi
    EDIT_REQUIREMENTS='Confirm every displayed repository is locally managed and approved, each existing fingerprint is authorized for that source, and no approved alternate verification process applies. No key or package will be imported, changed or installed.'
    if (( ${#missing[@]} )); then
        EDIT_REQUIREMENTS+=" Separately review unmanaged definitions and unverifiable existing keys for: ${missing[*]}."
    fi
}


# Staged boot and session configuration. These rules require an individual
# decision. The script does not reboot or restart logind.

boot_defaults_args() {
    awk '
        /^[[:space:]]*($|#)/ {next}
        /^[[:space:]]*GRUB_CMDLINE_LINUX[[:space:]]*=/ {
            count++; value=$0
            sub(/^[^=]*=[[:space:]]*/, "", value); sub(/[[:space:]]*$/, "", value)
            if (value !~ /^"[^"$`\\]*"$/ && value !~ /^\047[^\047]*\047$/) bad=1;
            print substr(value,2,length(value)-2); next
        }
        /(^|[^[:alnum:]_])GRUB_CMDLINE_LINUX([[:space:]]*=|[[:space:]]|$)/ {bad=1}
        END {if (bad || count>1) exit 2; if (count==0) exit 1}
    ' "$1"
}

boot_poison_state() {
    awk '
        {
            for (i=1;i<=NF;i++) {
                if ($i ~ /^init_on_free(=|$)/) {found++; value=$i}
            }
        }
        END {
            if (found>1) print "ambiguous";
            else if (found==0) print "absent";
            else if (value=="init_on_free=1") print "enabled";
            else if (value=="init_on_free=0") print "disabled";
            else print "ambiguous";
        }
    '
}

boot_poison_args() {
    local current=$1 state
    state=$(boot_poison_state <<< "$current") || return 1
    case $state in
        disabled) printf '%s\n' "$current" |
            sed -E 's/(^|[[:blank:]])init_on_free=0([[:blank:]]|$)/\1init_on_free=1\2/' ;;
        absent) printf '%s%sinit_on_free=1\n' "$current" "${current:+ }" ;;
        enabled) printf '%s\n' "$current" ;;
        *) return 1 ;;
    esac
}

boot_static_defaults() {
    local file=$1
    bash -n -- "$file" || return 1
    awk '
        /^[[:space:]]*($|#)/ {next}
        {
            line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
            if (line !~ /^GRUB_[A-Z0-9_]+[[:space:]]*=[[:space:]]*/) exit 2
            key=line; sub(/[[:space:]]*=.*/, "", key)
            if (++keys[key]!=1) exit 2
            sub(/^[^=]*=[[:space:]]*/, "", line)
            if (key!="GRUB_CMDLINE_LINUX" && line ~ /(^|["\047[:blank:]])init_on_free(=|["\047[:blank:]]|$)/) exit 2
            if (key=="GRUB_ENABLE_BLSCFG" && line ~ /^(true|"true"|\047true\047)$/) bls=1
            if (line ~ /^[-+[:alnum:]_.,:\/@=]*$/ ||
                line ~ /^"[-+[:alnum:]_.,:\/@=[:blank:]]*"$/ ||
                line ~ /^\047[-+[:alnum:]_.,:\/@=[:blank:]]*\047$/) next
            if (key=="GRUB_DISTRIBUTOR" &&
                line=="\"$(sed \047s, release .*$,,g\047 /etc/system-release)\"") next
            exit 2
        }
        END {if (!bls || keys["GRUB_CMDLINE_LINUX"]!=1) exit 2}
    ' "$file"
}

boot_render_defaults() {
    local file=$1 current next
    current=$(boot_defaults_args "$file") && next=$(boot_poison_args "$current") || return 1
    BOOT_RENDER_ARGS=$next awk '
        /^[[:space:]]*GRUB_CMDLINE_LINUX[[:space:]]*=/ {
            prefix=$0; sub(/=.*/, "=", prefix)
            value=$0; sub(/^[^=]*=[[:space:]]*/, "", value); quote=substr(value,1,1)
            print "# STIG id V-230279 original configuration"
            print "# " $0
            print prefix quote ENVIRON["BOOT_RENDER_ARGS"] quote
            next
        }
        {print}
    ' "$file"
}

boot_defaults_validate() {
    local current
    boot_static_defaults "$1" && current=$(boot_defaults_args "$1") &&
        [[ $(boot_poison_state <<< "$current") == enabled ]]
}

boot_grubby_state() {
    awk '
        /^index=[0-9]+$/ {
            if (index_count && entries[index_value]!=1) bad=1;
            index_value=substr($0,7); index_count++;
            if (index_value in entries) bad=1;
            entries[index_value]=0; next
        }
        /^args=/ {
            if (!index_count || ++entries[index_value]!=1 || $0 !~ /^args="[^"]*"$/) {bad=1; next}
            args=substr($0,7,length($0)-7)
            ct=split(args,a,/[[:space:]]+/); found=0; value=""
            for(i=1;i<=ct;i++) if (a[i] ~ /^init_on_free(=|$)/) {found++; value=a[i]}
            if (found>1) bad=1;
            if (found!=1 || value!="init_on_free=1") missing=1;
        }
        END {
            if (bad || !index_count || entries[index_value]!=1) exit 2;
            print (missing ? "incomplete" : "enabled");
        }
    '
}

boot_grub_config() {
    local link expected resolved
    if [[ -d /sys/firmware/efi ]]; then
        link=/etc/grub2-efi.cfg expected=/boot/efi/EFI/redhat/grub.cfg
    else
        link=/etc/grub2.cfg expected=/boot/grub2/grub.cfg
    fi
    [[ -L $link ]] && resolved=$(readlink -e -- "$link") || return 1
    [[ $resolved == "$expected" && -f $resolved && ! -L $resolved && -r $resolved ]] || return 1
    printf '%s\n' "$resolved"
}

boot_grub_layout() {
    local config=$1
    grep -Fxq '### BEGIN /etc/grub.d/10_linux ###' "$config" &&
        grep -Eq '^[[:blank:]]*blscfg([[:blank:]]|$)' "$config" &&
        grep -Eq '^[[:blank:]]*load_env([[:blank:]]|$)' "$config" &&
        timeout 10 grub2-script-check "$config" >/dev/null 2>&1
}

boot_bios_grubenv_selection() {
    awk '
        /^[[:space:]]*($|#)/ {next}
        {
            line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
            if (line ~ /^load_env([[:space:]]|$)/) {
                loads++;
                if (line!="load_env" && line!="load_env -f ${config_directory}/grubenv") bad=1
            }
            if (line ~ /^set[[:space:]]+kernelopts=/) {
                if (++fallback>1 || previous!="if [ -z \"${kernelopts}\" ]; then") bad=1
            }
            if (line ~ /^(set[[:space:]]+blsdir=|unset[[:space:]]+(blsdir|kernelopts)([[:space:]]|$)|menuentry[[:space:]])/) bad=1
            if (line=="blscfg") bls++
            previous=line
        }
        END {if (bad || !loads || loads>2 || bls!=1) exit 2}
    ' "$1"
}

boot_env_kernelopts() {
    local file=$1 block size
    size=$(stat -c '%s' -- "$file") && [[ $size == 1024 ]] || return 1
    IFS= read -r block < "$file" && [[ $block == '# GRUB Environment Block' ]] || return 1
    timeout 10 grub2-editenv "$file" list 2>/dev/null | awk '
        /^[[:alnum:]_]+=/ {
            key=$0; sub(/=.*/, "", key)
            if (++counts[key]!=1 || key=="blsdir") bad=1;
            if (key=="kernelopts") print substr($0,12);
            next
        }
        {bad=1}
        END {if (bad || counts["kernelopts"]!=1) exit 2}
    '
}

boot_grubenv_validate() {
    local current effective
    current=$(boot_env_kernelopts "$1") && [[ $(boot_poison_state <<< "$current") == enabled ]] || return 1
    if [[ $1 == "$2" ]]; then
        effective=$(timeout 10 grubby --info=ALL 2>/dev/null | boot_grubby_state) &&
            [[ $effective == enabled ]]
    fi
}

boot_make_grubenv() {
    local source=$1 target=$2 current next originals staged
    current=$(boot_env_kernelopts "$source") || return 1
    [[ $current =~ ^[-+[:alnum:]_.,:/@=[:blank:]]+$ ]] || return 1
    next=$(boot_poison_args "$current") || return 1
    [[ $current != "$next" ]] || return 1
    cp -- "$source" "$target" &&
        timeout 10 grub2-editenv "$target" set "kernelopts=$next" >/dev/null 2>&1 &&
        [[ $(boot_env_kernelopts "$target") == "$next" ]] || return 1
    originals=$(timeout 10 grub2-editenv "$source" list 2>/dev/null | awk '!/^kernelopts=/ {print}' | LC_ALL=C sort) &&
        staged=$(timeout 10 grub2-editenv "$target" list 2>/dev/null | awk '!/^kernelopts=/ {print}' | LC_ALL=C sort) &&
        [[ $originals == "$staged" ]]
}

boot_bls_shared_inventory() (
    local entry dir=/boot/loader/entries count=0 mode owner digest
    boot_trusted_bls_directory "$dir" && local_filesystem "$dir" || return 1
    for entry in "$dir"/*.conf; do
        [[ $entry =~ ^/boot/loader/entries/[a-zA-Z0-9_.-]+\.conf$ && -f $entry && ! -L $entry ]] || return 1
        text_input_file "$entry" || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$entry") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        awk '
            /^[[:blank:]]*options[[:blank:]]/ {
                count++;
                if ($0 !~ /^[[:blank:]]*options[[:blank:]]+\$kernelopts([[:blank:]]+\$tuned_params)?[[:blank:]]*$/) bad=1
            }
            /^[[:blank:]]*linux[[:blank:]]+\/vmlinuz-[-.a-zA-Z0-9_]+[[:blank:]]*$/ {linux++}
            END {if (bad || count!=1 || linux!=1) exit 2}
        ' "$entry" || return 1
        digest=$(sha256_file "$entry") || return 1
        printf '%s\t%s\n' "${entry##*/}" "$digest"
        (( ++count <= 64 )) || return 1
    done
    (( count > 0 ))
)

boot_trusted_bls_directory() {
    local dir=$1 owner mode
    while [[ $dir != / ]]; do
        [[ -d $dir && ! -L $dir ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$dir") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        dir=${dir%/*}; dir=${dir:-/}
    done
}

rule_V_230279_plan() {
    local defaults=/etc/default/grub environment=/boot/grub2/grubenv config defaults_args defaults_state
    local inventory='' grubby_info effective current_environment env_state config_digest stage diff
    if ! have_tools grubby grub2-script-check readlink sed || ! text_input_file "$defaults" ||
       ! boot_static_defaults "$defaults" || ! config=$(boot_grub_config) || ! boot_grub_layout "$config" ||
       ! grubby_info=$(timeout 10 grubby --info=ALL 2>/dev/null) ||
       ! effective=$(boot_grubby_state <<< "$grubby_info"); then
        edit_fail 'an unambiguous Red Hat GRUB2/BLS configuration and effective grubby inventory are required'; return
    fi
    defaults_args=$(boot_defaults_args "$defaults") || return 1
    defaults_state=$(boot_poison_state <<< "$defaults_args") || return 1
    if [[ $defaults_state == ambiguous ]]; then
        edit_fail 'duplicate or noncanonical init_on_free settings need administrator review'; return
    fi
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm local ownership of GRUB. Reserve a recovery console and maintenance window, and consider the effect of memory clearing on performance-sensitive workloads.'
    EDIT_ACTIVATION="Review the boot entry inventory. Run grubby --update-kernel=ALL --args=init_on_free=1 and grub2-mkconfig -o $config before the planned reboot. Then verify grubby --info=ALL and /proc/cmdline."
    if [[ $defaults_state != enabled ]]; then
        stage=$EDIT_TEMP/grub-defaults
        boot_render_defaults "$defaults" > "$stage" || return 1
        diff="GRUB_CMDLINE_LINUX init_on_free ($defaults_state) -> init_on_free=1. The original assignment is retained in a comment."
        edit_content "$defaults" keep "$diff" boot_defaults_validate < "$stage" || return 1
    fi
    if [[ ! -d /sys/firmware/efi && $config == /boot/grub2/grub.cfg && $effective == incomplete ]] &&
       have_tools grub2-editenv &&
       edit_safe_path "$environment" &&
       boot_bios_grubenv_selection "$config" &&
       inventory=$(boot_bls_shared_inventory) &&
       [[ $(wc -l <<< "$inventory") == "$(grep -c '^index=' <<< "$grubby_info")" ]] &&
       current_environment=$(boot_env_kernelopts "$environment"); then
        env_state=$(boot_poison_state <<< "$current_environment") || return 1
        if [[ $env_state == absent || $env_state == disabled ]]; then
            stage=$EDIT_TEMP/grubenv
            if ! boot_make_grubenv "$environment" "$stage"; then
                edit_fail 'native grub2-editenv could not stage a verified kernelopts-only edit'; return
            fi
            diff="Shared BLS kernelopts init_on_free ($env_state) -> init_on_free=1. Other boot variables and arguments are preserved."
            edit_content "$environment" keep "$diff" boot_grubenv_validate < "$stage" || return 1
            EDIT_ACTIVATION="GRUB defaults and effective installed BLS entries are staged. Regenerate the boot menu with grub2-mkconfig -o $config during the approved maintenance window, verify the installed entries, then reboot and confirm /proc/cmdline."
        fi
    elif [[ $effective == enabled ]]; then
        EDIT_ACTIVATION='The installed boot entries already contain init_on_free=1. Verify /proc/cmdline after the next approved reboot if the live kernel still lacks this argument.'
    fi
    if (( ${#EDIT_PATHS[@]} == 0 )); then
        if [[ $effective == enabled ]]; then
            edit_fail 'persistent GRUB settings already contain init_on_free=1. Only the approved reboot and live verification remain'; return
        fi
        edit_fail "defaults already contain init_on_free=1. Follow the administrator activation steps for $config"; return
    fi
    config_digest=$(sha256_file "$config") || return 1
    EDIT_CONTEXT=$(printf '%s\n' "$config" "$config_digest" "$grubby_info" "$inventory" | sha256sum) || return 1
}

logind_257258_scope() {
    local virt code=0 sshd_state interval
    have_tools systemd-detect-virt || return 1
    virt=$(timeout 5 systemd-detect-virt --vm 2>/dev/null) || code=$?
    if (( code == 1 )) && [[ $virt == none ]]; then printf '%s\n' physical; return; fi
    (( code == 0 )) && [[ $virt =~ ^[[:alnum:]_-]+$ ]] || return 1
    if [[ ! -e /usr/sbin/sshd && ! -L /usr/sbin/sshd ]] &&
        [[ $(LC_ALL=C rpm -q openssh-server 2>/dev/null) == 'package openssh-server is not installed' ]]; then
        printf '%s\n' "$virt without openssh-server"; return
    fi
    [[ -f /etc/ssh/sshd_config && ! -L /etc/ssh/sshd_config ]] &&
        [[ $(expanded_ssh_topology /etc/ssh/sshd_config) == plain ]] &&
        sshd_state=$(expanded_sshd_invocation) || return 1
    interval=$(timeout 8 sshd -T -f /etc/ssh/sshd_config 2>/dev/null | awk '
        $1=="clientaliveinterval" && NF==2 && $2~/^[0-9]+$/ {count++; print $2}
        END {if(count!=1) exit 2}
    ') || return 1
    [[ $interval =~ ^[0-9]{1,12}$ ]] || return 1
    (( 10#$interval == 0 || 10#$interval > 600 )) || return 1
    printf '%s\n' "$virt with SSH interval $interval" "$sshd_state"
}

logind_257258_source() {
    local assembled
    have_tools systemd-analyze || return 1
    assembled=$(timeout 10 systemd-analyze --no-pager cat-config systemd/logind.conf 2>/dev/null) || return 1
    [[ ${assembled%%$'\n'*} == '# /etc/systemd/logind.conf' ]] || return 1
    [[ ${assembled#*$'\n'} == "$(< /etc/systemd/logind.conf)" ]]
}

logind_257258_idle() {
    local file=$1 mode=$2
    awk -v mode="$mode" '
        function emit() {print "StopIdleSessionSec=600"; changed=1}
        /^[[:space:]]*($|#|;)/ {
            if (mode=="render") print
            next
        }
        {
            line=$0; sub(/^[[:space:]]*/, "", line); sub(/[[:space:]]*$/, "", line)
            if (line ~ /\\$/) {bad=1; next}
            if (line ~ /^\[[[:alnum:]_-]+\]$/) {
                if (mode=="render" && section=="[Login]" && count==0) emit()
                section=line
                if (section=="[Login]") login++
            } else if (line ~ /^StopIdleSessionSec[[:space:]]*=/) {
                if (section!="[Login]" || ++count>1) bad=1
                sub(/^[^=]*=[[:space:]]*/, "", line); value=line
                if (value !~ /^(infinity|[0-9]{1,12})$/) bad=1
                if (mode=="render" && value!="600") {
                    print "# STIG id V-257258 original configuration"
                    print "# " $0; emit(); next
                }
            } else if (line !~ /^[[:alnum:]_]+[[:space:]]*=/ || section=="") bad=1
            if (mode=="render") print
        }
        END {
            if (bad || login!=1) exit 2
            if (mode=="render") {
                if (section=="[Login]" && count==0) emit()
                if (!changed) exit 2
            } else print (count==0 ? "unset" : value)
        }
    ' "$file"
}

logind_257258_package() {
    local release
    # RHBA-2024:11158 corrected unintended RHEL 8.10 session terminations.
    release=$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' systemd 2>/dev/null) || return 1
    [[ $release =~ ^239-([0-9]{1,3})\.el8_10\.([0-9]{1,4})$ ]] || return 1
    (( 10#${BASH_REMATCH[1]} > 82 ||
        (10#${BASH_REMATCH[1]} == 82 && 10#${BASH_REMATCH[2]} >= 3) )) || return 1
    printf '%s\n' "$release"
}

logind_257258_validate() {
    local candidate=$1 target=$2 root assembled
    [[ $(logind_257258_idle "$candidate" check) == 600 ]] || return 1
    if [[ $candidate == "$target" ]]; then logind_257258_source; return; fi
    root=$EDIT_TEMP/logind-native
    mkdir -p -- "$root/etc/systemd" && cp -- "$candidate" "$root/etc/systemd/logind.conf" || return 1
    assembled=$(timeout 10 systemd-analyze --root="$root" --no-pager cat-config systemd/logind.conf 2>/dev/null) || return 1
    [[ ${assembled%%$'\n'*} == '# /etc/systemd/logind.conf' ||
        ${assembled%%$'\n'*} == "# $root/etc/systemd/logind.conf" ]] &&
        [[ ${assembled#*$'\n'} == "$(< "$candidate")" ]]
}

rule_V_257258_plan() {
    local path=/etc/systemd/logind.conf scope package unit value staged=$EDIT_TEMP/logind
    if ! scope=$(logind_257258_scope); then
        edit_fail 'the cloud SSH idle-session exception could not be excluded'; return
    fi
    if ! package=$(logind_257258_package); then
        edit_fail 'verify a RHEL 8.10 systemd build with the logind correction from RHBA-2024:11158'; return
    fi
    if ! unit=$(timeout 10 systemctl show --all --property=FragmentPath,DropInPaths,ExecStart systemd-logind.service 2>/dev/null) ||
       ! grep -Fxq 'FragmentPath=/usr/lib/systemd/system/systemd-logind.service' <<< "$unit" ||
       ! grep -Fxq 'DropInPaths=' <<< "$unit" ||
       ! grep -Eq '^ExecStart=.*argv\[\]=/usr/lib/systemd/systemd-logind[[:blank:]]+;' <<< "$unit"; then
        edit_fail 'an unmodified vendor logind service is required'; return
    fi
    if ! text_input_file "$path" || ! logind_257258_source ||
       ! value=$(logind_257258_idle "$path" check) ||
       ! logind_257258_idle "$path" render > "$staged"; then
        edit_fail 'logind configuration has drop-ins, unsupported syntax or no pending edit'; return
    fi
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm active users and automation can tolerate idle-session termination. Retain working console access and arrange a maintenance window.'
    EDIT_ACTIVATION='During the approved window, use systemctl restart systemd-logind.service and verify a fresh supported session terminates after 600 seconds idle.'
    EDIT_CONTEXT=$(printf '%s\n' "$scope" "$package" "$unit" | sha256sum) || return 1
    edit_content "$path" keep "StopIdleSessionSec changes from $value to 600 in [Login]." logind_257258_validate < "$staged"
}


# Restrict the write paths to unambiguous local interactive accounts. A broader
# account classification can still produce a finding through the ordinary check.
attended_account_rows() {
    local minimum
    minimum=$(expanded_uid_min /etc/login.defs) && [[ $minimum =~ ^[1-9][0-9]{0,5}$ ]] || return 1
    awk -F: -v minimum="$minimum" '
        NF!=7 || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ {bad=1; next}
        {names[$1]++; ids[$3]++; if ($6 ~ /^\/home\//) homes[$6]++}
        $3 >= minimum && $3 != 65534 && $7 ~ /\/(bash|sh)$/ &&
            $1 ~ /^[a-zA-Z_][a-zA-Z0-9_.@-]*$/ &&
            $6 ~ /^\/home\/[a-zA-Z0-9_.@-]+$/ && $6 != "/home/." && $6 != "/home/.." {
                users[++n]=$1; uid[n]=$3; gid[n]=$4; home[n]=$6; shell[n]=$7
        }
        END {
            if (bad) exit 1
            for (i=1;i<=n;i++)
                if (names[users[i]]==1 && ids[uid[i]]==1 && homes[home[i]]==1)
                    printf "%s\t%s\t%s\t%s\t%s\n", users[i],uid[i],gid[i],home[i],shell[i]
        }
    ' /etc/passwd
}

attended_home_account() {
    local rows
    rows=$(attended_account_rows) || return 1
    awk -F '\t' -v path="$1" '$4==path {print; n++} END {exit n!=1}' <<< "$rows"
}

attended_group_exists() {
    awk -F: -v gid="$1" 'NF==4 && $3==gid {n++} END {exit n!=1}' /etc/group
}

# Use descriptors for home operations. A user can rename paths inside a home
# while the plan runs. Never follow links or cross a mount, including bind
# mounts on the same device. Metadata changes pin the checked inode.
attended_home_tool() {
    have_tools python3 || return 1
    timeout --kill-after=2s 20s python3 -I - "$@" <<'PYTHON'
import os
import re
import stat
import subprocess
import sys

SAFE = re.compile(r"^[A-Za-z0-9_.@-]+$")
O_PATH = os.O_PATH | os.O_NOFOLLOW


def mount_id(fd):
    with open("/proc/self/fdinfo/{}".format(fd)) as info:
        for line in info:
            if line.startswith("mnt_id:"):
                return line.split()[1]
    raise ValueError("Mount identity unavailable")


def local_mount(fd):
    identity = mount_id(fd)
    with open("/proc/self/mountinfo") as info:
        for line in info:
            fields, options = line.split(" - ", 1)
            if fields.split()[0] == identity:
                return options.split()[0] in ("xfs", "ext2", "ext3", "ext4", "btrfs")
    return False


def info(fd):
    return os.fstat(fd)


def state(fd):
    value = info(fd)
    return "{}:{}:{:04o}:{}:{}:{}".format(value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode),
                                          value.st_dev, value.st_ino, value.st_mtime_ns)


def read_fd(fd):
    value = info(fd)
    if not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)):
        raise ValueError("Unsupported node")
    return os.open("/proc/self/fd/{}".format(fd), os.O_RDONLY | os.O_NONBLOCK)


def plain_attributes(fd):
    return not set(os.listxattr(fd)).intersection(("system.posix_acl_access", "system.posix_acl_default",
                                                  "security.capability"))


def open_child(parent, name):
    if name in (".", "..") or not SAFE.fullmatch(name):
        raise ValueError("Unsupported path")
    fd = os.open(name, O_PATH, dir_fd=parent)
    if mount_id(fd) != mount_id(parent) or stat.S_ISLNK(info(fd).st_mode):
        os.close(fd)
        raise ValueError("Link or nested mount")
    return fd


def locate(parent, parts):
    fd = os.dup(parent)
    try:
        for name in parts:
            child = open_child(fd, name)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def home_operation(parent, name, operation, expected, desired):
    try:
        fd = open_child(parent, name)
    except FileNotFoundError:
        fd = None
    actual = "absent" if fd is None else state(fd)
    if fd is not None and not stat.S_ISDIR(info(fd).st_mode):
        raise ValueError("Object at home path is not a directory")
    if operation == "home-observe":
        print(actual)
    elif expected != actual:
        raise ValueError("Home changed after review")
    elif operation == "home-create" and actual == "absent":
        uid, gid, mode = desired.split(":")
        if mode != "0750" or not uid.isdigit() or not gid.isdigit() or int(uid) == 0:
            raise ValueError("Invalid home ownership or permissions")
        os.mkdir(name, 0o700, dir_fd=parent)
        fd = open_child(parent, name)
        try:
            label = subprocess.check_output(["getenforce"], timeout=4).strip()
            if label in (b"Enforcing", b"Permissive"):
                path = "/home/" + name
                subprocess.check_call(["restorecon", "-F", "--", path], timeout=8)
                subprocess.check_call(["matchpathcon", "-V", path], timeout=5, stdout=subprocess.DEVNULL)
            elif label != b"Disabled":
                raise ValueError("Unknown SELinux state")
            action = read_fd(fd)
            try:
                if not plain_attributes(action):
                    raise ValueError("Unexpected inherited ACL")
                os.fchown(action, int(uid), int(gid))
                os.fchmod(action, 0o750)
            finally:
                os.close(action)
        except Exception:
            os.rmdir(name, dir_fd=parent)  # Removes it only if still empty.
            raise
    elif operation == "home-remove" and desired == "absent":
        os.rmdir(name, dir_fd=parent)
    else:
        raise ValueError("Unexpected home operation")
    if fd is not None:
        os.close(fd)


def mode_state(fd, uid):
    value = info(fd)
    if (not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode)) or
            value.st_uid not in (0, uid) or (stat.S_ISREG(value.st_mode) and value.st_nlink != 1)):
        raise ValueError("Unsupported owner, node or hard link")
    return state(fd)


def walk(fd, path, uid, budget, depth):
    if depth > 32:
        raise ValueError("Home depth limit")
    with os.scandir("/proc/self/fd/{}".format(fd)) as entries:
        for entry in entries:
            budget[0] -= 1
            if budget[0] < 0:
                raise ValueError("Home inventory limit")
            if entry.name.startswith("."):
                continue
            child_path = path + "/" + entry.name
            try:
                child = open_child(fd, entry.name)
            except (OSError, ValueError):
                print("gap")
                continue
            try:
                raw = info(child)
                if stat.S_ISREG(raw.st_mode) or stat.S_ISDIR(raw.st_mode):
                    mode = stat.S_IMODE(raw.st_mode)
                    if mode & ~0o750:
                        try:
                            before = mode_state(child, uid)
                            wanted = before.split(":")
                            wanted[2] = "{:04o}".format(mode & 0o750)
                            action = read_fd(child)
                            try:
                                if not plain_attributes(action):
                                    raise ValueError("Extended ACL or file capability")
                            finally:
                                os.close(action)
                            print("mode\t{}\t{}\t{}".format(child_path, before, ":".join(wanted)))
                        except (OSError, ValueError):
                            print("blocked")
                    if stat.S_ISDIR(raw.st_mode):
                        walk(child, child_path, uid, budget, depth + 1)
                else:
                    print("gap")
            finally:
                os.close(child)


def main():
    operation, path, user_id = sys.argv[1:4]
    parts = path.split("/")
    if len(parts) < 3 or parts[:2] != ["", "home"]:
        raise ValueError("Unexpected home path")
    parts = parts[2:]
    uid = int(user_id)
    if uid <= 0:
        raise ValueError("Expected a local non-root owner")
    parent = os.open("/home", O_PATH | os.O_DIRECTORY)
    root = info(parent)
    if root.st_uid != 0 or root.st_mode & 0o022 or not local_mount(parent):
        raise ValueError("Parent must be root-controlled local storage")
    if operation in ("home-observe", "home-create", "home-remove") and len(parts) == 1:
        home_operation(parent, parts[0], operation, *sys.argv[4:])
        return
    home = open_child(parent, parts[0])
    if not stat.S_ISDIR(info(home).st_mode) or info(home).st_uid not in (0, uid):
        raise ValueError("Unexpected local home owner")
    if operation == "inventory" and len(parts) == 1:
        walk(home, path, uid, [20000], 0)
        return
    if operation in ("home-mode-observe", "home-mode-change") and len(parts) == 1:
        target = os.dup(home)
        operation = operation[5:]
    elif operation in ("init-mode-observe", "init-mode-change") and len(parts) == 2:
        startup_files = (".bash_profile", ".bash_login", ".bashrc", ".bash_logout", ".profile",
                         ".cshrc", ".tcshrc", ".login", ".logout", ".kshrc", ".zprofile",
                         ".zshrc", ".zlogin", ".zlogout")
        if parts[1] not in startup_files:
            raise ValueError("Excluded initialization file")
        target = locate(home, parts[1:])
        if not stat.S_ISREG(info(target).st_mode):
            raise ValueError("Initialization object is not a file")
        operation = operation[5:]
    else:
        if len(parts) < 2 or any(part.startswith(".") for part in parts):
            raise ValueError("Excluded path")
        target = locate(home, parts[1:])
    actual = mode_state(target, uid)
    fd = read_fd(target)
    if not plain_attributes(fd):
        raise ValueError("Extended ACL or file capability")
    if operation == "mode-observe":
        print(actual)
        return
    expected, desired = sys.argv[4:]
    new = desired.split(":")
    old = expected.split(":")
    if operation != "mode-change" or expected != actual or len(old) != 6 or len(new) != 6:
        raise ValueError("Mode state changed after review")
    if new[:2] != old[:2] or new[3:] != old[3:] or not re.fullmatch(r"[0-7]{4}", new[2]):
        raise ValueError("Invalid metadata transition")
    if state(fd) != actual:
        raise ValueError("Pinned file changed after review")
    os.fchmod(fd, int(new[2], 8))


try:
    main()
except (OSError, ValueError, subprocess.SubprocessError):
    sys.exit(1)
PYTHON
}

rule_V_230323_observe() {
    local row owner
    row=$(attended_home_account "$1") || return 1
    IFS=$'\t' read -r _ owner _ _ _ <<< "$row"
    attended_home_tool home-observe "$1" "$owner" '' ''
}

rule_V_230323_plan() {
    local rows login owner group home shell current
    if ! have_tools python3 getenforce; then edit_fail 'missing Python 3 or SELinux tools'; return; fi
    rows=$(attended_account_rows) || return 1
    while IFS=$'\t' read -r login owner group home shell; do
        [[ $login && $shell ]] || continue
        current=$(rule_V_230323_observe "$home") || continue
        if [[ $current != absent ]] || ! attended_group_exists "$group"; then continue; fi
        action_add "$home" absent "$owner:$group:0750" 'missing' \
            "create an empty 0750 directory for $login ($owner:$group), with the native SELinux label" || return 1
    done <<< "$rows"
    ACTION_REQUIREMENTS='Confirm local account ownership and site home provisioning. This creates empty directories.'
}

rule_V_230323_change() {
    local row owner group
    row=$(attended_home_account "$1") || return 1
    IFS=$'\t' read -r _ owner group _ _ <<< "$row"
    [[ $3 == "$owner:$group:0750" ]] && attended_group_exists "$group" || return 1
    attended_home_tool home-create "$1" "$owner" "$2" "$3"
}

rule_V_230323_matches() { [[ $1 == "$2":* ]]; }

rule_V_230323_restore() {
    local row owner
    [[ $2 == absent ]] || return 1
    row=$(attended_home_account "$1") || return 1
    IFS=$'\t' read -r _ owner _ _ _ <<< "$row"
    attended_home_tool home-remove "$1" "$owner" "$3" "$2"
}

rule_V_230367_observe() {
    local target=$1 rows owner
    [[ $target =~ ^[a-zA-Z_][a-zA-Z0-9_.@-]*$ ]] || return 1
    rows=$(attended_account_rows) && owner=$(awk -F '\t' -v name="$target" \
        '$1==name {print $2; n++} END {exit n!=1}' <<< "$rows") || return 1
    awk -F: -v name="$target" -v uid="$owner" '
        $1==name {
            if (++n!=1 || NF!=9 || $3 !~ /^[0-9]{1,9}$/ || ($5!="" && $5 !~ /^-?[0-9]{1,9}$/)) bad=1
            last=$3; maximum=$5=="" ? -1 : $5+0
        }
        END {if (bad || n!=1) exit 1; printf "%d:%d:%d\n", uid,last,maximum}
    ' /etc/shadow
}

rule_V_230367_plan() {
    local rows login owner group home shell state last maximum today note
    have_tools chage || { edit_fail 'chage is unavailable'; return; }
    rows=$(attended_account_rows) && today=$(date -u +%s) || return 1
    today=$(( today / 86400 ))
    while IFS=$'\t' read -r login owner group home shell; do
        [[ $login && $group && $home && $shell ]] || continue
        state=$(rule_V_230367_observe "$login") || continue
        IFS=: read -r owner last maximum <<< "$state"
        if (( maximum >= 1 && maximum <= 180 )); then continue; fi
        note=''
        if (( last == 0 || last + 180 <= today )); then note=' (password expiry can take effect immediately)'; fi
        action_add "$login" "$state" "$owner:$last:180" "maximum password age $maximum days" \
            "maximum password age 180 days$note" || return 1
    done <<< "$rows"
    ACTION_REQUIREMENTS='Confirm affected local accounts and acceptance of any immediately expiring passwords.'
}

rule_V_230367_change() {
    [[ $(rule_V_230367_observe "$1") == "$2" && $3 == "${2%:*}:180" ]] || return 1
    timeout 10 chage -M 180 -- "$1" >/dev/null 2>&1
}

rule_V_230367_restore() {
    local old=${2##*:}
    [[ $old =~ ^(-1|[0-9]{1,9})$ && ${2%:*} == "${3%:*}" && $(rule_V_230367_observe "$1") == "$3" ]] ||
        return 1
    timeout 10 chage -M "$old" -- "$1" >/dev/null 2>&1
}

attended_umask_render() {
    awk '
        /^[[:space:]]*umask[[:space:]]+[0-7]{1,4}([[:space:]]*|[[:space:]]+#.*)$/ {
            bits=$2; sub(/^0+/,"",bits)
            if (length(bits)<2 || substr(bits,length(bits)-1)!="77") {
                print "# STIG V-230384 prior: " $0
                print "umask 077"
                next
            }
        }
        {print}
    ' "$1"
}

attended_umask_validate() {
    local counts bad unknown
    bash -n -- "$1" 2>/dev/null && counts=$(expanded_literal_umask "$1") || return 1
    read -r bad unknown _ <<< "$counts"
    [[ $bad == 0 && $unknown == 0 ]]
}

rule_V_230384_plan() {
    local rows login owner group home shell path counts bad unknown candidate before proposed
    rows=$(attended_account_rows) || return 1
    candidate=$EDIT_TEMP/umask
    while IFS=$'\t' read -r login owner group home shell; do
        if [[ ! $login || ! $owner || ! $group || ! $shell =~ /bash$ ]] ||
           ! expanded_home_path_safe "$home"; then continue; fi
        for path in "$home"/{.bash_profile,.bash_login,.profile,.bashrc}; do
            if ! edit_safe_path "$path" || ! text_input_file "$path" || ! edit_target_metadata "$path"; then
                continue
            fi
            counts=$(expanded_literal_umask "$path") || return 1
            read -r bad unknown _ <<< "$counts"
            if (( ! bad || unknown )); then continue; fi
            before=$(awk '
                /^[[:space:]]*umask[[:space:]]+[0-7]{1,4}([[:space:]]*|[[:space:]]+#.*)$/ {
                    bits=$2; sub(/^0+/,"",bits)
                    if (length(bits)<2 || substr(bits,length(bits)-1)!="77") print "- umask " $2 "\n+ umask 077"
                }
            ' "$path") || return 1
            attended_umask_render "$path" > "$candidate" || return 1
            proposed="Root-managed startup file $path"$'\n'"$before"
            edit_content "$path" keep "$proposed" attended_umask_validate < "$candidate" || return 1
        done
    done <<< "$rows"
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm root-managed files and authorized application exceptions. User-managed or compound shell sources require review.'
    EDIT_ACTIVATION='Verify umask 077 in fresh interactive logins and review other startup sources.'
}

attended_home_mode_inventory() {
    local rows login owner group home shell
    rows=$(attended_account_rows) || return 1
    while IFS=$'\t' read -r login owner group home shell; do
        [[ $login && $group && $shell ]] || continue
        attended_home_tool inventory "$home" "$owner" || printf '%s\n' gap
    done <<< "$rows"
}

rule_V_244531_check() {
    local sample
    if (( EUID != 0 )) || ! have_tools python3; then
        rule_result NEEDS_REVIEW 'Root and Python 3 are required for the guarded local home mode inventory'; return
    fi
    sample=$(attended_home_mode_inventory) ||
        { rule_result NEEDS_REVIEW 'Local account inventory could not be verified'; return; }
    if [[ $sample =~ (^|$'\n')(mode$'\t'|blocked) ]]; then
        rule_result FAIL 'Verified local home entries exceed 0750. Complex ACLs, links and mount boundaries require separate review.'
    else
        rule_result NEEDS_REVIEW 'No violations in the bounded eligible home scan. Review account coverage and excluded entries.'
    fi
}

rule_V_244531_plan() {
    local sample kind target before desired oldmode newmode
    sample=$(attended_home_mode_inventory) || return 1
    while IFS=$'\t' read -r kind target before desired; do
        [[ $kind == mode ]] || continue
        IFS=: read -r _ _ oldmode _ <<< "$before"
        IFS=: read -r _ _ newmode _ <<< "$desired"
        action_add "$target" "$before" "$desired" "mode $oldmode" "mode $newmode" || return 1
    done <<< "$sample"
    ACTION_REQUIREMENTS='Confirm the selected mode reductions with the owners. Hidden entries, ACLs, hard links and mount crossings are excluded.'
}

attended_mode_action() {
    local operation=$1 target=$2 home rest row owner
    rest=${target#/home/}
    home=/home/${rest%%/*}
    [[ $target == "$home"/* ]] || return 1
    row=$(attended_home_account "$home") || return 1
    IFS=$'\t' read -r _ owner _ _ _ <<< "$row"
    attended_home_tool "$operation" "$target" "$owner" "${3:-}" "${4:-}"
}

rule_V_244531_observe() { attended_mode_action mode-observe "$1"; }
rule_V_244531_change() { attended_mode_action mode-change "$@"; }
rule_V_244531_restore() { attended_mode_action mode-change "$1" "$3" "$2"; }


# Stage only the intended smart-card settings. SSSD and authselect activation
# stay under the operator's control, with an independent recovery login open.

identity_authselect_smartcard() {
    local current
    have_tools authselect || return 1
    timeout 10 authselect check >/dev/null 2>&1 || return 1
    current=$(timeout 10 authselect current -r 2>/dev/null) || return 1
    [[ $current =~ ^(sssd|custom/[A-Za-z0-9_][A-Za-z0-9_.-]*)([\ ][A-Za-z0-9_][A-Za-z0-9_-]*)*$ ]] || return 1
    case " $current " in
        *' with-smartcard '*|*' with-smartcard-required '*) printf '%s\n' "$current" ;;
        *) return 1 ;;
    esac
}

identity_sssd_secret_file() {
    edit_safe_path "$1" && text_input_file "$1" && edit_target_metadata "$1" &&
        [[ $EDIT_ORIGINAL_MODE == 600 && $EDIT_ORIGINAL_GROUP == 0 ]]
}

# Record both snippet membership and bytes. Copy only the verified inputs to
# the protected plan directory used by sssctl, never to the live conf.d.
identity_sssd_snippets() {
    local directory=$1 file name digest snippet_total=0
    if [[ ! -e $directory && ! -L $directory ]]; then return 0; fi
    [[ -d $directory ]] && edit_safe_path "$directory" && edit_target_metadata "$directory" &&
        (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 )) || return 1
    for file in "$directory"/*.conf; do
        [[ -e $file || -L $file ]] || continue
        name=${file##*/}
        [[ $name =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*\.conf$ ]] || return 1
        (( ++snippet_total <= 32 )) && identity_sssd_secret_file "$file" || return 1
        digest=$(sha256_file "$file") || return 1
        printf '%s %s\n' "$name" "$digest"
    done
}

identity_sssd_native_check() {
    local source=$1 parent=${2%/*} observed snippets
    local snapshot=$EDIT_TEMP/sssd-input candidate=$EDIT_TEMP/sssd-candidate.conf
    observed=$(identity_sssd_snippets "$parent/conf.d") || return 1
    [[ $observed == "$(< "$snapshot/manifest")" ]] || return 1
    snippets=$(awk 'NF {n++} END {print n+0}' "$snapshot/manifest") || return 1
    cp -- "$source" "$candidate" && chmod 0600 -- "$candidate" || return 1
    timeout 15 sssctl config-check -c "$candidate" -s "$snapshot/conf.d" \
        > "$snapshot/check-result" 2>&1 || return 1
    # Some SSSD builds print validation issues with a successful exit status.
    awk -v expected="$snippets" '
        /^Issues identified by validators:/ {i++; if ($NF != "0") bad=1}
        /^Messages generated during configuration merging:/ {m++; if ($NF != "0") bad=1}
        /^Used configuration snippet files:/ {s++; if ($NF != expected) bad=1}
        END {exit (i != 1 || m != 1 || s != 1 || bad)}
    ' "$snapshot/check-result"
}

identity_sssd_snapshot() {
    local base=$1 directory=${1%/*}/conf.d
    local snapshot=$EDIT_TEMP/sssd-input snippets file digest
    local -a copies=()
    if ! have_tools sssctl systemctl awk cp sha256sum ||
       ! timeout 10 systemctl is-active --quiet sssd.service ||
       ! identity_sssd_secret_file "$base"; then
        edit_fail 'an active SSSD service, sssctl and a regular root:root mode 0600 base configuration are required'; return;
    fi
    [[ ! -s $base ]] && { edit_fail 'the SSSD base configuration is empty'; return; }
    IDENTITY_AUTHSELECT=$(identity_authselect_smartcard) || {
        edit_fail 'a validated active SSSD authselect profile with an existing smart-card feature is required'; return;
    }
    mkdir -m 0700 -- "$snapshot" "$snapshot/conf.d" || return 1
    snippets=$(identity_sssd_snippets "$directory") || {
        edit_fail 'the SSSD snippet set is unreadable, untrusted or outside the supported layout'; return;
    }
    printf '%s\n' "$snippets" > "$snapshot/manifest" || return 1
    while read -r file digest; do
        [[ $file ]] || continue
        cp -- "$directory/$file" "$snapshot/conf.d/$file" &&
            chmod 0600 -- "$snapshot/conf.d/$file" &&
            [[ $(sha256_file "$snapshot/conf.d/$file") == "$digest" ]] || return 1
        copies+=("$snapshot/conf.d/$file")
    done <<< "$snippets"
    digest=$(sha256_file "$base") || return 1
    IDENTITY_BASE_VALUES=$(parse_sensitive_sssd_assignments "$base") &&
        IDENTITY_SNIPPET_VALUES=$(parse_sensitive_sssd_assignments "${copies[@]}") &&
        identity_sssd_native_check "$base" "$base" &&
        [[ $(sha256_file "$base") == "$digest" ]] || {
        edit_fail 'the existing SSSD configuration or its snippets failed validation'; return;
    }
    EDIT_CONTEXT=$(printf '%s\n%s\n%s\n' "$IDENTITY_AUTHSELECT" "$digest" "$snippets" | sha256sum)
}

# Read one authoritative value. Conflicting, duplicate or misplaced instances
# require review because they can change which value SSSD actually uses.
identity_sssd_option() {
    local section=$1 key=$2 value
    if awk -F '\t' -v key="$key" '$2 == key {found=1} END {exit !found}' <<< "$IDENTITY_SNIPPET_VALUES"; then
        edit_fail "an SSSD snippet supplies $key; review precedence and the authoritative owner"; return
    fi
    value=$(awk -F '\t' -v section="$section" -v key="$key" '
        $2 == key {if ($1 != section) bad=1; value=$3; count++}
        END {if (bad || count>1) exit 1; if (count) printf "%s.", value}
    ' <<< "$IDENTITY_BASE_VALUES") || {
        edit_fail "duplicate or misplaced $key needs SSSD precedence review"; return;
    }
    IDENTITY_PRESENT=$value
    IDENTITY_OLD=${value%.}
}

identity_sssd_cache_active() {
    printf '%s\n%s\n' "$IDENTITY_BASE_VALUES" "$IDENTITY_SNIPPET_VALUES" |
        awk -F '\t' '
            $1 == "sssd" && $2 == "domains" {domains=$3; lists++}
            $1 ~ /^domain\// && $2 == "cache_credentials" {
                name=substr($1, 8); value=tolower($3)
                if (name !~ /^[A-Za-z0-9_.-]+$/ || seen[name]++ ||
                    (value != "true" && value != "false")) bad=1
                if (value == "true") cached[name]=1
            }
            END {
                if (lists != 1 || bad || !domains) exit 1
                count=split(domains, names, /[[:space:]]*,[[:space:]]*/)
                for (i=1; i<=count; i++) {
                    name=names[i]; if (name !~ /^[A-Za-z0-9_.-]+$/ || selected[name]++) exit 1
                    if (cached[name]) enabled=1
                }
                exit !enabled
            }
        '
}

identity_sssd_render() {
    local source=$1 section=$2 key=$3 value=$4 id=$5
    awk -v section="$section" -v key="$key" -v value="$value" -v id="$id" '
        function finish_section() {
            if (current == section && !inserted) {print key " = " value; inserted=1}
        }
        /^[[:space:]]*\[/ {
            finish_section(); current=$0; sub(/^[[:space:]]*\[/,"",current); sub(/\][[:space:]]*$/,"",current);
            if (current == section) matches++;
        }
        current == section && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (inserted) {bad=1; next}
            match($0,/^[[:space:]]*/); indent=substr($0,1,RLENGTH);
            print "# rhel8-stig " id " original: " $0;
            print indent key " = " value; inserted=1; next
        }
        {print}
        END {
            if (bad || matches>1) exit 1
            finish_section()
            if (!matches) {print ""; print "[" section "]"; print key " = " value}
        }
    ' "$source"
}

identity_plan_sssd_value() {
    local id=$1 ocsp
    IDENTITY_SECTION=pam
    case $id in
        V-230274)
            IDENTITY_SECTION=sssd IDENTITY_KEY=certificate_verification IDENTITY_VALUE=ocsp_dgst=sha1
            identity_sssd_option "$IDENTITY_SECTION" "$IDENTITY_KEY" || return
            # Only replace known digest or bypass options. Additional PKI
            # policy and responder overrides have their own site semantics.
            ocsp='(ocsp_dgst=sha(1|224|256|384|512)|no_ocsp|no_verification|soft_ocsp)'
            if [[ $IDENTITY_PRESENT && ! $IDENTITY_OLD =~ ^$ocsp([[:space:]]*,[[:space:]]*$ocsp)*$ ]]; then
                edit_fail 'certificate_verification contains a value outside the reviewed digest/bypass options'; return
            fi ;;
        V-230372)
            identity_sssd_option sssd certificate_verification || return
            if [[ $IDENTITY_PRESENT && ! $IDENTITY_OLD =~ ^ocsp_dgst=sha(1|224|256|384|512)$ ]]; then
                edit_fail 'resolve the existing certificate-verification override before staging smart-card authentication'; return
            fi
            IDENTITY_KEY=pam_cert_auth IDENTITY_VALUE=True
            identity_sssd_option "$IDENTITY_SECTION" "$IDENTITY_KEY" || return
            if [[ $IDENTITY_PRESENT && ! ${IDENTITY_OLD,,} =~ ^(true|false)$ ]]; then
                edit_fail 'pam_cert_auth is outside the supported Boolean form'; return
            fi ;;
        V-230376)
            IDENTITY_KEY=offline_credentials_expiration IDENTITY_VALUE=1
            identity_sssd_cache_active || {
                edit_fail 'an unambiguous active SSSD domain with explicitly enabled caching is required'; return;
            }
            identity_sssd_option "$IDENTITY_SECTION" "$IDENTITY_KEY" || return
            if [[ $IDENTITY_PRESENT && ! $IDENTITY_OLD =~ ^[0-9]{1,9}$ ]]; then
                edit_fail 'offline_credentials_expiration is outside the supported integer form'; return
            fi ;;
        *) return 1 ;;
    esac
}

identity_authselect_stack() {
    local raw=$1 stack=$2
    local -a args
    read -r -a args <<< "$raw"
    case $stack in system-auth|smartcard-auth) ;; *) return 1 ;; esac
    timeout 10 authselect test "${args[0]}" "--$stack" "${args[@]:1}" 2>/dev/null
}

identity_render_pam_cert() {
    local source=$1 stack=$2 mode=$3
    awk -v stack="$stack" -v mode="$mode" '
        BEGIN {
            if (stack=="system-auth") control="\\[success=done[[:space:]]+authinfo_unavail=ignore[[:space:]]+ignore=ignore[[:space:]]+default=die\\]"
            else control="sufficient"
            directive="^[[:space:]]*auth[[:space:]]+" control "[[:space:]]+pam_sss\\.so"
        }
        $0 ~ directive "([[:space:]]+(forward_pass|use_first_pass))?[[:space:]]*$" {
            line=$0; sub(/[[:space:]]*$/, "", line); revised=line " try_cert_auth";
            if (mode=="diff") {print "- " line; print "+ " revised}
            else {print "# rhel8-stig V-230372 original: " line; print revised}
            edits++; next
        }
        mode!="diff" {print}
        END {if (edits != 1) exit 1}
    ' "$source"
}

identity_validate_pam_cert() {
    local source=$1 path=$2 stack=${2##*/} raw rendered
    check_sensitive_pam_cert "$source" || return 1
    if [[ $source == "$path" ]]; then
        raw=$(identity_authselect_smartcard) || return 1
        rendered=$(identity_authselect_stack "$raw" "$stack") || return 1
        printf '%s\n' "$rendered" > "$EDIT_TEMP/identity-rendered-pam" &&
            check_sensitive_pam_cert "$EDIT_TEMP/identity-rendered-pam"
    fi
}

identity_plan_smartcard_pam() {
    local stack profile=${IDENTITY_AUTHSELECT%% *} live rendered effective target draft diff evidence
    IDENTITY_PAM_PATHS=() IDENTITY_PAM_DRAFTS=() IDENTITY_PAM_DIFFS=()
    IDENTITY_PAM_CONTEXT=''
    for stack in system-auth smartcard-auth; do
        live=/etc/pam.d/$stack
        rendered=$(identity_authselect_stack "$IDENTITY_AUTHSELECT" "$stack") || {
            edit_fail "authselect could not render $stack"; return;
        }
        effective=$(expanded_pam_active_lines < "$live") || return 1
        if [[ ! $effective || $(expanded_pam_active_lines <<< "$rendered") != "$effective" ]]; then
            edit_fail "active $stack differs from its generated authselect profile"; return
        fi
        evidence=$(printf '%s\n' "$effective" | sha256sum) || return 1
        IDENTITY_PAM_CONTEXT+=$'\n'"$stack $evidence"
        if check_sensitive_pam_cert "$live"; then continue; fi
        if [[ $profile != custom/* ]]; then
            edit_fail 'changing PAM requires a locally copied custom authselect profile'; return
        fi
        target=/etc/authselect/$profile/$stack
        draft=$EDIT_TEMP/$stack.identity
        if ! desktop_controlled_source "$target" ||
           ! identity_render_pam_cert "$target" "$stack" render > "$draft" ||
           ! check_sensitive_pam_cert "$draft"; then
            edit_fail "$stack does not contain a single supported direct smart-card PAM template line"; return
        fi
        diff=$(identity_render_pam_cert "$target" "$stack" diff) || return 1
        IDENTITY_PAM_PATHS+=("$target") IDENTITY_PAM_DRAFTS+=("$draft") IDENTITY_PAM_DIFFS+=("$diff")
    done
}

identity_sssd_plan() {
    local requested=$1 id section key value old present draft data change='' i pem
    local base=/etc/sssd/sssd.conf source=/etc/sssd/sssd.conf
    local IDENTITY_AUTHSELECT IDENTITY_BASE_VALUES IDENTITY_SNIPPET_VALUES
    local IDENTITY_SECTION IDENTITY_KEY IDENTITY_VALUE IDENTITY_OLD IDENTITY_PRESENT IDENTITY_PAM_CONTEXT
    local -a IDENTITY_PAM_PATHS=() IDENTITY_PAM_DRAFTS=() IDENTITY_PAM_DIFFS=()
    local -A planned=()
    identity_sssd_snapshot "$base" || return
    # The plan can reuse one backup for compatible selected rules that share
    # sssd.conf. Unsupported siblings remain independent blocked findings.
    for id in "$requested" V-230274 V-230372 V-230376; do
        [[ ${EFFECTIVE[$id]+selected} && ! ${planned[$id]+seen} ]] || continue
        if ! identity_plan_sssd_value "$id"; then
            if [[ $id == "$requested" ]]; then return 1; fi
            continue
        fi
        section=$IDENTITY_SECTION key=$IDENTITY_KEY value=$IDENTITY_VALUE
        old=$IDENTITY_OLD present=$IDENTITY_PRESENT
        if [[ $id == V-230372 ]]; then
            pem=/etc/sssd/pki/sssd_auth_ca_db.pem
            if ! desktop_controlled_source "$pem" || ! identity_plan_smartcard_pam; then
                if [[ $id == "$requested" ]]; then
                    PLAN_REASON=${PLAN_REASON:-'approve and provision a root-controlled SSSD trust bundle before staging smart-card PAM'}
                    return 1
                fi
                IDENTITY_PAM_PATHS=() IDENTITY_PAM_DRAFTS=() IDENTITY_PAM_DIFFS=()
                continue
            fi
        fi
        if [[ ${old,,} == "${value,,}" ]]; then
            if [[ $id != V-230372 || ${#IDENTITY_PAM_PATHS[@]} == 0 ]]; then
                if [[ $id == "$requested" ]]; then edit_fail 'the requested persistent setting already matches'; return; fi
                continue
            fi
        else
            draft=$EDIT_TEMP/$id.sssd
            if ! identity_sssd_render "$source" "$section" "$key" "$value" "$id" > "$draft"; then
                if [[ $id == "$requested" ]]; then edit_fail "cannot edit the authoritative [$section] section safely"; return; fi
                if [[ $id == V-230372 ]]; then
                    IDENTITY_PAM_PATHS=() IDENTITY_PAM_DRAFTS=() IDENTITY_PAM_DIFFS=()
                fi
                continue
            fi
            source=$draft
            change+="@@ [$section] $id @@"$'\n'
            if [[ $present ]]; then change+="- $key = $old"$'\n'; fi
            change+="+ $key = $value"$'\n'
        fi
        planned[$id]=1
        if [[ $id == V-230372 ]]; then
            data=$(sha256_file "$pem") || return 1
            EDIT_CONTEXT+=$'\n'"SSSD trust bundle fingerprint $data$IDENTITY_PAM_CONTEXT"
        fi
        if [[ $id != "$requested" ]]; then
            EDIT_RELATED="${EDIT_RELATED:+$EDIT_RELATED }$id"
            EDIT_GROUPED=$EDIT_RELATED
        fi
    done
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm approved smart-card MFA, ownership of the SSSD configuration and a tested independent administrative console. Coordinate with the identity owner before activation.'
    EDIT_ACTIVATION='Review queued changes and run sssctl config-check.'
    if [[ $change ]]; then
        edit_content "$base" keep "${change%$'\n'}" identity_sssd_native_check < "$source" || return 1
    fi
    for i in "${!IDENTITY_PAM_PATHS[@]}"; do
        edit_content "${IDENTITY_PAM_PATHS[i]}" keep "${IDENTITY_PAM_DIFFS[i]}" \
            identity_validate_pam_cert < "${IDENTITY_PAM_DRAFTS[i]}" || return 1
    done
    if (( ${#IDENTITY_PAM_PATHS[@]} )); then
        EDIT_ACTIVATION+=' Compare authselect test output with both generated PAM stacks and review all pending regeneration. In the approved window use authselect apply-changes -b, then verify authselect check.'
    fi
    EDIT_ACTIVATION+=' Restart sssd.service only in the approved maintenance window. Verify a fresh smart-card login and any selected OCSP or offline-cache behavior.'
}

rule_V_230274_plan() { identity_sssd_plan V-230274; }
rule_V_230372_plan() { identity_sssd_plan V-230372; }
rule_V_230376_plan() { identity_sssd_plan V-230376; }

rule_V_230351_plan() {
    local section=org/gnome/settings-daemon/peripherals/smartcard key=removal-action
    local expected="'lock-screen'" previous preview all_values
    # The native dconf path is independent of authselect regeneration.
    desktop_source_snapshot user || return
    desktop_key_owner "$section" "$key" || {
        edit_fail 'multiple smart-card removal definitions require dconf precedence review'; return;
    }
    previous=$DESKTOP_VALUE
    if ! all_values=$(expanded_dconf_values "$section" "$key") || [[ $all_values != "$previous" ]]; then
        edit_fail 'a removal action outside the verified user dconf database needs precedence review'; return
    fi
    if [[ $DESKTOP_OWNER && $previous != "'none'" ]]; then
        edit_fail 'retain an existing nonstandard or enforced removal action for administrator review'; return
    fi
    desktop_source_target V-230351 "$DESKTOP_OWNER" || return
    desktop_render_key "$DESKTOP_INPUT" "$section" "$key" "$expected" V-230351 \
        > "$EDIT_TEMP/smartcard-removal" || return 1
    preview="+ $key=$expected"
    if [[ $previous ]]; then preview="- $key=$previous"$'\n'"$preview"; fi
    desktop_stage_activation 'Review queued desktop changes before running dconf update. In a fresh GNOME smart-card session, remove an authorized test card and verify that the session locks and can be unlocked by reauthentication. Check all applicable connection types separately.'
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" "$preview" desktop_validate_source < "$EDIT_TEMP/smartcard-removal"
}


# Authoritative crypto policy and PAM source edits. The existing transaction
# handles backup and replacement. Regeneration and service recovery stay
# separate because they can affect other applications and login paths.

readonly ATTENDED_SSH_SCOPE='V-230251 V-230252 V-272482 V-272483'
readonly ATTENDED_SSH_MODULE='RHEL8STIGOPENSSH'
readonly ATTENDED_FAILLOCK_SCOPE='V-244533 V-244534'
readonly ATTENDED_FAILLOCK_MARK='# rhel8-stig enabled verified faillock directives in this custom template'

attended_policy_group() {
    local rule=$1 members=$2 sibling
    EDIT_RELATED=$members
    EDIT_GROUPED=''
    for sibling in $members; do
        if [[ $sibling != "$rule" ]]; then EDIT_GROUPED+=" $sibling"; fi
    done
    EDIT_GROUPED=${EDIT_GROUPED# }
}

attended_policy_source() {
    edit_safe_path "$1" && text_input_file "$1" && edit_target_metadata "$1" &&
        (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 ))
}

attended_same_files() {
    local first second
    first=$(sha256_file "$1") && second=$(sha256_file "$2") && [[ $first == "$second" ]]
}

attended_ssh_module() {
    printf '%s\n' '# Restrict OpenSSH to the pinned RHEL 8 V2R9 cipher and MAC sets.' \
        'cipher@OpenSSH = AES-256-GCM AES-256-CTR AES-128-GCM AES-128-CTR' \
        'mac@OpenSSH = HMAC-SHA2-256 HMAC-SHA2-512'
}

attended_crypto_config_value() {
    awk '
        /^[[:space:]]*(#.*)?$/ {next}
        /^[[:blank:]]*[A-Z][A-Z0-9:-]*[[:blank:]]*$/ {value=$1; count++; next}
        {bad=1}
        END {if (bad || count!=1) exit 1; print value}
    ' "$1"
}

attended_ssh_id() {
    case $1 in
        V-230251|V-230252|V-272482|V-272483) return 0 ;;
        *) return 1 ;;
    esac
}

attended_ssh_base() {
    local dir=/etc/crypto-policies base active
    attended_policy_source "$dir/config" && attended_policy_source "$dir/state/current" &&
        base=$(attended_crypto_config_value "$dir/config") &&
        active=$(attended_crypto_config_value "$dir/state/current") &&
        [[ $base == "$active" && $base =~ ^(DEFAULT|FIPS)$ ]] || return 1
    printf '%s\n' "$base"
}

# Expand only a catalog preview for an SSH finding that actually needs a plan.
# An inferred OpenSSL row records impact and keeps rollback scope complete.
include_ssh_scope() {
    local base id companion missing=0 wants_plan=0
    SSH_SCOPE_ADDED=()
    if (( SSH_IMPACT_ONLY )) && [[ ${EFFECTIVE[V-288829]+included} ]]; then
        SSH_SCOPE_ADDED[V-288829]=impact
    fi
    [[ $MODE =~ ^(apply|dry-run|diff)$ && $MAX_RISK == high &&
       ! ${CKL_PATH-} && ! ${RESUME_ID-} ]] || return 0
    for id in $ATTENDED_SSH_SCOPE; do
        if [[ ${EFFECTIVE[$id]+selected} ]]; then
            rule_dispatch "$id"
            if check_supports_plan "$id"; then wants_plan=1; break; fi
        fi
    done
    (( wants_plan )) || return 0
    base=$(attended_ssh_base) || return 0
    companion=$ATTENDED_SSH_SCOPE
    if [[ $base == DEFAULT ]]; then companion+=' V-288829'; fi
    for id in $companion; do
        [[ ! ${SKIPPED[$id]+excluded} ]] || return 0
        if [[ ! ${EFFECTIVE[$id]+selected} ]]; then missing=1; fi
    done
    (( missing )) || return 0
    for id in $companion; do
        [[ ! ${EFFECTIVE[$id]+selected} ]] || continue
        SCOPE+=("$id")
        EFFECTIVE[$id]=1 SSH_SCOPE_ADDED[$id]=shared
        if [[ $id == V-288829 ]]; then SSH_SCOPE_ADDED[$id]=impact; fi
    done
    mapfile -t SCOPE < <(printf '%s\n' "${SCOPE[@]}" | LC_ALL=C sort -u)
}

attended_crypto_pending() {
    local dir=/etc/crypto-policies module state
    module="$dir/policies/modules/$ATTENDED_SSH_MODULE.pmod"
    state="$dir/state/current"
    attended_policy_source "$dir/config" && attended_policy_source "$module" &&
        [[ $(attended_crypto_config_value "$dir/config") == "FIPS:$ATTENDED_SSH_MODULE" &&
           $(< "$module") == "$(attended_ssh_module)" ]] || return 1
    if ! attended_policy_source "$state" || [[ $(attended_crypto_config_value "$state") != "FIPS:$ATTENDED_SSH_MODULE" ]]; then
        return 0
    fi
    [[ $ASSESSMENT == FAIL ]]
}

attended_ssh_check() {
    check_ssh_backend "$1" "$2" "$3"
    if attended_crypto_pending; then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW 'The staged crypto policy needs native regeneration and live SSH verification.'
    fi
    return 0
}

rule_V_230251_check() { attended_ssh_check server MACs "$SSH_MACS_V2R9"; }
rule_V_230252_check() { attended_ssh_check server Ciphers "$SSH_CIPHERS_V2R9"; }
rule_V_272482_check() { attended_ssh_check client MACs "$SSH_MACS_V2R9"; }
rule_V_272483_check() { attended_ssh_check client Ciphers "$SSH_CIPHERS_V2R9"; }

attended_crypto_packages() {
    local versions vendor
    versions=$(timeout 12 rpm -q --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}\n' \
        crypto-policies crypto-policies-scripts 2>/dev/null) || return 1
    vendor=$(awk -F '|' '$3=="Red Hat, Inc." && $2 ~ /^[A-Za-z0-9_.-]+$/ { n++ } END {print n+0}' <<< "$versions") || return 1
    [[ $vendor == 2 ]] && timeout 20 rpm -V --noscripts --nodeps crypto-policies crypto-policies-scripts \
        >/dev/null 2>&1 || return 1
    printf '%s\n' "$versions"
}

attended_crypto_stock_backend() {
    local directory=$1 stock=$2 base=$3 backend=$4 path resolved
    path="$directory/back-ends/$backend.config"
    resolved=$(realpath -e -- "$path") || return 1
    case $resolved in
        "$path") attended_policy_source "$path" || return 1 ;;
        "$stock/$base/$backend.txt"|"$stock/back-ends/$base/$backend.config") ;;
        *) return 1 ;;
    esac
    attended_same_files "$resolved" "$stock/back-ends/$base/$backend.config" || return 1
    sha256_file "$resolved"
}

# Use the verified vendor library's pure generator in a private directory.
# Running update-crypto-policies itself here could regenerate live backends.
attended_crypto_generate() {
    local stock=$1 scratch=$2 python=$3
    timeout 20 env -i PATH=/usr/sbin:/usr/bin LC_ALL=C "$python" -I -B - "$stock" "$scratch" "$ATTENDED_SSH_MODULE" <<'PY'
import os
import sys
from pathlib import Path

stock, scratch, module = sys.argv[1:]
os.chdir(scratch)
sys.path.insert(0, os.path.join(stock, "python"))
from cryptopolicies import UnscopedCryptoPolicy
from policygenerators.openssh import OpenSSHClientGenerator, OpenSSHServerGenerator

UnscopedCryptoPolicy.SHARE_DIR = stock
UnscopedCryptoPolicy.CONFIG_DIR = scratch
policy = UnscopedCryptoPolicy("FIPS", module)
for generator in (OpenSSHClientGenerator, OpenSSHServerGenerator):
    backend = generator.generate_config(policy.scoped(generator.SCOPES))
    (Path(scratch) / (generator.CONFIG_NAME + ".config")).write_text(backend, encoding="ascii")
PY
}

attended_crypto_validate_generated() (
    local directory=$1 side file
    for side in client server; do
        file="$directory/openssh.config"
        if [[ $side == server ]]; then file="$directory/opensshserver.config"; fi
        check_ssh_backend "$side" MACs "$SSH_MACS_V2R9" "$file"
        [[ $ASSESSMENT == PASS ]] || return 1
        check_ssh_backend "$side" Ciphers "$SSH_CIPHERS_V2R9" "$file"
        [[ $ASSESSMENT == PASS ]] || return 1
    done
)

attended_crypto_config_validate() {
    [[ $(attended_crypto_config_value "$1") == "FIPS:$ATTENDED_SSH_MODULE" ]]
}

attended_crypto_module_validate() {
    attended_same_files "$1" "$EDIT_TEMP/crypto-proof/policies/modules/$ATTENDED_SSH_MODULE.pmod"
}

attended_ssh_plan() {
    local id=$1 dir=/etc/crypto-policies stock=/usr/share/crypto-policies
    local config module base versions client_digest server_digest path
    local scratch="$EDIT_TEMP/crypto-proof"
    config="$dir/config"
    module="$dir/policies/modules/$ATTENDED_SSH_MODULE.pmod"
    if ! have_tools rpm timeout env realpath update-crypto-policies ||
       [[ ! -x /usr/libexec/platform-python ]] || ! versions=$(attended_crypto_packages); then
        edit_fail 'verified Red Hat crypto-policies packages and platform Python are required'; return
    fi
    if ! base=$(attended_ssh_base); then
        edit_fail 'a stock DEFAULT or FIPS policy with matching applied state is required'; return
    fi
    if ! edit_safe_path "$module" || [[ -e $module || -L $module ||
        -e $stock/policies/modules/$ATTENDED_SSH_MODULE.pmod || -L $stock/policies/modules/$ATTENDED_SSH_MODULE.pmod ||
        -e $dir/policies/$base.pol || -L $dir/policies/$base.pol ||
        -e $dir/policies/FIPS.pol || -L $dir/policies/FIPS.pol ]]; then
        edit_fail 'a colliding module or local policy override needs review'; return
    fi
    if [[ ! -d $dir/local.d ]] || ! edit_safe_path "$dir/local.d" ||
       ! edit_target_metadata "$dir/local.d" || (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
        edit_fail 'the local crypto override directory is outside the supported layout'; return
    fi
    for path in "$dir"/local.d/*.config; do
        if [[ -e $path || -L $path ]]; then
            edit_fail 'local cryptographic backend overrides need site review'; return
        fi
    done
    if ! client_digest=$(attended_crypto_stock_backend "$dir" "$stock" "$base" openssh) ||
       ! server_digest=$(attended_crypto_stock_backend "$dir" "$stock" "$base" opensshserver); then
        edit_fail 'the two active OpenSSH backends differ from the verified stock policy'; return
    fi
    if [[ -e /etc/sysconfig/sshd || -L /etc/sysconfig/sshd ]]; then
        if ! attended_policy_source /etc/sysconfig/sshd ||
           grep -Eq '^[[:space:]]*(export[[:space:]]+)?CRYPTO_POLICY[[:space:]]*=' /etc/sysconfig/sshd; then
            edit_fail 'the SSH daemon crypto-policy override requires site review'; return
        fi
    fi
    attended_policy_group "$id" "$ATTENDED_SSH_SCOPE"
    if [[ $base == DEFAULT ]]; then EDIT_RELATED+=' V-288829'; fi
    allow_rule_plan "$id" "$EDIT_RELATED" || return 1
    mkdir -p -- "$scratch/policies/modules" || return 1
    attended_ssh_module > "$scratch/policies/modules/$ATTENDED_SSH_MODULE.pmod" || return 1
    if ! attended_crypto_generate "$stock" "$scratch" /usr/libexec/platform-python >/dev/null 2>&1 ||
       ! attended_crypto_validate_generated "$scratch"; then
        edit_fail 'native crypto-policy generation did not validate all four proposed OpenSSH allowlists'; return
    fi
    EDIT_CONTEXT=$(printf '%s\n' "$versions" "$client_digest" "$server_digest" "$base" | sha256sum) || return 1
    if [[ -f /etc/sysconfig/sshd ]]; then
        EDIT_CONTEXT+=" $(sha256_file /etc/sysconfig/sshd)" || return 1
    fi
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Approve the shared change only if you control the host crypto policy and have recovery console access. Review dependent services and clients before activation.'
    if [[ $base == DEFAULT ]]; then
        EDIT_REQUIREMENTS+=' DEFAULT to FIPS changes generated defaults for consumers including OpenSSL, GnuTLS, NSS, Java, Kerberos, IKE and libssh.'
    fi
    EDIT_ACTIVATION="Before a restart or package-triggered regeneration, conduct the approved maintenance review. Run update-crypto-policies --no-reload, validate both SSH allowlists, and confirm fresh client and server sessions after a separately approved restart. A FIPS-based crypto policy alone does not establish kernel FIPS mode or module certification. Before activation the file rollback restores the inputs. After activation regenerate the restored policy and recover affected services separately."
    edit_content "$module" 0644 'Add an OpenSSH-scoped module that limits both SSH backends to the four approved ciphers and four approved MAC names.' \
        attended_crypto_module_validate < "$scratch/policies/modules/$ATTENDED_SSH_MODULE.pmod" || return
    awk -v policy="FIPS:$ATTENDED_SSH_MODULE" '
        /^[[:space:]]*(#.*)?$/ {print; next}
        {print "# rhel8-stig original policy: " $1; print policy}
    ' "$config" > "$scratch/config.staged" || return 1
    edit_content "$config" keep "Configured policy $base → FIPS:$ATTENDED_SSH_MODULE. The installed package generated compliant proposed OpenSSH client/server lists in scratch space." \
        attended_crypto_config_validate < "$scratch/config.staged"
}

rule_V_230251_plan() { attended_ssh_plan V-230251; }
rule_V_230252_plan() { attended_ssh_plan V-230252; }
rule_V_272482_plan() { attended_ssh_plan V-272482; }
rule_V_272483_plan() { attended_ssh_plan V-272483; }

attended_faillock_source() {
    awk -v label="$ATTENDED_FAILLOCK_MARK" '
        BEGIN {print label}
        /^[[:space:]]*#/ {if ($0 == label) invalid=1; print; next}
        /pam_faillock\.so/ {
            if ($0 !~ /[[:blank:]]+\{include if "with-faillock"\}[[:blank:]]*$/) {invalid=1; next}
            sub(/[[:blank:]]+\{include if "with-faillock"\}[[:blank:]]*$/, "")
            if ($0 ~ /^[[:space:]]*auth[[:blank:]]+required[[:blank:]]+pam_faillock\.so[[:blank:]]+preauth([[:blank:]]+silent)?$/) preauth++
            else if ($0 ~ /^[[:space:]]*auth[[:blank:]]+required[[:blank:]]+pam_faillock\.so[[:blank:]]+authfail$/) authfail++
            else if ($0 ~ /^[[:space:]]*account[[:blank:]]+required[[:blank:]]+pam_faillock\.so$/) account++
            else invalid=1
        }
        {print}
        END {exit (invalid || preauth!=1 || authfail!=1 || account!=1)}
    ' "$1"
}

attended_faillock_compare_other_lines() {
    local active candidate
    active=$(awk '$3 != "pam_faillock.so"' "$1") &&
        candidate=$(awk '$3 != "pam_faillock.so"' "$2") && [[ $active == "$candidate" ]]
}

attended_faillock_candidate_pass() (
    access_pam_check "$1" faillock
    [[ $ASSESSMENT == PASS ]]
)

attended_faillock_validate_staged() {
    local path=$1 target=$2 stack=${2##*/} rendered
    [[ $stack == system-auth || $stack == password-auth ]] &&
        attended_same_files "$path" "$EDIT_TEMP/$stack.faillock-source" || return 1
    if [[ $path == "$target" ]]; then
        rendered=$(expanded_auth_select_render "$ATTENDED_PAM_RAW" "$stack") || return 1
        [[ $(expanded_pam_active_lines <<< "$rendered") == "$(< "$EDIT_TEMP/$stack.faillock-after")" ]]
    fi
}

attended_faillock_check() {
    local stack=$1 raw path
    access_pam_check "/etc/pam.d/$stack" faillock
    if [[ $ASSESSMENT == FAIL ]] && raw=$(expanded_auth_select_raw); then
        path="/etc/authselect/${raw%% *}/$stack"
        if attended_policy_source "$path" && grep -Fxq -- "$ATTENDED_FAILLOCK_MARK" "$path"; then
            CHECK_PENDING=1
            rule_result NEEDS_REVIEW 'Faillock changes are staged in the active custom template. Compare the native render and apply the approved profile activation.'
        fi
    fi
    return 0
}

attended_faillock_plan() {
    local id=$1 profile stack path normal candidate active
    attended_policy_group "$id" "$ATTENDED_FAILLOCK_SCOPE"
    allow_rule_plan "$id" "$EDIT_RELATED" || return 1
    if ! ATTENDED_PAM_RAW=$(expanded_auth_select_raw) ||
       [[ " $ATTENDED_PAM_RAW " == *' with-faillock '* ]]; then
        edit_fail 'a valid copied custom authselect profile with the native faillock feature available and disabled is required'; return
    fi
    profile=${ATTENDED_PAM_RAW%% *}
    for stack in system-auth password-auth; do
        path="/etc/authselect/$profile/$stack"
        normal="$EDIT_TEMP/$stack.faillock-before"
        candidate="$EDIT_TEMP/$stack.faillock-after"
        if ! attended_policy_source "$path" ||
           ! active=$(expanded_auth_select_render "$ATTENDED_PAM_RAW" "$stack") ||
           ! expanded_pam_active_lines <<< "$active" > "$normal" ||
           [[ ! -s $normal || $(< "$normal") != "$(expanded_pam_active_lines < "/etc/pam.d/$stack")" ]]; then
            edit_fail 'the copied custom profile has unreviewed source or generated PAM changes'; return
        fi
        if ! active=$(expanded_auth_select_render "$ATTENDED_PAM_RAW with-faillock" "$stack") ||
           ! expanded_pam_active_lines <<< "$active" > "$candidate" ||
           ! attended_faillock_candidate_pass "$candidate" ||
           ! attended_faillock_compare_other_lines "$normal" "$candidate" ||
           ! attended_faillock_source "$path" > "$EDIT_TEMP/$stack.faillock-source"; then
            edit_fail 'the native faillock feature must add only the canonical, correctly ordered faillock directives'; return
        fi
        edit_content "$path" keep "Enable the three existing vendor faillock directives in the verified copied $stack template." \
            attended_faillock_validate_staged < "$EDIT_TEMP/$stack.faillock-source" || return
    done
    EDIT_CONTEXT=$( { printf '%s\n' "$ATTENDED_PAM_RAW"; cat -- \
        "$EDIT_TEMP/system-auth.faillock-before" "$EDIT_TEMP/system-auth.faillock-after" \
        "$EDIT_TEMP/password-auth.faillock-before" "$EDIT_TEMP/password-auth.faillock-after"; } | sha256sum) || return 1
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Keep a recovery console and a separate working privileged session. Confirm the locally managed custom profile and review all authselect-generated differences before activating the source changes.'
    EDIT_ACTIVATION='Review authselect test for the selected profile and existing features. Apply with authselect apply-changes -b during the approved maintenance window. Test fresh successful and failed logins and verify authselect check. After activation, restoring the two source files also requires an approved regeneration of the previous profile.'
}

rule_V_244533_check() { attended_faillock_check system-auth; }
rule_V_244534_check() { attended_faillock_check password-auth; }
rule_V_244533_plan() { attended_faillock_plan V-244533; }
rule_V_244534_plan() { attended_faillock_plan V-244534; }

# Attended persistent mount, GNOME, application-control and SELinux plans.

# Read the authoritative fstab and match the kernel's active source. Reject
# device aliases we cannot resolve and mounts owned by an alternate manager.
attended_fstab_source() {
    local target=$1 active_source=$2 filesystem=$3 configured source type extra unit props active_device configured_device
    configured=$(timeout 8 findmnt --fstab --evaluate --raw --noheadings \
        --mountpoint "$target" --output SOURCE,FSTYPE --tab-file /etc/fstab 2>/dev/null) || return 1
    [[ -n $configured && $configured != *$'\n'* ]] || return 1
    read -r source type extra <<< "$configured"
    [[ -z $extra && $source == /dev/* && $type == "$filesystem" && -b $source && -b $active_source ]] || return 1
    configured_device=$(stat -Lc '%t:%T' -- "$source") &&
        active_device=$(stat -Lc '%t:%T' -- "$active_source") &&
        [[ $configured_device == "$active_device" ]] || return 1
    unit=$(systemd-escape --path --suffix=mount -- "$target") || return 1
    [[ $unit =~ ^[A-Za-z0-9_.@\\-]+\.mount$ ]] || return 1
    props=$(timeout 8 systemctl show --property=LoadState,FragmentPath,SourcePath,DropInPaths \
        -- "$unit" 2>/dev/null) || return 1
    grep -Fxq 'LoadState=loaded' <<< "$props" &&
        grep -Fxq "FragmentPath=/run/systemd/generator/$unit" <<< "$props" &&
        grep -Fxq 'SourcePath=/etc/fstab' <<< "$props" &&
        grep -Fxq 'DropInPaths=' <<< "$props"
}

# Print the kernel row for each affected mount. A home must resolve to a
# verified separate local mount, including when the boot configuration is
# missing a flag that was set by a previous manual remount.
attended_mount_inventory() {
    local mount_flag=$1 mountinfo=$2 passwd=$3 mount_home_rows=''
    if [[ $mount_flag == noexec ]]; then
        mount_home_rows=$(awk -F: '
            NF!=7 || $3 !~ /^[0-9]+$/ {bad=1; next}
            $3>=1000 && $7 !~ /nologin/ {
                if ($6 !~ /^\/home\/[a-zA-Z0-9_.@-]+$/ || $6 ~ /^\/home\/\.\.?$/ || ++seen[$6]>1) bad=1
                else print $6
                if (++count>1024) bad=1
            }
            END {if (bad || !count) exit 1}
        ' "$passwd") || return 1
    fi
    awk -v wanted="$mount_flag" '
        function row(point, home) {
            print point "\t" source[point] "\t" fs[point] "\t" root[point] "\t" opts[point] "\t" identity[point] "\t" home
        }
        FILENAME==ARGV[1] {
            sep=7; while (sep<=NF && $sep!="-") sep++;
            if (NF<10 || sep+3!=NF || $5 !~ /^\// || $1 !~ /^[0-9]+$/ ||
                $3 !~ /^[0-9]+:[0-9]+$/ || NR>8192) {bad=1; next}
            point=$5; count[point]++; source[point]=$(sep+2); fs[point]=$(sep+1); root[point]=$4; opts[point]=$6;
            identity[point]=$1 ":" $3;
            if (wanted=="nodev" && point!="/" && $(sep+2) ~ /^\/dev\// && $6 !~ /(^|,)nodev(,|$)/)
                deficient[point]=1;
            next
        }
        wanted=="noexec" {
            home=$0; point="";
            for (candidate in fs) if ((candidate=="/" || home==candidate || index(home,candidate "/")==1) &&
                                      length(candidate)>length(point)) point=candidate;
            if (!point || point=="/" || count[point]!=1) bad=1;
            else row(point,home);
        }
        END {
            if (wanted=="nodev") for (point in deficient) {
                if (count[point]!=1) bad=1;
                else row(point,"-");
            }
            if (bad) exit 1;
        }
    ' "$mountinfo" - <<< "$mount_home_rows" | sort -u
}

attended_mount_verified() {
    local option=$1 rows target source filesystem root options identity home
    local -A verified=()
    rows=$(attended_mount_inventory "$option" /proc/self/mountinfo /etc/passwd) || return 1
    [[ -n $rows ]] || return 1
    while IFS=$'\t' read -r target source filesystem root options identity home; do
        [[ $target =~ ^/[A-Za-z0-9_.@/-]+$ && $source =~ ^/dev/[A-Za-z0-9_.@/+:-]+$ &&
           $options =~ ^[A-Za-z0-9_.,=+/-]+$ && $root == / &&
           $filesystem =~ ^(xfs|ext[234]|vfat)$ ]] && valid_output_path "$target" || return 1
        if [[ $option == noexec ]]; then
            [[ $filesystem != vfat ]] && expanded_home_path_safe "$home" &&
                [[ $(realpath -e -- "$home") == "$home" ]] || return 1
        fi
        if [[ ! ${verified[$target]+seen} ]]; then
            (( ${#verified[@]} < 64 )) && attended_fstab_source "$target" "$source" "$filesystem" || return 1
            verified[$target]=1
            printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$target" "$option" "$source" "$filesystem" "$options" "$identity"
        fi
    done <<< "$rows"
}

# Change only the fourth fstab field of reviewed targets. Print a reduced
# before/after view so credentials or other private options stay out of logs.
attended_fstab_render() {
    local fstab=$1 fstab_targets=$2 report=$3
    awk -v report="$report" '
        function set_flag(opts, want, target,    n,i,a,position,current,result) {
            n=split(opts,a,",");
            for (i=1;i<=n;i++) {
                if (!a[i]) bad=1;
                if (a[i]==want || a[i]==substr(want,3)) {
                    if (position) bad=1;
                    position=i; current=a[i];
                }
            }
            if (current==want) return opts;
            print "- " target " " (current=="" ? "(no explicit " want " flag)" : current) > report;
            print "+ " target " " want > report;
            changes++;
            if (!position) return opts "," want;
            a[position]=want; result=a[1];
            for (i=2;i<=n;i++) result=result "," a[i];
            return result;
        }
        FILENAME==ARGV[1] {
            if ($2=="nodev") nodev[$1]=1;
            else if ($2=="noexec") noexec[$1]=1;
            else bad=1;
            next
        }
        /^[[:space:]]*($|#)/ {print; next}
        {
            raw=$0; sub(/[[:space:]]+#.*/, "");
            if (NF<4 || NF>6 || ++seen[$2]>1) {bad=1; print raw; next}
            target=$2; previous=$4; new=previous;
            if (target in nodev) new=set_flag(new,"nodev",target);
            if (target in noexec) new=set_flag(new,"noexec",target);
            if (new==previous) {print raw; next}
            rest=raw; prefix=0;
            for (i=1;i<=3;i++) {
                match(rest,/^[[:space:]]*[^[:space:]]+/); prefix+=RLENGTH; rest=substr(rest,RLENGTH+1);
            }
            match(rest,/^[[:space:]]+/); prefix+=RLENGTH;
            print "# rhel8-stig original local mount entry: " raw;
            print substr(raw,1,prefix) new substr(raw,prefix+length(previous)+1);
        }
        END {
            for (point in nodev) if (seen[point]!=1) bad=1;
            for (point in noexec) if (seen[point]!=1) bad=1;
            if (bad || !changes) exit 1;
        }
    ' - "$fstab" <<< "$fstab_targets"
}

attended_mount_plan() {
    local option=$1 fstab_targets companion draft=$EDIT_TEMP/attended-fstab report=$EDIT_TEMP/attended-mount-diff
    if ! have_tools findmnt systemctl systemd-escape sort stat realpath || ! desktop_controlled_source /etc/fstab; then
        edit_fail 'a root-controlled regular fstab and the native mount and systemd tools are required'; return
    fi
    if ! fstab_targets=$(attended_mount_verified "$option"); then
        edit_fail 'a candidate lacks an unambiguous separate local mount and verified fstab-generated unit'; return
    fi
    if ! attended_fstab_render /etc/fstab "$fstab_targets" "$report" > "$draft"; then
        edit_fail "no unambiguous persistent $option edit is needed. Review pending remount or conflicting options."; return
    fi
    if [[ $option == nodev && ${EFFECTIVE[V-230302]+selected} ]] &&
       companion=$(attended_mount_verified noexec) &&
       attended_fstab_render /etc/fstab "$companion" "$report.home" > "$draft.home"; then
        fstab_targets+=$'\n'"$companion"
        attended_fstab_render /etc/fstab "$fstab_targets" "$report" > "$draft" || return 1
        EDIT_RELATED=V-230302 EDIT_GROUPED=V-230302
    fi
    EDIT_CONTEXT=$fstab_targets
    EDIT_REQUIREMENTS='Confirm fstab is locally managed, the current mount namespace is the target, and affected applications do not need the restricted operation. Keep console recovery available.'
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Review the fstab change before an approved targeted remount or reboot. Verify the VFS flags and affected applications afterward. Restoring fstab alone does not restore active mounts.'
    edit_content /etc/fstab keep "$(< "$report")" scope_validate_fstab < "$draft"
}

rule_V_230301_plan() { attended_mount_plan nodev; }
rule_V_230302_plan() { attended_mount_plan noexec; }

rule_V_230530_plan() {
    local section=org/gnome/settings-daemon/plugins/media-keys value="''" previous range
    local binding="^'[A-Za-z0-9_<>+. -]{1,120}'$"
    if [[ ${ARCH-} != x86_64 || $(expanded_gui_state) != gnome ]] || ! have_tools gsettings ||
       ! range=$(timeout 8 gsettings range org.gnome.settings-daemon.plugins.media-keys logout 2>/dev/null) ||
       [[ $range != 'type s' ]]; then
        edit_fail 'a supported x86 GNOME logout string schema is required'; return
    fi
    desktop_source_snapshot user || return
    desktop_key_owner "$section" logout || {
        edit_fail 'multiple active GNOME logout bindings require precedence review'; return;
    }
    previous=$DESKTOP_VALUE
    if [[ $DESKTOP_OWNER && ( $previous == "$value" || ! $previous =~ $binding ) ]]; then
        edit_fail 'the current logout binding is compliant or is outside the supported literal form'; return
    fi
    desktop_source_target V-230530 "$DESKTOP_OWNER" || return
    desktop_render_key "$DESKTOP_INPUT" "$section" logout "$value" V-230530 > "$EDIT_TEMP/gnome-cad" || return 1
    desktop_stage_activation 'Review pending dconf sources and run dconf update. Use a fresh GNOME session to verify the effective logout shortcut and check for user overrides.'
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" "- logout=${previous:-(absent)}
+ logout=$value" desktop_validate_source < "$EDIT_TEMP/gnome-cad"
}

# Add an exact SELinux context rule through semanage. Existing potentially
# overlapping local policy is left for the administrator to reconcile.
attended_faillock_pattern() {
    local target=$1 directory status
    [[ $target =~ ^/var/log(/[A-Za-z0-9_-]+)+$ && $target != /var/log && -d $target ]] &&
        edit_safe_path "$target" && edit_target_metadata "$target" &&
        (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 )) || return 1
    desktop_controlled_source /etc/security/faillock.conf &&
        directory=$(expanded_faillock_dir /etc/security/faillock.conf) &&
        [[ $directory == "$target" ]] || return 1
    status=$(timeout 8 sestatus 2>/dev/null) || return 1
    grep -Eq '^Current mode:[[:blank:]]+enforcing$' <<< "$status" &&
        grep -Eq '^Loaded policy name:[[:blank:]]+targeted$' <<< "$status" || return 1
    awk '
        !/^[[:space:]]*#/ && /(^|[[:space:]\/])pam_faillock\.so([[:space:]]|$)/ {
            found=1; if ($0 ~ /[[:space:]]dir[[:space:]]*=/) override=1
        }
        END {exit !found || override}
    ' /etc/pam.d/system-auth /etc/pam.d/password-auth || return 1
    printf '%s(/.*)?\n' "$target"
}

attended_faillock_local_state() {
    local target=$1 pattern=$2
    # Accept unrelated literal paths or independently bounded subtrees. Reject
    # policy regexes and equivalences whose overlaps cannot be proved.
    awk -v target="$target" -v wanted="$pattern" '
        /^[[:space:]]*$/ {next}
        NF>=4 && $1==wanted {
            if (++present!=1 || NF!=4 || $2!="all" || $3!="files" ||
                $4!="system_u:object_r:faillog_t:s0") bad=1;
            next
        }
        {
            spec=$1;
            recursive=(length(spec)>6 && substr(spec,length(spec)-5)=="(/.*)?");
            if (recursive) spec=substr(spec,1,length(spec)-6);
            if (NF<4 || spec !~ /^\/[A-Za-z0-9_\/-]+$/ || spec ~ /\/\// || spec ~ /\/$/ ||
                $NF !~ /^[A-Za-z0-9_]+:object_r:[A-Za-z0-9_]+:[A-Za-z0-9_:.,-]+$/ ||
                spec==target || index(spec,target "/")==1 || (recursive && index(target,spec "/")==1)) bad=1;
            print;
        }
        END {if (bad) exit 1; print present ? "present" : "absent"}
    '
}

rule_V_250315_observe() {
    local target=$1 pattern listing state content baseline hardware effective
    pattern=$(attended_faillock_pattern "$target") || return 1
    listing=$(timeout 18 semanage fcontext -l -C -n -S targeted 2>/dev/null) || return 1
    content=$(attended_faillock_local_state "$target" "$pattern" <<< "$listing") || return 1
    state=${content##*$'\n'}
    [[ $state =~ ^(absent|present)$ ]] || return 1
    if [[ $state == present ]]; then
        effective=$(timeout 8 matchpathcon -n "$target" 2>/dev/null) &&
            [[ $effective == system_u:object_r:faillog_t:s0 ]] || return 1
    fi
    hardware=$(stat -c '%d:%i' -- "$target") || return 1
    baseline=$(printf '%s\n%s\n' "$hardware" "${content%"$state"}" | sha256sum) || return 1
    printf '%s:%s\n' "$state" "${baseline%% *}"
}

rule_V_250315_plan() {
    local target state effective label digest
    if ! have_tools sestatus semanage matchpathcon restorecon ||
       ! target=$(expanded_faillock_dir /etc/security/faillock.conf) ||
       ! state=$(rule_V_250315_observe "$target"); then
        edit_fail 'an unambiguous existing /var/log tally directory, enforcing targeted policy, and non-overlapping local contexts are required'; return
    fi
    effective=$(timeout 8 matchpathcon -n "$target" 2>/dev/null) &&
        label=$(stat -c '%C' -- "$target" 2>/dev/null) || return 1
    if [[ $state != absent:* || $effective == *:faillog_t:* ]]; then
        edit_fail 'persistent faillog_t policy already exists. Review the separate restorecon activation.'; return
    fi
    digest=$(sha256sum /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth) || return 1
    ACTION_CONTEXT="$label $effective"$'\n'"$digest"
    ACTION_REQUIREMENTS='Confirm this dedicated directory contains only faillock tallies. Keep console recovery available and review any pre-existing child label requirements.'
    ACTION_ACTIVATION="Review the recursive relabel preview with restorecon -nRv -- $target. Run restorecon -Rv only in an approved window and verify lockout and recovery with a test account. Restoring the persistent mapping does not restore labels already applied to files."
    action_add "$target" "$state" "present:${state#*:}" 'No local recursive faillog_t mapping' \
        "Persistent faillog_t mapping for $target and descendants"
}

rule_V_250315_change() {
    local target=$1 expected=$2 desired=$3 pattern current
    [[ $expected =~ ^absent:[a-f0-9]{64}$ && $desired == "present:${expected#*:}" ]] || return 1
    pattern=$(attended_faillock_pattern "$target") && current=$(rule_V_250315_observe "$target") &&
        [[ $current == "$expected" ]] || return 1
    timeout 30 semanage fcontext -a -N -S targeted -f a -s system_u -t faillog_t -r s0 "$pattern"
}

rule_V_250315_restore() {
    local target=$1 original=$2 post=$3 pattern current
    [[ $original =~ ^absent:[a-f0-9]{64}$ && $post == "present:${original#*:}" ]] || return 1
    pattern=$(attended_faillock_pattern "$target") && current=$(rule_V_250315_observe "$target") &&
        [[ $current == "$post" ]] || return 1
    timeout 30 semanage fcontext -d -N -S targeted -f a "$pattern"
}

# Fingerprint the exact prevalidated policy that would be used on start.
# Recreate the read-only fagenrules comparison without loading or publishing it.
attended_fapolicy_digest() {
    local base=/etc/fapolicyd path part actual expected list owner group mode digest
    local -a inputs=() fragments=()
    for path in "$base" "$base/rules.d" "$base/trust.d"; do
        [[ -d $path ]] && edit_safe_path "$path" && edit_target_metadata "$path" &&
            (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 )) || return 1
    done
    [[ ! -e $base/fapolicyd.rules && ! -L $base/fapolicyd.rules ]] || return 1
    for part in fapolicyd.conf compiled.rules fapolicyd.trust; do
        path=$base/$part
        desktop_controlled_source "$path" || return 1
        inputs+=("$path")
    done
    path=$base/fapolicyd-filter.conf
    if [[ -e $path || -L $path ]]; then
        desktop_controlled_source "$path" || return 1
        inputs+=("$path")
    fi
    for path in "$base"/rules.d/* "$base"/trust.d/*; do
        [[ -e $path || -L $path ]] || continue
        [[ ${path##*/} =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]+$ ]] &&
            (( ${#inputs[@]} < 96 )) && desktop_controlled_source "$path" || return 1
        inputs+=("$path")
        if [[ $path == "$base"/rules.d/*.rules ]]; then fragments+=("$path"); fi
    done
    for path in "$base"/{rules.d,trust.d}/{.[!.]*,..?*}; do
        [[ ! -e $path && ! -L $path ]] || return 1
    done
    (( ${#fragments[@]} )) || return 1
    awk '
        /^[[:space:]]*permissive[[:space:]]*=/ {
            n++; if ($0 ~ /^[[:space:]]*permissive[[:space:]]*=[[:space:]]*0[[:space:]]*(#.*)?$/) good++
        }
        END {exit !(n==1 && good==1)}
    ' "$base/fapolicyd.conf" || return 1
    awk '
        !/^[[:space:]]*(#|$)/ {last=$0}
        END {exit !(last ~ /^[[:space:]]*deny(_audit|_syslog|_log)?[[:space:]]+perm=any[[:space:]]+all[[:space:]]*:[[:space:]]*all[[:space:]]*$/)}
    ' "$base/compiled.rules" || return 1
    list=$(printf '%s\n' "${fragments[@]}" | sort -V) || return 1
    mapfile -t fragments <<< "$list"
    expected=$(
        {
            printf '%s\n' '## This file is automatically generated from /etc/fapolicyd/rules.d'
            cat -- "${fragments[@]}" | awk 'length($0)>0 && !/^[[:space:]]*#/'
        } | sha256sum
    ) || return 1
    actual=$(sha256_file "$base/compiled.rules") && [[ $actual == "${expected%% *}" ]] || return 1
    timeout 12 fapolicyd-cli --check-config >/dev/null 2>&1 || return 1
    for path in "${inputs[@]}"; do
        read -r owner group mode < <(stat -c '%u %g %a' -- "$path") && digest=$(sha256_file "$path") || return 1
        printf '%s %s %s %s %s\n' "$path" "$owner" "$group" "$mode" "$digest"
    done
}

attended_fapolicy_unit() {
    local unit=/usr/lib/systemd/system/fapolicyd.service property expected actual
    local wants=/etc/systemd/system/multi-user.target.wants
    [[ -f $unit && ! -L $unit && -d $wants ]] && edit_safe_path "$wants" &&
        edit_target_metadata "$wants" && (( (8#$EDIT_ORIGINAL_MODE & 022) == 0 )) || return 1
    property=$(timeout 8 systemctl show --property=LoadState,UnitFileState,ActiveState,SubState,FragmentPath,DropInPaths,Names \
        fapolicyd.service 2>/dev/null) || return 1
    grep -Fxq 'LoadState=loaded' <<< "$property" && grep -Fxq "FragmentPath=$unit" <<< "$property" &&
        grep -Fxq 'DropInPaths=' <<< "$property" && grep -Fxq 'Names=fapolicyd.service' <<< "$property" || return 1
    expected=$(timeout 8 rpm -q --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' fapolicyd 2>/dev/null |
        awk -F'[|]' -v unit="$unit" '$1==unit {n++; print $2} END {if(n!=1) exit 1}') || return 1
    actual=$(sha256_file "$unit") && [[ $expected =~ ^[0-9a-f]{64}$ && $actual == "$expected" ]] || return 1
    # The vendor installation must create one known persistent unit link.
    awk '
        /^[[:space:]]*(#|;|$)/ {next}
        /^[[:space:]]*\[/ {section=$0; if (section=="[Install]") n++; next}
        section=="[Install]" {
            if ($0=="WantedBy=multi-user.target") match_count++; else bad=1
        }
        END {exit !(n==1 && match_count==1 && !bad)}
    ' "$unit" || return 1
    printf '%s\n%s\n' "$actual" "$property"
}

rule_V_244545_observe() {
    local target=$1 unit inventory digest link_id state activity runtime
    local link=/etc/systemd/system/multi-user.target.wants/fapolicyd.service
    [[ $target == fapolicyd.service ]] || return 1
    unit=$(attended_fapolicy_unit) && inventory=$(attended_fapolicy_digest) || return 1
    state=$(awk -F= '$1=="UnitFileState" {print $2}' <<< "$unit")
    activity=$(awk -F= '$1=="ActiveState" {print $2}' <<< "$unit")
    runtime=$(awk -F= '$1=="SubState" {print $2}' <<< "$unit")
    [[ $activity:$runtime == active:running || $activity:$runtime == inactive:dead ]] || return 1
    digest=$(printf '%s\n%s\n' "${unit%%$'\n'*}" "$inventory" | sha256sum) || return 1
    digest=${digest%% *}
    case $state in
        disabled)
            [[ ! -e $link && ! -L $link ]] || return 1
            printf 'disabled:%s\n' "$digest" ;;
        enabled)
            [[ -L $link && $(readlink -- "$link") == /usr/lib/systemd/system/fapolicyd.service ]] || return 1
            link_id=$(stat -c '%d:%i' -- "$link") || return 1
            [[ $link_id =~ ^[0-9]+:[0-9]+$ ]] || return 1
            printf 'enabled:%s:%s\n' "$digest" "$link_id" ;;
        *) return 1 ;;
    esac
}

rule_V_244545_plan() {
    local state unit
    if ! have_tools systemctl rpm readlink fapolicyd-cli sort || ! state=$(rule_V_244545_observe fapolicyd.service); then
        edit_fail 'a stock service unit and an approved, current enforcing fapolicyd policy are required before enablement'; return
    fi
    if [[ $state != disabled:* ]]; then
        edit_fail 'the service is already persistently enabled. Review separate startup and application verification.'; return
    fi
    unit=$(attended_fapolicy_unit) || return 1
    ACTION_CONTEXT=$unit
    ACTION_REQUIREMENTS="Confirm the exact compiled policy and trust sources were approved and tested with representative applications. Fingerprint ${state#*:}. Keep a console and validated recovery path."
    if grep -Fxq 'ActiveState=inactive' <<< "$unit"; then
        ACTION_ACTIVATION='The service was enabled for boot. In an approved window run systemctl start fapolicyd.service and verify trusted applications and blocked unauthorized execution. Rollback removes only the enablement link. Stop the daemon separately if it was started.'
    fi
    action_add fapolicyd.service "$state" "enabled:${state#*:}" 'Disabled at startup' 'Enabled at startup. Service activation is separate.'
}

rule_V_244545_matches() {
    local observed=$1 desired=$2
    [[ $observed == "$desired" ]] ||
        [[ $desired =~ ^enabled:[a-f0-9]{64}$ && $observed == "$desired:"* && ${observed#"$desired:"} =~ ^[0-9]+:[0-9]+$ ]]
}

rule_V_244545_change() {
    local target=$1 expected=$2 desired=$3 current
    [[ $target == fapolicyd.service && $expected =~ ^disabled:[a-f0-9]{64}$ && $desired == "enabled:${expected#*:}" ]] || return 1
    current=$(rule_V_244545_observe "$target") && [[ $current == "$expected" ]] || return 1
    timeout 20 systemctl --no-reload enable fapolicyd.service
}

rule_V_244545_restore() {
    local target=$1 original=$2 post=$3 current
    local link=/etc/systemd/system/multi-user.target.wants/fapolicyd.service
    [[ $target == fapolicyd.service && $original =~ ^disabled:[a-f0-9]{64}$ ]] &&
        rule_V_244545_matches "$post" "enabled:${original#*:}" || return 1
    current=$(rule_V_244545_observe "$target") && [[ $current == "$post" ]] &&
        [[ -L $link && $(readlink -- "$link") == /usr/lib/systemd/system/fapolicyd.service ]] || return 1
    rm -- "$link"
}

# Legacy CKL import. The parser returns only bounded identity/status data.
# Candidate metadata is separate from the committed worklist so a canceled
# replacement leaves the existing scope and its recorded checksum untouched.
ckl_parse() {
    if ! command -v python3 >/dev/null || ! command -v timeout >/dev/null; then
        printf '%s\n' 'CKL import requires the RHEL python3 and coreutils packages. Install them through your normal package process.' >&2
        return 1
    fi
    local status
    if timeout --kill-after=2s 15s python3 -I -B - "$@" <<'PYTHON'
import hashlib
import ipaddress
import os
import re
import stat
import sys
import unicodedata
from xml.parsers import expat


MAX_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 24
MAX_NODES = 300000
MAX_SECTIONS = 64
MAX_RECORDS = 10000
MAX_ATTRIBUTES = 64
MAX_FIELD = 4096
STATUS_VALUES = {"Open", "NotAFinding", "Not_Applicable", "Not_Reviewed"}
BENCHMARK = "RHEL_8_STIG"
VERSION = "2"
RELEASE = "9"
BENCHMARK_DATE = "30 Sep 2026"
BENCHMARK_TITLE = "Red Hat Enterprise Linux 8 Security Technical Implementation Guide"

ROOT = ("CHECKLIST",)
ASSET = ROOT + ("ASSET",)
STIGS = ROOT + ("STIGS",)
SECTION = STIGS + ("iSTIG",)
INFO = SECTION + ("STIG_INFO",)
SECTION_FIELD = INFO + ("SI_DATA",)
VULN = SECTION + ("VULN",)
RULE_FIELD = VULN + ("STIG_DATA",)
ASSET_NAMES = ("HOST_NAME", "HOST_FQDN", "HOST_IP", "ROLE")
SECTION_NAMES = ("stigid", "title", "version", "releaseinfo")
RULE_NAMES = ("Vuln_Num", "Rule_ID", "Rule_Ver")
LEAVES = ({ASSET + (name,) for name in ASSET_NAMES}
          | {SECTION_FIELD + ("SID_NAME",), SECTION_FIELD + ("SID_DATA",),
             RULE_FIELD + ("VULN_ATTRIBUTE",), RULE_FIELD + ("ATTRIBUTE_DATA",),
             VULN + ("STATUS",)})


class InvalidChecklist(ValueError):
    pass


def reject(message):
    raise InvalidChecklist(message)


def stat_key(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def load_bytes(path):
    path_info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(path_info.st_mode) or path_info.st_size > MAX_BYTES:
        reject("Choose a regular local file of at most 32 MiB.")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or stat_key(before) != stat_key(path_info):
            reject("The input changed while it was opened.")
        data = file.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            reject("The input exceeds 32 MiB.")
        after = os.fstat(file.fileno())
        named = os.stat(path, follow_symlinks=False)
        if len(data) != before.st_size or stat_key(before) != stat_key(after) or stat_key(after) != stat_key(named):
            reject("The input changed while it was read. Import it again.")
    return data


def clean_text(value, limit=300):
    # Remove control/format characters and dialog's backslash markup. The
    # pipe is the private field delimiter. Ignore every checklist comment.
    value = "".join(c if c not in "|\\" and c.isprintable() else " " for c in value)
    return " ".join(value.split())[:limit]


def normalized_name(value):
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def unique_value(target, name, value, context):
    if name in target:
        reject("Duplicate {} field {}.".format(context, name))
    target[name] = value


class Checklist:
    def __init__(self):
        self.path = []
        self.namespace = ""
        self.node_count = 0
        self.stigs_seen = False
        self.asset_seen = False
        self.asset = {}
        self.sections = []
        self.section = None
        self.vuln = None
        self.pair = None
        self.text = None
        self.text_length = 0
        self.record_count = 0

    def start(self, qualified, attributes):
        namespace, _, name = qualified.rpartition("\x1f")
        self.node_count += 1
        if len(self.path) >= MAX_DEPTH or self.node_count > MAX_NODES or len(attributes) > MAX_ATTRIBUTES:
            reject("The XML exceeds the depth or structural limits.")
        if not self.path:
            if name != ROOT[0]:
                reject("Expected a legacy CHECKLIST XML document.")
            self.namespace = namespace
        if namespace != self.namespace or "http://www.w3.org/2001/XInclude" == namespace:
            reject("Unexpected element namespace or XInclude.")
        for attribute in attributes:
            if attribute.rsplit("\x1f", 1)[-1] in ("schemaLocation", "noNamespaceSchemaLocation", "href", "base"):
                reject("External document references and XInclude are prohibited.")
        if self.text is not None:
            reject("A checklist field contains unexpected nested content.")
        self.path.append(name)
        path = tuple(self.path)
        if path in LEAVES:
            self.text, self.text_length = [], 0
        elif path == ASSET:
            if self.asset_seen:
                reject("More than one ASSET makes the checklist ambiguous.")
            self.asset_seen = True
        elif path == STIGS:
            if self.stigs_seen:
                reject("More than one STIGS container makes the checklist ambiguous.")
            self.stigs_seen = True
        elif path == SECTION:
            if len(self.sections) >= MAX_SECTIONS:
                reject("The checklist contains more than 64 STIG sections.")
            self.section = {"meta": {}, "records": {}, "rules": {}, "duplicates": 0, "info_seen": False}
        elif path == INFO:
            if self.section["info_seen"]:
                reject("More than one STIG_INFO in a section.")
            self.section["info_seen"] = True
        elif path == VULN:
            self.record_count += 1
            if self.record_count > MAX_RECORDS:
                reject("The checklist contains more than 10000 finding records.")
            self.vuln = {}
        elif path in (SECTION_FIELD, RULE_FIELD):
            self.pair = {}

    def characters(self, data):
        if self.text is None:
            return
        self.text_length += len(data)
        if self.text_length > MAX_FIELD:
            if tuple(self.path) in (RULE_FIELD + ("ATTRIBUTE_DATA",), SECTION_FIELD + ("SID_DATA",)):
                # Large prose in unused metadata pairs is not imported.
                self.text = []
                return
            reject("A checklist identity or status field exceeds the field limit.")
        self.text.append(data)

    def end(self, _qualified):
        path = tuple(self.path)
        name = self.path.pop()
        if path in LEAVES:
            value = "".join(self.text).strip(" \r\n\t") if self.text_length <= MAX_FIELD else None
            self.text = None
            if path[:-1] == ASSET:
                unique_value(self.asset, name, value, "ASSET")
            elif path == VULN + ("STATUS",):
                unique_value(self.vuln, name, value, "finding")
            else:
                unique_value(self.pair, name, value, "XML pair")
        elif path == SECTION_FIELD:
            key = self.pair.get("SID_NAME", "").lower()
            if key in SECTION_NAMES:
                if self.pair.get("SID_DATA") is None:
                    reject("A benchmark field is missing SID_DATA or exceeds the field limit.")
                unique_value(self.section["meta"], key, self.pair["SID_DATA"], "benchmark")
            self.pair = None
        elif path == RULE_FIELD:
            key = self.pair.get("VULN_ATTRIBUTE", "")
            if key in RULE_NAMES:
                if self.pair.get("ATTRIBUTE_DATA") is None:
                    reject("A finding identity field is missing or exceeds the field limit.")
                unique_value(self.vuln, key, self.pair["ATTRIBUTE_DATA"], "finding")
            self.pair = None
        elif path == VULN:
            self.add_record()
            self.vuln = None
        elif path == SECTION:
            if not self.section["info_seen"]:
                reject("A STIG section is missing STIG_INFO.")
            self.sections.append(self.section)
            self.section = None

    def add_record(self):
        vuln = self.vuln.get("Vuln_Num", "")
        rule = self.vuln.get("Rule_ID", "")
        policy = self.vuln.get("Rule_Ver", "")
        status = self.vuln.get("STATUS", "")
        if not re.fullmatch(r"V-[1-9][0-9]{0,8}", vuln):
            reject("Malformed or missing Vuln_Num in finding record {}.".format(self.record_count))
        if not re.fullmatch(r"SV-[1-9][0-9]{0,8}r[0-9]{1,9}_rule", rule):
            reject("Malformed or missing Rule_ID for {}.".format(vuln))
        if policy and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", policy):
            reject("Malformed Rule_Ver for {}.".format(vuln))
        if status not in STATUS_VALUES:
            reject("Invalid or missing STATUS for {}.".format(vuln))
        record = (status, rule, policy)
        previous = self.section["records"].get(vuln)
        if previous is not None:
            if previous != record:
                reject("Conflicting duplicate finding {} in a STIG section.".format(vuln))
            self.section["duplicates"] += 1
            return
        if rule in self.section["rules"]:
            reject("Two findings specify the same Rule_ID in a STIG section.")
        self.section["records"][vuln] = record
        self.section["rules"][rule] = vuln

    def validated_asset(self):
        metadata = [self.asset.get(key, "") for key in ASSET_NAMES]
        for value in metadata[:2]:
            if value and not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,253}", value):
                reject("Malformed HOST_NAME or HOST_FQDN. Correct the checklist asset metadata before importing.")
        if metadata[2]:
            try:
                metadata[2] = str(ipaddress.ip_address(metadata[2]))
            except ValueError:
                reject("Malformed HOST_IP in the checklist asset metadata.")
        return tuple(clean_text(value, 254) for value in metadata)


def plausible_section(meta):
    identifiers = ("rhel8stig", "redhatenterpriselinux8stig")
    titles = tuple(normalized_name(value) for value in (
        BENCHMARK_TITLE, "Red Hat Enterprise Linux 8 STIG", "RHEL 8 STIG"
    ))
    return normalized_name(meta.get("stigid", "")) in identifiers or normalized_name(meta.get("title", "")) in titles


def baseline_status(meta):
    benchmark = meta.get("stigid", "")
    version = meta.get("version", "")
    release_info = " ".join(meta.get("releaseinfo", "").split())
    release = re.fullmatch(r"Release:\s*([0-9]+)(?:\s+Benchmark Date:\s*([A-Za-z0-9 ]+))?", release_info)
    if benchmark != BENCHMARK:
        return "no", "Unreviewed benchmark ID. Expected RHEL_8_STIG."
    if version != VERSION or not release or release.group(1) != RELEASE:
        return "no", "Unreviewed source version or release. Expected V2R9."
    if release.group(2) and release.group(2) != BENCHMARK_DATE:
        return "no", "Unreviewed benchmark date. Expected 30 Sep 2026 for V2R9."
    return "yes", "The benchmark identity matches the pinned baseline."


def parse(data):
    if data.lstrip(b"\xef\xbb\xbf \t\r\n").startswith((b"{", b"[")):
        reject("CKLB/JSON is a separate format. Export a legacy CKL (XML) file first.")
    checklist = Checklist()
    parser = expat.ParserCreate(namespace_separator="\x1f")
    parser.StartElementHandler = checklist.start
    parser.EndElementHandler = checklist.end
    parser.CharacterDataHandler = checklist.characters
    parser.StartDoctypeDeclHandler = lambda *args: reject("DTDs and entity declarations are prohibited.")
    parser.EntityDeclHandler = lambda *args: reject("Entity declarations are prohibited.")
    parser.ExternalEntityRefHandler = lambda *args: reject("External entity references are prohibited.")
    parser.SkippedEntityHandler = lambda *args: reject("Entity references outside the XML predefined set are prohibited.")
    parser.ProcessingInstructionHandler = lambda *args: reject("XML processing instructions are prohibited.")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.Parse(data, True)
    return checklist


def main(operation, path):
    path = os.path.abspath(path)
    try:
        display_path = os.fsencode(path).decode("utf-8")
    except UnicodeError:
        reject("The filename must be valid UTF-8.")
    if any(c in "|\\" or unicodedata.category(c) in ("Cc", "Cf", "Cs", "Zl", "Zp") for c in display_path):
        reject("The filename contains a control character or an unsupported separator.")
    if path.lower().endswith(".cklb"):
        reject("CKLB/JSON is a separate format. Export a legacy CKL (XML) file first.")
    content = load_bytes(path)
    digest = hashlib.sha256(content).hexdigest()
    if operation == "digest":
        print(digest)
        return
    checklist = parse(content)
    relevant = [(index, section) for index, section in enumerate(checklist.sections, 1)
                if plausible_section(section["meta"])]
    if not relevant:
        reject("No recognizable RHEL 8 STIG section was found.")
    asset = checklist.validated_asset()
    print("file", display_path, digest, clean_text(os.path.basename(display_path)), sep="|")
    print("asset", *asset, sep="|")
    for index, section in relevant:
        meta = section["meta"]
        baseline, reason = baseline_status(meta)
        print("section", index, *(clean_text(meta.get(key, "")) for key in SECTION_NAMES), sep="|")
        print("baseline", index, baseline, reason, section["duplicates"], sep="|")
        for vuln, (status, rule, policy) in section["records"].items():
            print("finding", index, vuln, status, rule, policy, sep="|")


try:
    sys.stdout = open(sys.stdout.fileno(), "w", encoding="utf-8", closefd=False)
    main(*sys.argv[1:])
except InvalidChecklist as error:
    print("CKL import error: {}".format(error), file=sys.stderr)
    sys.exit(2)
except expat.ExpatError as error:
    print("CKL import error: malformed XML at line {}, column {}.".format(
        error.lineno, error.offset), file=sys.stderr)
    sys.exit(2)
except OSError:
    print("CKL import error: could not read a stable local file. Check the path and permissions.", file=sys.stderr)
    sys.exit(2)
PYTHON
    then
        return 0
    else
        status=$?
    fi
    if [[ $status == 124 || $status == 137 ]]; then
        printf '%s\n' 'CKL import error: the parser exceeded its processing limit.' >&2
    elif [[ $status != 2 ]]; then
        printf '%s\n' 'CKL import error: Python 3 could not run the embedded Expat parser.' >&2
    fi
    return 1
}

ckl_read() {
    local output tag index value1 value2 value3 value4
    CKL_NEXT_PATH='' CKL_NEXT_SECTION=''
    output=$(ckl_parse read "$1") || return 1
    declare -ga CKL_NEXT_SECTIONS=()
    declare -gA CKL_NEXT_SECTION_BENCHMARK=() CKL_NEXT_SECTION_TITLE=() CKL_NEXT_SECTION_VERSION=()
    declare -gA CKL_NEXT_SECTION_RELEASE=() CKL_NEXT_SECTION_MATCH=() CKL_NEXT_SECTION_REASON=()
    declare -gA CKL_NEXT_SECTION_DUPLICATES=() CKL_NEXT_SECTION_RECORDS=()
    while IFS='|' read -r tag index value1 value2 value3 value4; do
        case $tag in
            file) CKL_NEXT_PATH=$index CKL_NEXT_SHA256=$value1 CKL_NEXT_SOURCE_NAME=$value2 ;;
            asset) CKL_NEXT_ASSET_HOST=$index CKL_NEXT_ASSET_FQDN=$value1
                   CKL_NEXT_ASSET_IP=$value2 CKL_NEXT_ASSET_ROLE=$value3 ;;
            section)
                CKL_NEXT_SECTIONS+=("$index")
                CKL_NEXT_SECTION_BENCHMARK[$index]=$value1 CKL_NEXT_SECTION_TITLE[$index]=$value2
                CKL_NEXT_SECTION_VERSION[$index]=$value3 CKL_NEXT_SECTION_RELEASE[$index]=$value4
                ;;
            baseline)
                CKL_NEXT_SECTION_MATCH[$index]=$value1 CKL_NEXT_SECTION_REASON[$index]=$value2
                CKL_NEXT_SECTION_DUPLICATES[$index]=$value3
                ;;
            finding)
                CKL_NEXT_SECTION_RECORDS[$index]+="$value1|$value2|$value3|$value4"$'\n'
                ;;
        esac
    done <<< "$output"
    [[ -n $CKL_NEXT_PATH && ${#CKL_NEXT_SECTIONS[@]} -gt 0 ]]
}

ckl_select_section() {
    local section=$1 id status revision policy count
    CKL_NEXT_SECTION=''
    [[ -n ${CKL_NEXT_PATH:-} && $section =~ ^[1-9][0-9]?$ ]] || return 1
    [[ ${CKL_NEXT_SECTION_MATCH[$section]+present} ]] || return 1
    declare -gA CKL_NEXT_HISTORY=() CKL_NEXT_OPEN_UNMAPPED=()
    declare -gA CKL_NEXT_STATUS_COUNTS=([Open]=0 [NotAFinding]=0 [Not_Applicable]=0 [Not_Reviewed]=0)
    declare -ga CKL_NEXT_OPEN_IDS=()
    CKL_NEXT_BASELINE_MATCH=${CKL_NEXT_SECTION_MATCH[$section]}
    CKL_NEXT_BASELINE_REASON=${CKL_NEXT_SECTION_REASON[$section]}
    CKL_NEXT_DUPLICATES=${CKL_NEXT_SECTION_DUPLICATES[$section]}
    while IFS='|' read -r id status revision policy; do
        [[ -n $id ]] || continue
        CKL_NEXT_HISTORY[$id]=$status
        count=${CKL_NEXT_STATUS_COUNTS[$status]}
        CKL_NEXT_STATUS_COUNTS[$status]=$((count + 1))
        [[ $status == Open ]] || continue
        if [[ $id == V-230285 ]]; then
            # This rule is in the reviewed V2R8 archive and absent from V2R9.
            CKL_NEXT_OPEN_UNMAPPED[$id]='Removed from V2R9. No approved replacement mapping.'
        elif ! known_id "$id"; then
            CKL_NEXT_OPEN_UNMAPPED[$id]='Unsupported ID. No reviewed handler or replacement mapping.'
        elif [[ $CKL_NEXT_BASELINE_MATCH != yes ]]; then
            CKL_NEXT_OPEN_UNMAPPED[$id]=$CKL_NEXT_BASELINE_REASON
        elif [[ $revision != "${REVISION[$id]}" ]]; then
            CKL_NEXT_OPEN_UNMAPPED[$id]="Unreviewed revision $revision. Expected ${REVISION[$id]}."
        elif [[ -n $policy && $policy != "${POLICY_NAME[$id]}" ]]; then
            CKL_NEXT_OPEN_UNMAPPED[$id]="Ambiguous control mapping $policy. Expected ${POLICY_NAME[$id]}."
        else
            CKL_NEXT_OPEN_IDS+=("$id")
        fi
    done <<< "${CKL_NEXT_SECTION_RECORDS[$section]-}"
    CKL_NEXT_SECTION=$section
}

ckl_commit() {
    local section=${CKL_NEXT_SECTION:-} key
    [[ -n $section ]] || return 1
    CKL_PATH=$CKL_NEXT_PATH CKL_SHA256=$CKL_NEXT_SHA256 CKL_SOURCE_NAME=$CKL_NEXT_SOURCE_NAME
    CKL_ASSET_HOST=$CKL_NEXT_ASSET_HOST CKL_ASSET_FQDN=$CKL_NEXT_ASSET_FQDN
    CKL_ASSET_IP=$CKL_NEXT_ASSET_IP CKL_ASSET_ROLE=$CKL_NEXT_ASSET_ROLE
    CKL_SECTION=$section CKL_BASELINE_MATCH=$CKL_NEXT_BASELINE_MATCH
    CKL_BASELINE_REASON=$CKL_NEXT_BASELINE_REASON CKL_DUPLICATES=$CKL_NEXT_DUPLICATES
    declare -ga CKL_OPEN_IDS=("${CKL_NEXT_OPEN_IDS[@]}")
    declare -gA CKL_SECTION_BENCHMARK=(["$section"]="${CKL_NEXT_SECTION_BENCHMARK[$section]}")
    declare -gA CKL_SECTION_TITLE=(["$section"]="${CKL_NEXT_SECTION_TITLE[$section]}")
    declare -gA CKL_SECTION_VERSION=(["$section"]="${CKL_NEXT_SECTION_VERSION[$section]}")
    declare -gA CKL_SECTION_RELEASE=(["$section"]="${CKL_NEXT_SECTION_RELEASE[$section]}")
    declare -gA CKL_HISTORY=() CKL_OPEN_UNMAPPED=() CKL_STATUS_COUNTS=()
    for key in "${!CKL_NEXT_HISTORY[@]}"; do CKL_HISTORY[$key]=${CKL_NEXT_HISTORY[$key]}; done
    for key in "${!CKL_NEXT_OPEN_UNMAPPED[@]}"; do CKL_OPEN_UNMAPPED[$key]=${CKL_NEXT_OPEN_UNMAPPED[$key]}; done
    for key in "${!CKL_NEXT_STATUS_COUNTS[@]}"; do CKL_STATUS_COUNTS[$key]=${CKL_NEXT_STATUS_COUNTS[$key]}; done
}

ckl_verify_source() {
    local path=${1:-${CKL_PATH:-}} expected=${2:-${CKL_SHA256:-}} actual
    [[ -n $path && $expected =~ ^[a-f0-9]{64}$ ]] || return 1
    actual=$(ckl_parse digest "$path") || return 1
    if [[ $actual != "$expected" ]]; then
        printf '%s\n' 'CKL import error: the source checksum changed. Import again and review the new scope.' >&2
        return 1
    fi
}

# Checklist selection and presentation. Keep source provenance separate from
# scope, and use the ordinary assessment/plan state for interactive review.

detect_selection_host() {
    IFS= read -r HOST_NAME < /proc/sys/kernel/hostname || HOST_NAME=
    if [[ ! $HOST_NAME =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$ ]]; then HOST_NAME=; fi
}

open_selection_terminal() {
    if [[ -n ${TTY_FD-} ]] && [[ -t $TTY_FD ]]; then return 0; fi
    [[ -t 0 ]] && { exec {TTY_FD}<> /dev/tty; } 2>/dev/null && [[ -t $TTY_FD ]]
}

choose_ckl_section() {
    local requested=$1 section label release
    local -a choices=()
    if [[ -n $requested ]]; then
        for section in "${CKL_NEXT_SECTIONS[@]}"; do
            if [[ $section == "$requested" ]]; then ckl_select_section "$section"; return; fi
        done
        usage_error 'requested CKL section is absent or does not identify RHEL 8'
        return
    fi
    if (( ${#CKL_NEXT_SECTIONS[@]} == 1 )); then
        ckl_select_section "${CKL_NEXT_SECTIONS[0]}"
        return
    fi
    for section in "${CKL_NEXT_SECTIONS[@]}"; do
        release=${CKL_NEXT_SECTION_RELEASE[$section]:-}
        if [[ $release =~ ^[Rr]elease:[[:space:]]*([0-9]+) ]]; then
            release=${BASH_REMATCH[1]}
        else
            release='?'
        fi
        printf -v label 'V%sR%s | %s | %s' "${CKL_NEXT_SECTION_VERSION[$section]:-?}" "$release" \
            "${CKL_NEXT_SECTION_BENCHMARK[$section]:-unknown benchmark}" "${CKL_NEXT_SECTION_TITLE[$section]:-unavailable}"
        choices+=("$section" "$label")
    done
    if (( GUI )); then
        tui_choose 'Choose RHEL 8 checklist section' 'Several RHEL 8 sections match. Select the intended section.' \
            "${choices[@]}" || return
        requested=$TUI_CHOICE
    else
        printf 'RHEL 8 checklist sections\n' >&2
        printf '  %s  %s\n' "${choices[@]}" >&2
        if ! open_selection_terminal; then
            blocked 'choose an identified section with --ckl-section NUMBER'; return
        fi
        printf 'Section number (Enter cancels) > ' >&"$TTY_FD" || return 1
        IFS= read -r -u "$TTY_FD" requested || return 1
    fi
    [[ $requested =~ ^[1-9][0-9]{0,3}$ ]] || return 1
    ckl_select_section "$requested"
}

ckl_host_mismatch() {
    local local_name=${HOST_NAME,,} asset=${CKL_NEXT_ASSET_HOST,,} fqdn=${CKL_NEXT_ASSET_FQDN,,}
    local addresses
    local_name=${local_name%.} asset=${asset%.} fqdn=${fqdn%.}
    if [[ -z $local_name || $local_name == localhost || $local_name == localhost.localdomain ]]; then
        printf 'Local hostname is unavailable or generic.\n'
    elif [[ -z $asset && -z $fqdn ]]; then
        printf 'The checklist has no asset hostname or FQDN.\n'
    elif [[ $local_name != "$asset" && $local_name != "$fqdn" ]]; then
        printf 'The checklist hostname and FQDN differ from the detected host.\n'
    elif [[ -n $fqdn && $local_name == *.* && $local_name != "$fqdn" ]]; then
        printf 'The checklist FQDN differs from the detected FQDN.\n'
    elif [[ -n $asset && -n $fqdn && ${asset%%.*} != "${fqdn%%.*}" ]]; then
        printf 'The checklist hostname and FQDN identify different hosts.\n'
    fi
    if [[ -n $CKL_NEXT_ASSET_IP ]]; then
        addresses=$(timeout 4 ip -o address show scope global 2>/dev/null |
            awk '{split($4, addr, "/"); if (addr[1] != "") print tolower(addr[1])}') || addresses=
        if [[ $'\n'$addresses$'\n' != *$'\n'"${CKL_NEXT_ASSET_IP,,}"$'\n'* ]]; then
            printf 'The recorded asset IP could not be matched to a local global address.\n'
        fi
    fi
}

load_ckl_selection() {
    local path=$1 requested=$2 acknowledged_digest=$3 expected_digest=${4:-}
    local id mismatch source_info answer ack summary available=0
    ckl_read "$path" || return
    if [[ -n $expected_digest && $expected_digest != "$CKL_NEXT_SHA256" ]]; then
        blocked 'the checklist digest differs from the original run; reimport with --ckl'; return
    fi
    if [[ -n $acknowledged_digest && ${acknowledged_digest,,} != "$CKL_NEXT_SHA256" ]]; then
        blocked 'the supplied host acknowledgment digest does not match this checklist'; return
    fi
    choose_ckl_section "$requested" || return
    mismatch=$(ckl_host_mismatch) || return
    printf -v source_info 'Source asset %s | FQDN %s | IP %s | role %s\nDetected host %s' \
        "${CKL_NEXT_ASSET_HOST:-missing}" "${CKL_NEXT_ASSET_FQDN:-missing}" \
        "${CKL_NEXT_ASSET_IP:-missing}" "${CKL_NEXT_ASSET_ROLE:-missing}" "${HOST_NAME:-unavailable}"
    ack='Asset matched detected host. No acknowledgment required.'
    if [[ -n $mismatch ]]; then
        if [[ ${acknowledged_digest,,} == "$CKL_NEXT_SHA256" ]]; then
            ack='Operator acknowledged for the exact source digest with --ack-ckl-host.'
        elif (( GUI )); then
            tui_confirm 'Confirm checklist asset' "$source_info"$'\n\n'"$mismatch"$'\n\nUse this checklist as the selection source?' \
                'Use checklist' 'Back' || return
            ack='Operator acknowledged the asset differences in the checklist dialog.'
        else
            printf '%s\n%s\nSource SHA-256 %s\n' "$source_info" "$mismatch" "$CKL_NEXT_SHA256" >&2
            if ! open_selection_terminal; then
                blocked 'asset acknowledgment requires --ack-ckl-host with this source SHA-256 or an interactive terminal'; return
            fi
            printf 'Type USE CHECKLIST to use this asset as the selection source (Enter cancels) > ' >&"$TTY_FD" || return 1
            IFS= read -r -u "$TTY_FD" answer && [[ $answer == 'USE CHECKLIST' ]] || return 1
            ack='Operator acknowledged the asset differences at the terminal.'
        fi
    fi
    for id in "${CKL_NEXT_OPEN_IDS[@]}"; do
        if [[ ${SKIPPED[$id]+excluded} ]]; then continue; fi
        if (( SELECT_EXPLICIT )) && [[ ! ${REQUESTED[$id]+selected} ]]; then continue; fi
        (( available += 1 ))
    done
    printf -v summary '%s\nSection %s | %s\n%s\nHistorical Open %s | matched %s | unmapped %s | available after CLI scope %s' \
        "$source_info" "$CKL_NEXT_SECTION" "${CKL_NEXT_SECTION_RELEASE[$CKL_NEXT_SECTION]:-unknown release}" \
        "$CKL_NEXT_BASELINE_REASON" "${CKL_NEXT_STATUS_COUNTS[Open]}" "${#CKL_NEXT_OPEN_IDS[@]}" \
        "${#CKL_NEXT_OPEN_UNMAPPED[@]}" "$available"
    if (( GUI )); then
        tui_message 'Checklist import' "$summary" || return
    else
        printf 'Checklist import\n%s\n' "$summary" >&2
    fi
    if ! ckl_verify_source "$CKL_NEXT_PATH" "$CKL_NEXT_SHA256"; then
        blocked 'the checklist changed during import; reopen the original source'; return
    fi
    ckl_commit || return
    CKL_MAPPED=()
    for id in "${CKL_OPEN_IDS[@]}"; do CKL_MAPPED[$id]=1; done
    CKL_ACK_RECORD=$ack CKL_ACK_REASONS=$mismatch
    printf -v CKL_UI_SUMMARY 'CKL %s | asset %s | host %s | section %s' \
        "$CKL_SOURCE_NAME" "${CKL_ASSET_FQDN:-${CKL_ASSET_HOST:-missing}}" "${HOST_NAME:-unavailable}" "$CKL_SECTION"
}

verify_selection_source() {
    [[ -z ${CKL_PATH-} ]] && return 0
    if ckl_verify_source; then return 0; fi
    notice BLOCKED 'The original CKL changed or is unavailable. Reimport it and review a fresh plan.'
    return 1
}

write_ckl_import_report() {
    local id status reason allowed=0 scoped_out=0 skipped=0
    local -a ckl_exclusions=()
    printf 'Legacy DISA CKL import\nSource file %s\nSHA-256 %s\n' "$CKL_SOURCE_NAME" "$CKL_SHA256"
    printf 'Section %s | %s | %s | version %s | %s\n' "$CKL_SECTION" \
        "${CKL_SECTION_TITLE[$CKL_SECTION]}" "${CKL_SECTION_BENCHMARK[$CKL_SECTION]}" \
        "${CKL_SECTION_VERSION[$CKL_SECTION]}" "${CKL_SECTION_RELEASE[$CKL_SECTION]}"
    printf 'Pinned baseline %s | exact baseline match %s\n' "$BASELINE" "$CKL_BASELINE_MATCH"
    printf '%s\n' "$CKL_BASELINE_REASON"
    printf 'Asset hostname %s | FQDN %s | IP %s | role %s\n' "${CKL_ASSET_HOST:-missing}" \
        "${CKL_ASSET_FQDN:-missing}" "${CKL_ASSET_IP:-missing}" "${CKL_ASSET_ROLE:-missing}"
    printf 'Detected hostname %s\nAcknowledgment %s\n' "${HOST_NAME:-unavailable}" "$CKL_ACK_RECORD"
    if [[ -n $CKL_ACK_REASONS ]]; then printf '%s\n' "$CKL_ACK_REASONS"; fi
    printf '\nHistorical checklist statuses, deduplicated\n'
    for status in Open NotAFinding Not_Applicable Not_Reviewed; do
        printf '  %-16s %s\n' "$status" "${CKL_STATUS_COUNTS[$status]:-0}"
    done
    printf 'Identical duplicate records collapsed %s\n' "$CKL_DUPLICATES"
    printf '\nUnmapped Open findings\n'
    if (( ! ${#CKL_OPEN_UNMAPPED[@]} )); then printf '  None\n'; fi
    for id in "${!CKL_OPEN_UNMAPPED[@]}"; do
        printf '  %s  %s\n' "$id" "${CKL_OPEN_UNMAPPED[$id]}"
    done | sort
    for id in "${CKL_OPEN_IDS[@]}"; do
        if (( SELECT_EXPLICIT )) && [[ ! ${REQUESTED[$id]+present} ]]; then
            (( scoped_out += 1 )); reason='outside explicit CLI scope'
        elif [[ ${SKIPPED[$id]+present} ]]; then
            (( skipped += 1 )); reason='excluded by --skip'
        else
            (( allowed += 1 )); continue
        fi
        ckl_exclusions+=("  $id  $reason")
    done
    printf '\nMatched Open %s | unmapped Open %s\n' "${#CKL_OPEN_IDS[@]}" "${#CKL_OPEN_UNMAPPED[@]}"
    printf 'Available after scope %s | outside CLI scope %s | skipped %s\n' "$allowed" "$scoped_out" "$skipped"
    if (( ${#ckl_exclusions[@]} )); then printf '%s\n' "${ckl_exclusions[@]}"; fi
    printf 'Final selected %s of %s available\n' "${#SCOPE[@]}" "$allowed"
    if (( ${#SCOPE[@]} )); then printf '  %s\n' "${SCOPE[@]}"; fi
}

# The checklist can browse a larger allowed universe. Rebuild the effective
# scope before review so shared effects are checked against selected IDs only.
tui_seed_scope() {
    local id
    resolve_scope || return 1
    TUI_IDS=() TUI_SELECTED=()
    for id in "${SCOPE[@]}"; do
        [[ ${EFFECTIVE[$id]+allowed} ]] || continue
        TUI_IDS+=("$id")
        if (( SELECT_EXPLICIT )) || [[ -n $CKL_PATH ]]; then TUI_SELECTED[$id]=1; fi
    done
}

tui_backend_refresh() {
    local phase=$1 id
    [[ $phase == browse || $phase == review ]] || return 1
    verify_selection_source || return 1
    SCOPE=() EFFECTIVE=()
    for id in "${TUI_IDS[@]}"; do
        if [[ $phase == review && ! ${TUI_SELECTED[$id]+selected} ]]; then continue; fi
        SCOPE+=("$id")
        EFFECTIVE[$id]=1
    done
    include_ssh_scope
    : > "$RUN_DIR/run.log" || return 1
    init_results
    status_cache_begin
    for id in "${SCOPE[@]}"; do assess_one "$id" || return 1; done
    status_cache_finish && status_check_counts
}

tui_backend_import() {
    local old_path=$CKL_PATH message errors=$SELECTION_WORK/import.err
    if ! load_ckl_selection "$1" '' '' 2> "$errors"; then
        if [[ -s $errors ]]; then
            message=$(head -c 1800 -- "$errors" | tr -cd '\011\012\040-\176') || return 2
            tui_message 'Checklist import stopped' "$message" || return 2
        fi
        return 1
    fi
    # An accepted import replaces the source and selection. A failed refresh
    # after this point aborts UI review rather than retaining stale assessments.
    tui_seed_scope && tui_backend_refresh browse && return 0
    notice ERROR "Could not assess the replacement checklist scope${old_path:+ after replacing the previous checklist}."
    return 2
}

open_selection_work() {
    secure_directory "$REPORT_BASE" 1 yes && local_filesystem "$REPORT_BASE" || return 1
    SELECTION_WORK=$(mktemp -d -- "$REPORT_BASE/.selection.XXXXXXXX") || return 1
    RUN_DIR=$SELECTION_WORK TUI_SCANNING=1
    : > "$RUN_DIR/run.log"
}

close_selection_work() {
    if [[ -n ${SELECTION_WORK-} ]]; then
        rm -f -- "$SELECTION_WORK/run.log" "$SELECTION_WORK/summary.txt" "$SELECTION_WORK/import.err" 2>/dev/null || true
        rmdir -- "$SELECTION_WORK" 2>/dev/null || true
        SELECTION_WORK=
    fi
}


# Interactive findings worklist. The backend supplies and rechecks the allowed
# IDs and builds plans with the same assessment functions as ordinary CLI mode.

tui_exec() {
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TERM="$TUI_TERM" \
        DIALOGRC="$TUI_TEMP/dialogrc" DIALOG_ESC=255 DIALOG_ERROR=254 \
        "$TUI_DIALOG" "$@"
}

tui_close() {
    if [[ -n ${TUI_FD-} ]]; then
        exec {TUI_FD}>&-
        TUI_FD=
    fi
    if [[ ${TUI_TEMP-} =~ ^/var/tmp/rhel8-stig-tui\.[A-Za-z0-9]{8}$ && -d $TUI_TEMP && ! -L $TUI_TEMP ]]; then
        rm -f -- "$TUI_TEMP/dialogrc" "$TUI_TEMP/view.txt" "$TUI_TEMP/selection.ids" || true
        rmdir -- "$TUI_TEMP" || true
        TUI_TEMP=
    fi
}

tui_prepare() {
    local capabilities option
    TUI_TEMP='' TUI_FD=''
    TUI_TERM=${TERM:-dumb}
    TUI_COLOR=0
    TUI_CURSOR_OPTION=()
    if [[ ! -t 0 || ! $TUI_TERM =~ ^[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}$ || $TUI_TERM == dumb ]]; then
        blocked 'the terminal interface requires terminal stdin and a supported TERM value'
        return
    fi
    if ! TUI_DIALOG=$(type -P dialog); then
        blocked 'the terminal interface needs the optional dialog 1.3 package. Install it from an approved repository or rerun without --gui or --tui.'
        return
    fi
    if ! TUI_TEMP=$(mktemp -d -- /var/tmp/rhel8-stig-tui.XXXXXXXX) ||
       ! { exec {TUI_FD}<> /dev/tty; } 2>/dev/null || [[ ! -t $TUI_FD ]]; then
        tui_close
        blocked 'could not open a private dialog session on the controlling terminal'
        return
    fi
    if [[ $COLOR == always || ( $COLOR == auto && ! ${NO_COLOR+x} ) ]]; then
        TUI_COLOR=1
    fi
    # A private rc file avoids user and site bindings, which could redefine
    # the keys for affirmative and cancel actions. --colors is used on rows
    # only, after escaping display data, and can be disabled independently.
    {
        if (( TUI_COLOR )); then
            printf '%s\n' 'use_colors = ON' \
                'screen_color = (WHITE,BLUE,OFF)' \
                'dialog_color = (WHITE,BLACK,OFF)' \
                'title_color = (WHITE,BLACK,ON)' \
                'border_color = (WHITE,BLACK,OFF)' \
                'button_active_color = (BLACK,CYAN,ON)' \
                'button_key_active_color = (BLACK,CYAN,ON)' \
                'button_label_active_color = (BLACK,CYAN,ON)' \
                'button_inactive_color = (WHITE,BLACK,OFF)' \
                'button_key_inactive_color = (WHITE,BLACK,OFF)' \
                'button_label_inactive_color = (WHITE,BLACK,OFF)' \
                'menubox_color = (WHITE,BLACK,OFF)' \
                'menubox_border_color = (WHITE,BLACK,OFF)' \
                'item_color = (WHITE,BLACK,OFF)' \
                'tag_color = (WHITE,BLACK,OFF)' \
                'tag_key_color = (WHITE,BLACK,OFF)' \
                'check_color = (WHITE,BLACK,OFF)' \
                'item_selected_color = (WHITE,BLUE,ON)' \
                'tag_selected_color = (WHITE,BLUE,ON)' \
                'tag_key_selected_color = (WHITE,BLUE,ON)' \
                'check_selected_color = (WHITE,BLUE,ON)'
        else
            printf '%s\n' 'use_colors = OFF'
        fi
        printf '%s\n' 'use_shadow = OFF' 'bindkey checklist ^A HELP'
    } > "$TUI_TEMP/dialogrc" || { tui_close; operational_error 'could not create dialog settings'; return; }

    TUI_VERSION=$(tui_exec --version 2>&1) || TUI_VERSION=
    capabilities=$(tui_exec --help 2>&1) || capabilities=
    if [[ ! $TUI_VERSION =~ ^Version:[[:space:]]+1\.[3-9]([.-][0-9]+)*$ ]]; then
        tui_close
        blocked 'the terminal interface requires dialog 1.3 or a compatible 1.x release'
        return
    fi
    for option in --checklist --menu --inputbox --msgbox --textbox --yesno --output-fd --extra-button \
                  --help-status --help-tags --default-item --defaultno --separate-output --no-collapse \
                  --no-nl-expand --colors --clear --no-shadow --hline --last-key; do
        if [[ $capabilities != *"$option"* ]]; then
            tui_close
            blocked "the installed dialog lacks $option. Use the ordinary command-line options with this build."
            return
        fi
    done
    if [[ $capabilities == *--cursor-off-label* ]]; then
        TUI_CURSOR_OPTION=(--cursor-off-label)
    fi
    return 0
}

tui_dialog() {
    if [[ ! -t ${TUI_FD:--1} ]]; then return 254; fi
    TUI_REPLY=$(
        exec 3>&1
        tui_exec --output-fd 3 --no-shadow --clear "${TUI_CURSOR_OPTION[@]}" "$@" \
            <&"$TUI_FD" >&"$TUI_FD" 2>&"$TUI_FD"
    )
}

# Printable ASCII keeps control bytes and dialog's backslash markup out
# of field values and gives column widths that match terminal cells.
tui_line() {
    local value=${1//[^[:print:]]/ }
    REPLY=${value//\\//}
}

tui_block() {
    local line value=''
    while IFS= read -r line; do
        tui_line "$line"
        value+="$REPLY"$'\n'
    done <<< "$1"
    REPLY=${value%$'\n'}
}

tui_shorten() {
    tui_line "$1"
    local limit=$2
    if (( ${#REPLY} > limit )); then REPLY="${REPLY:0:limit-1}~"; fi
}

tui_size() {
    local size
    size=$(stty size <&"$TUI_FD") || return 1
    [[ $size =~ ^([1-9][0-9]{0,3})[[:blank:]]([1-9][0-9]{0,3})$ ]] || return 1
    TUI_ROWS=${BASH_REMATCH[1]} TUI_COLS=${BASH_REMATCH[2]}
    (( TUI_ROWS >= 14 && TUI_COLS >= 46 ))
}

tui_message() {
    local result
    tui_block "$2"
    tui_dialog --title "$1" --no-nl-expand --msgbox "$REPLY" 0 0
    result=$?
    case $result in 0|1|255) return 0 ;; *) return 2 ;; esac
}

tui_confirm() {
    local result
    tui_block "$2"$'\n\n'"$4 is the default. Tab moves focus."
    tui_dialog --title "$1" --no-nl-expand --defaultno --yes-label "$3" --no-label "$4" \
        --yesno "$REPLY" 0 0
    result=$?
    case $result in 0) return 0 ;; 1|255) return 1 ;; *) return 2 ;; esac
}

tui_choose() {
    local title=$1 prompt result tag label count rows width
    tui_block "$2"; prompt=$REPLY
    shift 2
    local -a entries=()
    local -A allowed=()
    TUI_CHOICE=
    if ! tui_size || (( $# == 0 || $# % 2 )); then return 2; fi
    width=$(( TUI_COLS - 2 ))
    if (( width > 86 )); then width=86; fi
    while (( $# )); do
        tag=$1
        [[ $tag =~ ^[A-Za-z0-9_-]+$ && $tag != --* && ! ${allowed[$tag]+seen} ]] || return 2
        tui_shorten "$2" "$(( width - ${#tag} - 12 ))"
        label=$REPLY
        entries+=("$tag" "$label")
        allowed[$tag]=1
        shift 2
    done
    count=$(( ${#entries[@]} / 2 ))
    rows=$(( TUI_ROWS - 9 ))
    if (( rows > count )); then rows=$count; fi
    tui_dialog --title "$title" --no-nl-expand --cancel-label Back \
        --menu "$prompt" 0 "$width" "$rows" "${entries[@]}"
    result=$?
    case $result in
        0)
            [[ $TUI_REPLY =~ ^[A-Za-z0-9_-]+$ && ${allowed[$TUI_REPLY]+seen} ]] || return 2
            TUI_CHOICE=$TUI_REPLY ;;
        1|255) return 1 ;;
        *) return 2 ;;
    esac
}

tui_input() {
    local result initial=$3
    # The final argument is optional in dialog. Treat option-like defaults
    # as an empty input rather than pass them to its option parser.
    if [[ $initial == --* ]]; then initial=; fi
    tui_dialog --title "$1" --no-nl-expand --cancel-label Back --inputbox "$2" 0 0 "$initial"
    result=$?
    case $result in
        0) [[ ${#TUI_REPLY} -le 1024 && $TUI_REPLY != *[^[:print:]]* ]] || return 2 ;;
        1|255) return 1 ;;
        *) return 2 ;;
    esac
}

tui_area() {
    case $1 in
        V-230324|V-230357|V-230358|V-230359|V-230360|V-230361|V-230362|V-230363|V-230365|V-230366|V-230369|V-230375|V-230377|V-230378|V-230383|V-251716) REPLY=Identity ;;
        V-230281) REPLY=Packages ;;
        V-230393|V-230395|V-230397|V-230399|V-230404|V-230405|V-230406|V-230407|V-230408|V-230409|V-230410|V-230412|V-230418|V-230419|V-230421|V-230422|V-230423|V-230424|V-230426|V-230427|V-230428|V-230429|V-230430|V-230431|V-230432|V-230433|V-230434|V-230435|V-230436|V-230437|V-230444|V-230447|V-230448|V-230462|V-230463|V-230464|V-230465|V-230467|V-230472|V-230474) REPLY=Audit ;;
        V-230267|V-230268|V-230269|V-230270|V-230280|V-230547) REPLY=Kernel ;;
        V-230535|V-230536|V-230537|V-230538|V-230539|V-230543|V-230544|V-244550|V-244551|V-244552|V-244553|V-284948|V-284949) REPLY=Network ;;
        V-230244|V-230286|V-230288|V-230290|V-230330|V-230382|V-230556|V-244525) REPLY=SSH ;;
        V-230245|V-230246|V-230247|V-230248|V-230250) REPLY=Logging ;;
        V-230321|V-230325) REPLY=Files ;;
        V-230347|V-244519|V-244535) REPLY=Desktop ;;
        V-230227|V-230531) REPLY=Sessions ;;
        V-230224|V-230301|V-230302|V-230306|V-230307|V-230498|V-230503) REPLY=Storage ;;
        V-230226|V-230352|V-230530|V-244536|V-251718) REPLY=Desktop ;;
        V-230229|V-230274|V-230351|V-230372) REPLY=PKI ;;
        V-230233|V-230367|V-230376|V-244533|V-244534|V-244541|V-251713|V-268322) REPLY=Identity ;;
        V-230234|V-230279) REPLY=Boot ;;
        V-230243|V-230257|V-230323|V-230326|V-230327|V-230384|V-244531|V-244532) REPLY=Files ;;
        V-230251|V-230252|V-230287|V-230296|V-244528|V-272482|V-272483) REPLY=SSH ;;
        V-230264|V-230492|V-288829) REPLY=Packages ;;
        V-230316|V-230494|V-230496|V-230497|V-230504|V-230550) REPLY=Network ;;
        V-230396|V-230398|V-230400|V-230401|V-230471|V-274877|V-288831) REPLY=Audit ;;
        V-230479) REPLY=Logging ;;
        V-230484) REPLY=Time ;;
        V-230495|V-230499) REPLY=Kernel ;;
        V-244545|V-244546|V-250315|V-251710|V-272484) REPLY=Security ;;
        V-257258|V-279929) REPLY=Sessions ;;
        *) REPLY=Other ;;
    esac
}

tui_assessment() {
    case ${AFTER[$1]-UNKNOWN} in
        PASS|FAIL|NOT_APPLICABLE|NEEDS_REVIEW|UNKNOWN|ERROR) REPLY=${AFTER[$1]-UNKNOWN} ;;
        *) REPLY=UNKNOWN ;;
    esac
}

tui_handling() {
    local id=$1
    case ${ACTIONS[$id]-} in
        BLOCKED|PENDING_ACTIVATION) REPLY=Blocked; return ;;
        MANUAL_REQUIRED) REPLY=Manual; return ;;
    esac
    if [[ ${AFTER[$id]-} == ERROR ]]; then
        REPLY=Blocked
    elif [[ ${HANDLING[$id]-} == attended-* ]]; then
        REPLY=Automatic
    else
        REPLY=Manual
    fi
}

tui_action_summary() {
    local id=$1 plan=${DISPLAY_PLAN[$1]-}
    if [[ -n $plan ]]; then
        REPLY=${plan%%$'\n'*}
    else
        case ${ACTIONS[$id]-}/${AFTER[$id]-} in
            MANUAL_REQUIRED/*) REPLY='Review administrator steps' ;;
            PENDING_ACTIVATION/*) REPLY='Review pending activation' ;;
            */PASS) REPLY='Already compliant' ;;
            */NOT_APPLICABLE) REPLY='Not applicable' ;;
            */ERROR) REPLY='Resolve assessment error' ;;
            *) REPLY='Review evidence' ;;
        esac
    fi
}

tui_index() {
    local id
    TUI_ALLOWED=()
    for id in "${TUI_IDS[@]}"; do
        known_id "$id" || return 1
        [[ ! ${SKIPPED[$id]+excluded} && ! ${TUI_ALLOWED[$id]+duplicate} ]] || return 1
        TUI_ALLOWED[$id]=1
    done
    for id in "${!TUI_SELECTED[@]}"; do
        [[ ${TUI_ALLOWED[$id]+allowed} ]] || return 1
    done
}

tui_matches() {
    local id needle=${TUI_SEARCH,,} content
    TUI_MATCH=()
    TUI_VISIBLE=()
    TUI_HIDDEN=${#TUI_SELECTED[@]}
    for id in "${TUI_IDS[@]}"; do
        [[ ! $TUI_CAT || ${CATEGORY[$id]} == "$TUI_CAT" ]] || continue
        if (( TUI_SELECTED_ONLY )) && [[ ! ${TUI_SELECTED[$id]+selected} ]]; then continue; fi
        tui_assessment "$id"
        [[ ! $TUI_RESULT || $REPLY == "$TUI_RESULT" ]] || continue
        tui_handling "$id"
        [[ ! $TUI_HANDLING || $REPLY == "$TUI_HANDLING" ]] || continue
        tui_area "$id"
        [[ ! $TUI_AREA || $REPLY == "$TUI_AREA" ]] || continue
        if [[ $needle ]]; then
            tui_action_summary "$id"
            content="$id ${TITLE[$id]} $REPLY ${DISPLAY_PLAN[$id]-}"
            [[ ${content,,} == *"$needle"* ]] || continue
        fi
        TUI_MATCH+=("$id")
        TUI_VISIBLE[$id]=1
        if [[ ${TUI_SELECTED[$id]+selected} ]]; then (( TUI_HIDDEN -= 1 )); fi
    done
    if [[ $TUI_SORT != ID ]] && (( ${#TUI_MATCH[@]} > 1 )); then
        local ordered
        ordered=$(
            for id in "${TUI_MATCH[@]}"; do
                case $TUI_SORT in
                    CAT) REPLY=${CATEGORY[$id]} ;;
                    Result) tui_assessment "$id" ;;
                    Area) tui_area "$id" ;;
                    *) exit 1 ;;
                esac
                printf '%s %s\n' "$REPLY" "$id"
            done | sort -k1,1 -k2,2
        ) || return 1
        TUI_MATCH=()
        while IFS=' ' read -r content id; do TUI_MATCH+=("$id"); done <<< "$ordered"
    fi
    return 0
}

tui_status_label() {
    case $1 in
        NOT_APPLICABLE) REPLY=N/A ;;
        NEEDS_REVIEW) REPLY=REVIEW ;;
        *) REPLY=$1 ;;
    esac
}

tui_row_text() {
    local id=$1 width=$2 cat result area handling action risk prefix code
    printf -v cat '%-7s' "CAT ${CATEGORY[$id]}"
    tui_assessment "$id"; tui_status_label "$REPLY"
    printf -v result '%-7s' "$REPLY"
    tui_handling "$id"; handling=$REPLY
    tui_area "$id"; area=$REPLY
    if (( TUI_COLOR )); then
        case ${CATEGORY[$id]} in I) code=1 ;; II) code=3 ;; *) code=6 ;; esac
        cat="\\Z${code}${cat}\\Zn"
        case ${AFTER[$id]-} in
            PASS) result="\\Z2${result}\\Zn" ;;
            FAIL|ERROR) result="\\Z1${result}\\Zn" ;;
        esac
    fi
    printf -v prefix '%s %s %-9s' "$cat" "$result" "$handling"
    if (( width >= 110 )); then
        local description_width=$(( (width - 68) / 2 )) action_width
        action_width=$(( width - 66 - description_width ))
        tui_action_summary "$id"
        tui_shorten "$REPLY" "$action_width"; action=$REPLY
        tui_shorten "${TITLE[$id]}" "$description_width"
        risk=${PREVIEW_RISK[$id]:-${RISK[$id]}}
        printf -v REPLY '%s %-9s %-*s %-*s %s' "$prefix" "$area" \
            "$description_width" "$REPLY" "$action_width" "$action" "${risk^^}"
    elif (( width >= 60 )); then
        tui_shorten "${TITLE[$id]}" "$(( width - 47 ))"
        REPLY="$prefix $REPLY"
    else
        REPLY=$prefix
    fi
}

tui_header() {
    local width=$1 description_width action_width
    if (( width >= 110 )); then
        description_width=$(( (width - 68) / 2 ))
        action_width=$(( width - 66 - description_width ))
        printf -v REPLY '     %-9s %-7s %-7s %-9s %-9s %-*s %-*s %s' 'Vuln ID' CAT Result Handling Area \
            "$description_width" Description "$action_width" 'Proposed action' Risk
    elif (( width >= 60 )); then
        printf -v REPLY '     %-9s %-7s %-7s %-9s %s' 'Vuln ID' CAT Result Handling Description
    else
        printf -v REPLY '     %-9s %-7s %-7s %s' 'Vuln ID' CAT Result Handling
    fi
}

tui_filter_text() {
    local text=''
    if [[ $TUI_SEARCH ]]; then text+="Search=$TUI_SEARCH "; fi
    if [[ $TUI_CAT ]]; then text+="CAT=$TUI_CAT "; fi
    if [[ $TUI_RESULT ]]; then text+="Result=$TUI_RESULT "; fi
    if [[ $TUI_HANDLING ]]; then text+="Handling=$TUI_HANDLING "; fi
    if [[ $TUI_AREA ]]; then text+="Area=$TUI_AREA "; fi
    if (( TUI_SELECTED_ONLY )); then text+='Selected only'; fi
    REPLY=${text:-None}
}

tui_checklist() {
    local id width height count list_height line state prompt='' focus='' result
    local -a rows=() options=()
    if ! tui_size; then return 254; fi
    width=$(( TUI_COLS - 2 ))
    if (( width > 220 )); then width=220; fi
    line="Host ${HOST_NAME:-unknown} | ${MODE^^} | No changes made"
    if [[ $MODE == status ]]; then
        line="STATUS | $STATUS_FRESH_COUNT checked live | $STATUS_REUSED_COUNT reused | Host ${HOST_NAME:-unknown}"
    fi
    tui_shorten "$line" "$(( width - 6 ))"
    prompt=$REPLY
    if [[ ${CKL_UI_SUMMARY-} ]]; then
        tui_line "$CKL_UI_SUMMARY"
        if (( ${#prompt} + ${#REPLY} + 3 <= width - 6 )); then
            prompt+=" | $REPLY"
        else
            tui_shorten "$CKL_UI_SUMMARY" "$(( width - 6 ))"
            prompt+=$'\n'"$REPLY"
        fi
    fi
    tui_filter_text; tui_shorten "Filters: $REPLY" "$(( width - 6 ))"
    prompt+=$'\n'"$REPLY"
    line="${#TUI_MATCH[@]} matches | ${#TUI_SELECTED[@]} selected, $TUI_HIDDEN hidden (last refreshed)"
    if (( ${#line} > width - 6 )); then
        prompt+=$'\n'"${#TUI_MATCH[@]} match | ${#TUI_SELECTED[@]} selected | $TUI_HIDDEN hidden"
        prompt+=$'\n''Counts at last refresh'
    else
        prompt+=$'\n'"$line"
    fi
    tui_header "$width"; prompt+=$'\n'"$REPLY"
    for id in "${TUI_MATCH[@]}"; do
        tui_row_text "$id" "$width"
        state=off
        if [[ ${TUI_SELECTED[$id]+selected} ]]; then state=on; fi
        rows+=("$id" "$REPLY" "$state")
    done
    count=${#TUI_MATCH[@]}
    if (( count == 0 )); then
        # Native checklist requires at least one row. Its sentinel is never
        # an ID, never selected in our state, and can never broaden scope.
        rows=(none 'No matching findings. Open Actions to change filters.' off)
        count=1
    elif [[ $TUI_FOCUS && ${TUI_VISIBLE[$TUI_FOCUS]+visible} ]]; then
        focus=$TUI_FOCUS
    else
        focus=${TUI_MATCH[0]}
    fi
    if [[ $focus ]]; then options+=(--default-item "$focus"); fi
    if (( TUI_COLOR )); then options+=(--colors); fi
    height=$(( count + 9 ))
    if (( height > TUI_ROWS )); then height=$TUI_ROWS; fi
    list_height=$(( height - 9 ))
    if (( list_height > count )); then list_height=$count; fi
    # The stock dialog recalculates its window and preserves checked rows on
    # resize. Reformat our columns from current geometry on the next render.
    tui_dialog --title 'Select findings' --no-nl-expand --no-collapse --last-key \
        --ok-label Review --extra-button --extra-label Actions --cancel-label Cancel \
        --help-button --help-label Details --help-status --help-tags --separate-output \
        --hline 'Space toggle | Tab buttons | Ctrl+A Actions' \
        "${options[@]}" --checklist "$prompt" "$height" "$width" "$list_height" "${rows[@]}"
    result=$?
    return "$result"
}

tui_accept_checklist() {
    local code=$1 output=$TUI_REPLY id last_key
    local -A checked=()
    TUI_ACTION_SHORTCUT=0
    # The packaged dialog appends the final key number after checklist rows.
    # A private Ctrl+A binding requests Help status to obtain the focused ID.
    last_key=${output##*$'\n'}
    if [[ $last_key =~ ^-?[0-9]{1,6}$ ]]; then
        if [[ $output == *$'\n'* ]]; then output=${output%$'\n'*}; else output=; fi
        if (( code == 2 )) && [[ $last_key == 1 ]]; then TUI_ACTION_SHORTCUT=1; fi
    fi
    if (( code == 2 )); then
        id=${output%%$'\n'*}
        [[ $id == 'HELP '* ]] || return 1
        id=${id#HELP }
        if [[ $id == none && ${#TUI_MATCH[@]} == 0 ]]; then
            :
        elif known_id "$id" && [[ ${TUI_VISIBLE[$id]+visible} ]]; then
            TUI_FOCUS=$id
        else
            return 1
        fi
        if [[ $output == *$'\n'* ]]; then output=${output#*$'\n'}; else output=; fi
    fi
    if [[ $output ]]; then
        while IFS= read -r id; do
            if [[ $id == none && ${#TUI_MATCH[@]} == 0 ]]; then continue; fi
            known_id "$id" && [[ ${TUI_VISIBLE[$id]+visible} && ! ${checked[$id]+duplicate} ]] || return 1
            checked[$id]=1
        done <<< "$output"
    fi
    # Replace only visible selections. Remember the last focused tag
    # returned by Details; native dialog does not return it on Extra or OK.
    for id in "${TUI_MATCH[@]}"; do unset 'TUI_SELECTED[$id]'; done
    for id in "${!checked[@]}"; do TUI_SELECTED[$id]=1; done
    return 0
}

tui_save_directory() {
    local current=$1 owner access
    valid_state_path "$current" && local_filesystem "$current" || return 1
    while [[ $current != / ]]; do
        [[ -d $current && ! -L $current ]] || return 1
        read -r owner access < <(stat -c '%u %a' -- "$current") || return 1
        [[ $access =~ ^[0-7]{3,4}$ && ( $owner == 0 || $owner == "$EUID" ) ]] || return 1
        if (( 8#$access & 022 )) && { [[ $current == "$1" || $owner != 0 ]] || (( !(8#$access & 01000) )); }; then
            return 1
        fi
        current=${current%/*}
        current=${current:-/}
    done
}

tui_save_selection() {
    local path id result selected_ids_temp
    if (( ! ${#TUI_SELECTED[@]} )); then
        tui_message 'Save selection' 'Select at least one finding before saving an ID file.'
        return
    fi
    tui_input 'Save selection' 'Absolute path for a new ID file in a directory you control' ''
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    path=$TUI_REPLY
    if ! valid_state_path "$path" || ! tui_save_directory "${path%/*}" || [[ -e $path || -L $path ]]; then
        tui_message 'Selection could not be saved' 'Choose a new filename in an existing, protected local directory.'
        return
    fi
    if ! selected_ids_temp=$(mktemp -- "${path%/*}/.rhel8-stig-ids.XXXXXXXX"); then
        tui_message 'Selection could not be saved' 'The protected directory could not create a temporary file.'
        return
    fi
    if ! (
        for id in "${TUI_IDS[@]}"; do
            if [[ ${TUI_SELECTED[$id]+selected} ]]; then printf '%s\n' "$id" || exit 1; fi
        done > "$selected_ids_temp"
    ) || ! ln -T -- "$selected_ids_temp" "$path"; then
        rm -f -- "$selected_ids_temp"
        tui_message 'Selection could not be saved' 'The ID file could not be written.'
        return
    fi
    rm -f -- "$selected_ids_temp" || return 2
    tui_message 'Selection saved' "${#TUI_SELECTED[@]} IDs saved. Use this file with --ids-file."
}

tui_load_selection() {
    local path id TRIMMED result
    local -A loaded_ids=()
    tui_input 'Load selection' 'Absolute path of a saved ID file' ''
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    path=$TUI_REPLY
    if ! valid_output_path "$path" || ! small_regular_file "$path" ||
       ! timeout 5 head -c 131073 -- "$path" > "$TUI_TEMP/selection.ids" ||
       ! text_input_file "$TUI_TEMP/selection.ids"; then
        tui_message 'Selection could not be read' 'Choose a small local ID file.'
        return
    fi
    while IFS= read -r id || [[ $id ]]; do
        trim_line "$id"
        [[ $TRIMMED && $TRIMMED != \#* ]] || continue
        if ! known_id "$TRIMMED" || [[ ! ${TUI_ALLOWED[$TRIMMED]+allowed} ]]; then
            tui_message 'Selection could not be loaded' 'The file contains an unknown or out-of-scope ID. The current selection is unchanged.'
            return
        fi
        loaded_ids[$TRIMMED]=1
    done < "$TUI_TEMP/selection.ids"
    tui_confirm 'Load selection' "Replace the current selection with ${#loaded_ids[@]} IDs from this file?" Load Back
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    TUI_SELECTED=()
    for id in "${!loaded_ids[@]}"; do TUI_SELECTED[$id]=1; done
    return 0
}

tui_bulk() {
    local operation=$1 id
    for id in "${TUI_MATCH[@]}"; do
        if [[ $operation == deselect ]]; then
            unset 'TUI_SELECTED[$id]'
            continue
        fi
        if [[ $operation == failed && ${AFTER[$id]-} != FAIL ]]; then continue; fi
        if [[ ${PREVIEW_KEY[$id]+planned} || ${PLANNED_BY[$id]+grouped} ]]; then
            TUI_SELECTED[$id]=1
        fi
    done
}

tui_filters_clear() {
    TUI_SEARCH='' TUI_CAT='' TUI_RESULT='' TUI_HANDLING='' TUI_AREA='' TUI_SELECTED_ONLY=0
}

tui_actions() {
    local result action
    local -a focus_action=()
    tui_matches || return 2
    tui_filter_text
    if [[ $MODE == apply ]]; then
        focus_action=(Implement-Selected "Review all ${#TUI_SELECTED[@]} selected findings")
        if (( TUI_ACTION_SHORTCUT )); then
            focus_action+=(Implement-One 'Review only the highlighted finding')
        else
            focus_action+=(Implement-One 'Choose one finding to review separately')
        fi
    fi
    if resolution_supported "$TUI_FOCUS"; then
        focus_action+=(Resolve "Review prerequisites and evidence for $TUI_FOCUS")
    fi
    tui_choose Actions "Filters: $REPLY. Bulk actions use all ${#TUI_MATCH[@]} matching rows." \
        "${focus_action[@]}" \
        Search 'Search IDs, descriptions and actions' \
        CAT 'Filter by official CAT' Result 'Filter by current result' \
        Handling 'Filter by automatic, manual or blocked' Area 'Filter by functional area' \
        Selected 'Toggle selected findings only' Clear 'Clear search and filters' \
        All 'Select all eligible matching results' Failed 'Select matching failed automatic results' \
        Deselect 'Deselect all matching results' Save 'Save selection' Load 'Load selection' \
        Import 'Import CKL' Sort 'Sort displayed findings' Refresh 'Refresh local assessment'
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    action=$TUI_CHOICE
    case $action in
        Implement-Selected)
            tui_review
            result=$?
            if (( result == 0 )); then TUI_IMPLEMENT=1; elif (( result == 2 )); then return 2; fi ;;
        Implement-One) tui_choose_implementation || return 2 ;;
        Resolve) tui_resolution "$TUI_FOCUS" || return 2 ;;
        Search)
            tui_input Search 'Enter part of an ID, description or proposed action' "$TUI_SEARCH"
            result=$?
            if (( result == 0 )); then TUI_SEARCH=$TUI_REPLY; elif (( result == 2 )); then return 2; fi ;;
        CAT|Result|Handling|Area)
            case $action in
                CAT) set -- I 'CAT I' II 'CAT II' III 'CAT III' ;;
                Result) set -- PASS Pass FAIL Fail NEEDS_REVIEW 'Needs review' NOT_APPLICABLE 'Not applicable' UNKNOWN Unknown ERROR Error ;;
                Handling) set -- Automatic Automatic Manual Manual Blocked Blocked ;;
                Area)
                    set -- Audit Audit Boot Boot Desktop Desktop Files Files Identity Identity Kernel Kernel \
                        Logging Logging Network Network Packages Packages PKI PKI Security Security \
                        Sessions Sessions SSH SSH Storage Storage Time Time Other Other ;;
            esac
            tui_choose "Filter by $action" 'Choose a filter value.' Any 'Show all values' "$@"
            result=$?
            if (( result == 2 )); then return 2; fi
            if (( result == 0 )); then
                if [[ $TUI_CHOICE == Any ]]; then TUI_CHOICE=; fi
                case $action in
                    CAT) TUI_CAT=$TUI_CHOICE ;; Result) TUI_RESULT=$TUI_CHOICE ;;
                    Handling) TUI_HANDLING=$TUI_CHOICE ;; Area) TUI_AREA=$TUI_CHOICE ;;
                esac
            fi ;;
        Selected) TUI_SELECTED_ONLY=$(( 1 - TUI_SELECTED_ONLY )) ;;
        Clear) tui_filters_clear ;;
        All) tui_bulk all ;;
        Failed) tui_bulk failed ;;
        Deselect) tui_bulk deselect ;;
        Save) tui_save_selection || return 2 ;;
        Load) tui_load_selection || return 2 ;;
        Import) tui_import || return 2 ;;
        Sort)
            tui_choose 'Sort findings' 'Choose how to order matching findings.' \
                ID 'Vulnerability ID' CAT 'Official CAT' Result 'Current result' Area 'Functional area'
            result=$?
            if (( result == 0 )); then TUI_SORT=$TUI_CHOICE; elif (( result == 2 )); then return 2; fi ;;
        Refresh) FORCE_FRESH=1 tui_backend_refresh browse || return 2 ;;
    esac
    return 0
}

tui_choose_implementation() {
    local id result
    local -a findings=()
    if (( TUI_ACTION_SHORTCUT )); then tui_implement_focused; return; fi
    for id in "${TUI_MATCH[@]}"; do findings+=("$id" "${TITLE[$id]}"); done
    if (( ! ${#findings[@]} )); then tui_message Implement 'No findings match the current filters.'; return; fi
    tui_choose Implement 'Choose exactly one finding to review for implementation.' "${findings[@]}"
    result=$?
    case $result in
        0) tui_implement_focused "$TUI_CHOICE" ;;
        1) return 0 ;;
        *) return 2 ;;
    esac
}

tui_resolution() {
    local id=$1 result value previous
    local -a choices=(Evidence 'Record a non-sensitive evidence reference')
    resolution_text "$id" | tr -d '\000-\010\013-\037\177-\377' > "$TUI_TEMP/view.txt" || return 2
    tui_view "Resolve | $id" Options
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    if [[ $id == V-230484 ]]; then choices+=(Source 'Enter a site-approved chrony source'); fi
    if [[ $id == V-251710 ]]; then choices+=(AIDE 'Check the existing AIDE baseline'); fi
    if [[ $MODE == apply && ( ${PREVIEW_KEY[$id]+ready} || ${PLANNED_BY[$id]+included} ) ]]; then
        choices+=(Plan 'Review the proposed change')
    fi
    tui_choose "Resolve | $id" 'Choose an action or return to Findings.' "${choices[@]}"
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    case $TUI_CHOICE in
        Evidence)
            tui_input 'Evidence reference' 'Enter a non-sensitive reference to keep with this finding in the run report.' \
                "${RESOLUTION_NOTES[$id]-}"
            result=$?
            if (( result == 2 )); then return 2; elif (( result )); then return 0; fi
            if ! resolution_note_set "$id" "$TUI_REPLY"; then
                tui_message Resolve 'Use at most 512 bytes and omit control characters.'; return
            fi
            tui_message Resolve 'The reference will be included if you save a report for this finding.' ;;
        Source)
            tui_input 'Approved time source' 'Enter the hostname or IPv4 address the site approved.' \
                "${CHRONY_RUN_SERVER:-${CHRONY_APPROVED_SERVER-}}"
            result=$?
            if (( result == 2 )); then return 2; elif (( result )); then return 0; fi
            value=$TUI_REPLY
            if ! chrony_valid_approved_server "$value"; then tui_message Resolve 'Enter a DNS hostname or IPv4 address.'; return; fi
            previous=$CHRONY_RUN_SERVER
            CHRONY_RUN_SERVER=$value
            if ! tui_backend_refresh browse; then CHRONY_RUN_SERVER=$previous; return 2; fi ;;
        AIDE)
            resolution_aide_check || return 2
            tui_message 'AIDE evidence' "$RESOLUTION_AIDE_RESULT" ;;
        Plan) tui_implement_focused "$id" ;;
    esac
}

tui_implement_focused() {
    local id=${1:-$TUI_FOCUS} result selected_id
    local -a saved_selection=("${!TUI_SELECTED[@]}")
    if ! known_id "$id" || [[ ! ${TUI_VISIBLE[$id]+visible} ]]; then
        tui_message Implement 'Highlight a finding before choosing Implement.'
        return
    fi
    TUI_SELECTED=()
    TUI_SELECTED[$id]=1
    tui_matches || return 2
    tui_review "$id"
    result=$?
    case $result in
        0) TUI_IMPLEMENT=1; return 0 ;;
        2) return 2 ;;
    esac
    TUI_SELECTED=()
    for selected_id in "${saved_selection[@]}"; do TUI_SELECTED[$selected_id]=1; done
}

tui_apply_results() {
    local id
    {
        printf 'Completed run %s\n\n' "$RUN_ID" || return 2
        render_applied_ids && printf '\n' || return 2
        printf 'Finding results\n---------------\n' || return 2
        for id in "${SCOPE[@]}"; do
            printf '%s | %s | %s\n%s\n\n' "$id" "${ACTIONS[$id]}" "${AFTER[$id]}" "${DETAIL[$id]}" ||
                return 2
        done
        if [[ -s $RUN_DIR/changes.txt ]]; then
            printf 'Recorded changes\n----------------\n' || return 2
            cat -- "$RUN_DIR/changes.txt" || return 2
            printf '\n' || return 2
        fi
        if [[ -s $RUN_DIR/next-steps.txt ]]; then
            cat -- "$RUN_DIR/next-steps.txt" && printf '\n' || return 2
        fi
        printf 'Reports\n-------\n%s\n' "$RUN_DIR"
    } | tr -d '\000-\010\013-\037\177' > "$TUI_TEMP/view.txt" || return 2
    tui_highlighted_view 'Implementation results' Close results
}

tui_import() {
    local path result
    tui_input 'Import CKL' 'Absolute path of a legacy CKL XML checklist' ''
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    path=$TUI_REPLY
    if ! valid_output_path "$path"; then tui_message 'Import CKL' 'Enter an absolute local path.'; return; fi
    tui_confirm 'Replace imported scope' 'Importing a checklist replaces the current import scope and selection. Continue?' Replace Back
    result=$?
    if (( result == 1 )); then return 0; elif (( result )); then return 2; fi
    tui_backend_import "$path"
    result=$?
    case $result in
        0) tui_index || return 2; tui_filters_clear ;;
        1) return 0 ;;
        *) return 2 ;;
    esac
}

tui_view() {
    local result width
    if ! tui_size; then return 2; fi
    width=$(( TUI_COLS - 2 ))
    if (( width > 120 )); then width=120; fi
    tui_dialog --title "$1" --exit-label "$2" --textbox "$TUI_TEMP/view.txt" -1 "$width"
    result=$?
    case $result in 0) return 0 ;; 1|255) return 1 ;; *) return 2 ;; esac
}

tui_details_text() {
    local id=$1
    tui_assessment "$id"
    printf '%s | CAT %s | %s\n%s\n\n' "$id" "${CATEGORY[$id]}" "${REVISION[$id]}" "${TITLE[$id]}"
    if [[ ${CKL_UI_SUMMARY-} ]]; then printf 'Checklist status: Open at export\n'; fi
    printf 'Current assessment: %s\n' "$REPLY"
    if [[ ${ASSESSMENT_SOURCE[$id]-} == reused ]]; then
        printf 'Reused result | checked %s\n' "${ASSESSMENT_AT[$id]}"
    fi
    tui_handling "$id"
    printf 'Handling: %s | Operational risk: %s\n' "$REPLY" "${PREVIEW_RISK[$id]:-${RISK[$id]}}"
    printf 'Evidence: %s\n\n' "${DETAIL[$id]-No local evidence recorded.}"
    if [[ ${DISPLAY_PLAN[$id]-} ]]; then
        printf 'Proposed change or blocking reason\n%s\n\n' "${DISPLAY_PLAN[$id]}"
    else
        tui_action_summary "$id"; printf 'Proposed action: %s\n\n' "$REPLY"
    fi
    if [[ ${PREVIEW_KEY[$id]+planned} || ${PLANNED_BY[$id]+grouped} ]]; then
        printf '%s\n' 'Use the affected paths, services and activation steps listed in the plan.' \
            'Apply verifies and backs up the original state before changing it.' \
            'Rollback can restore supported files and metadata. Review active service,' \
            'mount or boot state separately if the operation was activated.'
    fi
    printf '\n'
    render_admin_action "$id"
}

tui_details() {
    local result
    if [[ ! $TUI_FOCUS || ! ${TUI_VISIBLE[$TUI_FOCUS]+visible} ]]; then
        tui_message Details 'There are no matching findings to show.'
        return
    fi
    tui_details_text "$TUI_FOCUS" | tr -d '\000-\010\013-\037\177-\377' > "$TUI_TEMP/view.txt" || return 2
    tui_view "Details | $TUI_FOCUS" Back
    result=$?
    if (( result == 2 )); then return 2; fi
    return 0
}

tui_implement_preview() {
    local id=$1 width=72 owner=${PLANNED_BY[$1]:-$1} proposal delta risk label
    proposal=${DISPLAY_PLAN[$owner]-} delta=${DISPLAY_DIFF[$owner]-}
    if [[ -n ${TUI_FD-} ]] && tui_size; then
        width=$(( TUI_COLS - 8 ))
        if (( width > 112 )); then width=112; fi
    fi
    risk=${PREVIEW_RISK[$owner]:-${RISK[$id]}}
    label=${ACTIONS[$id]}
    if [[ ${PREVIEW_KEY[$owner]+planned} ]]; then label=PROPOSED; fi
    printf '%s  |  CAT %s  |  %s RISK\n' "$id" "${CATEGORY[$id]}" "${risk^^}" || return 1
    printf '%s\n' "${TITLE[$id]}" | fold -s -w "$width" || return 1
    printf '\nPress G to jump to the diff.\n\nASSESSMENT\n----------\n%s  |  %s\n' \
        "${AFTER[$id]}" "$label" || return 1
    printf '%s\n' "${DETAIL[$id]}" | fold -s -w "$width" || return 1

    # Native action previews begin with the same exact lines as their delta.
    # Move that prefix below the plan requirements so it appears once.
    if [[ ${HANDLING[$id]} == attended-action && $delta && $proposal == "$delta"$'\n'* ]]; then
        proposal=${proposal#"$delta"$'\n'}
    fi
    if [[ ! $proposal ]]; then
        tui_action_summary "$id"
        proposal=$REPLY
    fi
    printf '\nIMPLEMENTATION PLAN\n-------------------\n' || return 1
    if [[ $owner != "$id" ]]; then printf 'Shared operation led by %s\n' "$owner" || return 1; fi
    render_ssh_scope_additions || return 1
    printf '%s\n' "$proposal" | fold -s -w "$width" || return 1
    if [[ ${PREVIEW_KEY[$owner]+planned} ]]; then
        printf '\nReview the diff, then start the attended approval.\n' || return 1
    fi

    printf '\nBEFORE / AFTER\n--------------\n' || return 1
    if [[ $delta ]]; then
        printf '%s\n\n%s\n' '- Current    + Proposed' "$delta"
    elif [[ ${PREVIEW_KEY[$owner]+planned} ]]; then
        printf '%s\n' 'The implementation plan above describes the reviewed change.'
    else
        printf '%s\n' 'No proposed changes for this finding.'
    fi
}

tui_highlighted_view() {
    local title=$1 exit_label=$2 screen_type=$3 result
    if (( ${TUI_COLOR:-0} )) && have_tools python3; then
        tui_color_view "$title" "$screen_type" "$exit_label"
        result=$?
        case $result in
            0|1) return "$result" ;;
            3) ;; # This terminal or Python installation cannot render the color view.
            *) return 2 ;;
        esac
    fi
    tui_view "$title" "$exit_label"
}

tui_color_view() {
    # Load the embedded program from stdin, then use the already-open terminal
    # for curses input. Only sanitized preview or results text is rendered.
    env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C TERM="$TUI_TERM" ESCDELAY=200 \
        python3 -I - "$TUI_TEMP/view.txt" "$1" "$2" "${3:-Continue}" \
        3<&"$TUI_FD" >&"$TUI_FD" 2>&"$TUI_FD" <<'PY'
import os
import sys

try:
    import curses
except ImportError:
    sys.exit(3)

PREVIEW_HEADINGS = {"ASSESSMENT", "IMPLEMENTATION PLAN", "BEFORE / AFTER"}
RESULT_HEADINGS = {"Finding results", "Recorded changes", "Reports"}


def result_color(line, heading, removed, added, attention):
    if line in RESULT_HEADINGS or line.startswith("Applied IDs ("):
        return heading
    if line.startswith("  V-"):
        return added
    fields = line.split(" | ", 2)
    if len(fields) != 3 or not fields[0].startswith("V-"):
        return 0
    _, action, assessment = fields
    if action in {"BLOCKED", "PENDING_ACTIVATION", "MANUAL_REQUIRED"}:
        return attention
    if action == "SKIPPED":
        return 0
    if action == "FAILED" or assessment in {"FAIL", "ERROR"}:
        return removed
    if assessment in {"NEEDS_REVIEW", "UNKNOWN"}:
        return attention
    if action == "APPLIED" or assessment == "PASS":
        return added
    return 0


def styled_lines(lines, results, heading, removed, added, attention):
    in_diff = False
    for index, line in enumerate(lines):
        if line == "BEFORE / AFTER":
            in_diff = True
        color = 0
        if index == 0 or (line and line.strip("-") == ""):
            color = heading
        elif results:
            color = result_color(line, heading, removed, added, attention)
        elif line in PREVIEW_HEADINGS:
            color = heading
        elif in_diff and line != "- Current    + Proposed":
            if line.startswith(("--- ", "+++ ", "@@ ")):
                color = heading
            elif line.startswith("-"):
                color = removed
            elif line.startswith("+"):
                color = added
        elif line.startswith("FAIL  |"):
            color = removed
        elif line.startswith("PASS  |"):
            color = added
        yield line.expandtabs(4), color


def review(screen, title, lines, results, action):
    if not curses.has_colors() or curses.COLOR_PAIRS < 5 or curses.COLORS < 8:
        return 3
    background = -1
    try:
        curses.use_default_colors()
    except curses.error:
        background = curses.COLOR_BLACK
    colors = (curses.COLOR_CYAN, curses.COLOR_RED, curses.COLOR_GREEN, curses.COLOR_YELLOW)
    for pair, color in enumerate(colors, 1):
        curses.init_pair(pair, color, background)
    heading, removed, added, attention = [
        curses.color_pair(pair) | curses.A_BOLD for pair in range(1, len(colors) + 1)
    ]
    source = list(styled_lines(lines, results, heading, removed, added, attention))
    top = 0
    at_end = False
    last_width = 0
    focused = 0
    buttons = ("Close",) if results else (action, "Back")
    while True:
        height, cols = screen.getmaxyx()
        width = max(1, cols - 2)
        visible = max(0, height - 6)
        if width != last_width:
            body = [
                (line[start:start + width], color)
                for line, color in source
                for start in range(0, max(len(line), 1), width)
            ]
            last_width = width
        end = max(0, len(body) - visible)
        top = end if at_end else max(0, min(top, end))
        screen.erase()
        ready = height >= 8 and cols >= 30
        if ready:
            screen.addnstr(0, 1, title, width, heading)
            for row, (line, color) in enumerate(body[top:top + visible], 2):
                screen.addnstr(row, 1, line, width, color)
            screen.addnstr(height - 4, 1, "Lines {}-{} of {}".format(
                min(top + 1, len(body)), min(top + visible, len(body)), len(body)), width)
            screen.addnstr(height - 3, 1, "PgUp/PgDn | G end | g top", width)
            column = 1
            for index, name in enumerate(buttons):
                active = focused == index
                label = "[> {} <]".format(name) if active else "[  {}  ]".format(name)
                style = heading | curses.A_REVERSE if active else 0
                screen.addstr(height - 2, column, label, style)
                column += len(label) + 2
            shortcuts = "Tab/Left/Right focus | Enter selects | Esc back"
            if width < len(shortcuts):
                shortcuts = "Tab focus | Enter | Esc back"
            if results:
                shortcuts = "Enter or Esc closes"
            screen.addnstr(height - 1, 1, shortcuts, width)
        elif cols > 2:
            screen.addnstr(0, 1, "Resize terminal or Esc", width)
        screen.refresh()

        key = screen.getch()
        if key in (27, -1):
            return 1
        if ready and key in (10, 13, curses.KEY_ENTER):
            return focused
        if key in (9, curses.KEY_BTAB, curses.KEY_LEFT, curses.KEY_RIGHT):
            focused = (focused + 1) % len(buttons)
        if key in (ord("G"), curses.KEY_END):
            at_end = True
        elif key in (ord("g"), curses.KEY_HOME):
            at_end = False
            top = 0
        elif key in (curses.KEY_NPAGE, curses.KEY_PPAGE, curses.KEY_DOWN, curses.KEY_UP):
            at_end = False
            top += {curses.KEY_NPAGE: visible, curses.KEY_PPAGE: -visible,
                    curses.KEY_DOWN: 1, curses.KEY_UP: -1}[key]


try:
    with open(sys.argv[1], encoding="ascii", errors="backslashreplace") as preview:
        lines = preview.read().splitlines()
    os.dup2(3, 0)
    curses.setupterm()
except curses.error:
    sys.exit(3)
except (OSError, UnicodeError):
    sys.exit(2)
try:
    sys.exit(curses.wrapper(review, sys.argv[2], lines, sys.argv[3] == "results", sys.argv[4]))
except KeyboardInterrupt:
    sys.exit(1)
except curses.error:
    sys.exit(2)
PY
}

tui_review() {
    local focused=${1-} result prompt action=Continue approvals=0 title='Review | complete selected scope'
    local IMPLEMENT_DIFF=0
    if (( ! ${#TUI_SELECTED[@]} )); then
        tui_message Review 'No findings are selected. Choose findings and open Review again.' || return 2
        return 1
    fi
    if [[ $focused || $MODE == apply ]]; then IMPLEMENT_DIFF=1; fi
    tui_backend_refresh review || return 2
    if [[ $MODE == apply ]]; then
        approvals=${#PREVIEW_KEY[@]}
        case $approvals in
            0) action='Save report' ;;
            1) action='Start approval' ;;
            *) action='Start approvals' ;;
        esac
    fi
    if [[ $focused ]]; then
        [[ ${EFFECTIVE[$focused]+selected} ]] || return 2
        title="Implement | $focused"
        tui_implement_preview "$focused" | tr -d '\000-\010\013-\037\177-\377' > "$TUI_TEMP/view.txt" ||
            return 2
        tui_highlighted_view "$title" "$action" preview
        result=$?
    else
        if [[ $MODE == apply ]]; then
            title='Implement selected findings'
        fi
        {
            if [[ $MODE == apply ]]; then render_apply_inventory || return 2; fi
            render_apply_preview
        } | tr -d '\000-\010\013-\037\177-\377' > "$TUI_TEMP/view.txt" || return 2
        tui_view "$title" "$action"
        result=$?
    fi
    if (( result == 0 )); then
        if (( approvals )); then return 0; fi
        if [[ $MODE == apply ]]; then
            prompt='Save the assessed findings and follow-up actions to a report?'
        elif [[ $focused ]]; then
            prompt="Continue with $focused only?"$'\n''Any proposed change still needs attended approval.'
        else
            prompt="Continue with all ${#TUI_SELECTED[@]} selected findings, including $TUI_HIDDEN hidden by the current filters?"
            prompt+=$'\n''This mode only assesses and writes reports.'
        fi
        tui_confirm 'Confirm reviewed scope' "$prompt" "$action" Back
        result=$?
        if (( result == 0 )); then return 0; fi
    fi
    if (( result == 2 )); then return 2; fi
    IMPLEMENT_DIFF=0
    tui_backend_refresh browse || return 2
    return 1
}

tui_run() {
    local result
    local TUI_SEARCH TUI_CAT TUI_RESULT TUI_HANDLING TUI_AREA TUI_SELECTED_ONLY
    local TUI_FOCUS='' TUI_HIDDEN=0 TUI_SORT=ID TUI_ACTION_SHORTCUT=0 TUI_IMPLEMENT=0
    local -a TUI_MATCH=()
    local -A TUI_ALLOWED=() TUI_VISIBLE=()
    tui_filters_clear
    tui_index || return 2
    while :; do
        tui_matches || return 2
        tui_checklist
        result=$?
        case $result in
            0|2|3) tui_accept_checklist "$result" || return 2 ;;
            1|255) return 1 ;;
            *) return 2 ;;
        esac
        case $result in
            0)
                tui_matches || return 2
                tui_review
                result=$?
                case $result in 0) return 0 ;; 2) return 2 ;; esac ;;
            2)
                if (( TUI_ACTION_SHORTCUT )); then tui_actions || return 2
                else tui_details || return 2; fi ;;
            3) tui_actions || return 2 ;;
        esac
        if (( TUI_IMPLEMENT )); then return 0; fi
    done
}


# 9. Main orchestration and final summary

list_rules() {
    local id
    printf 'ID\tCAT\tHANDLING\tTITLE\n'
    for id in "${RULE_IDS[@]}"; do
        printf '%s\t%s\t%s\t%s\n' "$id" "${CATEGORY[$id]}" "${HANDLING[$id]}" "${TITLE[$id]}"
    done
}

explain_rule() {
    local id=$1 fn="rule_${1//-/_}_admin"
    printf '%s — %s\n' "$id" "${TITLE[$id]}"
    printf '%s | %s | CAT %s | %s\n' "${POLICY_NAME[$id]}" "${REVISION[$id]}" \
        "${CATEGORY[$id]}" "$BASELINE"
    printf 'Handling %s | operational risk %s | default scope %s\n' \
        "${HANDLING[$id]}" "${RISK[$id]}" "${DEFAULT_RULE[$id]}"
    if [[ ${AFFECTED[$id]} != "$id" ]]; then printf 'Affected rule IDs %s\n' "${AFFECTED[$id]}"; fi
    printf 'Official archive %s\n' "$ARCHIVE_URL"
    printf '\nDISA check %s\n%s\n' "${CHECK_REF[$id]}" "${OFFICIAL_CHECK[$id]}"
    printf '\nDISA fix %s (reference only)\n%s\n\n' "${FIX_REF[$id]}" "${OFFICIAL_FIX[$id]}"
    if resolution_supported "$id"; then rule_resolution_guidance "$id" && printf '\n'; fi
    if declare -F "$fn" >/dev/null; then "$fn"; fi
}

rule_dispatch() {
    local id=$1 fn="rule_${1//-/_}_check"
    CHECK_PENDING=0 CHECK_PLAN_CANDIDATE=0
    rule_result NEEDS_REVIEW 'additional evidence or a reviewed local procedure is required'
    if declare -F "$fn" >/dev/null; then
        if ! "$fn"; then rule_result ERROR 'rule check returned an operational error'; fi
    fi
    case $ASSESSMENT in PASS|FAIL|NOT_APPLICABLE|NEEDS_REVIEW|UNKNOWN|ERROR) ;;
        *) rule_result ERROR 'rule check returned an invalid result' ;;
    esac
    EVIDENCE=$(clean_text "$EVIDENCE") || rule_result ERROR 'could not sanitize rule evidence'
    return 0
}

check_supports_plan() {
    local id=$1
    if (( CHECK_PENDING )); then return 1; fi
    case ${HANDLING[$id]} in
        attended-module) [[ $ASSESSMENT == FAIL ]] ;;
        attended-file|attended-action)
            # Some authored checks can identify a specific edit before a
            # separate policy or site-evidence requirement has been resolved.
            [[ $ASSESSMENT == FAIL || ( $ASSESSMENT == NEEDS_REVIEW && $CHECK_PLAN_CANDIDATE == 1 ) ]] ;;
        *) return 1 ;;
    esac
}

risk_level() {
    case $1 in low) printf 1 ;; medium) printf 2 ;; high) printf 3 ;; esac
}

allow_rule_plan() {
    local id=$1 affected
    PLAN_REASON=
    for affected in ${AFFECTED[$id]} ${2:-}; do
        if ! known_id "$affected"; then PLAN_REASON='plan declares an unknown affected rule'; return 1; fi
        if [[ ! ${EFFECTIVE[$affected]+selected} ]]; then
            PLAN_REASON="shared effect would change skipped or unselected $affected"; return 1
        fi
        if (( $(risk_level "${RISK[$affected]}") > $(risk_level "$MAX_RISK") )); then
            PLAN_REASON="operational risk for $affected exceeds $MAX_RISK"; return 1
        fi
    done
    return 0
}

init_results() {
    declare -gA BEFORE=() AFTER=() ACTIONS=() DETAIL=() DISPLAY_PLAN=() EDIT_TOUCHED=()
    declare -gA DISPLAY_DIFF=()
    declare -gA PLANNED_BY=() GROUPED_BY=()
    declare -gA PREVIEW_KEY=() PREVIEW_RISK=() PREVIEW_GROUP=()
    declare -gA ASSESSMENT_SOURCE=() ASSESSMENT_AT=()
    STATUS_OBSERVED='' CACHE_DIR='' STATUS_FRESH_COUNT=0 STATUS_REUSED_COUNT=0
    MUTATION_STOP=0 RUN_BLOCKED=0 RUN_ERROR=0
}

prepare_rule_plan() {
    local id=$1 related related_rules='' affected_rules=$1 handling=${HANDLING[$1]}
    PLAN_REASON='' PLAN_TEXT='' PLAN_SIGNATURE='' PLAN_DIFF='' PLAN_GROUP=''
    PLAN_RISK=${RISK[$id]}
    allow_rule_plan "$id" || return 1
    if guided_module_id "$id" && (( ! REVIEW_EACH )); then handling=attended-file; fi
    case $handling in
        attended-module)
            PLAN_APPLIER=apply_module_plan
            module_plan "$id" || return 1
            if plan_diff_requested; then
                PLAN_DIFF=$(printf -- '--- before %s\n+++ after %s\n- absent\n' "$(module_path "$id")" "$(module_path "$id")"
                    module_bytes "$id" "$BOOT_ID" | awk '{print "+ " $0}') || return 1
            fi
            PLAN_TEXT+=$'\nConfirm the module is unused, policy is locally managed, no ISSO exception applies, and a maintenance plan covers next-boot image review and console recovery.' ;;
        attended-file)
            PLAN_APPLIER=apply_file_plan
            file_plan "$id" || return 1
            related_rules=$EDIT_RELATED PLAN_GROUP=$EDIT_GROUPED
            for related in $PLAN_GROUP; do
                if [[ ${PREVIEW_KEY[$related]+planned} ||
                      ( ${PLANNED_BY[$related]+grouped} && ${PLANNED_BY[$related]} != "$id" ) ]]; then
                    PLAN_REASON="grouped plan would overlap another operation for $related"
                    return 1
                fi
            done
            PLAN_TEXT+=$'\nConfirm the affected paths are locally managed and the stated prerequisites are met.' ;;
        attended-action)
            PLAN_APPLIER=apply_action_plan
            action_plan "$id" || return 1
            if plan_diff_requested; then PLAN_DIFF=$(action_preview_delta) || return 1; fi ;;
        *) return 1 ;;
    esac
    for related in ${AFFECTED[$id]} $related_rules; do
        if (( $(risk_level "${RISK[$related]}") > $(risk_level "$PLAN_RISK") )); then
            PLAN_RISK=${RISK[$related]}
        fi
        if [[ " $affected_rules " != *" $related "* ]]; then affected_rules+=" $related"; fi
    done
    if [[ ! $PLAN_SIGNATURE || ! $PLAN_TEXT ]]; then
        PLAN_REASON='the operation did not produce a plan with a review fingerprint'; return 1
    fi
    if [[ $affected_rules != "$id" ]]; then PLAN_TEXT+=$'\n'"Affected rule IDs $affected_rules"; fi
    PLAN_TEXT=$(clean_text "$PLAN_TEXT") || return 1
    # Bind both the transaction arguments and the text presented to the operator.
    PLAN_KEY=$(printf '%s\0' "$PLAN_SIGNATURE" "$PLAN_RISK" "$PLAN_GROUP" "$PLAN_TEXT" | sha256sum)
}

assess_one() {
    local id=$1 related
    if [[ ${SKIPPED[$id]+excluded} ]]; then
        BEFORE[$id]=UNKNOWN AFTER[$id]=UNKNOWN ACTIONS[$id]=SKIPPED
        DETAIL[$id]='excluded by --skip'
        ASSESSMENT_SOURCE[$id]=skipped
        event INFO "$id excluded by scope"
        return
    fi
    if status_cache_capture "$id" && status_cache_lookup "$id"; then
        if [[ ${PLANNED_BY[$id]+planned} ]]; then
            DISPLAY_PLAN[$id]="Included in the proposed ${PLANNED_BY[$id]} change."
        fi
        event INFO "$id reused evidence from ${ASSESSMENT_AT[$id]} after verifying unchanged inputs"
        return
    fi
    rule_dispatch "$id"
    ASSESSMENT_SOURCE[$id]=live ASSESSMENT_AT[$id]=$STATUS_OBSERVED
    BEFORE[$id]=$ASSESSMENT AFTER[$id]=$ASSESSMENT DETAIL[$id]=$EVIDENCE ACTIONS[$id]=UNCHANGED
    event "$ASSESSMENT" "$id $EVIDENCE" || return 1
    if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
    if [[ ${PLANNED_BY[$id]+planned} ]]; then
        DISPLAY_PLAN[$id]="Included in the proposed ${PLANNED_BY[$id]} change."
        return 0
    fi
    if [[ $id == V-288829 && ${SSH_SCOPE_ADDED[$id]+included} ]]; then
        DISPLAY_PLAN[$id]='Included for the OpenSSL impact of the shared SSH crypto-policy change. This run proposes no separate OpenSSL configuration edit.'
        if [[ $ASSESSMENT =~ ^(FAIL|NEEDS_REVIEW|UNKNOWN)$ ]]; then ACTIONS[$id]=MANUAL_REQUIRED; fi
        return 0
    fi
    if (( CHECK_PENDING )); then ACTIONS[$id]=PENDING_ACTIVATION; return 0; fi
    if [[ $ASSESSMENT =~ ^(PASS|NOT_APPLICABLE|ERROR)$ ]]; then return 0; fi
    if ! check_supports_plan "$id"; then
        ACTIONS[$id]=MANUAL_REQUIRED; return 0
    fi
    if ! prepare_rule_plan "$id"; then
        ACTIONS[$id]=BLOCKED
        DISPLAY_PLAN[$id]=$(clean_text "${PLAN_REASON:-the proposed change could not be verified}") || return 1
        edit_reset || return 1
        event BLOCKED "$id ${DISPLAY_PLAN[$id]}"
        return
    fi
    DISPLAY_PLAN[$id]=$PLAN_TEXT
    DISPLAY_DIFF[$id]=$(clean_text "$PLAN_DIFF") || return 1
    PREVIEW_KEY[$id]=$PLAN_KEY PREVIEW_RISK[$id]=$PLAN_RISK PREVIEW_GROUP[$id]=$PLAN_GROUP
    for related in $PLAN_GROUP; do PLANNED_BY[$related]=$id; done
    edit_reset
}

render_apply_finding() {
    local id=$1 plan=$2 delta=${3-${DISPLAY_DIFF[$1]-}}
    printf '%s | CAT %s | %s\n%s\n' "$id" "${CATEGORY[$id]}" "${AFTER[$id]}" "${TITLE[$id]}" || return 1
    printf 'Evidence: %s\n' "${DETAIL[$id]}" || return 1
    if [[ $plan ]]; then printf '%s\n' "$plan" || return 1; fi
    if [[ $delta && ${HANDLING[$id]-} != attended-action ]]; then
        printf '%s\n' "$delta" || return 1
    fi
    printf '\n'
}

render_ssh_scope_additions() {
    local id
    local -a shared=()
    for id in "${SCOPE[@]}"; do
        if [[ ${SSH_SCOPE_ADDED[$id]-} == shared ]]; then shared+=("$id"); fi
    done
    if (( ${#shared[@]} )); then
        printf 'Included for the shared SSH operation: %s\n' "${shared[*]}" || return 1
    fi
    if [[ ${SSH_SCOPE_ADDED[V-288829]-} == impact ]]; then
        printf '%s\n' 'V-288829 is included for the OpenSSL impact only.' || return 1
    fi
    return 0
}

render_apply_inventory() {
    local id group offset
    local -a groups=('Proposed changes' 'Included in another change' 'Shared OpenSSL impact' 'Manual work or evidence' \
        'Blocked' 'Pending activation' 'Already compliant' 'Not applicable' 'Skipped' 'Check errors')
    local -a ids=()
    local -A members=()
    for id in "${SCOPE[@]}"; do
        if [[ ${PREVIEW_KEY[$id]+planned} ]]; then group='Proposed changes'
        elif [[ ${PLANNED_BY[$id]+grouped} ]]; then group='Included in another change'
        elif [[ ${SSH_SCOPE_ADDED[$id]-} == impact ]]; then group='Shared OpenSSL impact'
        else
            case ${ACTIONS[$id]}:${AFTER[$id]} in
                BLOCKED:*) group='Blocked' ;;
                PENDING_ACTIVATION:*) group='Pending activation' ;;
                SKIPPED:*) group='Skipped' ;;
                *:PASS) group='Already compliant' ;;
                *:NOT_APPLICABLE) group='Not applicable' ;;
                *:ERROR) group='Check errors' ;;
                *) group='Manual work or evidence' ;;
            esac
        fi
        members[$group]+="$id "
    done
    printf '%s selected | %s proposed changes\n' "${#SCOPE[@]}" "${#PREVIEW_KEY[@]}" || return 1
    for group in "${groups[@]}"; do
        [[ ${members[$group]+listed} ]] || continue
        read -r -a ids <<< "${members[$group]}"
        printf '\n%s (%s)\n' "$group" "${#ids[@]}" || return 1
        for (( offset=0; offset<${#ids[@]}; offset+=6 )); do
            printf '  %s\n' "${ids[*]:offset:6}" || return 1
        done
    done
}

render_apply_preview() {
    local id operations=${#PREVIEW_KEY[@]} low_risk=0 position=0 title='Full apply preview'
    for id in "${SCOPE[@]}"; do
        if [[ ${PREVIEW_RISK[$id]-} == low ]]; then (( low_risk += 1 )); fi
    done
    if [[ $MODE != apply ]]; then title='Full review preview'; fi
    printf '\n%s\n%s selected | %s operations | %s without a separate operation\n' \
        "$title" "${#SCOPE[@]}" "$operations" "$(( ${#SCOPE[@]} - operations ))" || return 1
    render_ssh_scope_additions || return 1
    if [[ $MODE == apply ]]; then
        printf 'Approval at preview: %s low risk | %s individual (medium or high risk)\n\n' \
            "$low_risk" "$(( operations - low_risk ))" || return 1
    fi
    if (( operations )); then
        printf '%s\n' 'Proposed changes in approval order' || return 1
        for id in "${SCOPE[@]}"; do
            [[ ${PREVIEW_KEY[$id]+planned} ]] || continue
            (( position += 1 ))
            printf '\nChange %s of %s | %s risk\n' "$position" "$operations" "${PREVIEW_RISK[$id]}" || return 1
            render_apply_finding "$id" "${DISPLAY_PLAN[$id]-}" || return 1
        done
    else
        printf '%s\n\n' 'No changes are eligible for approval in this run.' || return 1
    fi
    if (( ${#SCOPE[@]} > operations )); then
        printf '%s\n\n' 'Other selected findings' || return 1
        for id in "${SCOPE[@]}"; do
            [[ ! ${PREVIEW_KEY[$id]+planned} ]] || continue
            printf '%s\n' "${ACTIONS[$id]}" || return 1
            render_apply_finding "$id" "${DISPLAY_PLAN[$id]-}" || return 1
        done
    fi
    if [[ $MODE == apply ]]; then
        printf '%s\n' 'Y approves the current change. N or Enter skips it. D shows its full details.' \
            'Where offered, A approves this and the remaining unchanged low-risk changes from this preview.' \
            'Revised plans and medium- or high-risk changes require individual approval.' || return 1
    fi
}

show_apply_item() {
    local id=$1 position=$2 total=$3 line displayed=0
    printf '\nChange %s of %s | %s | %s risk\n%s\n\nPROPOSED CHANGE\n' \
        "$position" "$total" "$id" "$PLAN_RISK" "${TITLE[$id]}" || return 1
    while IFS= read -r line; do
        case $line in
            ''|'--- '*|'+++ '*|'@@ '*|' '*) continue ;;
        esac
        if (( displayed == 6 )); then
            printf '  More proposal details available with D.\n' || return 1
            break
        fi
        if (( ${#line} > 96 )); then line="${line:0:93}..."; fi
        # Keep +/- at the start of native before/after lines so the terminal
        # renderer can color them without coloring the rest of the proposal.
        case $line in
            '- '*|'+ '*) printf '%s\n' "$line" || return 1 ;;
            *) printf '  %s\n' "$line" || return 1 ;;
        esac
        (( displayed += 1 ))
    done <<< "$PLAN_TEXT"
    return 0
}

apply_choice() {
    local id=$1 risk=$2 allow_all=$3 revised=$4 response approve_options='y/n'
    local heading='' approve='' skip='' reset=''
    if terminal_colors "$TTY_FD"; then
        heading=$'\033[1;36m' approve=$'\033[1;32m' skip=$'\033[1;33m' reset=$'\033[0m'
    fi
    printf '\n%sAPPROVAL%s\n' "$heading" "$reset" >&"$TTY_FD" || return 2
    printf '  %sY%s Approve  |  %sN or Enter%s Skip (default)  |  %sD%s Full details\n' \
        "$approve" "$reset" "$skip" "$reset" "$heading" "$reset" >&"$TTY_FD" || return 2
    if (( allow_all )); then
        approve_options='y/n/a'
        printf '%sA%s approves this and the remaining unchanged low-risk changes.\n' \
            "$approve" "$reset" >&"$TTY_FD" || return 2
    elif (( REVIEW_EACH )); then
        printf '%s\n' 'Individual review is enabled. Choose separately for this change.' >&"$TTY_FD" || return 2
    elif (( revised )); then
        printf '%s\n' 'A is unavailable because this plan changed after the full preview.' >&"$TTY_FD" || return 2
    else
        printf 'A is unavailable for %s-risk changes. This change requires its own decision.\n' \
            "$risk" >&"$TTY_FD" || return 2
    fi
    while :; do
        printf '%sApprove %s (%s risk) [%s]?%s ' \
            "$heading" "$id" "$risk" "$approve_options" "$reset" >&"$TTY_FD" || return 2
        IFS= read -r -u "$TTY_FD" response || return 2
        case ${response,,} in
            y|yes) return 0 ;;
            n|no|'') return 1 ;;
            a) if (( allow_all )); then return 3; fi ;;
            d|details)
                printf '\n%sCurrent proposal for %s (%s risk)%s\n' \
                    "$heading" "$id" "$risk" "$reset" >&"$TTY_FD" || return 2
                render_apply_finding "$id" "$PLAN_TEXT" "${PLAN_DIFF-}" |
                    display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 2
                continue ;;
        esac
        printf 'Choose %s or D for details, or press Enter to skip.\n' "$approve_options" >&"$TTY_FD" || return 2
    done
}

refresh_apply_plan() {
    local id=$1
    if ! verify_script; then
        ACTIONS[$id]=BLOCKED MUTATION_STOP=1 RUN_BLOCKED=1
        DISPLAY_PLAN[$id]='the script changed since preflight. Rerun with verified bytes.'
        event BLOCKED "$id ${DISPLAY_PLAN[$id]}" || return 2
        return 1
    fi
    rule_dispatch "$id"
    AFTER[$id]=$ASSESSMENT DETAIL[$id]=$EVIDENCE
    if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
    if ! check_supports_plan "$id"; then
        ACTIONS[$id]=UNCHANGED
        if [[ $ASSESSMENT =~ ^(NEEDS_REVIEW|UNKNOWN)$ ]]; then ACTIONS[$id]=MANUAL_REQUIRED; fi
        if (( CHECK_PENDING )); then ACTIONS[$id]=PENDING_ACTIVATION; fi
        DISPLAY_PLAN[$id]='the latest assessment no longer supports the original proposed change'
        event "$ASSESSMENT" "$id ${DISPLAY_PLAN[$id]}" || return 2
        return 1
    fi
    if ! prepare_rule_plan "$id"; then
        ACTIONS[$id]=BLOCKED
        DISPLAY_PLAN[$id]=$(clean_text "${PLAN_REASON:-the proposed change could not be verified}") || return 2
        event BLOCKED "$id ${DISPLAY_PLAN[$id]}" || return 2
        return 1
    fi
    if ! verify_selection_source; then
        ACTIONS[$id]=BLOCKED MUTATION_STOP=1 RUN_BLOCKED=1
        DISPLAY_PLAN[$id]='the checklist source changed or could not be verified. Re-import before applying.'
        event BLOCKED "$id ${DISPLAY_PLAN[$id]}" || return 2
        return 1
    fi
    return 0
}

commit_reviewed_plan() {
    local id=$1 approval=$2
    if ! verify_selection_source; then
        ACTIONS[$id]=BLOCKED MUTATION_STOP=1 RUN_BLOCKED=1
        DISPLAY_PLAN[$id]='the original checklist changed before committing the proposed operation'
        event BLOCKED "$id ${DISPLAY_PLAN[$id]}"
        return
    fi
    REVIEWED_GROUP=$PLAN_GROUP
    event INFO "$id $approval approval recorded for plan ${PLAN_KEY%% *}" || return 1
    status_cache_forget "$id $REVIEWED_GROUP ${AFFECTED[$id]}"
    if "$PLAN_APPLIER" "$id" "$PLAN_SIGNATURE"; then
        ACTIONS[$id]=APPLIED AFTER[$id]=$ASSESSMENT DETAIL[$id]=$EVIDENCE
        if (( CHECK_PENDING )); then ACTIONS[$id]=PENDING_ACTIVATION; fi
        if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
        event "${ACTIONS[$id]}" "$id $EVIDENCE" || return 1
    else
        if [[ -n ${STAGING_FILE-} && -f $STAGING_FILE && ! -L $STAGING_FILE ]]; then
            rm -f -- "$STAGING_FILE" || true
        fi
        STAGING_FILE=
        ACTIONS[$id]=FAILED MUTATION_STOP=1 RUN_ERROR=1
        rule_dispatch "$id"
        AFTER[$id]=$ASSESSMENT DETAIL[$id]="$EVIDENCE; check journal and backups before retry"
        event ERROR "$id could not complete the transaction; further mutation stopped" || return 1
    fi
}

apply_reviewed_rule() {
    local id=$1 position=$2 total=$3 presented_key=${PREVIEW_KEY[$1]} result revised=0 allow_all reply approval
    local IMPLEMENT_DIFF=${GUI:-0}
    REVIEWED_GROUP=''
    if (( MUTATION_STOP )); then
        ACTIONS[$id]=BLOCKED DISPLAY_PLAN[$id]='earlier interruption or operation failure stopped mutation'
        return 0
    fi
    refresh_apply_plan "$id"
    result=$?
    if (( result == 2 )); then return 1; fi
    if (( result )); then return 0; fi
    while :; do
        if [[ $PLAN_KEY != "$presented_key" ]]; then
            revised=1 presented_key=$PLAN_KEY DISPLAY_PLAN[$id]=$PLAN_TEXT
            printf '\nRevised plan for %s (%s risk)\n%s\n' "$id" "$PLAN_RISK" "$PLAN_TEXT" |
                display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 1
        fi
        allow_all=0 reply=0 approval=individual
        if (( ! revised && ! REVIEW_EACH )) && [[ $PLAN_RISK == low ]]; then
            allow_all=1
            if (( BULK_APPROVED )); then reply=3; fi
        fi
        if (( reply == 3 )); then
            printf '\nChange %s of %s | %s | unchanged low risk, approved with A\n' \
                "$position" "$total" "$id" >&"$TTY_FD" || return 1
        else
            show_apply_item "$id" "$position" "$total" |
                display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 1
            apply_choice "$id" "$PLAN_RISK" "$allow_all" "$revised"
            reply=$?
        fi
        case $reply in
            1)
                ACTIONS[$id]=SKIPPED DETAIL[$id]+='; operator skipped the proposed change'
                event INFO "$id operator skipped change"
                return ;;
            2)
                ACTIONS[$id]=BLOCKED MUTATION_STOP=1 RUN_BLOCKED=1
                DETAIL[$id]+='; interactive approval was interrupted'
                event BLOCKED "$id approval input closed; further mutation stopped"
                return ;;
            3) BULK_APPROVED=1 approval='original-preview bulk' ;;
        esac
        refresh_apply_plan "$id"
        result=$?
        if (( result == 2 )); then return 1; fi
        if (( result )); then return 0; fi
        if [[ $PLAN_KEY != "$presented_key" ]]; then continue; fi
        commit_reviewed_plan "$id" "$approval"
        return
    done
}

finish_grouped_review() {
    local id=$1 related action=${ACTIONS[$1]}
    local -A seen=()
    for related in ${PREVIEW_GROUP[$id]} $REVIEWED_GROUP; do
        [[ ! ${seen[$related]+seen} ]] || continue
        seen[$related]=1
        if [[ " $REVIEWED_GROUP " == *" $related "* ]]; then
            rule_dispatch "$related"
            AFTER[$related]=$ASSESSMENT DETAIL[$related]=$EVIDENCE ACTIONS[$related]=$action
            if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
            if [[ $action == PENDING_ACTIVATION ]]; then AFTER[$related]=NEEDS_REVIEW; fi
            DISPLAY_PLAN[$related]="Part of the $id operation. Follow its activation and recovery record."
        elif [[ $action == SKIPPED || $action == BLOCKED ]]; then
            ACTIONS[$related]=$action
            DISPLAY_PLAN[$related]="The proposed $id operation did not run."
        else
            ACTIONS[$related]=BLOCKED
            DISPLAY_PLAN[$related]="Revalidation removed this ID from the $id operation. Reassess it separately."
        fi
    done
}

do_apply() {
    local id preview=$RUN_DIR/preview.txt operations=${#PREVIEW_KEY[@]} position=0
    BULK_APPROVED=0
    render_apply_preview > "$preview" || return 1
    if (( ! ${GUI:-0} )); then
        display_terminal_text "$TTY_FD" < "$preview" >&"$TTY_FD" || return 1
    fi
    printf 'Full preview saved to %s\n' "$preview" >&"$TTY_FD" || return 1
    for id in "${SCOPE[@]}"; do
        [[ ${PREVIEW_KEY[$id]+planned} ]] || continue
        (( position += 1 ))
        apply_reviewed_rule "$id" "$position" "$operations" || return 1
        printf '%s %s\n' "$id" "${ACTIONS[$id]}" | display_terminal_text "$TTY_FD" >&"$TTY_FD" || return 1
        finish_grouped_review "$id"
        edit_reset || return 1
    done
}

do_rollback() {
    local old=$1 id result rollback
    if ! have_tools rm getfacl getfattr; then
        blocked 'rollback requires ACL and extended-attribute tools'; return
    fi
    for id in "${SCOPE[@]}"; do
        if [[ ${SKIPPED[$id]+excluded} ]]; then
            BEFORE[$id]=UNKNOWN AFTER[$id]=UNKNOWN ACTIONS[$id]=SKIPPED DETAIL[$id]='excluded by the original scope'
            continue
        fi
        rule_dispatch "$id"
        BEFORE[$id]=$ASSESSMENT AFTER[$id]=$ASSESSMENT DETAIL[$id]=$EVIDENCE ACTIONS[$id]=UNCHANGED
        if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
        if [[ ${GROUPED_BY[$id]+restored} ]]; then
            ACTIONS[$id]=ROLLED_BACK
            DISPLAY_PLAN[$id]="Restored with ${GROUPED_BY[$id]}. Verify related runtime state separately."
            continue
        fi
        case ${HANDLING[$id]} in
            attended-module)
                if guided_module_id "$id" && [[ -e $old/$id.edits || -L $old/$id.edits ]]; then
                    rollback=rollback_file_plan
                else
                    [[ -e $old/$id.pre || -L $old/$id.pre ]] || continue
                    rollback=rollback_module
                fi ;;
            attended-file)
                [[ -e $old/$id.edits || -L $old/$id.edits ]] || continue
                rollback=rollback_file_plan ;;
            attended-action)
                [[ -e $old/$id.actions || -L $old/$id.actions ]] || continue
                rollback=rollback_action_plan ;;
            *) continue ;;
        esac
        if (( MUTATION_STOP )) || ! allow_rule_plan "$id"; then
            ACTIONS[$id]=BLOCKED DETAIL[$id]+='; rollback blocked by interrupted or out-of-scope operation'; continue
        fi
        status_cache_forget "$id ${AFFECTED[$id]}"
        "$rollback" "$id" "$old"
        result=$?
        case $result in
            0) ACTIONS[$id]=ROLLED_BACK ;;
            1) continue ;;
            2)
                ACTIONS[$id]=BLOCKED RUN_BLOCKED=1 MUTATION_STOP=1
                DETAIL[$id]+='; backup incomplete, identity diverged, or file action failed'
                event BLOCKED "$id rollback stopped; inspect the source backup and journal" || return 70
                continue ;;
            3) ACTIONS[$id]=SKIPPED; event INFO "$id operator skipped rollback" || return 70; continue ;;
            4) ACTIONS[$id]=BLOCKED RUN_BLOCKED=1 MUTATION_STOP=1; continue ;;
        esac
        rule_dispatch "$id"
        AFTER[$id]=$ASSESSMENT DETAIL[$id]="$EVIDENCE; review active state after file removal"
        if [[ $ASSESSMENT == ERROR ]]; then RUN_ERROR=1; fi
    done
    return 0
}

render_applied_ids() {
    local id offset
    local -a applied_ids=()
    for id in "${SCOPE[@]}"; do
        if [[ ${ACTIONS[$id]-} == APPLIED ]]; then applied_ids+=("$id"); fi
    done
    printf 'Applied IDs (%s)\n' "${#applied_ids[@]}" || return 1
    for ((offset = 0; offset < ${#applied_ids[@]}; offset += 6)); do
        printf '  %s\n' "${applied_ids[*]:offset:6}" || return 1
    done
}

render_resolution_next_steps() {
    local id group message source
    local -a blockers=() groups=('Boot and kernel modules' 'SSH crypto policy' 'Mounts' 'Time service' 'Desktop' 'Authentication' 'Session timeout' 'Audit rules')
    local -a verify=(--status --fresh --resume "$RUN_ID" --output-dir "$REPORT_BASE")
    local -A pending=()
    for id in "${SCOPE[@]}"; do
        resolution_supported "$id" || continue
        case ${ACTIONS[$id]-} in
            PENDING_ACTIVATION)
                case $id in
                    V-230279|V-23049[4-9]) group='Boot and kernel modules' ;;
                    V-230251|V-230252|V-272482|V-272483) group='SSH crypto policy' ;;
                    V-230301) group=Mounts ;;
                    V-230484) group='Time service' ;;
                    V-230530) group=Desktop ;;
                    V-244541|V-268322) group=Authentication ;;
                    V-257258) group='Session timeout' ;;
                    V-274877|V-288831) group='Audit rules' ;;
                    *) continue ;;
                esac
                pending[$group]="${pending[$group]-}$id " ;;
            BLOCKED|MANUAL_REQUIRED|FAILED) blockers+=("$id") ;;
            APPLIED)
                if [[ ! ${AFTER[$id]} =~ ^(PASS|NOT_APPLICABLE)$ ]]; then blockers+=("$id"); fi ;;
        esac
    done
    (( ${#pending[@]} || ${#blockers[@]} )) || return 0
    printf 'Next steps\n----------\n' || return 1
    for group in "${groups[@]}"; do
        [[ ${pending[$group]+present} ]] || continue
        case $group in
            'Boot and kernel modules') message='Review the boot-entry, initramfs and kdump instructions for the listed findings. Coordinate one reboot after all approved changes are ready.' ;;
            'SSH crypto policy') message='Review dependent clients and services, use the approved policy regeneration and restart steps, then test a fresh SSH connection.' ;;
            Mounts) message='Use the approved targeted remount or reboot. Verify the active options and affected applications.' ;;
            'Time service') message='Activate chronyd in the approved window and verify that it synchronizes to the approved source.' ;;
            Desktop) message='Review queued dconf changes, publish the approved changes, and verify in a fresh GNOME session.' ;;
            Authentication) message='Review the complete authselect diff, regenerate once with recovery access available, then test a fresh login.' ;;
            'Session timeout') message='Activate the logind change in the approved window and test a fresh idle session.' ;;
            'Audit rules') message='Review the full queued policy and activate once. Use an approved reboot when the policy is immutable, then verify loaded rules and expected events.' ;;
        esac
        printf '\n%s | %s\n  %s\n' "$group" "${pending[$group]% }" "$message" || return 1
    done
    if (( ${#blockers[@]} )); then
        printf '\nInput, evidence, or a blocker to resolve\n' || return 1
        for id in "${blockers[@]}"; do
            message=${DETAIL[$id]}
            if [[ ${ACTIONS[$id]} == BLOCKED && ${DISPLAY_PLAN[$id]-} ]]; then message=${DISPLAY_PLAN[$id]}; fi
            printf '  %s | %s\n' "$id" "$message" || return 1
        done
        printf '%s\n' 'Open Resolve for the available in-tool actions and the exact prerequisites.' || return 1
    fi
    if (( ${#pending[@]} )); then
        if [[ ${CONFIG_FILE-} ]]; then verify+=(--config "$CONFIG_FILE"); fi
        source=${CHRONY_RUN_SERVER:-${CHRONY_APPROVED_SERVER-}}
        if [[ $source ]]; then verify+=(--approved-time-source "$source"); fi
        printf '\nRecheck this run after activation\n ' || return 1
        printf ' %q' "$SCRIPT_PATH" "${verify[@]}" && printf '\n'
    fi
}

finalize_run() {
    local id result_file=$RUN_DIR/summary.txt applied=0 blocked_count=0
    UNRESOLVED=0 PENDING_COUNT=0 SKIPPED_COUNT=0
    status_check_counts
    for id in "${SCOPE[@]}"; do
        if [[ ${ACTIONS[$id]} == SKIPPED ]]; then (( SKIPPED_COUNT += 1 )); fi
        if [[ ! ${AFTER[$id]} =~ ^(PASS|NOT_APPLICABLE)$ ]]; then (( UNRESOLVED += 1 )); fi
        if [[ ${ACTIONS[$id]} == PENDING_ACTIVATION ]]; then (( PENDING_COUNT += 1 )); fi
        if [[ ${ACTIONS[$id]} == APPLIED ]]; then (( applied += 1 )); fi
        if [[ ${ACTIONS[$id]} == BLOCKED ]]; then (( blocked_count += 1 )); fi
    done
    {
        report_text || return 70
        if [[ $MODE == apply ]]; then
            { printf '\n' && render_applied_ids; } || return 70
        fi
    } > "$result_file" || return 70
    if [[ $MODE == diff ]]; then cp -- "$result_file" "$RUN_DIR/diff.txt" || return 70; fi
    write_admin_actions | tr -d '\000-\010\013-\037\177' > "$RUN_DIR/admin-actions.txt" || return 70
    if [[ $MODE == apply ]]; then
        render_resolution_next_steps | tr -d '\000-\010\013-\037\177' > "$RUN_DIR/next-steps.txt" || return 70
    fi
    case $FORMAT in
        json) result_file=$RUN_DIR/results.json; report_json > "$result_file" || return 70 ;;
        csv) result_file=$RUN_DIR/results.csv; report_csv > "$result_file" || return 70 ;;
    esac
    event INFO "completed with $UNRESOLVED unresolved, $PENDING_COUNT pending, $SKIPPED_COUNT skipped" || return 70
    if [[ $FORMAT == text && -t 1 ]] && { [[ $MODE == apply ]] || (( GUI )); }; then
        printf '\n%s selected | %s applied | %s unresolved | %s blocked | %s pending activation | %s skipped\n' \
            "${#SCOPE[@]}" "$applied" "$UNRESOLVED" "$blocked_count" "$PENDING_COUNT" "$SKIPPED_COUNT" || return 70
        if [[ $MODE == apply ]]; then render_applied_ids || return 70; fi
        printf 'Full results %s\nAdministrator actions %s\n' "$result_file" "$RUN_DIR/admin-actions.txt" || return 70
        if [[ -s $RUN_DIR/next-steps.txt ]]; then printf 'Next steps %s\n' "$RUN_DIR/next-steps.txt" || return 70; fi
        if [[ -n ${BACKUP_RUN-} ]]; then printf 'Backups %s\n' "$BACKUP_RUN" || return 70; fi
    elif [[ $FORMAT == text ]]; then
        display_terminal_text 1 < "$result_file" || return 70
    else
        cat -- "$result_file" || return 70
    fi
    if [[ $FORMAT != text ]]; then
        notice INFO "$UNRESOLVED unresolved, $PENDING_COUNT pending, $SKIPPED_COUNT skipped. Reports: $RUN_DIR"
    fi
    if (( RUN_ERROR )); then return 70; fi
    if (( RUN_BLOCKED )); then return 69; fi
    if (( UNRESOLVED )); then return 2; fi
    return 0
}

interrupt_run() {
    if [[ -n ${STAGING_FILE-} && -f $STAGING_FILE && ! -L $STAGING_FILE ]]; then
        rm -f -- "$STAGING_FILE" || true
    fi
    if [[ -n ${RUN_DIR-} ]]; then
        event ERROR 'run interrupted; inspect manifest, changes and backups before retrying' || true
        printf 'Run interrupted. Use the journal and inspect the actual target state before resuming.\n' \
            >> "$RUN_DIR/summary.txt"
    fi
    exit 70
}

cleanup_ephemeral() {
    if [[ -n ${STAGING_FILE-} && -f $STAGING_FILE && ! -L $STAGING_FILE ]]; then
        rm -f -- "$STAGING_FILE" || true
    fi
    edit_reset || true
    if (( ${GUI:-0} )); then tui_close || true; fi
    close_selection_work
}

main() {
    local id previous='' volatility ui_result reviewed=0 run_result
    PATH=/usr/sbin:/usr/bin:/sbin:/bin
    export PATH LC_ALL=C
    unset CDPATH ENV BASH_ENV MODPROBE_OPTIONS GLOBIGNORE
    umask 077
    set -o pipefail
    init_options
    TUI_TEMP='' TUI_FD='' TTY_FD='' RUN_DIR='' BACKUP_RUN='' EDIT_TEMP='' STAGING_FILE='' PRIOR_BOOT=''
    if ! register_rules; then operational_error 'embedded rule registry failed verification'; return; fi
    parse_args "$@" || return
    case $MODE in
        help) usage; return ;;
        list) list_rules; return ;;
        explain) explain_rule "$EXPLAIN_ID"; return ;;
        changelog) changelog; return ;;
        version) printf 'rhel8-stig.sh %s | %s | %s\n' "$SCRIPT_VERSION" "$BASELINE" "$ARCHIVE_SHA256"; return ;;
        self-hash)
            if ! identify_script; then operational_error 'cannot hash the executing regular script'; return; fi
            printf '%s  %s\n' "$SCRIPT_HASH" "$SCRIPT_PATH"; return ;;
    esac
    preflight || return
    if [[ $MODE == diff ]] && ! have_tools diff; then blocked 'diff mode requires diffutils'; return; fi
    detect_selection_host
    if [[ $MODE == apply || $MODE == rollback ]]; then
        open_attended_terminal || return
        if ! trust_script_location || ! verify_script; then
            blocked 'mutation requires the verified executing script in a root-controlled directory'; return
        fi
        if (( ! GUI )) && ! lock_mutation; then blocked 'host mutation lock could not be acquired'; return; fi
    fi
    if [[ -n $RESUME_ID ]]; then
        previous=$REPORT_BASE/$RESUME_ID
        if ! secure_directory "$previous" 0 yes || ! verify_digest "$previous/manifest" ||
            ! load_manifest "$previous/manifest" "$RESUME_ID"; then
            blocked 'resume manifest is unavailable, unsafe or from different host/script/policy'; return
        fi
    fi
    if [[ $MODE == rollback ]]; then
        previous=$BACKUP_BASE/$ROLLBACK_ID
        if ! secure_directory "$previous" 0 no || ! local_filesystem "$previous" ||
            ! verify_digest "$previous/manifest" || ! load_manifest "$previous/manifest" "$ROLLBACK_ID"; then
            blocked 'backup manifest is unavailable, unsafe or from different host/script/policy'; return
        fi
    fi
    trap interrupt_run INT TERM HUP
    trap cleanup_ephemeral EXIT
    if (( GUI )); then
        tui_prepare || return 69
    fi
    if [[ -n $CKL_RESUME_PATH ]]; then
        load_ckl_selection "$CKL_RESUME_PATH" "$CKL_RESUME_SECTION" "$CKL_HOST_ACK" "$CKL_RESUME_SHA256" || return 69
        CKL_ACK_RECORD+=" Source digest verified against the prior run."
    elif [[ -n $CKL_FILE ]]; then
        load_ckl_selection "$CKL_FILE" "$CKL_SECTION_OPT" "$CKL_HOST_ACK" || return 69
    elif [[ -n $CKL_HOST_ACK ]]; then
        usage_error 'the resumed run contains no CKL to acknowledge'; return
    fi
    if (( GUI )); then
        if ! open_selection_work; then operational_error 'could not create protected selection workspace'; return; fi
        notice INFO 'Assessing the available selection scope.'
        tui_seed_scope && tui_backend_refresh browse || return 70
        tui_run
        ui_result=$?
        tui_close || return 70
        TUI_SCANNING=0
        case $ui_result in
            0) reviewed=1 ;;
            1)
                notice INFO 'Selection canceled or empty. No changes were authorized.'
                if [[ -z $CKL_PATH ]]; then return 0; fi
                SCOPE=() EFFECTIVE=() TUI_SELECTED=()
                : > "$SELECTION_WORK/run.log" || return 70 ;;
            *) operational_error 'interactive selection ended before review was accepted'; return ;;
        esac
        if (( reviewed )) && [[ $MODE == apply ]] && ! lock_mutation; then
            blocked 'host mutation lock could not be acquired'; return
        fi
    else
        if ! resolve_scope; then usage_error 'the selected scope is empty'; return; fi
        include_ssh_scope
    fi
    verify_selection_source || return 69
    if ! create_run || ! record_digest "$RUN_DIR/manifest"; then
        operational_error 'could not create a protected local report and manifest'; return
    fi
    if (( reviewed )); then
        cat -- "$SELECTION_WORK/run.log" >> "$RUN_DIR/run.log" || return 70
    else
        init_results
    fi
    close_selection_work
    if [[ -n $CKL_PATH ]]; then
        write_ckl_import_report | tr -d '\000-\010\013-\037\177' > "$RUN_DIR/ckl-import.txt" || return 70
        notice INFO "CKL import selected ${#SCOPE[@]} of ${CKL_STATUS_COUNTS[Open]} historical Open findings. Import report $RUN_DIR/ckl-import.txt"
    fi
    collect_host_context || return 70
    if (( DEFER )); then event INFO 'only staging with safely deferred activation is enabled' || return 70; fi
    if [[ -n ${PRIOR_BOOT-} ]]; then
        volatility=unchanged
        if [[ $PRIOR_BOOT != "$BOOT_ID" ]]; then volatility=changed; fi
        event INFO "related run boot identity is $volatility; performing a fresh assessment" || return 70
    fi
    if [[ $MODE == rollback ]]; then
        do_rollback "$previous" || return
    else
        if (( ! reviewed )); then
            status_cache_begin
            for id in "${SCOPE[@]}"; do assess_one "$id" || return 70; done
            status_cache_finish && status_check_counts || return 70
        fi
        verify_selection_source || return 69
        if [[ $MODE == apply && ${#SCOPE[@]} -gt 0 ]]; then do_apply || return 70; fi
    fi
    finalize_run
    run_result=$?
    if (( GUI && reviewed && run_result != 70 )) && [[ $MODE == apply ]]; then
        if tui_prepare; then
            tui_apply_results || true
            tui_close || true
        fi
    fi
    return "$run_result"
}

# Scoped password-quality, account defaults and DNF cleanup plans.

account_policy_path() {
    case $1 in
        quality) printf '%s\n' /etc/security/pwquality.conf ;;
        login) printf '%s\n' /etc/login.defs ;;
        dnf) printf '%s\n' /etc/dnf/dnf.conf ;;
        *) return 1 ;;
    esac
}

account_policy_pam_directory() { printf '%s\n' /etc/pam.d; }

# Keep explicit benchmark values separate from effective PAM behavior. Only
# stage direct local directives. Other sources enter the plan fingerprint.
account_policy_io() {
    repo_platform_python -I - "$@" <<'PY'
import configparser
import ctypes
import hashlib
import os
from pathlib import Path
import re
import stat
import sys


class Review(Exception):
    pass


POLICY = {
    "quality": {
        "V-230357": ("ucredit", "-1", "negative"),
        "V-230358": ("lcredit", "-1", "negative"),
        "V-230359": ("dcredit", "-1", "negative"),
        "V-230360": ("maxclassrepeat", "4", "positive_max"),
        "V-230361": ("maxrepeat", "3", "positive_max"),
        "V-230362": ("minclass", "4", "exact"),
        "V-230363": ("difok", "8", "minimum"),
        "V-230369": ("minlen", "15", "minimum"),
        "V-230375": ("ocredit", "-1", "negative"),
        "V-230377": ("dictcheck", "1", "exact"),
        "V-251716": ("retry", "3", "positive_max"),
    },
    "login": {
        "V-230324": ("CREATE_HOME", "yes", "yes"),
        "V-230365": ("PASS_MIN_DAYS", "1", "minimum"),
        "V-230366": ("PASS_MAX_DAYS", "180", "positive_max"),
        "V-230378": ("FAIL_DELAY", "4", "minimum"),
        "V-230383": ("UMASK", "077", "exact"),
    },
    "dnf": {"V-230281": ("clean_requirements_on_remove", "True", "true")},
}
QUALITY_KEYS = set(spec[0] for spec in POLICY["quality"].values())
PAM_OPTIONS = {
    "debug", "try_first_pass", "use_first_pass", "use_authtok", "enforce_for_root",
    "local_users_only", "authtok_type", "type", "badwords", "dictpath",
    "usercheck", "usersubstr", "gecoscheck", "enforcing",
} | QUALITY_KEYS
INTEGER = re.compile(r"-?(?:0|[1-9][0-9]{0,8})\Z")
DIRECT_PATH = re.compile(r"[A-Za-z0-9_.-]+\.conf\Z")


def controlled(path, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not path.is_absolute():
        raise Review("a configuration path is not absolute")
    info = path.lstat()
    if not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise Review("a configuration source is linked, writable or outside the root-owned layout")
    if not directory and (info.st_size > 131072 or info.st_nlink != 1):
        raise Review("a configuration source is oversized or hard linked")
    for parent in path.parents:
        info = parent.lstat()
        # Temporary test fixtures may live under a root-owned sticky directory.
        # Production paths and transaction candidates are already constrained
        # by the Bash backend and have private/root-controlled immediate parents.
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise Review("a configuration parent is linked or has unexpected ownership")
        if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
            raise Review("a configuration parent is writable")


def read_file(path):
    controlled(path)
    with path.open("rb") as file:
        data = file.read(131073)
    if (len(data) > 131072 or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", data)
            or b"\r" in data.replace(b"\r\n", b"")):
        raise Review("a configuration source contains unsupported bytes or exceeds the size limit")
    return data.decode("utf-8")


def active_line(line):
    return line.partition("#")[0].strip()


def settings(text, separator, keys):
    result = {}
    for index, line in enumerate(text.splitlines(True)):
        active = active_line(line)
        if not active:
            continue
        key = re.split(r"[ \t=]", active, maxsplit=1)[0]
        normalize = str.upper if separator == "login" else str.lower
        key_match = normalize(key)
        if key_match not in keys:
            continue
        if separator == "login" and key != key_match:
            raise Review("login.defs has an unsupported spelling for a policy option")
        tail = active[len(key):]
        lead = r"[ \t]+" if separator == "login" else r"(?:[ \t]*=[ \t]*|[ \t]+)"
        found = re.fullmatch(lead + r"([^ \t=]+)", tail)
        if not found:
            raise Review("a policy option has unsupported assignment syntax")
        result.setdefault(key_match, []).append((index, found.group(1)))
    return result


def meets(value, target, predicate):
    if value is None:
        return False
    if predicate in {"yes", "true"}:
        accepted = {"yes"} if predicate == "yes" else {"1", "true", "yes"}
        rejected = {"no"} if predicate == "yes" else {"0", "false", "no"}
        if value.lower() not in accepted | rejected:
            raise Review("a Boolean policy option has unsupported syntax")
        return value.lower() in accepted
    if not INTEGER.fullmatch(value) and not (
        target == "077" and re.fullmatch(r"[0-7]{1,4}", value)
    ):
        raise Review("a policy option is outside its supported integer syntax")
    actual = int(value, 8 if target == "077" else 10)
    needed = int(target, 8 if target == "077" else 10)
    if predicate == "negative":
        return actual <= needed
    if predicate == "positive_max":
        return 0 < actual <= needed
    if predicate == "minimum":
        return actual >= needed
    return actual == needed


def native_pwquality(path):
    library = ctypes.CDLL("/usr/lib64/libpwquality.so.1")
    library.pwquality_default_settings.restype = ctypes.c_void_p
    library.pwquality_read_config.argtypes = (
        ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p),
    )
    library.pwquality_free_settings.argtypes = (ctypes.c_void_p,)
    library.pwquality_free_settings.restype = None
    handle = library.pwquality_default_settings()
    if not handle:
        raise Review("libpwquality could not allocate settings")
    try:
        if library.pwquality_read_config(handle, os.fsencode(str(path)), None):
            raise Review("the native libpwquality parser rejected the configuration")
    finally:
        library.pwquality_free_settings(handle)


def read_pam(pam):
    sources = []
    stacks = []
    for name in ("system-auth", "password-auth"):
        link = pam / name
        active = link.resolve(strict=True)
        if active not in {link, Path("/etc/authselect") / name}:
            raise Review("the active PAM stack resolves outside the supported local layout")
        data = read_file(active)
        sources.append((str(active), data))
        before_writer = True
        quality_count = 0
        token_writers = 0
        overrides = {}
        for line in data.splitlines():
            words = active_line(line).split()
            if not words or words[0].lstrip("-") != "password":
                continue
            if len(words) < 3 or words[0] != "password":
                raise Review("the active password stack contains an unsupported control")
            control, module_path = words[1:3]
            module = Path(module_path).name
            if module_path not in {module, "/usr/lib64/security/" + module, "/lib64/security/" + module}:
                raise Review("the local PAM stack references a module outside the native directory")
            options = words[3:]
            if module == "pam_pwquality.so":
                if not before_writer or quality_count or control not in {"required", "requisite"}:
                    raise Review("the password-quality module is not an unambiguous required check")
                quality_count += 1
                for option in options:
                    option_name, equal, value = option.partition("=")
                    if (option_name not in PAM_OPTIONS or option_name in overrides
                        or not re.fullmatch(r"[a-zA-Z0-9_./,-]*", value)):
                        raise Review("an active PAM password-quality override needs administrator review")
                    if option_name in QUALITY_KEYS | {"enforcing"}:
                        if not equal or not INTEGER.fullmatch(value):
                            raise Review("an active PAM password-quality override is not a supported integer")
                    # Record nonnumeric option names only, not their values.
                    overrides[option_name] = value if option_name in QUALITY_KEYS | {"enforcing"} else None
            elif module == "pam_unix.so":
                if (not quality_count or token_writers
                        or control not in {"required", "requisite", "sufficient"}
                        or "use_authtok" not in options):
                    raise Review("the local PAM password writer bypasses or replaces the checked token")
                before_writer = False
                token_writers += 1
            elif before_writer and not (
                quality_count and module == "pam_pwhistory.so"
                and control in {"required", "requisite"} and "use_authtok" in options
            ):
                raise Review("a PAM branch can bypass or replace the checked password token")
        if quality_count != 1 or token_writers != 1:
            raise Review("a supported local PAM password quality and writer pair was not found")
        stacks.append(overrides)
    # The standard local passwd service must actually delegate to the checked
    # system-auth stack. Never evaluate password changes or submit credentials.
    passwd = pam / "passwd"
    data = read_file(passwd)
    statements = [line.split() for raw in data.splitlines()
                  for line in [active_line(raw)] if re.match(r"^-?password(?:\s|$)", line)]
    if (not statements or statements[0] not in
        (["password", "substack", "system-auth"], ["password", "include", "system-auth"])
        or any(s != ["password", "include", "postlogin"] for s in statements[1:])):
        raise Review("the local passwd service does not have the supported PAM delegation")
    sources.append((str(passwd), data))
    if len(statements) > 1:
        post = (pam / "postlogin").resolve(strict=True)
        if post not in {pam / "postlogin", Path("/etc/authselect/postlogin")}:
            raise Review("the local PAM postlogin source resolves outside the supported layout")
        data = read_file(post)
        if any(re.match(r"^-?password(?:\s|$)", active_line(raw)) for raw in data.splitlines()):
            raise Review("PAM postlogin also modifies passwords")
        sources.append((str(post), data))
    return sources, stacks


def read_dnf(path, text):
    from dnf.conf import Conf

    parser = configparser.ConfigParser(
        interpolation=None, strict=True, delimiters=("=",), empty_lines_in_values=False,
    )
    lines = text.splitlines(True)
    try:
        parser.read_string(text)
    except configparser.Error:
        raise Review("DNF main configuration failed strict INI validation")
    if (parser.sections() != ["main"] or parser.defaults()
            or {"include", "config_file_path"} & set(parser["main"])):
        raise Review("DNF uses an unsupported configuration source or section layout")
    key = "clean_requirements_on_remove"
    parsed = parser["main"].get(key)
    records = [
        (index, match.group(1)) for index, line in enumerate(lines)
        for match in [re.fullmatch(r"(?i)[ \t]*" + key + r"[ \t]*=[ \t]*([^\s#;=]+)[ \t]*", line.strip("\r\n"))]
        if match
    ]
    if (parsed is None and records or parsed is not None
            and (len(records) != 1 or records[0][1] != parsed)):
        raise Review("DNF cleanup policy is not a standalone literal option")
    native = Conf()
    native.config_file_path = str(path)
    try:
        native.read()
    except (RuntimeError, OSError):
        raise Review("the native DNF parser rejected the configuration")
    if parsed is not None and native.clean_requirements_on_remove != meets(parsed, "True", "true"):
        raise Review("the native DNF parser disagrees with the declared cleanup setting")
    return {key: records}


def inspect(family, path, original, pam, ids):
    main = read_file(path)
    contexts = [(str(original), main)]
    followers = {}
    overrides = []
    tracked = {spec[0] for spec in POLICY[family].values()}
    if family == "quality":
        directory = Path(str(original) + ".d")
        if directory.exists() or directory.is_symlink():
            controlled(directory, directory=True)
            dropins = sorted(directory.glob("*.conf"), key=lambda entry: os.fsencode(entry.name))
            if len(dropins) > 32 or any(not DIRECT_PATH.fullmatch(entry.name) for entry in dropins):
                raise Review("the password-quality drop-in set is outside the supported precedence layout")
            for entry in dropins:
                data = read_file(entry)
                contexts.append((str(entry), data))
                for key, occurrences in settings(data, family, tracked | {"enforcing"}).items():
                    followers.setdefault(key, []).extend(occurrences)
        active, overrides = read_pam(pam)
        contexts.extend(active)
        # The native parser validates the active drop-ins and main file and
        # independently parses the staged main bytes. The explicit merge below
        # also includes original drop-ins when evaluating staged candidates.
        native_pwquality(original)
        if path != original:
            native_pwquality(path)
        current = settings(main, family, tracked | {"enforcing"})
        enforcement = (followers.get("enforcing", []) + current.get("enforcing", []))
        configured = enforcement[-1][1] if enforcement else "1"
        if any(stack.get("enforcing", configured) != "1" for stack in overrides):
            raise Review("a local PAM password stack is not in password-quality enforcing mode")
    elif family == "login":
        current = settings(main, family, tracked)
    else:
        current = read_dnf(path, main)
    selected_keys = {POLICY[family][id][0] for id in ids}
    evidence = {}
    for id in ids:
        key, target, predicate = POLICY[family][id]
        # libpwquality reads ASCII-sorted drop-ins first, the main file last
        # and PAM module arguments after all configuration.
        owned = current.get(key, [])
        dropins = followers.get(key, [])
        records = dropins + owned
        value = records[-1][1] if records else None
        if len({part for _, part in records}) > 1:
            evidence[id] = ("FAIL", "conflict", key, "conflicting-sources", target)
            continue
        expected = meets(value, target, predicate)
        configured_length_credits = False
        fixable_length_credits = False
        if key == "minlen":
            for stack in overrides:
                for credit in ("ucredit", "lcredit", "dcredit", "ocredit"):
                    configured_credit = followers.get(credit, []) + current.get(credit, [])
                    credit_value = stack.get(credit, configured_credit[-1][1] if configured_credit else "0")
                    if not INTEGER.fullmatch(credit_value):
                        raise Review("a password-length credit cannot be interpreted safely")
                    if int(credit_value) <= 0:
                        continue
                    if (credit not in stack and credit in selected_keys and not followers.get(credit)
                            and len(current.get(credit, [])) == 1
                            and all(credit not in other or int(other[credit]) <= -1 for other in overrides)):
                        fixable_length_credits = True
                        continue
                    configured_length_credits = True
        # Positive length credits can allow passwords shorter than minlen.
        # Review these jointly with the four character-class checks.
        override = configured_length_credits or any(
            key in stack and not meets(stack[key], target, predicate) for stack in overrides
        )
        status = "PASS" if expected and not (override or fixable_length_credits) else "FAIL"
        location = "override" if override else "drop-in" if dropins else "local"
        if status == "FAIL" and location == "local" and len(owned) > 1:
            location = "conflict"
        if key == "UMASK" and value is not None and not expected and int(value, 8) & 0o077 == 0o077:
            location = "custom-mask"
        if key == "minlen" and expected and fixable_length_credits and not override:
            location = "related"
        evidence[id] = (status, location, key, value if value is not None else "unset", target)
    digest = hashlib.sha256()
    support = hashlib.sha256()
    for name, data in contexts:
        # Lengths bind contents and keep path/header bytes out of the report.
        record = name.encode("utf-8") + b"\0" + data.encode("utf-8") + b"\0"
        digest.update(record)
        if name != str(original):
            support.update(record)
    return main, current, evidence, digest.hexdigest(), support.hexdigest()


def render(family, text, current, evidence):
    lines = text.splitlines(True)
    newline = "\r\n" if lines and lines[0].endswith("\r\n") else "\n"
    pending = []
    for id, (status, location, key, value, target) in evidence.items():
        if (status, location) == ("FAIL", "related"):
            continue
        if (status, location) != ("FAIL", "local"):
            raise Review("the selected option changed or still has an external configuration override")
        delimiter = " " if family == "login" else "=" if family == "dnf" else " = "
        replacement = key + delimiter + target + newline
        if key in current and current[key]:
            index = current[key][0][0]
            original = lines[index].rstrip("\r\n")
            lines[index] = "# rhel8-stig " + id + " original: " + original + newline + replacement
        else:
            pending.append(replacement)
    if pending:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += newline
        lines.extend(pending)
    return "".join(lines)


def main():
    action, family, candidate, original, pam, verify_digest, *ids = sys.argv[1:]
    path = Path(candidate)
    original = Path(original)
    if not ids or any(id not in POLICY[family] for id in ids) or len(ids) != len(set(ids)):
        raise Review("the rule selection is not supported for this configuration")
    source, current, evidence, digest, support = inspect(family, path, original, Path(pam), ids)
    if action == "state":
        print(digest + "|" + support)
        for id in ids:
            print("\t".join((id,) + evidence[id]))
    elif action == "render":
        if digest != verify_digest:
            raise Review("supporting configuration changed while preparing the plan")
        sys.stdout.buffer.write(render(family, source, current, evidence).encode("utf-8"))
    elif action == "validate":
        if support != verify_digest:
            raise Review("supporting configuration changed since the plan was prepared")
        if any(row[0] != "PASS" for row in evidence.values()):
            raise Review("the staged settings do not satisfy the selected local policy")
        if set(ids) & {"V-230365", "V-230366"}:
            minimum = current.get("PASS_MIN_DAYS", [])
            maximum = current.get("PASS_MAX_DAYS", [])
            for values in (minimum, maximum):
                if len(values) > 1 or any(not INTEGER.fullmatch(value) for _, value in values):
                    raise Review("an existing password-aging limit is ambiguous")
            if minimum and maximum:
                low, high = int(minimum[0][1]), int(maximum[0][1])
                if 0 <= high < low:
                    raise Review("new accounts would expire before their password can be changed")
    else:
        raise Review("unsupported account policy operation")


try:
    main()
except Review as error:
    # Review text is selected from constants, never configuration contents.
    print(str(error), file=sys.stderr)
    sys.exit(2)
except (OSError, UnicodeError, ValueError, KeyError, ImportError):
    print("configuration, native parser or PAM source is unavailable", file=sys.stderr)
    sys.exit(2)
PY
}

account_policy_check() {
    local id=$1 family=$2 path pam state first actual status location key value target
    path=$(account_policy_path "$family") && pam=$(account_policy_pam_directory) || {
        rule_result ERROR 'the policy rule has no supported configuration source'; return;
    }
    if ! state=$(account_policy_io state "$family" "$path" "$path" "$pam" - "$id" 2>&1); then
        rule_result NEEDS_REVIEW "$state"; return
    fi
    first=${state#*$'\n'}
    IFS=$'\t' read -r actual status location key value target <<< "$first"
    [[ $actual == "$id" && $status =~ ^(PASS|FAIL)$ && $key && $target ]] || {
        rule_result ERROR 'the policy observation could not be interpreted'; return;
    }
    case $location in
        conflict) rule_result FAIL "$key has conflicting explicit settings. Review authoritative sources." ;;
        override) rule_result FAIL "$key = $value. Effective PAM arguments or length credits need review." ;;
        custom-mask) rule_result FAIL "$key = $value differs from the benchmark target $target and uses a stricter custom mask." ;;
        *) rule_result "$status" "$key = $value (benchmark target $target)."
    esac
}

account_policy_validate() {
    local family=$1 candidate=$2 target=$3 pam
    pam=$(account_policy_pam_directory) || return 1
    account_policy_io validate "$family" "$candidate" "$target" "$pam" "$ACCOUNT_VALIDATE_SUPPORT" \
        "${ACCOUNT_VALIDATE_IDS[@]}" >/dev/null
}

account_quality_validate() { account_policy_validate quality "$@"; }
account_login_validate() { account_policy_validate login "$@"; }
account_dnf_validate() { account_policy_validate dnf "$@"; }

account_policy_plan() {
    local id=$1 family=$2 path pam state hashes hash support actual status location key value target entry
    local validator draft="$EDIT_TEMP/$id.account-policy" description='' rules='' requirements
    local -a possible requested=() approved=()
    case $family in
        quality)
            possible=(V-230357 V-230358 V-230359 V-230360 V-230361 V-230362 V-230363 V-230369
                      V-230375 V-230377 V-251716)
            validator=account_quality_validate
            requirements='Confirm local PAM password policy ownership and test a new password on an authorized test account. The plan edits password-quality configuration only.'
            ;;
        login)
            possible=(V-230324 V-230365 V-230366 V-230378 V-230383)
            validator=account_login_validate
            requirements='Confirm local login.defs ownership and review console login and new-account defaults. Existing account credentials and aging entries are outside this change.'
            ;;
        dnf)
            possible=(V-230281)
            validator=account_dnf_validate
            requirements='Review dependency cleanup during future DNF removals. This changes configuration only and performs no package transaction.'
            ;;
        *) return 1 ;;
    esac
    path=$(account_policy_path "$family") && pam=$(account_policy_pam_directory) || return 1
    edit_safe_path "$path" || { edit_fail 'policy target is outside the supported local layout'; return; }
    for entry in "${possible[@]}"; do
        [[ ${EFFECTIVE[$entry]+selected} ]] && requested+=("$entry")
    done
    if ! state=$(account_policy_io state "$family" "$path" "$path" "$pam" - "${requested[@]}" 2>&1); then
        edit_fail "$state"; return
    fi
    hashes=${state%%$'\n'*}
    hash=${hashes%|*} support=${hashes#*|}
    [[ $hash =~ ^[0-9a-f]{64}$ && $support =~ ^[0-9a-f]{64}$ && $state == *$'\n'* ]] || return 1
    while IFS=$'\t' read -r actual status location key value target; do
        [[ $status == FAIL && $location =~ ^(local|related)$ ]] || continue
        approved+=("$actual")
        if [[ $location == related ]]; then
            description+="$actual $key stays at $value. The selected character-class settings remove effective length credits."$'\n'
        else
            description+="$actual $key: $value -> $target"$'\n'
        fi
        if [[ $actual != "$id" ]]; then rules+=" $actual"; fi
    done <<< "${state#*$'\n'}"
    if [[ " ${approved[*]} " != *" $id "* ]]; then
        edit_fail 'the exact directive is already compliant or requires review of another source'; return
    fi
    if ! account_policy_io render "$family" "$path" "$path" "$pam" "$hash" "${approved[@]}" > "$draft"; then
        edit_fail 'the account policy source changed or needs a separate guarded edit'; return
    fi
    ACCOUNT_VALIDATE_IDS=("${approved[@]}")
    ACCOUNT_VALIDATE_SUPPORT=$support
    EDIT_CONTEXT=$hash
    EDIT_GROUPED=${rules# }
    EDIT_RELATED=$EDIT_GROUPED
    EDIT_REQUIREMENTS=$requirements
    edit_content "$path" keep "${description%$'\n'}" "$validator" < "$draft"
}

account_policy_admin() {
    case $1 in
        quality)
            printf '%s\n' 'Review pwquality.conf, ASCII-ordered drop-ins, and any pam_pwquality arguments before correcting the selected setting.' \
                'Use the authoritative source and a disposable local test account to verify password changes.'
            ;;
        login)
            printf '%s\n' 'Review the selected login.defs directive with the account owner. Use the authoritative local source.' \
                'Verify behavior on a new local account or a fresh console login, as appropriate.'
            ;;
        dnf)
            printf '%s\n' 'Review the DNF main configuration. Explicit cleanup affects dependencies during future removal transactions.'
            ;;
    esac
}

rule_V_230357_check() { account_policy_check V-230357 quality; }
rule_V_230358_check() { account_policy_check V-230358 quality; }
rule_V_230359_check() { account_policy_check V-230359 quality; }
rule_V_230360_check() { account_policy_check V-230360 quality; }
rule_V_230361_check() { account_policy_check V-230361 quality; }
rule_V_230362_check() { account_policy_check V-230362 quality; }
rule_V_230363_check() { account_policy_check V-230363 quality; }
rule_V_230369_check() { account_policy_check V-230369 quality; }
rule_V_230375_check() { account_policy_check V-230375 quality; }
rule_V_230377_check() { account_policy_check V-230377 quality; }
rule_V_251716_check() { account_policy_check V-251716 quality; }
rule_V_230324_check() { account_policy_check V-230324 login; }
rule_V_230365_check() { account_policy_check V-230365 login; }
rule_V_230366_check() { account_policy_check V-230366 login; }
rule_V_230378_check() { account_policy_check V-230378 login; }
rule_V_230383_check() { account_policy_check V-230383 login; }
rule_V_230281_check() { account_policy_check V-230281 dnf; }

rule_V_230357_plan() { account_policy_plan V-230357 quality; }
rule_V_230358_plan() { account_policy_plan V-230358 quality; }
rule_V_230359_plan() { account_policy_plan V-230359 quality; }
rule_V_230360_plan() { account_policy_plan V-230360 quality; }
rule_V_230361_plan() { account_policy_plan V-230361 quality; }
rule_V_230362_plan() { account_policy_plan V-230362 quality; }
rule_V_230363_plan() { account_policy_plan V-230363 quality; }
rule_V_230369_plan() { account_policy_plan V-230369 quality; }
rule_V_230375_plan() { account_policy_plan V-230375 quality; }
rule_V_230377_plan() { account_policy_plan V-230377 quality; }
rule_V_251716_plan() { account_policy_plan V-251716 quality; }
rule_V_230324_plan() { account_policy_plan V-230324 login; }
rule_V_230365_plan() { account_policy_plan V-230365 login; }
rule_V_230366_plan() { account_policy_plan V-230366 login; }
rule_V_230378_plan() { account_policy_plan V-230378 login; }
rule_V_230383_plan() { account_policy_plan V-230383 login; }
rule_V_230281_plan() { account_policy_plan V-230281 dnf; }

rule_V_230357_admin() { account_policy_admin quality; }
rule_V_230358_admin() { account_policy_admin quality; }
rule_V_230359_admin() { account_policy_admin quality; }
rule_V_230360_admin() { account_policy_admin quality; }
rule_V_230361_admin() { account_policy_admin quality; }
rule_V_230362_admin() { account_policy_admin quality; }
rule_V_230363_admin() { account_policy_admin quality; }
rule_V_230369_admin() { account_policy_admin quality; }
rule_V_230375_admin() { account_policy_admin quality; }
rule_V_230377_admin() { account_policy_admin quality; }
rule_V_251716_admin() { account_policy_admin quality; }
rule_V_230324_admin() { account_policy_admin login; }
rule_V_230365_admin() { account_policy_admin login; }
rule_V_230366_admin() { account_policy_admin login; }
rule_V_230378_admin() { account_policy_admin login; }
rule_V_230383_admin() { account_policy_admin login; }
rule_V_230281_admin() { account_policy_admin dnf; }

# Bounded numeric sysctl and canonical SSH directives for RHEL 8 STIG V2R9.
# Closed world targets keep preview output and activation instructions precise.

network_sysctl_spec() {
    case $1 in
        V-230267) printf 'fs.protected_symlinks 1\n' ;;
        V-230268) printf 'fs.protected_hardlinks 1\n' ;;
        V-230269) printf 'kernel.dmesg_restrict 1\n' ;;
        V-230270) printf 'kernel.perf_event_paranoid 2\n' ;;
        V-230280) printf 'kernel.randomize_va_space 2\n' ;;
        V-230535) printf 'net.ipv6.conf.default.accept_redirects 0\n' ;;
        V-230536) printf 'net.ipv4.conf.all.send_redirects 0\n' ;;
        V-230537) printf 'net.ipv4.icmp_echo_ignore_broadcasts 1\n' ;;
        V-230538) printf 'net.ipv6.conf.all.accept_source_route 0\n' ;;
        V-230539) printf 'net.ipv6.conf.default.accept_source_route 0\n' ;;
        V-230543) printf 'net.ipv4.conf.default.send_redirects 0\n' ;;
        V-230544) printf 'net.ipv6.conf.all.accept_redirects 0\n' ;;
        V-230547) printf 'kernel.kptr_restrict 1\n' ;;
        V-244550) printf 'net.ipv4.conf.default.accept_redirects 0\n' ;;
        V-244551) printf 'net.ipv4.conf.all.accept_source_route 0\n' ;;
        V-244552) printf 'net.ipv4.conf.default.accept_source_route 0\n' ;;
        V-244553) printf 'net.ipv4.conf.all.accept_redirects 0\n' ;;
        V-284948) printf 'net.ipv4.conf.all.log_martians 1\n' ;;
        V-284949) printf 'net.ipv4.conf.default.log_martians 1\n' ;;
        *) return 1 ;;
    esac
}

network_sysctl_path() { printf '/etc/sysctl.d/90-rhel8-stig-%s.conf\n' "$1"; }
network_sysctl_main() { printf '/etc/sysctl.conf\n'; }
network_sysctl_locations() {
    # First directory wins a duplicate filename. /lib may alias /usr/lib.
    printf '%s\n' /etc/sysctl.d /run/sysctl.d /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d
}

network_sysctl_live() {
    local value
    value=$(timeout 8 sysctl -n -- "$1" 2>/dev/null) || return 1
    [[ $value =~ ^-?(0|[1-9][0-9]{0,8})$ ]] || return 1
    printf '%s\n' "$value"
}

network_sysctl_ipv6_disabled() {
    local source value found=0
    if grep -Eq '(^|[[:space:]])ipv6\.disable=1([[:space:]]|$)' /proc/cmdline 2>/dev/null; then
        return 0
    fi
    [[ -d /proc/sys/net/ipv6/conf ]] || return 1
    for source in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
        [[ -r $source ]] && IFS= read -r value < "$source" && [[ $value == 1 ]] || return 1
        found=1
    done
    (( found ))
}

network_sysctl_protected_path() {
    local path=$1 owner mode
    while [[ $path != / ]]; do
        [[ ! -L $path ]] || return 1
        read -r owner mode < <(stat -c '%u %a' -- "$path") || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        path=$(dirname -- "$path") || return 1
    done
}

network_sysctl_values() {
    # Output the normalized selector and a scalar, never the original content.
    awk '
        /^[[:blank:]]*([#;]|$)/ {next}
        {
            line=$0; sub(/\r$/,"",line)
            sub(/^[[:blank:]]*-?[[:blank:]]*/,"",line)
            selector=line; sub(/[[:blank:]=].*$/,"",selector); gsub(/\//,".",selector)
            if (!length(selector)) next
            if (!sub(/^[^=]*=[[:blank:]]*/,"",line)) line="?"
            sub(/[[:blank:]]+[#;].*$/,"",line); sub(/[[:blank:]]+$/,"",line)
            if (line !~ /^-?[0-9]{1,9}$/) line="?"
            if (selector ~ /^[a-zA-Z0-9_.*?\[\]!^-]+$/) print selector "\t" line
        }
    ' "$1"
}

network_sysctl_scan() {
    local key=$1 expected=$2 omit=$3 directory canonical path name resolved records selector value
    local digest context='' result=missing main
    local -a ordered_paths=()
    local -A seen_directory=() seen_name=()
    main=$(network_sysctl_main) || return 1
    while IFS= read -r directory; do
        [[ -e $directory || -L $directory ]] || continue
        canonical=$(realpath -e -- "$directory") || return 1
        if [[ $canonical != "$directory" && ( $directory != /lib/sysctl.d || $canonical != /usr/lib/sysctl.d ) ]]; then
            return 1
        fi
        [[ -d $canonical ]] && network_sysctl_protected_path "$canonical" || return 1
        [[ -z ${seen_directory[$canonical]+seen} ]] || continue
        seen_directory[$canonical]=1
        for path in "$canonical"/*.conf; do
            [[ -e $path || -L $path ]] || continue
            name=${path##*/}
            if [[ -n $omit && $name == "${omit##*/}" && $path != "$omit" ]]; then return 1; fi
            [[ -z ${seen_name[$name]+seen} ]] || continue
            seen_name[$name]=1
            [[ $path != "$omit" ]] || continue
            ordered_paths+=("$path")
        done
    done < <(network_sysctl_locations)
    if [[ -e $main || -L $main ]]; then ordered_paths+=("$main"); fi
    for path in "${ordered_paths[@]}"; do
        resolved=$path
        if [[ -L $path ]]; then
            resolved=$(realpath -e -- "$path") || return 1
            if [[ $resolved == /dev/null && $path != "$main" ]]; then
                context+="$path masked"$'\n'
                continue
            fi
            # RHEL commonly links this drop-in to the legacy configuration.
            [[ $path == /etc/sysctl.d/99-sysctl.conf && $resolved == "$main" ]] || return 1
        fi
        network_sysctl_protected_path "$resolved" && text_input_file "$resolved" || return 1
        digest=$(sha256_file "$resolved") && records=$(network_sysctl_values "$resolved") || return 1
        context+="$path $digest"$'\n'
        while IFS=$'\t' read -r selector value; do
            [[ -n $selector ]] || continue
            if [[ $selector != "$key" ]]; then
                # A configured wildcard that can supply this key needs review.
                # shellcheck disable=SC2053
                if [[ $key == $selector ]]; then result=ambiguous; fi
                continue
            fi
            case $result:$value in
                ambiguous:*|*:'?') result=ambiguous ;;
                *)
                    if [[ $value != "$expected" ]]; then
                        result=conflict
                    elif [[ $result == missing && $path != /run/* ]]; then
                        result=configured
                    fi ;;
            esac
        done <<< "$records"
    done
    digest=$(printf '%s' "$context" | sha256sum) || return 1
    printf '%s %s\n' "$result" "${digest%% *}"
}

network_sysctl_stricter() {
    local key=$1 live=$2 target=$3
    case $key in
        kernel.kptr_restrict|kernel.perf_event_paranoid) (( live > target )) ;;
        net.ipv6.conf.*.accept_source_route) (( live < target )) ;;
        *) return 1 ;;
    esac
}

network_sysctl_check() {
    local id=$1 spec key target live persisted state
    spec=$(network_sysctl_spec "$id") || { rule_result ERROR 'Unknown sysctl rule.'; return; }
    read -r key target <<< "$spec"
    if [[ $key == net.ipv6.* ]] && network_sysctl_ipv6_disabled; then
        rule_result NOT_APPLICABLE 'IPv6 is disabled on the host.'
        return
    fi
    if ! live=$(network_sysctl_live "$key") || ! persisted=$(network_sysctl_scan "$key" "$target" ''); then
        rule_result NEEDS_REVIEW "Could not establish the live and persistent settings for $key."
        return
    fi
    state=${persisted%% *}
    if network_sysctl_stricter "$key" "$live" "$target"; then
        rule_result NEEDS_REVIEW "$key is $live, a stricter value than the pinned target $target. Verify policy before any change."
    elif [[ $state == ambiguous || $state == conflict ]]; then
        rule_result NEEDS_REVIEW "$key is $live at runtime. Review conflicting or ambiguous persistent definitions."
    elif [[ $state == configured && $live == "$target" ]]; then
        rule_result PASS "$key is $target in the running kernel and a persistent source."
    elif [[ $state == configured ]]; then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW "$key is configured as $target but live at $live. Verify activation."
    else
        rule_result FAIL "$key is $live and lacks a verified persistent $target assignment."
    fi
}

network_sysctl_safe_role() {
    case $1 in
        net.ipv4.*) [[ $(network_sysctl_live net.ipv4.ip_forward) == 0 ]] ;;
        net.ipv6.*) [[ $(network_sysctl_live net.ipv6.conf.all.forwarding) == 0 ]] ;;
        *) return 0 ;;
    esac
}

network_sysctl_candidate() {
    local id=$1 key=$2 value=$3
    printf '# rhel8-stig %s\n%s = %s\n' "$id" "$key" "$value"
}

network_sysctl_validate() {
    local observed live expected bytes
    if [[ $NETWORK_SYSCTL_KEY == net.ipv6.* ]] && network_sysctl_ipv6_disabled; then return 1; fi
    observed=$(network_sysctl_scan "$NETWORK_SYSCTL_KEY" "$NETWORK_SYSCTL_VALUE" "$2") &&
        live=$(network_sysctl_live "$NETWORK_SYSCTL_KEY") &&
        network_sysctl_safe_role "$NETWORK_SYSCTL_KEY" || return 1
    [[ "$observed $live" == "$EDIT_CONTEXT" ]] || return 1
    expected=$(network_sysctl_candidate "$NETWORK_SYSCTL_ID" "$NETWORK_SYSCTL_KEY" "$NETWORK_SYSCTL_VALUE" | sha256sum) &&
        bytes=$(sha256sum < "$1") && [[ $bytes == "$expected" ]]
}

network_sysctl_plan() {
    local id=$1 spec key target path source live
    spec=$(network_sysctl_spec "$id") && path=$(network_sysctl_path "$id") || return 1
    read -r key target <<< "$spec"
    if [[ -e $path || -L $path ]]; then edit_fail "Review the existing $path before changing $key"; return; fi
    if [[ $key == net.ipv6.* ]] && network_sysctl_ipv6_disabled; then
        edit_fail 'IPv6 is disabled on the host'; return
    fi
    if ! live=$(network_sysctl_live "$key") || ! source=$(network_sysctl_scan "$key" "$target" "$path"); then
        edit_fail "Could not establish the live and persistent sources for $key"; return
    fi
    if [[ ${source%% *} != missing ]] || network_sysctl_stricter "$key" "$live" "$target"; then
        edit_fail "Persistent configuration or a stricter live value for $key needs review"; return
    fi
    if ! network_sysctl_safe_role "$key"; then
        edit_fail 'Review router, forwarding, or managed network policy before staging the setting'; return
    fi
    NETWORK_SYSCTL_ID=$id NETWORK_SYSCTL_KEY=$key NETWORK_SYSCTL_VALUE=$target
    EDIT_CONTEXT="$source $live" EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm the kernel setting is locally managed and compatible with the host role and dependent services.'
    EDIT_ACTIVATION="After reviewing impact, activate only $key with sysctl -w $key=$target and recheck the live and persistent values. If restoring the policy after activation, separately restore the prior runtime value $live or use an approved reboot."
    edit_content "$path" 0644 "Add persistent $key = $target. Live value before activation is $live." \
        network_sysctl_validate < <(network_sysctl_candidate "$id" "$key" "$target")
}

network_sysctl_admin() {
    local spec key target
    spec=$(network_sysctl_spec "$1") || return 1
    read -r key target <<< "$spec"
    printf '%s\n' "Review the authoritative persistent definition and live value for $key. The pinned value is $target." \
        'Resolve competing definitions at their managed source. Activate only the reviewed setting in an approved window and rerun Status.'
}

network_ssh_path() { printf '/etc/ssh/sshd_config\n'; }

network_ssh_ids() {
    printf '%s\n' V-230244 V-230288 V-230290 V-230330 V-230382 V-230556 V-244525
}

network_ssh_spec() {
    case $1 in
        V-230244) printf 'ClientAliveCountMax 1\n' ;;
        V-230288) printf 'StrictModes yes\n' ;;
        V-230290) printf 'IgnoreUserKnownHosts yes\n' ;;
        V-230330) printf 'PermitUserEnvironment no\n' ;;
        V-230382) printf 'PrintLastLog yes\n' ;;
        V-230556) printf 'X11UseLocalhost yes\n' ;;
        V-244525) printf 'ClientAliveInterval 600\n' ;;
        *) return 1 ;;
    esac
}

network_ssh_authority() {
    local invocation env crypto=/etc/crypto-policies/back-ends/opensshserver.config
    local resolved backend=absent
    invocation=$(expanded_sshd_invocation) || return 1
    env=$(timeout 8 systemctl show sshd.service --no-pager --all -p Environment -p EnvironmentFiles 2>/dev/null) || return 1
    if ! awk '
        /^Environment=$/ {empty=1; next}
        /^EnvironmentFiles=/ {
            files=1
            sub(/^EnvironmentFiles=/,"")
            gsub(/(\/etc\/sysconfig\/sshd|\/etc\/crypto-policies\/back-ends\/opensshserver.config) \(ignore_errors=yes\)/,"")
            if ($0 !~ /^[[:blank:]]*$/) bad=1
            next
        }
        {bad=1}
        END {exit !(empty && files && !bad)}
    ' <<< "$env"; then return 1; fi
    if [[ -e /etc/sysconfig/sshd || -L /etc/sysconfig/sshd ]]; then
        network_sysctl_protected_path /etc/sysconfig/sshd && text_input_file /etc/sysconfig/sshd || return 1
    fi
    if [[ -e $crypto || -L $crypto ]]; then
        resolved=$(realpath -e -- "$crypto") || return 1
        case $resolved in /usr/share/crypto-policies/*|/etc/crypto-policies/*) ;; *) return 1 ;; esac
        network_sysctl_protected_path "$resolved" && text_input_file "$resolved" || return 1
        # The environment backend is data. Only allow crypto options here so it
        # cannot override the directives established with sshd -T.
        if ! awk '
            BEGIN {quote=sprintf("%c",39)}
            /^[[:blank:]]*($|#)/ {next}
            {
                line=$0; sub(/^[[:blank:]]*/,"",line)
                if (++lines>1 || index(line,"CRYPTO_POLICY=" quote)!=1) {bad=1; next}
                line=substr(line,length("CRYPTO_POLICY=")+2)
                ending=index(line,quote)
                if (!ending || substr(line,ending+1) !~ /^[[:blank:]]*(#.*)?$/) {bad=1; next}
                line=substr(line,1,ending-1); sub(/^[[:blank:]]*/,"",line); sub(/[[:blank:]]*$/,"",line)
                if (!length(line)) next
                n=split(line, options, /[[:blank:]]+/)
                for (i=1; i<=n; i++) {
                    if (options[i] !~ /^-o(Ciphers|MACs|KexAlgorithms|GSSAPIKexAlgorithms|HostKeyAlgorithms|HostbasedAcceptedAlgorithms|HostbasedAcceptedKeyTypes|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|CASignatureAlgorithms|RequiredRSASize)=[a-zA-Z0-9_@.,:+*-]+$/) bad=1
                }
            }
            END {exit bad}
        ' "$resolved"; then return 1; fi
        backend=$(sha256_file "$resolved") || return 1
    fi
    printf '%s\n' "$invocation" "$env" "$backend" | sha256sum
}

network_ssh_metric() {
    local current=$1 target=$2
    case $target in
        yes|no) [[ $current =~ ^(yes|no)$ ]] ;;
        1|600) [[ $current =~ ^(0|[1-9][0-9]{0,8})$ ]] ;;
        *) return 1 ;;
    esac
}

network_ssh_meets() {
    local current=$1 target=$2
    network_ssh_metric "$current" "$target" || return 1
    if [[ $target == 600 ]]; then (( current >= 1 && current <= target )); else [[ $current == "$target" ]]; fi
}

network_ssh_observe() {
    local path=$1 keyword=$2 target=$3
    NETWORK_SSH_SOURCE=$(expanded_ssh_values "$path" "$keyword") &&
        NETWORK_SSH_LIVE=$(expanded_ssh_effective "$path" "$keyword") &&
        network_ssh_metric "$NETWORK_SSH_LIVE" "$target" || return 2
    if [[ -n $NETWORK_SSH_SOURCE ]]; then
        network_ssh_metric "$NETWORK_SSH_SOURCE" "$target" &&
            [[ $NETWORK_SSH_SOURCE == "$NETWORK_SSH_LIVE" ]] || return 2
        network_ssh_meets "$NETWORK_SSH_LIVE" "$target"
    else
        return 1
    fi
}

network_ssh_check() {
    local id=$1 spec keyword target path state status=0
    spec=$(network_ssh_spec "$id") && path=$(network_ssh_path) || { rule_result ERROR 'Unknown SSH rule.'; return; }
    read -r keyword target <<< "$spec"
    if ! text_input_file "$path" || [[ $(expanded_ssh_topology "$path") != plain ]] ||
       ! network_ssh_authority >/dev/null; then
        rule_result NEEDS_REVIEW "Review the authoritative SSH service configuration and any Include or Match contexts for $keyword."
        return
    fi
    network_ssh_observe "$path" "$keyword" "$target" || status=$?
    case $status in
        2) rule_result NEEDS_REVIEW "Could not verify an unambiguous effective $keyword." ; return ;;
        1) rule_result FAIL "$keyword is absent from the source or the effective value does not meet the pinned rule." ; return ;;
    esac
    state=$(expanded_ssh_loaded_state "$path") || {
        rule_result NEEDS_REVIEW "$keyword is configured as $NETWORK_SSH_LIVE. Verify activation."; return;
    }
    case $state in
        pending) CHECK_PENDING=1; rule_result NEEDS_REVIEW "$keyword is configured as $NETWORK_SSH_LIVE. The active service started before the current file." ;;
        started|inactive) rule_result PASS "Verified explicit $keyword $NETWORK_SSH_LIVE in the reviewed service configuration." ;;
        *) rule_result NEEDS_REVIEW "$keyword is configured as $NETWORK_SSH_LIVE. Verify activation." ;;
    esac
}

network_ssh_render() {
    local path=$1 keyword=$2 value=$3 id=$4
    awk -v keyword="$keyword" -v value="$value" -v id="$id" '
        /^[[:blank:]]*#/ {print; next}
        {
            line=$0; sub(/^[[:blank:]]*/,"",line); split(line, fields, /[[:blank:]=]+/)
            if (tolower(fields[1]) != tolower(keyword)) {print; next}
            print "# rhel8-stig " id " original: " line
            print keyword " " value
            found=1
        }
        END {if (!found) {print ""; print "# rhel8-stig " id; print keyword " " value}}
    ' "$path"
}

network_ssh_validate() {
    local path=$1 id spec keyword target stamp
    stamp=$(network_ssh_authority) && [[ $stamp == "$EDIT_CONTEXT" ]] &&
        [[ $(expanded_ssh_topology "$path") == plain ]] &&
        timeout 12 sshd -t -f "$path" >/dev/null 2>&1 || return 1
    for id in $NETWORK_SSH_VALIDATE_IDS; do
        spec=$(network_ssh_spec "$id") || return 1
        read -r keyword target <<< "$spec"
        network_ssh_observe "$path" "$keyword" "$target" || return 1
    done
}

network_ssh_plan() {
    local id=$1 other path spec keyword target candidate status prior change value file source
    local diff='' i=0
    local -A assessed=() changes=() before=()
    path=$(network_ssh_path) || return 1
    if ! text_input_file "$path" || ! edit_safe_path "$path" ||
       [[ $(expanded_ssh_topology "$path") != plain ]] || ! EDIT_CONTEXT=$(network_ssh_authority); then
        edit_fail 'SSH staging requires the standard root-controlled service and an unscoped local configuration'; return
    fi
    for other in $(network_ssh_ids); do
        spec=$(network_ssh_spec "$other") || return 1
        read -r keyword target <<< "$spec"
        status=0
        network_ssh_observe "$path" "$keyword" "$target" || status=$?
        assessed[$other]=$status
        if [[ $status == 1 && ( $other == "$id" || ${EFFECTIVE[$other]+selected} ) ]]; then
            value=$target
            if network_ssh_meets "$NETWORK_SSH_LIVE" "$target"; then value=$NETWORK_SSH_LIVE; fi
            changes[$other]=$value
            before[$other]=$NETWORK_SSH_SOURCE
        fi
    done
    # A lone keepalive edit on a noncompliant pair would not establish the
    # required timeout. Group selected peers or keep the pair out of the edit.
    for other in V-230244 V-244525; do
        if [[ $other == V-230244 ]]; then candidate=V-244525; else candidate=V-230244; fi
        if [[ ${assessed[$candidate]} != 0 && ! ${changes[$candidate]+planned} ]]; then
            unset 'changes[$other]'
        fi
    done
    if [[ -z ${changes[$id]+planned} ]]; then
        edit_fail 'No unambiguous SSH change is available. For keepalive timing, select both failing counterpart IDs.'; return
    fi
    NETWORK_SSH_VALIDATE_IDS='' source=$path
    for other in $(network_ssh_ids); do
        [[ ${changes[$other]+planned} ]] || continue
        spec=$(network_ssh_spec "$other") || return 1
        read -r keyword target <<< "$spec"
        file="$EDIT_TEMP/ssh-$((++i)).conf"
        network_ssh_render "$source" "$keyword" "${changes[$other]}" "$other" > "$file" || return 1
        source=$file
        prior=${before[$other]}
        if [[ $prior ]]; then change="- $keyword $prior"; else change="- $keyword unset"; fi
        diff+="${diff:+$'\n'}$change"$'\n'"+ $keyword ${changes[$other]} ($other)"
        NETWORK_SSH_VALIDATE_IDS+="${NETWORK_SSH_VALIDATE_IDS:+ }$other"
        if [[ $other != "$id" ]]; then EDIT_RELATED+="${EDIT_RELATED:+ }$other"; fi
    done
    EDIT_GROUPED=$EDIT_RELATED
    if [[ ${changes[V-230244]+planned} || ${changes[V-244525]+planned} ]]; then
        NETWORK_SSH_VALIDATE_IDS+=' V-230244 V-244525'
    fi
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm local SSH ownership, approved access and environment use, a separate administrative session, and console recovery.'
    EDIT_ACTIVATION='Validate with sshd -t and use the separately approved SSH restart procedure. Verify a fresh authorized administrative login and the intended settings.'
    edit_content "$path" keep "$diff" network_ssh_validate < "$source"
}

network_ssh_admin() {
    local spec keyword target
    spec=$(network_ssh_spec "$1") || return 1
    read -r keyword target <<< "$spec"
    printf '%s\n' "Review $keyword in the authoritative SSH configuration. The pinned target is $target." \
        'For ClientAliveInterval, a positive value at or below 600 is allowed. Review ClientAliveInterval and ClientAliveCountMax together.' \
        'Inspect service overrides and scoped Include or Match blocks. Validate with sshd -t, keep console access, and verify a fresh login after separate activation approval.'
}

rule_V_230267_check() { network_sysctl_check V-230267; }
rule_V_230267_plan() { network_sysctl_plan V-230267; }
rule_V_230267_admin() { network_sysctl_admin V-230267; }
rule_V_230268_check() { network_sysctl_check V-230268; }
rule_V_230268_plan() { network_sysctl_plan V-230268; }
rule_V_230268_admin() { network_sysctl_admin V-230268; }
rule_V_230269_check() { network_sysctl_check V-230269; }
rule_V_230269_plan() { network_sysctl_plan V-230269; }
rule_V_230269_admin() { network_sysctl_admin V-230269; }
rule_V_230270_check() { network_sysctl_check V-230270; }
rule_V_230270_plan() { network_sysctl_plan V-230270; }
rule_V_230270_admin() { network_sysctl_admin V-230270; }
rule_V_230280_check() { network_sysctl_check V-230280; }
rule_V_230280_plan() { network_sysctl_plan V-230280; }
rule_V_230280_admin() { network_sysctl_admin V-230280; }
rule_V_230535_check() { network_sysctl_check V-230535; }
rule_V_230535_plan() { network_sysctl_plan V-230535; }
rule_V_230535_admin() { network_sysctl_admin V-230535; }
rule_V_230536_check() { network_sysctl_check V-230536; }
rule_V_230536_plan() { network_sysctl_plan V-230536; }
rule_V_230536_admin() { network_sysctl_admin V-230536; }
rule_V_230537_check() { network_sysctl_check V-230537; }
rule_V_230537_plan() { network_sysctl_plan V-230537; }
rule_V_230537_admin() { network_sysctl_admin V-230537; }
rule_V_230538_check() { network_sysctl_check V-230538; }
rule_V_230538_plan() { network_sysctl_plan V-230538; }
rule_V_230538_admin() { network_sysctl_admin V-230538; }
rule_V_230539_check() { network_sysctl_check V-230539; }
rule_V_230539_plan() { network_sysctl_plan V-230539; }
rule_V_230539_admin() { network_sysctl_admin V-230539; }
rule_V_230543_check() { network_sysctl_check V-230543; }
rule_V_230543_plan() { network_sysctl_plan V-230543; }
rule_V_230543_admin() { network_sysctl_admin V-230543; }
rule_V_230544_check() { network_sysctl_check V-230544; }
rule_V_230544_plan() { network_sysctl_plan V-230544; }
rule_V_230544_admin() { network_sysctl_admin V-230544; }
rule_V_230547_check() { network_sysctl_check V-230547; }
rule_V_230547_plan() { network_sysctl_plan V-230547; }
rule_V_230547_admin() { network_sysctl_admin V-230547; }
rule_V_244550_check() { network_sysctl_check V-244550; }
rule_V_244550_plan() { network_sysctl_plan V-244550; }
rule_V_244550_admin() { network_sysctl_admin V-244550; }
rule_V_244551_check() { network_sysctl_check V-244551; }
rule_V_244551_plan() { network_sysctl_plan V-244551; }
rule_V_244551_admin() { network_sysctl_admin V-244551; }
rule_V_244552_check() { network_sysctl_check V-244552; }
rule_V_244552_plan() { network_sysctl_plan V-244552; }
rule_V_244552_admin() { network_sysctl_admin V-244552; }
rule_V_244553_check() { network_sysctl_check V-244553; }
rule_V_244553_plan() { network_sysctl_plan V-244553; }
rule_V_244553_admin() { network_sysctl_admin V-244553; }
rule_V_284948_check() { network_sysctl_check V-284948; }
rule_V_284948_plan() { network_sysctl_plan V-284948; }
rule_V_284948_admin() { network_sysctl_admin V-284948; }
rule_V_284949_check() { network_sysctl_check V-284949; }
rule_V_284949_plan() { network_sysctl_plan V-284949; }
rule_V_284949_admin() { network_sysctl_admin V-284949; }

rule_V_230244_check() { network_ssh_check V-230244; }
rule_V_230244_plan() { network_ssh_plan V-230244; }
rule_V_230244_admin() { network_ssh_admin V-230244; }
rule_V_230288_check() { network_ssh_check V-230288; }
rule_V_230288_plan() { network_ssh_plan V-230288; }
rule_V_230288_admin() { network_ssh_admin V-230288; }
rule_V_230290_check() { network_ssh_check V-230290; }
rule_V_230290_plan() { network_ssh_plan V-230290; }
rule_V_230290_admin() { network_ssh_admin V-230290; }
rule_V_230330_check() { network_ssh_check V-230330; }
rule_V_230330_plan() { network_ssh_plan V-230330; }
rule_V_230330_admin() { network_ssh_admin V-230330; }
rule_V_230382_check() { network_ssh_check V-230382; }
rule_V_230382_plan() { network_ssh_plan V-230382; }
rule_V_230382_admin() { network_ssh_admin V-230382; }
rule_V_230556_check() { network_ssh_check V-230556; }
rule_V_230556_plan() { network_ssh_plan V-230556; }
rule_V_230556_admin() { network_ssh_admin V-230556; }
rule_V_244525_check() { network_ssh_check V-244525; }
rule_V_244525_plan() { network_ssh_plan V-244525; }
rule_V_244525_admin() { network_ssh_admin V-244525; }

# Identity and execution audit coverage. Keep rule staging separate from
# activation. The shared transaction owns backups and conditional rollback.

expansion_audit_spec() {
    case $1 in
        V-230404) printf '%s\n' 'watch /etc/shadow identity' ;;
        V-230405) printf '%s\n' 'watch /etc/security/opasswd identity' ;;
        V-230406) printf '%s\n' 'watch /etc/passwd identity' ;;
        V-230407) printf '%s\n' 'watch /etc/gshadow identity' ;;
        V-230408) printf '%s\n' 'watch /etc/group identity' ;;
        V-230409) printf '%s\n' 'watch /etc/sudoers identity' ;;
        V-230410) printf '%s\n' 'watch /etc/sudoers.d identity' ;;
        V-230412) printf '%s\n' 'exec /usr/bin/su privileged-priv_change' ;;
        V-230418) printf '%s\n' 'exec /usr/bin/chage privileged-chage' ;;
        V-230419) printf '%s\n' 'exec /usr/bin/chcon perm_mod' ;;
        V-230421) printf '%s\n' 'exec /usr/bin/ssh-agent privileged-ssh' ;;
        V-230422) printf '%s\n' 'exec /usr/bin/passwd privileged-passwd' ;;
        V-230423) printf '%s\n' 'exec /usr/bin/mount privileged-mount' ;;
        V-230424) printf '%s\n' 'exec /usr/bin/umount privileged-mount' ;;
        V-230426) printf '%s\n' 'exec /usr/sbin/unix_update privileged-unix-update' ;;
        V-230427) printf '%s\n' 'exec /usr/sbin/postdrop privileged-unix-update' ;;
        V-230428) printf '%s\n' 'exec /usr/sbin/postqueue privileged-unix-update' ;;
        V-230429) printf '%s\n' 'exec /usr/sbin/semanage privileged-unix-update' ;;
        V-230430) printf '%s\n' 'exec /usr/sbin/setfiles privileged-unix-update' ;;
        V-230431) printf '%s\n' 'exec /usr/sbin/userhelper privileged-unix-update' ;;
        V-230432) printf '%s\n' 'exec /usr/sbin/setsebool privileged-unix-update' ;;
        V-230433) printf '%s\n' 'exec /usr/sbin/unix_chkpwd privileged-unix-update' ;;
        V-230434) printf '%s\n' 'exec /usr/libexec/openssh/ssh-keysign privileged-ssh' ;;
        V-230435) printf '%s\n' 'exec /usr/bin/setfacl perm_mod' ;;
        V-230436) printf '%s\n' 'exec /usr/sbin/pam_timestamp_check privileged-pam_timestamp_check' ;;
        V-230437) printf '%s\n' 'exec /usr/bin/newgrp priv_cmd' ;;
        V-230444) printf '%s\n' 'exec /usr/bin/gpasswd privileged-gpasswd' ;;
        V-230447) printf '%s\n' 'exec /usr/bin/crontab privileged-crontab' ;;
        V-230448) printf '%s\n' 'exec /usr/bin/chsh priv_cmd' ;;
        V-230462) printf '%s\n' 'exec /usr/bin/sudo priv_cmd' ;;
        V-230463) printf '%s\n' 'exec /usr/sbin/usermod privileged-usermod' ;;
        V-230464) printf '%s\n' 'exec /usr/bin/chacl perm_mod' ;;
        V-230465) printf '%s\n' 'exec /usr/bin/kmod modules' ;;
        V-230467) printf '%s\n' 'watch /var/log/lastlog logins' ;;
        *) return 1 ;;
    esac
}

expansion_audit_payload() {
    local kind path key
    read -r kind path key < <(expansion_audit_spec "$1") || return 1
    if [[ $kind == watch ]]; then
        if [[ $1 == V-230410 ]]; then path+=/; fi
        printf '%s\n' "-w $path -p wa -k $key"
    else
        printf '%s\n' "-a always,exit -F path=$path -F perm=x -F auid>=1000 -F auid!=unset -k $key"
    fi
}

# Recognize the reviewed watch and execution forms, including the kernel's
# aliases for an unset login UID and key syntax. Ambiguous coverage goes to
# review. Treat suppressions and late deletes conservatively.
expansion_audit_rule_state() {
    local kind=$1 path=$2 key=$3
    awk -v kind="$kind" -v target="$path" -v key="$key" '
        function atom(flag, arg, parts) {
            if (flag == "-A") flag="-a"
            if (flag == "-a" && split(arg, parts, ",")==2) {
                if (parts[1] == "exit" || parts[1] == "task" || parts[1] == "exclude") {
                    arg=parts[2] "," parts[1]
                }
            }
            if (flag == "-F" && arg ~ /^key=/) {flag="-k"; sub(/^key=/,"",arg)}
            if (flag == "-F" && arg ~ /^auid!=(-1|4294967295)$/) arg="auid!=unset"
            if (flag == "-w" && arg != "/") sub(/\/+$/,"",arg)
            if (flag == "-p" && arg == "aw") arg="wa"
            return flag " " arg
        }
        function touches(path, field, cleaned) {
            cleaned=path
            sub(/\/+$/,"",cleaned)
            if (kind=="exec" && cleaned ~ /^\/(sbin|bin)\//) cleaned="/usr" cleaned
            if (cleaned == target) return 1
            if (target=="/etc/sudoers.d" && index(cleaned,target "/")==1) return 1
            return (field == "-w" || field == "dir") &&
                (cleaned == "" || index(target, cleaned "/")==1)
        }
        /^[[:space:]]*#/ {next}
        {
            sub(/[[:space:]]+#.*/,"")
            if (NF==0 || ($1=="No" && $2=="rules")) next
            if ($1=="-D") {
                if (NF!=1 || seen_action || seen_delete) uncertain=1
                seen_delete=1
                next
            }
            if ($1=="-q" || $1=="-t") uncertain=1
            delete tokens
            n=0; extra=0; overlap=0; saw_syscalls=0
            for (i=1; i<=NF; i++) {
                flag=$i
                if (flag !~ /^-(a|A|F|k|p|w|S)$/ || i==NF) {extra=1; continue}
                arg=$(++i)
                if (flag=="-a" || flag=="-A" || flag=="-w") seen_action=1
                if ((flag=="-a" || flag=="-A") && arg ~ /(^never,|,never$|^exclude,|,exclude$)/) uncertain=1
                if ((flag=="-w" && touches(arg,flag)) ||
                    (flag=="-F" && arg ~ /^(path|dir|exe)=/ &&
                     touches(substr(arg,index(arg,"=")+1),substr(arg,1,index(arg,"=")-1)))) overlap=1
                if (flag=="-S" && arg=="all" && kind=="exec" && !saw_syscalls++) continue
                a=atom(flag,arg)
                if (a in tokens) extra=1
                tokens[a]=1
                n++
            }
            if (!overlap) next
            if (!extra && kind=="watch" && n==3 && tokens["-w " target] &&
                tokens["-p wa"] && tokens["-k " key]) found++
            else if (!extra && kind=="exec" && n==6 && tokens["-a always,exit"] &&
                tokens["-F path=" target] && tokens["-F perm=x"] &&
                tokens["-F auid>=1000"] && tokens["-F auid!=unset"] &&
                tokens["-k " key]) found++
            else ambiguous=1
        }
        END {
            if (uncertain || ambiguous || found>1) print "review"
            else if (found==1) print "present"
            else print "missing"
        }'
}

expansion_audit_watched_object() {
    local kind=$1 path=$2 canonical metadata owner mode
    canonical=$(realpath -e -- "$path" 2>/dev/null) || return 1
    [[ $canonical == "$path" && ! -L $path ]] && local_filesystem "$path" || return 1
    if [[ $kind == exec ]]; then
        [[ -f $path && -x $path ]] || return 1
    elif [[ $path == /etc/sudoers.d ]]; then
        [[ -d $path ]] || return 1
    else
        [[ -f $path ]] || return 1
    fi
    metadata=$(stat -c '%u %a' -- "$path" 2>/dev/null) || return 1
    read -r owner mode <<< "$metadata"
    [[ $owner == 0 && $mode =~ ^[0-7]{1,4}$ ]] && (( (8#$mode & 022) == 0 ))
}

expansion_audit_loader() {
    local unit line post='' pattern='^ExecStartPost=\{[[:space:]]+path=(/usr)?/sbin/augenrules[[:space:]]+;[[:space:]]+argv\[\]=(/usr)?/sbin/augenrules[[:space:]]+--load[[:space:]]+;'
    unit=$(timeout 8 systemctl show auditd.service -p LoadState -p ActiveState -p FragmentPath \
        -p DropInPaths -p ExecStartPost 2>/dev/null) || return 1
    grep -Fxq 'LoadState=loaded' <<< "$unit" &&
        grep -Fxq 'ActiveState=active' <<< "$unit" &&
        grep -Fxq 'FragmentPath=/usr/lib/systemd/system/auditd.service' <<< "$unit" &&
        grep -Fxq 'DropInPaths=' <<< "$unit" || return 1
    while IFS= read -r line; do
        if [[ $line == ExecStartPost=* ]]; then
            [[ ! $post ]] || return 1
            post=$line
        fi
    done <<< "$unit"
    [[ $post =~ $pattern && $post != *'} {'* ]] || return 1
    printf '%s\n' "$unit"
}

expansion_audit_managed() {
    grep -Eiq '^[[:space:]]*#.*(ansible managed|managed by[[:space:]]+(ansible|puppet|chef|salt|ignition|cloud-init)|generated by[[:space:]]+(ansible|puppet|chef|salt|ignition|cloud-init)|do not edit|do not modify)' <<< "$1"
}

expansion_audit_kernel_status() {
    timeout 8 auditctl -s 2>/dev/null | awk '
        $1=="enabled" {count++; value=$2}
        END {if (count!=1 || value !~ /^[012]$/) exit 1; print value}'
}

expansion_audit_generated_rules() {
    local path=/etc/audit/audit.rules
    [[ ! -L $path ]] && text_input_file "$path" || return 1
    cat -- "$path"
}

expansion_audit_check_rule() {
    local kind path key source_names source generated active source_state generated_state active_state enabled
    read -r kind path key < <(expansion_audit_spec "$1") || return 1
    if ! have_tools auditctl systemctl awk realpath stat findmnt; then
        rule_result NEEDS_REVIEW 'Audit rule assessment requires the standard local audit, systemd and filesystem tools.'
        return
    fi
    if ! expansion_audit_watched_object "$kind" "$path"; then
        rule_result NEEDS_REVIEW "The referenced object is absent, linked or outside the trusted local layout ($path). Review applicability and the effective path."
        return
    fi
    if ! enabled=$(expansion_audit_kernel_status); then
        rule_result NEEDS_REVIEW 'The effective kernel audit state could not be read.'
        return
    elif [[ $enabled == 0 ]]; then
        rule_result FAIL 'Kernel auditing is disabled. Restore the approved audit service and reassess.'
        return
    fi
    if ! expansion_audit_loader >/dev/null ||
       ! source_names=$(audit_rule_source_inventory) ||
       ! source=$(audit_rule_source_contents <<< "$source_names") ||
       ! generated=$(expansion_audit_generated_rules); then
        rule_result NEEDS_REVIEW 'The standard augenrules source or generated audit rules could not be verified.'
        return
    fi
    if ! active=$(active_audit_rules); then
        rule_result NEEDS_REVIEW 'The active audit rules could not be read.'
        return
    fi
    source_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$source") &&
        generated_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$generated") &&
        active_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$active") || return 1
    case $source_state:$generated_state:$active_state in
        *review*) rule_result NEEDS_REVIEW "Audit rules overlap $path, contain duplicates, or include suppressions or deletes. Review the effective policy." ;;
        present:present:present) rule_result PASS "The required audit rule for $path is present in the authoritative source, generated rules and loaded rules." ;;
        present:*)
            CHECK_PENDING=1
            rule_result NEEDS_REVIEW "The source contains the required audit rule for $path. Approved activation and active verification remain."
            ;;
        missing:*) rule_result FAIL "The authoritative audit source lacks the required rule for $path." ;;
        *) return 1 ;;
    esac
}

expansion_audit_validate_dropin() {
    local candidate=$1 target=$2 id=${2##*/} expected digest
    [[ $target =~ ^/etc/audit/rules\.d/90-rhel8-stig-v[0-9]+\.rules$ ]] || return 1
    id=${id#90-rhel8-stig-v}
    id=V-${id%.rules}
    expected=$(expansion_audit_payload "$id") || return 1
    digest=$(printf '%s\n' "$expected" | sha256sum) || return 1
    [[ $(sha256_file "$candidate") == "${digest%% *}" ]]
}

expansion_audit_plan_rule() {
    local id=$1 kind path key unit enabled names source generated active target payload object_id source_state generated_state active_state
    read -r kind path key < <(expansion_audit_spec "$id") || return 1
    target=/etc/audit/rules.d/90-rhel8-stig-v${id#V-}.rules
    if ! have_tools systemctl auditctl augenrules || ! unit=$(expansion_audit_loader) ||
       ! enabled=$(expansion_audit_kernel_status) || [[ $enabled != 1 && $enabled != 2 ]]; then
        edit_fail 'the stock active auditd and augenrules configuration could not be verified'; return
    fi
    if ! expansion_audit_watched_object "$kind" "$path" ||
       ! object_id=$(stat -c '%d:%i:%u:%g:%a' -- "$path" 2>/dev/null); then
        edit_fail 'the referenced audit object is unavailable or outside the trusted local layout'; return
    fi
    if ! names=$(audit_rule_source_inventory) || ! source=$(audit_rule_source_contents <<< "$names") ||
       ! generated=$(expansion_audit_generated_rules) || ! active=$(active_audit_rules); then
        edit_fail 'the trusted source, generated rules or loaded audit policy could not be read'; return
    fi
    if expansion_audit_managed "$source"; then
        edit_fail 'audit rules appear to be managed by an external configuration source'; return
    fi
    source_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$source") &&
        generated_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$generated") &&
        active_state=$(expansion_audit_rule_state "$kind" "$path" "$key" <<< "$active") || return 1
    if [[ $source_state != missing || $generated_state == review || $active_state == review ]]; then
        edit_fail 'the source already covers this finding or audit rules may overlap or suppress it'; return
    fi
    if [[ -e $target || -L $target ]]; then
        edit_fail 'the dedicated rules source already exists and requires review'; return
    fi
    payload=$(expansion_audit_payload "$id") || return 1
    EDIT_CONTEXT=$(printf '%s\0' "$unit" "$enabled" "$object_id" "$names" "$source" "$generated" "$active" |
        sha256sum) || return 1
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm this audit rules source is locally managed and the new events are authorized. Consider log capacity.'
    if [[ $enabled == 2 ]]; then
        EDIT_ACTIVATION='The live audit policy is immutable. Review the complete queued policy, schedule an approved reboot, and verify generated and loaded rules.'
    else
        EDIT_ACTIVATION='Have the audit owner review the complete queued rules source, activate via approved augenrules loading, and verify generated and loaded rules.'
    fi
    edit_content "$target" 0600 "+ $payload" expansion_audit_validate_dropin <<< "$payload"
}

expansion_audit_admin_rule() {
    local kind path key
    read -r kind path key < <(expansion_audit_spec "$1") || return 1
    printf '%s\n' \
        "Confirm the applicability of $path and identify the authoritative audit rules source." \
        "Review the required $kind rule with key $key and check for overriding or duplicate rules." \
        'Review the complete queued policy and schedule any applicable activation or reboot separately.' \
        'Verify the generated configuration and loaded policy after activation.'
}

# Audit daemons keep these settings in their own configuration rather than
# the rule list. A staged change remains pending until the standard daemon
# starts after the configuration was written.
expansion_audit_config_spec() {
    case $1 in
        V-230393) printf '%s\n' 'local_events yes' ;;
        V-230395) printf '%s\n' 'log_format ENRICHED' ;;
        *) return 1 ;;
    esac
}

expansion_audit_config_observe() {
    local key=$1 path=$2 value
    value=$(audit_setting "$key" < "$path") || return $?
    case $key:${value,,} in
        local_events:yes|local_events:no|log_format:enriched|log_format:raw) printf '%s\n' "$value" ;;
        *) return 2 ;;
    esac
}

expansion_audit_daemon_started() {
    local log timestamp started
    expansion_audit_loader >/dev/null &&
        log=$(audit_log_object file) &&
        audit_writer_context "$log" >/dev/null || return 1
    timestamp=$(timeout 8 systemctl show auditd.service -p ExecMainStartTimestamp --value 2>/dev/null) ||
        return 1
    started=$(LC_ALL=C date -d "$timestamp" +%s 2>/dev/null) || return 1
    [[ $started =~ ^[1-9][0-9]*$ ]] || return 1
    printf '%s\n' "$started"
}

expansion_audit_check_config() {
    local key required_setting observed_value rc modified started audit_conf=/etc/audit/auditd.conf
    read -r key required_setting < <(expansion_audit_config_spec "$1") || return 1
    if [[ -L $audit_conf ]] || ! text_input_file "$audit_conf"; then
        rule_result NEEDS_REVIEW 'The standard auditd configuration is unavailable or ambiguous.'
        return
    fi
    observed_value=$(expansion_audit_config_observe "$key" "$audit_conf")
    rc=$?
    if (( rc > 1 )); then
        rule_result NEEDS_REVIEW "The auditd $key setting is duplicated or unrecognized."
        return
    elif [[ ${observed_value,,} != "${required_setting,,}" ]]; then
        rule_result FAIL "The standard auditd configuration does not explicitly set $key to $required_setting."
        return
    fi
    if ! started=$(expansion_audit_daemon_started) ||
       ! modified=$(stat -c '%Y' -- "$audit_conf") ||
       [[ ! $modified =~ ^[0-9]+$ ]]; then
        rule_result NEEDS_REVIEW "$key is configured as $required_setting. The standard running audit daemon and activation could not be verified."
    elif (( modified >= started )); then
        CHECK_PENDING=1
        rule_result NEEDS_REVIEW "$key is configured as $required_setting. Verify activation because the file is as recent as or newer than the last observed daemon start."
    else
        rule_result PASS "$key is configured as $required_setting and the standard audit daemon started after the configuration was written."
    fi
}

expansion_audit_config_render() {
    local source=$1 key=$2 value=$3 id=$4
    awk -v key="$key" -v value="$value" -v id="$id" '
        /^[[:space:]]*#/ {print; next}
        tolower($0) ~ ("^[[:space:]]*" key "[[:blank:]]+=[[:blank:]]+") {
            print "# rhel8-stig replaced " key " for " id
            print key " = " value
            replaced++
            next
        }
        {print}
        END {
            if (replaced>1) exit 1
            if (!replaced) {
                print "# rhel8-stig " id
                print key " = " value
            }
        }' "$source"
}

expansion_audit_config_validate() {
    local candidate=$1 target=$2 chosen_id=$3 id key required_setting observed_value
    [[ $target == /etc/audit/auditd.conf ]] || return 1
    for id in "$chosen_id" $EDIT_GROUPED; do
        read -r key required_setting < <(expansion_audit_config_spec "$id") || return 1
        observed_value=$(expansion_audit_config_observe "$key" "$candidate") || return 1
        [[ $observed_value == "$required_setting" ]] || return 1
    done
}

expansion_audit_validate_local() { expansion_audit_config_validate "$1" "$2" V-230393; }
expansion_audit_validate_enriched() { expansion_audit_config_validate "$1" "$2" V-230395; }

expansion_audit_plan_config() {
    local chosen_id=$1 sibling validator id input draft observed_value rc key required_setting context unit
    local audit_conf=/etc/audit/auditd.conf preview='' contents log
    if [[ $chosen_id == V-230393 ]]; then
        sibling=V-230395 validator=expansion_audit_validate_local
    else
        sibling=V-230393 validator=expansion_audit_validate_enriched
    fi
    if ! attended_policy_source "$audit_conf" ||
       ! unit=$(expansion_audit_loader) ||
       ! log=$(audit_log_object file) ||
       ! context=$(audit_writer_context "$log") ||
       ! contents=$(< "$audit_conf"); then
        edit_fail 'the root-controlled auditd configuration and its standard running writer could not be proven'; return
    fi
    if expansion_audit_managed "$contents"; then
        edit_fail 'auditd.conf appears to be managed by an external configuration source'; return
    fi
    input=$audit_conf
    for id in "$chosen_id" "$sibling"; do
        if [[ $id != "$chosen_id" && ! ${EFFECTIVE[$id]+selected} ]]; then continue; fi
        read -r key required_setting < <(expansion_audit_config_spec "$id") || return 1
        observed_value=$(expansion_audit_config_observe "$key" "$input")
        rc=$?
        if (( rc > 1 )); then
            edit_fail "the auditd $key definition is duplicated or unrecognized"; return
        fi
        if [[ ${observed_value,,} == "${required_setting,,}" ]]; then
            if [[ $id == "$chosen_id" ]]; then edit_fail 'the audit setting already has the required value'; return; fi
            continue
        fi
        draft=$EDIT_TEMP/auditd-$id.conf
        expansion_audit_config_render "$input" "$key" "$required_setting" "$id" > "$draft" || return 1
        input=$draft
        if [[ $observed_value ]]; then preview+="- $key = $observed_value"$'\n'; fi
        preview+="+ $key = $required_setting"$'\n'
        if [[ $id != "$chosen_id" ]]; then EDIT_RELATED=$id EDIT_GROUPED=$id; fi
    done
    EDIT_CONTEXT=$(printf '%s\0' "$unit" "$context" "$contents" | sha256sum) || return 1
    EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm local audit collection, storage capacity and that downstream tools accept any proposed output format.'
    EDIT_ACTIVATION='Review all pending audit changes, then arrange an approved audit daemon restart. Verify local audit events and downstream ingestion.'
    edit_content "$audit_conf" keep "${preview%$'\n'}" "$validator" < "$input"
}

rule_V_230393_check() { expansion_audit_check_config V-230393; }
rule_V_230395_check() { expansion_audit_check_config V-230395; }
rule_V_230393_plan() { expansion_audit_plan_config V-230393; }
rule_V_230395_plan() { expansion_audit_plan_config V-230395; }

rule_V_230393_admin() {
    printf '%s\n' \
        'Confirm the host is intended to collect local audit events and identify the authoritative auditd configuration.' \
        'Set local_events = yes. In the approved window restart the audit daemon and confirm representative local events.'
}

rule_V_230395_admin() {
    printf '%s\n' \
        'Confirm downstream audit clients can read enriched records and identify the authoritative auditd configuration.' \
        'Set log_format = ENRICHED. In the approved window restart auditd and verify enriched records and downstream ingestion.'
}

expansion_audit_tool_paths() {
    printf '%s\n' /usr/sbin/auditctl /usr/sbin/aureport /usr/sbin/ausearch \
        /usr/sbin/autrace /usr/sbin/auditd /usr/sbin/rsyslogd /usr/sbin/augenrules
}

expansion_audit_tool_integrity() {
    local path=$1 type=audit identity entries expected
    if [[ $path == /usr/sbin/rsyslogd ]]; then type=rsyslog; fi
    identity=$(timeout 8 rpm -qf --qf '%{NAME}|%{VENDOR}\n' -- "$path" 2>/dev/null) || return 1
    [[ $identity == "$type|Red Hat, Inc." ]] || return 1
    entries=$(timeout 8 rpm -qf --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' -- "$path" 2>/dev/null) || return 1
    expected=$(awk -F'|' -v target="$path" -v alias="${path#/usr}" '
        $1 == target || $1 == alias {seen++; digest=$2}
        END {if (seen!=1) exit 1; print digest}
    ' <<< "$entries") || return 1
    [[ $expected =~ ^[0-9a-f]{64}$ && $(sha256_file "$path") == "$expected" ]]
}

expansion_audit_check_tools() {
    local id=$1 path mode gid failed=0 unavailable=0
    while IFS= read -r path; do
        if [[ ! -f $path || -L $path ]] ||
           ! read -r mode gid < <(stat -c '%a %g' -- "$path" 2>/dev/null) ||
           [[ ! $mode =~ ^[0-7]{1,4}$ || ! $gid =~ ^[0-9]+$ ]]; then
            unavailable=$((unavailable + 1))
            continue
        fi
        if { [[ $id == V-230472 ]] && (( 8#$mode & ~0755 )); } ||
           [[ $id == V-230474 && $gid != 0 ]]; then
            failed=$((failed + 1))
        fi
    done < <(expansion_audit_tool_paths)
    if (( failed )); then
        rule_result FAIL "$failed listed audit tools fail the required metadata check. $unavailable objects could not be verified."
    elif (( unavailable )); then
        rule_result NEEDS_REVIEW "$unavailable listed audit tools are missing, linked, or inaccessible."
    else
        rule_result PASS 'All listed audit tools have the required metadata.'
    fi
}

expansion_audit_plan_tools() {
    local chosen_id=$1 sibling path mode gid new_mode new_gid edit_description digest context='' found_requested=0 found_sibling=0
    if [[ $chosen_id == V-230472 ]]; then sibling=V-230474; else sibling=V-230472; fi
    if ! have_tools rpm sha256sum realpath; then
        edit_fail 'audit tool repair requires local RPM and file integrity tools'; return
    fi
    while IFS= read -r path; do
        if [[ ! -f $path || -L $path || $(realpath -e -- "$path" 2>/dev/null) != "$path" ]] ||
           ! read -r mode gid < <(stat -c '%a %g' -- "$path" 2>/dev/null) ||
           [[ ! $mode =~ ^[0-7]{1,4}$ || ! $gid =~ ^[0-9]+$ ]]; then
            edit_fail "expected audit tool could not be verified: $path"; return
        fi
        new_mode=keep new_gid=keep edit_description=''
        if [[ $chosen_id == V-230472 || ${EFFECTIVE[V-230472]+selected} ]] && (( 8#$mode & ~0755 )); then
            printf -v new_mode '%04o' "$(( 8#$mode & 0755 ))"
            edit_description="Mode $mode -> $new_mode. Existing owner permissions are preserved."
            if [[ $chosen_id == V-230472 ]]; then found_requested=1; else found_sibling=1; fi
        fi
        if [[ $chosen_id == V-230474 || ${EFFECTIVE[V-230474]+selected} ]] && [[ $gid != 0 ]]; then
            new_gid=0
            edit_description+="${edit_description:+ }Group ID $gid -> 0 (root)."
            if [[ $chosen_id == V-230474 ]]; then found_requested=1; else found_sibling=1; fi
        fi
        if [[ $new_mode == keep && $new_gid == keep ]]; then continue; fi
        if ! expansion_audit_tool_integrity "$path" || ! digest=$(sha256_file "$path"); then
            edit_fail "RPM did not establish the integrity of $path. Review the binary before changing metadata."; return
        fi
        context+="$path $digest"$'\n'
        edit_metadata "$path" "$new_mode" "$new_gid" "$edit_description" || return 1
    done < <(expansion_audit_tool_paths)
    if (( ! found_requested )); then
        edit_fail 'the selected audit tool metadata already matches'; return
    fi
    if (( found_sibling )); then EDIT_RELATED=$sibling EDIT_GROUPED=$sibling; fi
    EDIT_CONTEXT=$(printf '%s' "$context" | sha256sum) || return 1
    EDIT_REQUIREMENTS='Confirm that authorized operators and audit services can still use the affected binaries. This metadata change is immediate.'
}

rule_V_230472_check() { expansion_audit_check_tools V-230472; }
rule_V_230474_check() { expansion_audit_check_tools V-230474; }
rule_V_230472_plan() { expansion_audit_plan_tools V-230472; }
rule_V_230474_plan() { expansion_audit_plan_tools V-230474; }

rule_V_230472_admin() {
    printf '%s\n' \
        'Verify the package and content integrity of each audit tool before changing permissions.' \
        'Remove mode bits outside 0755 and preserve any stricter approved mode. Retest authorized audit tool access.'
}

rule_V_230474_admin() {
    printf '%s\n' \
        'Verify the package and content integrity of each audit tool before changing ownership metadata.' \
        'Use root group ownership on the listed audit tools, and verify approved users and services can still run them.'
}

rule_V_230404_check() { expansion_audit_check_rule V-230404; }
rule_V_230404_plan() { expansion_audit_plan_rule V-230404; }
rule_V_230404_admin() { expansion_audit_admin_rule V-230404; }
rule_V_230405_check() { expansion_audit_check_rule V-230405; }
rule_V_230405_plan() { expansion_audit_plan_rule V-230405; }
rule_V_230405_admin() { expansion_audit_admin_rule V-230405; }
rule_V_230406_check() { expansion_audit_check_rule V-230406; }
rule_V_230406_plan() { expansion_audit_plan_rule V-230406; }
rule_V_230406_admin() { expansion_audit_admin_rule V-230406; }
rule_V_230407_check() { expansion_audit_check_rule V-230407; }
rule_V_230407_plan() { expansion_audit_plan_rule V-230407; }
rule_V_230407_admin() { expansion_audit_admin_rule V-230407; }
rule_V_230408_check() { expansion_audit_check_rule V-230408; }
rule_V_230408_plan() { expansion_audit_plan_rule V-230408; }
rule_V_230408_admin() { expansion_audit_admin_rule V-230408; }
rule_V_230409_check() { expansion_audit_check_rule V-230409; }
rule_V_230409_plan() { expansion_audit_plan_rule V-230409; }
rule_V_230409_admin() { expansion_audit_admin_rule V-230409; }
rule_V_230410_check() { expansion_audit_check_rule V-230410; }
rule_V_230410_plan() { expansion_audit_plan_rule V-230410; }
rule_V_230410_admin() { expansion_audit_admin_rule V-230410; }
rule_V_230412_check() { expansion_audit_check_rule V-230412; }
rule_V_230412_plan() { expansion_audit_plan_rule V-230412; }
rule_V_230412_admin() { expansion_audit_admin_rule V-230412; }
rule_V_230418_check() { expansion_audit_check_rule V-230418; }
rule_V_230418_plan() { expansion_audit_plan_rule V-230418; }
rule_V_230418_admin() { expansion_audit_admin_rule V-230418; }
rule_V_230419_check() { expansion_audit_check_rule V-230419; }
rule_V_230419_plan() { expansion_audit_plan_rule V-230419; }
rule_V_230419_admin() { expansion_audit_admin_rule V-230419; }
rule_V_230421_check() { expansion_audit_check_rule V-230421; }
rule_V_230421_plan() { expansion_audit_plan_rule V-230421; }
rule_V_230421_admin() { expansion_audit_admin_rule V-230421; }
rule_V_230422_check() { expansion_audit_check_rule V-230422; }
rule_V_230422_plan() { expansion_audit_plan_rule V-230422; }
rule_V_230422_admin() { expansion_audit_admin_rule V-230422; }
rule_V_230423_check() { expansion_audit_check_rule V-230423; }
rule_V_230423_plan() { expansion_audit_plan_rule V-230423; }
rule_V_230423_admin() { expansion_audit_admin_rule V-230423; }
rule_V_230424_check() { expansion_audit_check_rule V-230424; }
rule_V_230424_plan() { expansion_audit_plan_rule V-230424; }
rule_V_230424_admin() { expansion_audit_admin_rule V-230424; }
rule_V_230426_check() { expansion_audit_check_rule V-230426; }
rule_V_230426_plan() { expansion_audit_plan_rule V-230426; }
rule_V_230426_admin() { expansion_audit_admin_rule V-230426; }
rule_V_230427_check() { expansion_audit_check_rule V-230427; }
rule_V_230427_plan() { expansion_audit_plan_rule V-230427; }
rule_V_230427_admin() { expansion_audit_admin_rule V-230427; }
rule_V_230428_check() { expansion_audit_check_rule V-230428; }
rule_V_230428_plan() { expansion_audit_plan_rule V-230428; }
rule_V_230428_admin() { expansion_audit_admin_rule V-230428; }
rule_V_230429_check() { expansion_audit_check_rule V-230429; }
rule_V_230429_plan() { expansion_audit_plan_rule V-230429; }
rule_V_230429_admin() { expansion_audit_admin_rule V-230429; }
rule_V_230430_check() { expansion_audit_check_rule V-230430; }
rule_V_230430_plan() { expansion_audit_plan_rule V-230430; }
rule_V_230430_admin() { expansion_audit_admin_rule V-230430; }
rule_V_230431_check() { expansion_audit_check_rule V-230431; }
rule_V_230431_plan() { expansion_audit_plan_rule V-230431; }
rule_V_230431_admin() { expansion_audit_admin_rule V-230431; }
rule_V_230432_check() { expansion_audit_check_rule V-230432; }
rule_V_230432_plan() { expansion_audit_plan_rule V-230432; }
rule_V_230432_admin() { expansion_audit_admin_rule V-230432; }
rule_V_230433_check() { expansion_audit_check_rule V-230433; }
rule_V_230433_plan() { expansion_audit_plan_rule V-230433; }
rule_V_230433_admin() { expansion_audit_admin_rule V-230433; }
rule_V_230434_check() { expansion_audit_check_rule V-230434; }
rule_V_230434_plan() { expansion_audit_plan_rule V-230434; }
rule_V_230434_admin() { expansion_audit_admin_rule V-230434; }
rule_V_230435_check() { expansion_audit_check_rule V-230435; }
rule_V_230435_plan() { expansion_audit_plan_rule V-230435; }
rule_V_230435_admin() { expansion_audit_admin_rule V-230435; }
rule_V_230436_check() { expansion_audit_check_rule V-230436; }
rule_V_230436_plan() { expansion_audit_plan_rule V-230436; }
rule_V_230436_admin() { expansion_audit_admin_rule V-230436; }
rule_V_230437_check() { expansion_audit_check_rule V-230437; }
rule_V_230437_plan() { expansion_audit_plan_rule V-230437; }
rule_V_230437_admin() { expansion_audit_admin_rule V-230437; }
rule_V_230444_check() { expansion_audit_check_rule V-230444; }
rule_V_230444_plan() { expansion_audit_plan_rule V-230444; }
rule_V_230444_admin() { expansion_audit_admin_rule V-230444; }
rule_V_230447_check() { expansion_audit_check_rule V-230447; }
rule_V_230447_plan() { expansion_audit_plan_rule V-230447; }
rule_V_230447_admin() { expansion_audit_admin_rule V-230447; }
rule_V_230448_check() { expansion_audit_check_rule V-230448; }
rule_V_230448_plan() { expansion_audit_plan_rule V-230448; }
rule_V_230448_admin() { expansion_audit_admin_rule V-230448; }
rule_V_230462_check() { expansion_audit_check_rule V-230462; }
rule_V_230462_plan() { expansion_audit_plan_rule V-230462; }
rule_V_230462_admin() { expansion_audit_admin_rule V-230462; }
rule_V_230463_check() { expansion_audit_check_rule V-230463; }
rule_V_230463_plan() { expansion_audit_plan_rule V-230463; }
rule_V_230463_admin() { expansion_audit_admin_rule V-230463; }
rule_V_230464_check() { expansion_audit_check_rule V-230464; }
rule_V_230464_plan() { expansion_audit_plan_rule V-230464; }
rule_V_230464_admin() { expansion_audit_admin_rule V-230464; }
rule_V_230465_check() { expansion_audit_check_rule V-230465; }
rule_V_230465_plan() { expansion_audit_plan_rule V-230465; }
rule_V_230465_admin() { expansion_audit_admin_rule V-230465; }
rule_V_230467_check() { expansion_audit_check_rule V-230467; }
rule_V_230467_plan() { expansion_audit_plan_rule V-230467; }
rule_V_230467_admin() { expansion_audit_admin_rule V-230467; }

# Additional local policy, file metadata, and desktop controls.

expansion_console_notice() {
    awk '
        /^"You are accessing a U\.S\. Government/ {sub(/^"/, ""); banner=1}
        banner {print; if (sub(/"$/, "")) exit}
    ' <<< "${OFFICIAL_FIX[V-230227]}" | sed '$s/"$//'
}

expansion_notice_validate() {
    local expected actual
    expected=$(expansion_console_notice) && actual=$(cat -- "$1") || return 1
    [[ $expected == 'You are accessing a U.S. Government'* && $actual == "$expected" ]]
}

rule_V_230227_check() {
    local expected alternate actual
    expected=$(expansion_console_notice) || return 1
    [[ $expected == 'You are accessing a U.S. Government'* ]] || return 1
    if [[ ! -e /etc/issue && ! -L /etc/issue ]]; then
        rule_result FAIL 'The command-line notice file /etc/issue is absent.'
    elif ! text_input_file /etc/issue || ! actual=$(cat -- /etc/issue); then
        rule_result NEEDS_REVIEW 'The console notice is linked, unreadable, or outside the supported file format.'
    else
        # The pinned check and fix excerpts disagree on spaces around this dash.
        alternate=${expected/'interests -- not'/'interests--not'}
        if [[ $actual == "$expected" || $actual == "$alternate" ]]; then
            rule_result PASS 'The command-line notice file matches the pinned DoW wording.'
        else
            rule_result FAIL 'The command-line notice file differs from the pinned DoW wording.'
        fi
    fi
}

rule_V_230227_plan() {
    local expected mode=0644
    expected=$(expansion_console_notice) || return 1
    if [[ -e /etc/issue ]]; then mode=keep; fi
    EDIT_REQUIREMENTS='Confirm that the pinned DoW notice is authorized for this host and that the console login reads /etc/issue.'
    edit_content /etc/issue "$mode" 'Replace the command-line notice with the pinned DoW text shown by --explain V-230227.' \
        expansion_notice_validate <<< "$expected"
}

rule_V_230227_admin() {
    printf '%s\n' 'Use the approved pinned notice in the authoritative console banner file. Verify it at a fresh console login.'
}

expansion_log_target() {
    case $1 in
        V-230245|V-230246|V-230247) [[ -f /var/log/messages && ! -L /var/log/messages ]] && printf '/var/log/messages\n' ;;
        V-230248|V-230250) [[ -d /var/log && ! -L /var/log ]] && printf '/var/log\n' ;;
        V-230397) audit_log_object file ;;
        V-230399) audit_log_object directory ;;
        *) return 1 ;;
    esac
}

expansion_metadata_check() {
    local path=$1 field=$2 expected=$3 value
    case $field in
        mode) value=$(stat -c '%a' -- "$path" 2>/dev/null) && [[ $value =~ ^[0-7]{1,4}$ ]] || return 1
            (( (8#$value & ~8#$expected) == 0 )) ;;
        owner) value=$(stat -c '%u' -- "$path" 2>/dev/null) && [[ $value =~ ^[0-9]+$ ]] || return 1
            [[ $value == "$expected" ]] ;;
        group) value=$(stat -c '%g' -- "$path" 2>/dev/null) && [[ $value =~ ^[0-9]+$ ]] || return 1
            [[ $value == "$expected" ]] ;;
        *) return 1 ;;
    esac
    local status=$?
    if (( status )); then return 2; fi
    return 0
}

expansion_log_check() {
    local id=$1 field=$2 expected=$3 path result
    if ! path=$(expansion_log_target "$id"); then
        rule_result NEEDS_REVIEW 'The relevant log object is missing, linked, or cannot be determined. Verify the active logging configuration.'
        return
    fi
    expansion_metadata_check "$path" "$field" "$expected"
    result=$?
    case $result in
        0) rule_result PASS "$path meets the $field requirement ($expected)." ;;
        2) rule_result FAIL "$path exceeds the allowed mode or differs from the required $field ($expected)." ;;
        *) rule_result NEEDS_REVIEW "Could not verify $field for $path." ;;
    esac
}

expansion_log_admin() {
    printf '%s\n' 'Review the active log writer, rotation settings, and approved readers. Change only the specified mode, owner, or group on the verified local object. Recheck after log rotation.'
}

expansion_log_mode_plan() {
    local id=$1 limit=$2 path mode narrowed group=keep description sibling='' related='' current_gid
    path=$(expansion_log_target "$id") && mode=$(stat -c '%a' -- "$path") && [[ $mode =~ ^[0-7]{1,4}$ ]] || return 1
    narrowed=keep
    if [[ $limit != keep ]]; then printf -v narrowed '0%03o' "$((8#$mode & 8#$limit))"; else group=0; fi
    description="Keep the existing file contents and set only the required metadata (mode $narrowed, GID $group)."
    case $id in
        V-230245) related=V-230247 ;;
        V-230248) related=V-230250 ;;
    esac
    if [[ $related && ${EFFECTIVE[$related]+selected} ]]; then
        current_gid=$(stat -c '%g' -- "$path") || return 1
        if [[ $current_gid != 0 ]]; then
            group=0 sibling=$related
            description="Set mode $narrowed and GID 0 together for the two selected findings."
        fi
    fi
    EDIT_RELATED=$sibling EDIT_GROUPED=$sibling
    EDIT_REQUIREMENTS='Confirm logging and rotation ownership, approved reader access, and local management. Verify newly created logs after rotation.'
    edit_metadata "$path" "$narrowed" "$group" "$description"
}

rule_V_230245_check() { expansion_log_check V-230245 mode 0640; }
rule_V_230246_check() { expansion_log_check V-230246 owner 0; }
rule_V_230247_check() { expansion_log_check V-230247 group 0; }
rule_V_230248_check() { expansion_log_check V-230248 mode 0755; }
rule_V_230250_check() { expansion_log_check V-230250 group 0; }
rule_V_230397_check() { expansion_log_check V-230397 owner 0; }
rule_V_230399_check() { expansion_log_check V-230399 owner 0; }

rule_V_230245_plan() { expansion_log_mode_plan V-230245 0640; }
rule_V_230247_plan() { expansion_log_mode_plan V-230247 keep; }
rule_V_230248_plan() { expansion_log_mode_plan V-230248 0755; }
rule_V_230250_plan() { expansion_log_mode_plan V-230250 keep; }

rule_V_230245_admin() { expansion_log_admin; }
rule_V_230246_admin() { expansion_log_admin; }
rule_V_230247_admin() { expansion_log_admin; }
rule_V_230248_admin() { expansion_log_admin; }
rule_V_230250_admin() { expansion_log_admin; }
rule_V_230397_admin() { expansion_log_admin; }
rule_V_230399_admin() { expansion_log_admin; }

# Read and change UID on the pinned inode. Refuse linked objects, special
# bits, capabilities, or ACLs that would require additional rollback data.
expansion_owner_tool() {
    local id=$1 operation=$2 path=$3 expected=${4:-} desired=${5:-} target kind=file
    target=$(expansion_log_target "$id") || return 1
    [[ $target == "$path" && $path == /var/log/* ]] && edit_safe_path "$path" || return 1
    if [[ $id == V-230399 ]]; then kind=directory; fi
    have_tools python3 || return 1
    timeout --kill-after=2s 15s python3 -I - "$path" "$kind" "$operation" "$expected" "$desired" <<'PYTHON'
import hashlib
import os
import stat
import sys


def snapshot(fd, path, kind):
    value = os.fstat(fd)
    entry = os.lstat(path)
    if (value.st_dev, value.st_ino) != (entry.st_dev, entry.st_ino):
        raise ValueError('Object was replaced')
    if kind == 'file':
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
            raise ValueError('Not a single-link regular file')
    elif not stat.S_ISDIR(value.st_mode):
        raise ValueError('Not a directory')
    if value.st_mode & 0o7000:
        raise ValueError('Special mode bits need separate review')
    attributes = sorted(os.listxattr(fd))
    if set(attributes) & {'security.capability', 'system.posix_acl_default', 'system.posix_acl_access'}:
        raise ValueError('Extended permissions need separate review')
    digest = hashlib.sha256()
    for name in attributes:
        content = os.getxattr(fd, name)
        digest.update(os.fsencode(name) + b'\0' + str(len(content)).encode('ascii') + b'\0')
        digest.update(content)
    return '{}:{}:{:04o}:{}:{}:{}'.format(value.st_uid, value.st_gid, stat.S_IMODE(value.st_mode),
                                         value.st_dev, value.st_ino, digest.hexdigest())


def apply(path, kind, operation, expected, desired):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = snapshot(fd, path, kind)
        if operation == 'observe':
            print(before)
            return
        old, _, fingerprint = before.partition(':')
        uid, _, desired_fingerprint = desired.partition(':')
        if (before != expected or fingerprint != desired_fingerprint or not uid.isdigit() or
                len(uid) > 10 or int(uid) >= (1 << 32) - 1 or uid == old):
            raise ValueError('The state changed or the requested transition is invalid')
        if operation == 'change' and uid != '0':
            raise ValueError('Only root ownership can be applied')
        if operation == 'restore' and (old != '0' or uid == '0'):
            raise ValueError('Invalid rollback ownership')
        if operation not in ('change', 'restore'):
            raise ValueError('Unknown operation')
        os.fchown(fd, int(uid), -1)
        if snapshot(fd, path, kind) != desired:
            raise ValueError('Ownership verification failed')
    finally:
        os.close(fd)


try:
    apply(*sys.argv[1:])
except (OSError, ValueError):
    sys.exit(1)
PYTHON
}

expansion_log_owner_plan() {
    local id=$1 path snapshot uid
    path=$(expansion_log_target "$id") && snapshot=$(expansion_owner_tool "$id" observe "$path") || {
        edit_fail 'Owner changes require a pinned local log object with ordinary permissions and no extended ACL.'; return;
    }
    uid=${snapshot%%:*}
    [[ $uid != 0 ]] || return 1
    ACTION_REQUIREMENTS='Confirm the log writer, rotation settings, and readers work with root ownership. Owner changes take effect immediately.'
    action_add "$path" "$snapshot" "0:${snapshot#*:}" "UID $uid" 'UID 0 (root)'
}

rule_V_230246_plan() { expansion_log_owner_plan V-230246; }
rule_V_230246_observe() { expansion_owner_tool V-230246 observe "$1"; }
rule_V_230246_change() { expansion_owner_tool V-230246 change "$@"; }
rule_V_230246_restore() { expansion_owner_tool V-230246 restore "$1" "$3" "$2"; }
rule_V_230397_plan() { expansion_log_owner_plan V-230397; }
rule_V_230397_observe() { expansion_owner_tool V-230397 observe "$1"; }
rule_V_230397_change() { expansion_owner_tool V-230397 change "$@"; }
rule_V_230397_restore() { expansion_owner_tool V-230397 restore "$1" "$3" "$2"; }
rule_V_230399_plan() { expansion_log_owner_plan V-230399; }
rule_V_230399_observe() { expansion_owner_tool V-230399 observe "$1"; }
rule_V_230399_change() { expansion_owner_tool V-230399 change "$@"; }
rule_V_230399_restore() { expansion_owner_tool V-230399 restore "$1" "$3" "$2"; }

expansion_public_key_paths() {
    local path found=0
    [[ -d /etc/ssh && ! -L /etc/ssh ]] || return 1
    for path in /etc/ssh/*key.pub; do
        [[ -e $path || -L $path ]] || continue
        [[ -f $path && ! -L $path && $path =~ ^/etc/ssh/[a-zA-Z0-9_.-]+key\.pub$ ]] || return 1
        (( ++found <= 64 )) || return 1
        printf '%s\n' "$path"
    done
    (( found ))
}

rule_V_230286_check() {
    local paths path result
    paths=$(expansion_public_key_paths) || {
        rule_result NEEDS_REVIEW 'Public host keys are missing or use an unsupported path or link.'; return;
    }
    while IFS= read -r path; do
        expansion_metadata_check "$path" mode 0644
        result=$?
        if (( result == 2 )); then rule_result FAIL "At least one public host key exceeds mode 0644 ($path)."; return; fi
        if (( result )); then rule_result NEEDS_REVIEW 'Public host key metadata could not be verified.'; return; fi
    done <<< "$paths"
    rule_result PASS 'Verified the modes of local SSH public host key files.'
}

rule_V_230286_plan() {
    local config=/etc/ssh/sshd_config paths path mode narrowed invocation effective config_hash
    if ! edit_safe_path "$config" || ! text_input_file "$config" || ! edit_target_metadata "$config" ||
        (( 8#$EDIT_ORIGINAL_MODE & 022 )); then
        edit_fail 'The SSH configuration must be a trusted, root-controlled regular file.'; return
    fi
    paths=$(expansion_public_key_paths) && invocation=$(expanded_sshd_invocation) &&
        effective=$(standard_ssh_configured_key_paths "$config") && config_hash=$(sha256_file "$config") &&
        timeout 12 sshd -t -f "$config" >/dev/null 2>&1 || {
        edit_fail 'Confirm a valid packaged SSH service and a standard public host key layout first.'; return;
    }
    while IFS= read -r path; do
        standard_ssh_host_key_path "$path" || return 1
        if [[ -f $path && ! -f $path.pub ]]; then return 1; fi
    done <<< "$effective"
    while IFS= read -r path; do
        mode=$(stat -c '%a' -- "$path") && [[ $mode =~ ^[0-7]{1,4}$ ]] || return 1
        if (( (8#$mode & ~0644) == 0 )); then continue; fi
        printf -v narrowed '0%03o' "$((8#$mode & 0644))"
        edit_metadata "$path" "$narrowed" keep "Narrow public key mode from $mode to $narrowed." || return 1
    done <<< "$paths"
    EDIT_CONTEXT="$config_hash $invocation"
    EDIT_REQUIREMENTS='This changes public-key permissions immediately. Preserve the current authorized session and console access for later SSH activation.'
    EDIT_DISPOSITION=pending
    EDIT_ACTIVATION='Validate sshd, review the separately approved SSH service activation, then verify a fresh connection and key permissions.'
}

rule_V_230286_admin() {
    printf '%s\n' 'Review the effective HostKey paths and tighten the associated public key files. Validate sshd and verify access after planned SSH activation.'
}

expansion_home_targets() {
    local id=$1 homes home path name
    local -a names=(.bash_profile .bash_login .bashrc .bash_logout .profile .cshrc .tcshrc .login .logout .kshrc .zprofile .zshrc .zlogin .zlogout)
    # The pinned check includes UID 1000 and above. Do not hide unfamiliar
    # shells, shared homes or unusual paths filtered by the native action.
    homes=$(awk -F: '
        NF != 7 || $3 !~ /^[0-9]+$/ {invalid=1; next}
        {uses[$6]++}
        $3 >= 1000 && $3 != 65534 && $7 !~ /nologin|\/false$/ {wanted[$6]=1}
        END {
            if (invalid) exit 1
            for (home in wanted) print (uses[home] == 1 && home ~ /^\/home\/[A-Za-z0-9_.@-]+$/ ? home : "gap")
        }
    ' /etc/passwd | LC_ALL=C sort) || return 1
    while IFS= read -r home; do
        [[ $home ]] || continue
        if [[ $home == gap ]] || ! attended_home_account "$home" >/dev/null; then
            printf 'gap\n'; continue
        fi
        if [[ $id == V-230321 ]]; then printf '%s\n' "$home"; continue; fi
        if [[ ! -d $home || -L $home ]]; then
            printf 'gap\n'; continue
        fi
        for name in "${names[@]}"; do
            path=$home/$name
            if [[ -e $path || -L $path ]]; then printf '%s\n' "$path"; fi
        done
    done <<< "$homes"
}

expansion_home_mode_action() {
    local id=$1 operation=$2 target=$3 home account uid
    shift 3
    if [[ $id == V-230321 ]]; then
        home=$target operation=home-mode-$operation
    else
        home=${target%/*} operation=init-mode-$operation
    fi
    [[ $home =~ ^/home/[A-Za-z0-9_.@-]+$ ]] && account=$(attended_home_account "$home") || return 1
    IFS=$'\t' read -r _ uid _ _ _ <<< "$account"
    attended_home_tool "$operation" "$target" "$uid" "$@"
}

expansion_home_mode_check() {
    local id=$1 limit=$2 targets path state mode failure=0 partial=0 count=0
    targets=$(expansion_home_targets "$id") || { rule_result NEEDS_REVIEW 'Local account evidence is incomplete.'; return; }
    while IFS= read -r path; do
        [[ $path ]] || continue
        if [[ $path == gap ]] || ! state=$(expansion_home_mode_action "$id" observe "$path"); then
            partial=1; continue
        fi
        IFS=: read -r _ _ mode _ <<< "$state"
        [[ $mode =~ ^[0-7]{4}$ ]] || return 1
        (( ++count ))
        if (( 8#$mode & ~8#$limit )); then failure=1; fi
    done <<< "$targets"
    if (( failure )); then rule_result FAIL "At least one verified object exceeds mode $limit. Ambiguous home layouts are left for review."
    elif (( partial || count == 0 )) || [[ $id == V-230325 ]]; then
        rule_result NEEDS_REVIEW 'No violation was confirmed in the bounded scan. Verify excluded or nonstandard accounts and initialization files.'
    else rule_result PASS "Verified $count eligible objects against mode $limit."; fi
}

expansion_home_mode_plan() {
    local id=$1 limit=$2 targets path state uid gid mode identity narrowed
    targets=$(expansion_home_targets "$id") || return 1
    while IFS= read -r path; do
        [[ $path && $path != gap ]] || continue
        state=$(expansion_home_mode_action "$id" observe "$path") || continue
        IFS=: read -r uid gid mode identity <<< "$state"
        [[ $mode =~ ^[0-7]{4}$ ]] || return 1
        if (( (8#$mode & ~8#$limit) == 0 )); then continue; fi
        printf -v narrowed '%04o' "$((8#$mode & 8#$limit))"
        action_add "$path" "$state" "$uid:$gid:$narrowed:$identity" "mode $mode" "mode $narrowed" || return 1
    done <<< "$targets"
    ACTION_REQUIREMENTS='Confirm affected local users and file-sharing requirements. Linked objects, shared homes, nonstandard paths, and extended ACLs require review.'
}

rule_V_230321_check() { expansion_home_mode_check V-230321 0750; }
rule_V_230321_plan() { expansion_home_mode_plan V-230321 0750; }
rule_V_230321_observe() { expansion_home_mode_action V-230321 observe "$1"; }
rule_V_230321_change() { expansion_home_mode_action V-230321 change "$@"; }
rule_V_230321_restore() { expansion_home_mode_action V-230321 change "$1" "$3" "$2"; }
rule_V_230325_check() { expansion_home_mode_check V-230325 0740; }
rule_V_230325_plan() { expansion_home_mode_plan V-230325 0740; }
rule_V_230325_observe() { expansion_home_mode_action V-230325 observe "$1"; }
rule_V_230325_change() { expansion_home_mode_action V-230325 change "$@"; }
rule_V_230325_restore() { expansion_home_mode_action V-230325 change "$1" "$3" "$2"; }
rule_V_230321_admin() { printf '%s\n' 'Verify all local interactive home directories. Review shared layouts and preserve stricter permissions while removing access beyond 0750.'; }
rule_V_230325_admin() { printf '%s\n' 'Identify initialization files for all deployed shells. Preserve existing stricter modes and remove bits outside 0740 from each authorized local file.'; }

expansion_desktop_assignment() {
    local profile=$1 section=$2 key=$3 database directory file value result='' profile_path
    profile_path=/etc/dconf/profile/$profile
    desktop_controlled_source "$profile_path" || return 1
    database=$(desktop_profile_database "$profile" "$profile_path") || return 1
    if [[ $profile == gdm && $database != local ]]; then return 1; fi
    directory=/etc/dconf/db/$database.d
    [[ -d $directory ]] && edit_safe_path "$directory" && edit_target_metadata "$directory" &&
        (( !(8#$EDIT_ORIGINAL_MODE & 022) )) || return 1
    for file in "$directory"/* "$directory"/.[!.]* "$directory"/..?*; do
        [[ -e $file || -L $file ]] || continue
        [[ ${file##*/} != locks ]] || continue
        [[ ${file##*/} =~ ^[A-Za-z0-9_-][A-Za-z0-9_.-]*$ ]] && desktop_controlled_source "$file" || return 1
        value=$(expanded_dconf_extract "$section" "$key" "$file" && printf '.') || return 1
        [[ $value != . ]] || continue
        value=${value%$'\n.'}
        [[ ! $result && $value && $value != *$'\n'* ]] || return 1
        result=$value
    done
    printf '%s\n' "$result"
}

expansion_screen_value_valid() {
    local key=$1 value=$2
    case $key in
        lock-enabled|banner-message-enable) [[ $value == true || $value == false || ! $value ]] ;;
        lock-delay) [[ ! $value ]] || { [[ $value =~ ^uint32\ ([0-9]{1,10})$ ]] && (( 10#${BASH_REMATCH[1]} <= 4294967295 )); } ;;
        *) return 1 ;;
    esac
}

expansion_screen_value_compliant() {
    local key=$1 value=$2
    case $key in
        lock-enabled|banner-message-enable) [[ $value == true ]] ;;
        lock-delay) [[ $value =~ ^uint32\ ([0-9]{1,10})$ ]] && (( 10#${BASH_REMATCH[1]} <= 5 )) ;;
        *) return 1 ;;
    esac
}

expansion_desktop_check() {
    local profile=$1 section=$2 key=$3 source effective
    expanded_gnome_applicable || return 0
    if ! source=$(expansion_desktop_assignment "$profile" "$section" "$key") || ! expansion_screen_value_valid "$key" "$source"; then
        rule_result NEEDS_REVIEW "Could not resolve the authoritative dconf source for $key."
        return
    fi
    if [[ $profile == gdm ]]; then
        if expansion_screen_value_compliant "$key" "$source"; then
            rule_result PASS 'The active GDM profile source enables the notice. Verify the actual greeter after publication.'
        else rule_result FAIL 'The active GDM profile source lacks banner-message-enable=true.'; fi
        return
    fi
    if (( EUID != 0 )) && [[ ${XDG_SESSION_TYPE-} =~ ^(x11|wayland)$ && ${DBUS_SESSION_BUS_ADDRESS-} ]] &&
       have_tools gsettings && effective=$(timeout 8 gsettings get "${section//\//.}" "$key" 2>/dev/null) &&
       expansion_screen_value_valid "$key" "$effective"; then
        if ! expansion_screen_value_compliant "$key" "$effective"; then
            rule_result FAIL "The current GNOME session reports $key=$effective."
        elif [[ ! $source ]] || expansion_screen_value_compliant "$key" "$source"; then
            rule_result NEEDS_REVIEW "The observed session meets the $key requirement. Verify the other relevant user sessions and overrides."
        else rule_result NEEDS_REVIEW "The session and configured $key disagree. Check the active profile and overrides."; fi
        return
    fi
    if ! expansion_screen_value_compliant "$key" "$source"; then CHECK_PLAN_CANDIDATE=1; fi
    rule_result NEEDS_REVIEW "The system source has $key=${source:-absent}. Verify the effective value in a fresh GNOME session."
}

expansion_desktop_plan() {
    local id=$1 profile=$2 section=$3 key=$4 required=$5 owner previous expected draft preview
    [[ $(expanded_gui_state) == gnome ]] && desktop_source_snapshot "$profile" || return 1
    if [[ $profile == gdm ]]; then
        [[ $DESKTOP_DATABASE == local ]] || return 1
        expected=$(awk '/^banner-message-text=/ {sub(/^banner-message-text=/,"" ); print; exit}' <<< "${OFFICIAL_FIX[V-230226]}")
        if ! desktop_key_owner "$section" banner-message-text || [[ ! $expected || $DESKTOP_VALUE != "$expected" ]]; then
            edit_fail 'Stage the authorized notice text using V-230226 before enabling it.'; return
        fi
    fi
    desktop_key_owner "$section" "$key" || return 1
    owner=$DESKTOP_OWNER previous=$DESKTOP_VALUE
    expansion_screen_value_valid "$key" "$previous" && ! expansion_screen_value_compliant "$key" "$previous" || return 1
    desktop_source_target "$id" "$owner" || return 1
    draft=$EDIT_TEMP/new-desktop-key
    desktop_render_key "$DESKTOP_INPUT" "$section" "$key" "$required" "$id" > "$draft" || return 1
    preview="- $key=${previous:-absent}"$'\n'"+ $key=$required"
    if [[ $id == V-230347 && ${EFFECTIVE[V-244535]+selected} ]] &&
       desktop_key_owner "$section" lock-delay && [[ $DESKTOP_OWNER == "$owner" ]] &&
       expansion_screen_value_valid lock-delay "$DESKTOP_VALUE" && ! expansion_screen_value_compliant lock-delay "$DESKTOP_VALUE"; then
        desktop_render_key "$draft" "$section" lock-delay 'uint32 5' V-244535 > "$draft.pair" || return 1
        draft=$draft.pair
        preview+=$'\n'"- lock-delay=${DESKTOP_VALUE:-absent}"$'\n+ lock-delay=uint32 5'
        EDIT_RELATED=V-244535 EDIT_GROUPED=V-244535
    fi
    desktop_stage_activation 'Review pending dconf edits and publish with an approved dconf update. Verify the new setting in a fresh session or greeter as applicable.'
    edit_content "$DESKTOP_TARGET" "$DESKTOP_MODE" "$preview" desktop_validate_source < "$draft"
}

rule_V_230347_check() { expansion_desktop_check user org/gnome/desktop/screensaver lock-enabled; }
rule_V_244535_check() { expansion_desktop_check user org/gnome/desktop/screensaver lock-delay; }
rule_V_244519_check() { expansion_desktop_check gdm org/gnome/login-screen banner-message-enable; }
rule_V_230347_plan() { expansion_desktop_plan V-230347 user org/gnome/desktop/screensaver lock-enabled true; }
rule_V_244535_plan() { expansion_desktop_plan V-244535 user org/gnome/desktop/screensaver lock-delay 'uint32 5'; }
rule_V_244519_plan() { expansion_desktop_plan V-244519 gdm org/gnome/login-screen banner-message-enable true; }
rule_V_230347_admin() { printf '%s\n' 'Set lock-enabled=true in the active GNOME profile. Verify locking and reauthentication in a fresh graphical session.'; }
rule_V_244535_admin() { printf '%s\n' 'Set the GNOME lock-delay to uint32 5 or a shorter delay. Verify the screen locks within five seconds of screensaver activation.'; }
rule_V_244519_admin() { printf '%s\n' 'Use the verified GDM profile to display the authorized consent banner. Verify the visible notice at a fresh greeter.'; }

# Read literal Manager settings across the standard drop-in precedence paths.
expansion_burst_setting() {
    awk '
        /^[[:space:]]*(#|;|$)/ {next}
        /^[[:space:]]*\[/ {section=$0; gsub(/[[:space:]]/, "", section); next}
        section == "[Manager]" && /^[[:space:]]*CtrlAltDelBurstAction([[:space:]]|=|$)/ {
            n++
            if (!sub(/^[[:space:]]*CtrlAltDelBurstAction[[:space:]]*=[[:space:]]*/, "")) bad=1
            value=$0; sub(/[[:space:]]*$/, "", value)
            if (value !~ /^[a-z][a-z-]*$/) bad=1
        }
        END {if (bad || n>1) exit 1; if (n) print value}
    ' "$1"
}

expansion_burst_sources() {
    local directory path name setting sha base context=''
    local -A files=()
    local -a ordered=()
    EXP_BURST_VALUE='' EXP_BURST_OWNER='' EXP_BURST_CONTEXT=''
    for base in /etc/systemd/system.conf /run/systemd/system.conf /usr/local/lib/systemd/system.conf /usr/lib/systemd/system.conf; do
        if [[ -e $base || -L $base ]]; then ordered+=("$base"); break; fi
    done
    for directory in /usr/lib/systemd/system.conf.d /usr/local/lib/systemd/system.conf.d /run/systemd/system.conf.d /etc/systemd/system.conf.d; do
        [[ -e $directory || -L $directory ]] || continue
        [[ -d $directory && ! -L $directory ]] || return 1
        for path in "$directory"/*.conf; do
            [[ -e $path || -L $path ]] || continue
            name=${path##*/}
            [[ $name =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*\.conf$ ]] || return 1
            files[$name]=$path
            (( ${#files[@]} <= 128 )) || return 1
        done
    done
    if (( ${#files[@]} )); then
        while IFS= read -r name; do ordered+=("${files[$name]}"); done < <(printf '%s\n' "${!files[@]}" | LC_ALL=C sort)
    fi
    for path in "${ordered[@]}"; do
        if [[ -L $path && $(readlink -- "$path") == /dev/null ]]; then
            context+=$'\n'"$path mask"
            continue
        fi
        text_input_file "$path" && edit_target_metadata "$path" && (( !(8#$EDIT_ORIGINAL_MODE & 022) )) || return 1
        sha=$(sha256_file "$path") && setting=$(expansion_burst_setting "$path") || return 1
        [[ $(sha256_file "$path") == "$sha" ]] || return 1
        context+=$'\n'"$path $sha"
        if [[ $setting ]]; then EXP_BURST_VALUE=$setting EXP_BURST_OWNER=$path; fi
    done
    EXP_BURST_CONTEXT=$context
}

rule_V_230531_check() {
    if ! expansion_burst_sources; then
        rule_result NEEDS_REVIEW 'The systemd Manager configuration is unreadable or ambiguous.'
    elif [[ $EXP_BURST_VALUE == none ]]; then
        rule_result PASS 'The effective persistent Manager configuration sets CtrlAltDelBurstAction=none.'
    else
        rule_result FAIL "The effective persistent CtrlAltDelBurstAction is ${EXP_BURST_VALUE:-unset}."
    fi
}

expansion_burst_validate() { [[ $(expansion_burst_setting "$1") == none ]]; }

rule_V_230531_plan() {
    local path mode=keep draft=$EDIT_TEMP/burst.conf input
    expansion_burst_sources && [[ $EXP_BURST_VALUE != none ]] || return 1
    path=$EXP_BURST_OWNER
    if [[ -z $path ]]; then
        if [[ -d /etc/systemd/system.conf.d ]]; then path=/etc/systemd/system.conf.d/90-rhel8-stig-burst.conf
        else path=/etc/systemd/system.conf; fi
    elif [[ $path != /etc/systemd/system.conf && $path != /etc/systemd/system.conf.d/* ]]; then
        edit_fail 'A vendor or runtime file owns this Manager setting. Review a local override and its ordering.'; return
    fi
    input=$path
    if [[ ! -e $path && ! -L $path ]]; then input=/dev/null mode=0644; fi
    desktop_render_key "$input" Manager CtrlAltDelBurstAction none V-230531 > "$draft" || return 1
    EDIT_CONTEXT=$EXP_BURST_CONTEXT EDIT_DISPOSITION=pending
    EDIT_REQUIREMENTS='Confirm the host recovery procedures do not depend on the rapid console key sequence.'
    EDIT_ACTIVATION='Review the persistent Manager change before the systemd owner activates it or schedules a reboot. Verify the effective setting without triggering a production reboot.'
    edit_content "$path" "$mode" "- CtrlAltDelBurstAction=${EXP_BURST_VALUE:-unset}
+ CtrlAltDelBurstAction=none" expansion_burst_validate < "$draft"
}

rule_V_230531_admin() {
    printf '%s\n' 'Set CtrlAltDelBurstAction=none in the authoritative systemd Manager configuration, then arrange approved activation and verification.'
}

# Automatic Classic Status assessment cache.
# Verified assessment reuse for read-only Status. Plans and approvals stay live.

status_cache_begin() {
    local clock
    STATUS_OBSERVED='' CACHE_DIR='' CACHE_CONTEXT='' CACHE_NOW=''
    declare -gA CACHE_INITIAL=() CACHE_CURRENT=() CACHE_PROBES=() CACHE_KEYS=()
    [[ $MODE == status ]] || return 0
    clock=$(date -u '+%s %FT%TZ') || return 0
    read -r CACHE_NOW STATUS_OBSERVED <<< "$clock"
    if (( ! ASSESSMENT_CACHE_DEFAULT )) || [[ -n $RESUME_ID ]]; then return 0; fi
    [[ $CACHE_NOW =~ ^[0-9]{10}$ && $HOST_ID =~ ^[0-9a-f]{64}$ &&
       $SCRIPT_HASH =~ ^[0-9a-f]{64}$ && $BOOT_ID =~ ^[0-9a-f-]{36}$ ]] || return 0
    CACHE_CONTEXT=$(printf '%s\0' "$HOST_ID" "$SCRIPT_HASH" "$ARCHIVE_SHA256" "$BOOT_ID" "$EUID" \
        "$MODPROBE_MANAGED" "$GPGCHECK_ALTERNATE_REPOS" | sha256sum) || return 0
    CACHE_CONTEXT=${CACHE_CONTEXT%% *}
    local directory=$REPORT_BASE/.assessment-cache
    if secure_directory "$directory" 1 yes 2>/dev/null && local_filesystem "$directory"; then
        CACHE_DIR=$directory
    fi
}

status_cache_probe() {
    local probe=$1 collection=$2 value
    local -n fingerprints=$collection
    if [[ ! ${fingerprints[$probe]+observed} ]]; then
        value=$(cache_observe_source "$probe" 2>/dev/null) || value=unavailable
        if [[ ! $value =~ ^[0-9a-f]{64}$ ]]; then value=unavailable; fi
        fingerprints[$probe]=$value
    fi
    CACHE_PROBE_RESULT=${fingerprints[$probe]}
}

status_cache_capture() {
    local id=$1 probes probe key
    local -a parts=()
    [[ ${CACHE_DIR-} ]] || return 1
    probes=$(cache_probe_for "$id") || return 1
    [[ $probes =~ ^[A-Za-z0-9_-]+(\ [A-Za-z0-9_-]+)*$ ]] || return 1
    for probe in $probes; do
        status_cache_probe "$probe" CACHE_INITIAL
        [[ $CACHE_PROBE_RESULT != unavailable ]] || return 1
        parts+=("$probe" "$CACHE_PROBE_RESULT")
    done
    key=$(printf '%s\0' "$CACHE_CONTEXT" "$id" "${REVISION[$id]}" "${parts[@]}" | sha256sum) || return 1
    CACHE_KEYS[$id]=${key%% *}
    CACHE_PROBES[$id]=$probes
}

status_cache_lookup() {
    local id=$1 path attributes key observed_epoch observed_at outcome evidence extra
    (( ! FORCE_FRESH )) && [[ ${CACHE_KEYS[$id]+captured} ]] || return 1
    path=$CACHE_DIR/$id
    [[ -f $path && ! -L $path ]] || return 1
    attributes=$(stat -c '%u %a %h %s' -- "$path" 2>/dev/null) || return 1
    [[ $attributes =~ ^$EUID\ 600\ 1\ ([1-9][0-9]{0,3})$ ]] && (( BASH_REMATCH[1] <= 4096 )) || return 1
    {
        IFS=$'\t' read -r key observed_epoch observed_at outcome evidence || return 1
        if IFS= read -r extra || [[ $extra ]]; then return 1; fi
    } 2>/dev/null < "$path"
    [[ $key == "${CACHE_KEYS[$id]}" && $observed_epoch =~ ^[0-9]{10}$ &&
        $observed_at =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ &&
        $outcome =~ ^(PASS|NOT_APPLICABLE)$ && $evidence && $evidence != *[[:cntrl:]]* ]] || return 1
    (( observed_epoch <= CACHE_NOW && CACHE_NOW - observed_epoch <= 86400 )) || return 1
    BEFORE[$id]=$outcome AFTER[$id]=$outcome DETAIL[$id]=$evidence ACTIONS[$id]=UNCHANGED
    ASSESSMENT_SOURCE[$id]=reused ASSESSMENT_AT[$id]=$observed_at
    return 0
}

status_cache_write() {
    local id=$1 temp evidence=${DETAIL[$1]}
    [[ $evidence && $evidence != *[[:cntrl:]]* ]] && (( ${#evidence} <= 2048 )) || return 0
    temp=$(mktemp -- "$CACHE_DIR/.pending.XXXXXXXX" 2>/dev/null) || return 0
    if ! printf '%s\t%s\t%s\t%s\t%s\n' "${CACHE_KEYS[$id]}" "$CACHE_NOW" "$STATUS_OBSERVED" \
        "${AFTER[$id]}" "$evidence" > "$temp" || ! mv -fT -- "$temp" "$CACHE_DIR/$id" 2>/dev/null; then
        rm -f -- "$temp" 2>/dev/null || true
    fi
    return 0
}

status_cache_finish() {
    [[ $CACHE_DIR ]] || return 0
    local id probe consistent
    for id in "${SCOPE[@]}"; do
        [[ ${CACHE_KEYS[$id]+captured} ]] || continue
        consistent=1
        for probe in ${CACHE_PROBES[$id]}; do
            status_cache_probe "$probe" CACHE_CURRENT
            if [[ $CACHE_PROBE_RESULT != "${CACHE_INITIAL[$probe]}" ]]; then consistent=0; break; fi
        done
        if (( ! consistent )) && [[ ${ASSESSMENT_SOURCE[$id]-} == reused ]]; then
            event INFO "$id inputs changed during verification. Running a live check." || return 1
            CACHE_DIR='' assess_one "$id" || return 1
        fi
        if [[ ${ASSESSMENT_SOURCE[$id]-} == live ]]; then
            if (( consistent )) && [[ ${ACTIONS[$id]} == UNCHANGED && ${AFTER[$id]} =~ ^(PASS|NOT_APPLICABLE)$ ]]; then
                status_cache_write "$id"
            else
                rm -f -- "$CACHE_DIR/$id" 2>/dev/null || true
            fi
        fi
    done
}

status_check_counts() {
    local id
    STATUS_FRESH_COUNT=0 STATUS_REUSED_COUNT=0
    if [[ $MODE != status ]]; then return 0; fi
    for id in "${SCOPE[@]}"; do
        case ${ASSESSMENT_SOURCE[$id]-} in
            live) (( STATUS_FRESH_COUNT += 1 )) ;;
            reused) (( STATUS_REUSED_COUNT += 1 )) ;;
        esac
    done
    return 0
}

status_cache_forget() {
    (( ASSESSMENT_CACHE_DEFAULT )) || return 0
    local id directory=$REPORT_BASE/.assessment-cache
    [[ -d $directory ]] && secure_directory "$directory" 0 yes 2>/dev/null &&
        local_filesystem "$directory" || return 0
    local -a affected_ids=()
    IFS=' ' read -r -a affected_ids <<< "$1"
    for id in "${affected_ids[@]}"; do
        known_id "$id" || continue
        rm -f -- "$directory/$id" 2>/dev/null || true
    done
}

# Read-only dependency observations for the automatic status cache.
# An unproven dependency leaves the finding on the fresh assessment path.

cache_probe_for() {
    local id=$1
    case $id in
        V-230227) printf '%s\n' console-notice ;;
        V-230233|V-230324|V-230365|V-230366|V-230378|V-230383)
            printf '%s\n' account-defaults ;;
        V-230245|V-230246|V-230247) printf '%s\n' messages-file ;;
        V-230248|V-230250) printf '%s\n' messages-directory ;;
        V-230396|V-230397|V-230398) printf '%s\n' audit-log-file ;;
        V-230399|V-230400|V-230401) printf '%s\n' audit-log-directory ;;
        V-230472|V-230474) printf '%s\n' audit-tool-metadata ;;
        V-274877|V-288831) printf '%s\n' audit-rules ;;
        *)
            if network_sysctl_spec "$id" >/dev/null; then
                printf 'sysctl-policy sysctl-live-%s\n' "$id"
            elif expansion_audit_spec "$id" >/dev/null; then
                printf 'audit-rules audit-watch-%s\n' "$id"
            else
                return 1
            fi
            ;;
    esac
}

cache_hash_fields() {
    local digest
    digest=$(printf '%s\0' "$@" | sha256sum) || return 1
    digest=${digest%% *}
    [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$digest"
}

# Metadata is enough for ownership and mode checks. It does not unnecessarily
# read log contents or fingerprint the timestamps of routine log writes.
cache_probe_metadata() {
    local path=$1 kind=$2 canonical data
    [[ ! -L $path ]] || return 1
    case $kind in
        file) [[ -f $path ]] || return 1 ;;
        directory) [[ -d $path ]] || return 1 ;;
        *) return 1 ;;
    esac
    canonical=$(realpath -e -- "$path") || return 1
    [[ $canonical == "$path" ]] || return 1
    data=$(stat -c '%d:%i:%u:%g:%a:%F' -- "$path") || return 1
    [[ -n $data ]] || return 1
    cache_hash_fields "$path" "$kind" "$data"
}

# A text file is read only when its type, size and access are known. The
# pre/post identity includes nanosecond ctime to reject a change during the read.
cache_text_file_state() {
    local path=$1 max=$2 resolved before after size digest
    [[ -f $path && -r $path && ! -L $path ]] || return 1
    resolved=$(realpath -e -- "$path") || return 1
    [[ $resolved == "$path" ]] || return 1
    before=$(stat -c '%s %d:%i:%u:%g:%a:%h:%y:%z' -- "$path") || return 1
    size=${before%% *}
    [[ $size =~ ^(0|[1-9][0-9]{0,7})$ ]] && (( size <= max )) || return 1
    digest=$(sha256_file "$path") || return 1
    after=$(stat -c '%s %d:%i:%u:%g:%a:%h:%y:%z' -- "$path") || return 1
    [[ $before == "$after" && ! -L $path ]] || return 1
    cache_hash_fields "$path" "$before" "$digest"
}

cache_audit_rules_state() {
    local enabled loader inventory stored active generated
    have_tools auditctl systemctl awk realpath stat findmnt || return 1
    enabled=$(expansion_audit_kernel_status) || return 1
    [[ $enabled == 1 || $enabled == 2 ]] || return 1
    loader=$(expansion_audit_loader) || return 1
    inventory=$(audit_rule_source_inventory) || return 1
    stored=$(audit_rule_source_contents <<< "$inventory") || return 1
    generated=$(expansion_audit_generated_rules) || return 1
    active=$(active_audit_rules) || return 1
    (( ${#active} <= 1048576 )) || return 1
    cache_hash_fields "$enabled" "$loader" "$inventory" "$stored" "$generated" "$active"
}

cache_audit_watch_state() {
    local id=$1 spec kind path key
    spec=$(expansion_audit_spec "$id") || return 1
    read -r kind path key <<< "$spec"
    [[ -n $key ]] && expansion_audit_watched_object "$kind" "$path" || return 1
    if [[ $path == /etc/sudoers.d ]]; then
        cache_probe_metadata "$path" directory
    else
        cache_probe_metadata "$path" file
    fi
}

cache_sysctl_state() {
    local id=$1 spec key target value ipv6=active
    spec=$(network_sysctl_spec "$id") || return 1
    read -r key target <<< "$spec"
    [[ -n $target ]] || return 1
    if [[ $key == net.ipv6.* ]] && network_sysctl_ipv6_disabled; then
        ipv6=disabled value=unneeded
    else
        value=$(network_sysctl_live "$key") || return 1
    fi
    cache_hash_fields "$key" "$ipv6" "$value"
}

cache_probe_audit_log() {
    local kind=$1 path config metadata
    path=$(audit_log_object "$kind") || return 1
    config=$(cache_text_file_state /etc/audit/auditd.conf 1048576) || return 1
    metadata=$(cache_probe_metadata "$path" "$kind") || return 1
    cache_hash_fields "$config" "$metadata"
}

cache_probe_audit_tools() {
    local output path observed
    local -a values=()
    output=$(expansion_audit_tool_paths) || return 1
    while IFS= read -r path; do
        observed=$(cache_probe_metadata "$path" file) || return 1
        values+=("$observed")
    done <<< "$output"
    cache_hash_fields "${values[@]}"
}

cache_login_defaults_state() {
    local defaults interpreter runtime_identifier python_identity
    network_sysctl_protected_path /etc || return 1
    defaults=$(cache_text_file_state /etc/login.defs 131072) || return 1
    interpreter=$(realpath -e -- /usr/libexec/platform-python) && [[ -x $interpreter ]] || return 1
    runtime_identifier=$(cache_probe_metadata "$interpreter" file) || return 1
    python_identity=$(repo_platform_python -I -c 'import configparser, ctypes, hashlib, pathlib, re, stat, sys; print(sys.version)') || return 1
    [[ -n $python_identity ]] || return 1
    cache_hash_fields "$defaults" "$runtime_identifier" "$python_identity"
}

cache_observe_source() {
    local digest
    # Suppress native-probe diagnostics when a fresh check will report them.
    {
        case "$1" in
            console-notice) cache_text_file_state /etc/issue 131072 ;;
            account-defaults) cache_login_defaults_state ;;
            messages-file) cache_probe_metadata /var/log/messages file ;;
            messages-directory) cache_probe_metadata /var/log directory ;;
            audit-log-file) cache_probe_audit_log file ;;
            audit-log-directory) cache_probe_audit_log directory ;;
            audit-tool-metadata) cache_probe_audit_tools ;;
            audit-rules) cache_audit_rules_state ;;
            audit-watch-*) cache_audit_watch_state "${1#audit-watch-}" ;;
            sysctl-policy)
                digest=$(network_sysctl_scan cache-observation.invalid 0 '') || return 1
                digest=${digest##* }
                [[ $digest =~ ^[0-9a-f]{64}$ ]] || return 1
                printf '%s\n' "$digest" ;;
            sysctl-live-*) cache_sysctl_state "${1#sysctl-live-}" ;;
            *) return 1 ;;
        esac
    } 2>/dev/null
}

# Guided resolution reuses the same checks and guarded remediation plans.
resolution_supported() {
    case $1 in
        V-230251|V-230252|V-230264|V-230279|V-230287|V-230301|V-230484|V-23049[4-9]|\
        V-230530|V-244541|V-251710|V-257258|V-268322|V-272482|V-272483|V-274877|V-288831) return 0 ;;
        *) return 1 ;;
    esac
}

resolution_note_set() {
    local id=$1 note=$2 LC_ALL=C
    resolution_supported "$id" && (( ${#note} <= 512 )) &&
        [[ $note != *[[:cntrl:]]* ]] || return 1
    if [[ $note ]]; then RESOLUTION_NOTES[$id]=$note; else unset 'RESOLUTION_NOTES[$id]'; fi
}

resolution_aide_inventory() {
    local package='' path
    if have_tools rpm timeout; then
        package=$(timeout --kill-after=2s 8s rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' aide 2>/dev/null) || package=''
    fi
    if [[ $package =~ ^aide-[A-Za-z0-9_.+-]+$ ]]; then printf 'Installed package: %s\n' "$package"
    else printf '%s\n' 'Installed AIDE package: unavailable or not detected'; fi
    for path in /etc/aide.conf /var/lib/aide/aide.db.gz; do
        if [[ -f $path && ! -L $path && $(realpath -e -- "$path" 2>/dev/null) == "$path" ]]; then
            stat -c '%n | owner %u | mode %a | size %s bytes | modified %y' -- "$path" 2>/dev/null ||
                printf '%s | metadata unavailable\n' "$path"
        else
            printf '%s | absent, linked, or unavailable\n' "$path"
        fi
    done
}

resolution_aide_path() {
    local path=$1 owner mode
    [[ -s $path && -f $path && ! -L $path && -r $path &&
       $(realpath -e -- "$path") == "$path" ]] && local_filesystem "$path" || return 1
    while [[ $path != / ]]; do
        read -r owner mode < <(stat -c '%u %a' -- "$path" 2>/dev/null) || return 1
        [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] && (( (8#$mode & 022) == 0 )) || return 1
        path=${path%/*}
        path=${path:-/}
    done
}

# Verify both packaged inputs and keep reporting inside a private temporary
# directory. The vendor default otherwise also writes /var/log/aide/aide.log.
resolution_aide_scan() (
    local config=/etc/aide.conf program=/usr/sbin/aide baseline=/var/lib/aide/aide.db.gz
    local package manifest digest config_digest scratch before code=0 counts checked
    if (( EUID != 0 )); then
        printf '%s\n' 'Run the tool as root to read the protected AIDE baseline and files covered by its checks.'
        return
    fi
    if ! have_tools rpm timeout nice env awk grep stat realpath findmnt sha256sum mktemp cp rm rmdir date ||
       ! package=$(timeout --kill-after=2s 8s rpm -q --qf '%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}\n' aide 2>/dev/null) ||
       [[ ! $package =~ ^aide\|0\.16-[a-zA-Z0-9_.+-]*\.el8[a-zA-Z0-9_.+-]*\|Red\ Hat,\ Inc\.$ ]]; then
        printf '%s\n' 'The check needs the Red Hat RHEL 8 AIDE 0.16 package and local verification tools.'
        return
    fi
    if ! resolution_aide_path "$program" || ! resolution_aide_path "$config" ||
       ! text_input_file "$config" || [[ ! -x $program ]] ||
       ! manifest=$(timeout --kill-after=2s 8s rpm -q --qf '[%{FILENAMES}|%{FILEDIGESTS}\n]' aide 2>/dev/null); then
        printf '%s\n' 'The packaged AIDE executable or configuration is unavailable or outside a protected local path.'
        return
    fi
    config_digest=$(awk -F'|' -v path="$config" '$1 == path {print $2}' <<< "$manifest") || return 1
    digest=$(awk -F'|' -v path="$program" '$1 == path {print $2}' <<< "$manifest") || return 1
    if [[ ! $digest =~ ^[0-9a-f]{64}$ || ! $config_digest =~ ^[0-9a-f]{64}$ ||
          $(sha256_file "$program") != "$digest" || $(sha256_file "$config") != "$config_digest" ]]; then
        printf '%s\n' 'AIDE or its configuration differs from the installed RPM. Use the approved integrity-tool report for this site configuration.'
        return
    fi
    if ! resolution_aide_path "$baseline" ||
       ! before=$(stat -c '%d:%i:%u:%a:%s:%y:%z' -- "$baseline" 2>/dev/null); then
        printf '%s\n' 'The default AIDE baseline is missing, unreadable, or outside a protected local path.'
        return
    fi
    umask 077
    scratch=$(mktemp -d -- /var/tmp/rhel8-stig-aide.XXXXXXXX) || return 1
    trap 'rm -f -- "$scratch/vendor.conf" "$scratch/check.conf" "$scratch/result"; rmdir -- "$scratch"' EXIT
    cp -- "$config" "$scratch/vendor.conf" &&
        [[ $(sha256_file "$scratch/vendor.conf") == "$config_digest" ]] || return 1
    if ! awk '
        /^[[:space:]]*report_url[[:space:]]*=/ {next}
        /^[[:space:]]*@@define[[:blank:]]+DBDIR[[:blank:]]+\/var\/lib\/aide[[:blank:]]*$/ {directory++; print; next}
        /^[[:space:]]*@@define[[:blank:]]+LOGDIR[[:blank:]]+\/var\/log\/aide[[:blank:]]*$/ {print; next}
        /^[[:space:]]*database[[:blank:]]*=[[:blank:]]*file:@@\{DBDIR\}\/aide\.db\.gz[[:blank:]]*$/ {database++; print; next}
        /^[[:space:]]*@@|^[[:space:]]*database(_in)?[[:blank:]]*=/ {invalid=1}
        {print}
        END {
            if (invalid || directory != 1 || database != 1) exit 1
            print "\nreport_url=stdout"
        }
    ' "$scratch/vendor.conf" > "$scratch/check.conf"; then
        printf '%s\n' 'The packaged AIDE configuration does not use the supported default local baseline. Use the approved integrity-tool report.'
        return
    fi
    checked=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || return 1
    (ulimit -c 0 && ulimit -f 4096 &&
        timeout --kill-after=5s 120s nice -n 10 env -i PATH=/usr/sbin:/usr/bin LC_ALL=C \
            "$program" "--config=$scratch/check.conf" --check) \
        > "$scratch/result" 2>&1 || code=$?
    if [[ $(stat -c '%d:%i:%u:%a:%s:%y:%z' -- "$baseline" 2>/dev/null) != "$before" ||
          $(sha256_file "$config") != "$config_digest" || $(sha256_file "$program") != "$digest" ]]; then
        printf '%s | %s\n' "$checked" 'The configuration, executable, or baseline changed during the check. Gather evidence again.'
    elif (( code == 0 )) && grep -Fq 'AIDE found NO differences between database and filesystem' "$scratch/result"; then
        printf '%s | %s\n' "$checked" 'AIDE reported no differences against the existing baseline. Confirm baseline provenance and coverage.'
    elif (( code >= 1 && code <= 7 )) &&
         counts=$(awk '
            /^Summary:$/ {summary=1; next}
            summary && /^-{10,}$/ {exit}
            summary && /^[[:blank:]]*Added entries:[[:blank:]]*[0-9]{1,12}[[:blank:]]*$/ {added=$NF}
            summary && /^[[:blank:]]*Removed entries:[[:blank:]]*[0-9]{1,12}[[:blank:]]*$/ {removed=$NF}
            summary && /^[[:blank:]]*Changed entries:[[:blank:]]*[0-9]{1,12}[[:blank:]]*$/ {changed=$NF}
            END {
                if (added == "" || removed == "" || changed == "" || added+removed+changed == 0) exit 1
                printf "Added %s | Removed %s | Changed %s", added, removed, changed
            }
        ' "$scratch/result"); then
        printf '%s | %s. Review the changes with the integrity administrator.\n' "$checked" "$counts"
    elif (( code == 124 || code == 137 )); then
        printf '%s | %s\n' "$checked" 'The two-minute AIDE check did not finish. Use the approved scheduled check result.'
    else
        printf '%s | AIDE could not verify the existing baseline (exit %s). Review the approved integrity-tool result.\n' "$checked" "$code"
    fi
)

resolution_aide_check() {
    if ! RESOLUTION_AIDE_RESULT=$(resolution_aide_scan); then
        RESOLUTION_AIDE_RESULT='The protected AIDE evidence check could not be prepared.'
    fi
}

resolution_text() {
    local id=$1
    resolution_supported "$id" || return 1
    printf 'Assessment %s | Action %s\n\n' "${AFTER[$id]-UNKNOWN}" "${ACTIONS[$id]-UNCHANGED}" || return 1
    printf 'Observed evidence\n%s\n\n' "${DETAIL[$id]:-No evidence recorded for the current scope.}" || return 1
    if [[ ${DISPLAY_PLAN[$id]-} ]]; then
        if [[ ${ACTIONS[$id]-} == BLOCKED ]]; then printf 'Blocking prerequisite\n' || return 1
        else printf 'Prepared change or next action\n' || return 1; fi
        printf '%s\n\n' "${DISPLAY_PLAN[$id]}" || return 1
    fi
    if [[ $id == V-251710 ]]; then
        printf 'Default AIDE paths (local observations)\n' && resolution_aide_inventory || return 1
        if [[ ${RESOLUTION_AIDE_RESULT-} ]]; then printf '\nRead-only check result\n%s\n' "$RESOLUTION_AIDE_RESULT" || return 1; fi
        printf '\n' || return 1
    fi
    rule_resolution_guidance "$id" || return 1
    if [[ ${RESOLUTION_NOTES[$id]-} ]]; then
        printf '\nOperator-provided evidence reference\n%s\n' "${RESOLUTION_NOTES[$id]}"
    fi
    return 0
}

# Per-finding resolution guidance for the 22-item reviewed scope.
rule_resolution_guidance() {
    local id=${1-} method prerequisites decision verification subject
    case $id in
        V-230251|V-230252|V-272482|V-272483)
            case $id in
                V-230251) subject='SSH server MACs' ;;
                V-230252) subject='SSH server ciphers' ;;
                V-272482) subject='SSH client MACs' ;;
                V-272483) subject='SSH client ciphers' ;;
            esac
            method="Stage the required $subject with the shared client/server crypto-policy operation."
            prerequisites='Select any of the four SSH findings in a catalog apply or preview. The tool includes the related SSH findings and discloses the V-288829 OpenSSL impact for stock DEFAULT. It honors explicit skips and keeps checklist and resumed scope fixed. Configured and active policy must agree on stock DEFAULT or FIPS with verified OpenSSH backends.'
            decision='Confirm ownership of the crypto policy, compatibility for affected clients and services, and console recovery. A transition from DEFAULT affects non-SSH consumers as well.'
            verification='After approved policy regeneration and service activation, verify the effective client and server allowlists and test new SSH connections.'
            ;;
        V-230264)
            method='Enable gpgcheck=1 in the eligible enabled static DNF repository definitions shown in the plan.'
            prerequisites='DNF must resolve each repository to a unique local source and the planner must verify the existing signing-key fingerprints. Use the authoritative source for generated, managed, or unresolved repositories.'
            decision='Confirm the displayed keys are approved for their repositories and identify any approved alternate verification process. Obtain unverified keys from the authorized source.'
            verification='Recheck effective DNF signature settings and confirm package availability through the approved repositories.'
            ;;
        V-230279)
            method='Stage init_on_free=1 for a supported GRUB and Boot Loader Specification configuration.'
            prerequisites='The planner needs a recognizable GRUB configuration, static defaults, native boot tooling, and an unambiguous installed-kernel inventory. Resolve conflicting arguments or boot management at its authoritative source.'
            decision='Confirm boot policy ownership, workload impact, recovery console availability, and the maintenance window.'
            verification='Complete the boot-entry activation shown in the plan. Check the installed boot arguments and verify init_on_free=1 is in the running kernel command line after reboot.'
            ;;
        V-230287)
            method='Tighten standard SSH private host-key permissions to 0600 or stricter.'
            prerequisites='The planner requires an identifiable packaged sshd service, supported configured key paths, and trusted regular host key files. Custom paths, service arguments, linked keys, or insufficient owner access require review.'
            decision='Confirm nobody depends on group access to the affected keys and retain independent privileged console access.'
            verification='Validate sshd configuration, check the resulting file modes, and verify a separate fresh SSH login after the approved activation.'
            ;;
        V-230301)
            method='Stage nodev in supported /etc/fstab entries for mounted non-root local device partitions.'
            prerequisites='The planner needs an authoritative regular fstab, matching active mount topology, and corresponding fstab-generated systemd units.'
            decision='Confirm the mount namespace, mount ownership, application impact, and recovery access before activation.'
            verification='Use the approved targeted remount or reboot. Verify the active nodev flag and affected applications afterward.'
            ;;
        V-230484)
            method='Stage a reduction of an excessive explicit maxpoll to 16, or add an approved source for a supported chrony configuration with no configured sources.'
            prerequisites='The planner needs the supported vendor chronyd service, a trusted regular configuration, and settings that the native parser can verify. An empty source layout needs CHRONY_APPROVED_SERVER. Existing alternative source layouts require review.'
            decision='Identify the site-approved authoritative source. Confirm whether the source can be used with the proposed settings or requires authentication or another site configuration.'
            verification='After approved activation, check the authoritative source, actual synchronization, and poll behavior with chronyc tracking and chronyc sources.'
            ;;
        V-230494|V-230495|V-230496|V-230497|V-230498|V-230499)
            case $id in
                V-230494) subject='ATM networking (atm)' ;;
                V-230495) subject='physical or virtual CAN networking (can)' ;;
                V-230496) subject='SCTP transport (sctp)' ;;
                V-230497) subject='TIPC cluster networking (tipc)' ;;
                V-230498) subject='cramfs images or recovery media (cramfs)' ;;
                V-230499) subject='FireWire hardware or storage (firewire-core)' ;;
            esac
            method="Stage an install denial and blacklist for $subject."
            prerequisites='The module must resolve to an unused loadable object for the running kernel. The local modprobe policy directory and tools must pass checks. An existing target, competing directives, loaded or built-in module, or site-owned policy can block staging.'
            decision="Confirm dependencies for $subject and determine whether approved operational need applies. Review the next-boot initramfs and kdump before authorizing the reboot."
            verification='After the approved reboot, verify the module is absent and the effective modprobe policy denies loading.'
            ;;
        V-230530)
            method='Stage an empty GNOME Ctrl+Alt+Delete logout binding.'
            prerequisites='A supported x86 GNOME installation, string-valued logout schema, and a trusted unambiguous dconf profile and source are required.'
            decision='Confirm this is the authoritative desktop profile and review all pending dconf publications.'
            verification='Publish the approved dconf changes and verify the effective logout binding and user overrides from a fresh GNOME session.'
            ;;
        V-244541|V-268322)
            if [[ $id == V-244541 ]]; then subject=password-auth; else subject=system-auth; fi
            method="Remove the nullok option from supported pam_unix lines in the active custom $subject template. The tool validates eligible literal options and the stock authselect conditional."
            prerequisites="The active authselect profile needs an editable copied $subject template, ordinary supported PAM syntax, and generated files in sync with the source. Use the authoritative template for managed or alternate layouts."
            decision='Confirm local profile ownership and independent administrative access. Review the proposed generation and other pending authselect changes before activation.'
            verification="After approved authselect regeneration, verify authselect check, the effective $subject stack and a fresh relevant login."
            ;;
        V-251710)
            method='Show the default AIDE package and baseline metadata. Run the optional read-only AIDE check to collect a time-stamped result against the existing database.'
            prerequisites='The in-tool check needs root access and the verified Red Hat AIDE executable, stock configuration, and protected local default baseline. For customized AIDE or an alternative, use the approved integrity-tool result.'
            decision='Confirm the baseline provenance and security-function coverage. Record a reference to that approval and any externally gathered evidence.'
            verification='Review the check against the trusted database, investigate detected changes, and record evidence for the applicable security functions.'
            ;;
        V-257258)
            method='Stage StopIdleSessionSec=600 for a supported systemd-logind configuration.'
            prerequisites='The planner must resolve applicability including the cloud SSH alternative, verify a compatible systemd package containing the logind correction, and identify a supported vendor service and configuration without conflicting overrides.'
            decision='Confirm any applicable cloud SSH exception, the maintenance window and the impact of idle-session termination on users and automation.'
            verification='After approved logind activation, use a fresh applicable session to verify it terminates after 600 seconds idle.'
            ;;
        V-274877|V-288831)
            if [[ $id == V-274877 ]]; then
                method='Stage missing DISA audit watches for /etc/cron.d and /var/spool/cron.'
                subject='The standard cron directories must be ordinary directories. '
                decision='Confirm who owns the audit sources, and review whether the broader privileged cron execution requirement needs additional evidence. Review all queued rule changes before activation.'
            else
                method='Stage the DISA execution rule for /usr/sbin/useradd.'
                subject='The standard useradd target must be an ordinary executable. '
                decision='Confirm who owns the audit sources and whether the planned account filters cover the operators in scope. Review all queued rule changes before activation.'
            fi
            prerequisites="${subject}The planner requires the vendor audit tools, enabled kernel auditing, an identifiable augenrules loader and trusted audit source files. Conflicting, overlapping or suppressing rules require authoritative review."
            verification='Verify approved rules in the loaded audit policy and the expected events. Immutable audit policy needs a maintenance reboot to load new rules.'
            ;;
        *) return 1 ;;
    esac
    printf '%s\n' \
        'Automation' "$method" '' \
        'Prerequisites' "$prerequisites" '' \
        'Administrator decision' "$decision" '' \
        'Verification' "$verification"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
    exit $?
fi
