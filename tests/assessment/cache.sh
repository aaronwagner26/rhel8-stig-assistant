#!/bin/bash
# Run root in a network-disabled disposable container with private /var/tmp.
# This fixture writes only under its private directory and never approves a fix.
set -eo pipefail
[[ $# == 1 && -f /.dockerenv && $EUID == 0 &&
   $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]] || exit 64
source "$1"

umask 077
fixture=$(mktemp -d -- /var/tmp/stig-cache.XXXXXXXX)
reports=$fixture/reports
trace=$fixture/checks
messages=$fixture/messages
cache=$reports/.assessment-cache
identity=1111111111111111111111111111111111111111111111111111111111111111
checksum=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
boot=11111111-1111-1111-1111-111111111111
observation='1700000000 2023-11-14T22:13:20Z'
force_review=0
drift_during_scan=0
scope=V-230245,V-230247,V-230248,V-230269
live=V-230269
mkdir "$reports" "$fixture/log"
printf 'fixture log\n' > "$messages"
chmod 0640 "$messages"
chmod 0755 "$fixture/log"

preflight() {
    HOST_ID=$identity BOOT_ID=$boot SCRIPT_HASH=$checksum
    ARCH=x86_64 BOOT_MODE=BIOS KERNEL=fixture OPERATOR=fixture
}
collect_host_context() { :; }
date() {
    if [[ $# == 2 && $1 == -u && $2 == '+%s %FT%TZ' ]]; then
        printf '%s\n' "$observation"
    else
        command date "$@"
    fi
}
prepare_rule_plan() {
    PLAN_REASON='fixture configuration requires a separate authorized remedy'
    return 1
}
deny_approval() {
    printf 'unexpected approval request\n' > "$fixture/unexpected-approval"
    return 1
}
apply_choice() { deny_approval; }

# Keep the production log checkers and substitute the file and directory they
# observe. Each call records whether the actual assessment ran.
expansion_log_target() {
    printf '%s\n' "$1" >> "$trace"
    case $1 in
        V-230245) (( ! force_review )) && printf '%s\n' "$messages" ;;
        V-230247) printf '%s\n' "$messages" ;;
        V-230248) printf '%s\n' "$fixture/log" ;;
        *) return 1 ;;
    esac
}
rule_V_230269_check() {
    printf '%s\n' V-230269 >> "$trace"
    if (( drift_during_scan )); then chmod 0660 "$messages" || return; fi
    rule_result PASS 'Fixture runtime observation requires a fresh probe.'
}

cache_probe_for() {
    case $1 in
        V-230245|V-230247) printf '%s\n' fixture-file ;;
        V-230248) printf '%s\n' fixture-directory ;;
        *) return 1 ;;
    esac
}
cache_observe_source() {
    local path
    case $1 in
        fixture-file) path=$messages ;;
        fixture-directory) path=$fixture/log ;;
        *) return 1 ;;
    esac
    local fingerprint
    fingerprint=$(stat -c '%d:%i:%u:%g:%a' -- "$path" | sha256sum) || return 1
    printf '%s\n' "${fingerprint%% *}"
}

fail() {
    printf 'Cache fixture failed: %s\n' "$*" >&2
    if [[ -f ${std_err-} ]]; then cat "$std_err" >&2; fi
    exit 1
}

run_case() {
    local label=$1 expected_status=$2 actual_status
    shift 2
    output=$fixture/$label.json
    std_err=$fixture/$label.err
    : > "$trace"
    if ( main --output-dir "$reports" --format json "$@" ) > "$output" 2> "$std_err"; then
        actual_status=0
    else
        actual_status=$?
    fi
    [[ $actual_status == "$expected_status" ]] ||
        fail "$label returned $actual_status, expected $expected_status"
    [[ ! -e $fixture/unexpected-approval ]] || fail "$label requested approval"
}

expect_counts() {
    grep -Fq "\"fresh_checks\":$1,\"reused_results\":$2," "$output" ||
        fail "$(basename "$output") lacks fresh/reused counts $1/$2"
}

expect_trace() {
    local expected
    expected=$(printf '%s\n' "$@")
    [[ $(< "$trace") == "$expected" ]] ||
        fail "$(basename "$output") dispatched unexpected checks [$(< "$trace")]"
}

expect_row() {
    local finding=$1 source=$2 observed_at=$3
    grep -Eq "\"id\":\"$finding\"[^}]*\"assessment_source\":\"$source\",\"assessment_observed_at\":\"$observed_at\"" "$output" ||
        fail "$(basename "$output") lacks $finding $source evidence from $observed_at"
}

all=(V-230245 V-230247 V-230248 "$live")
run_case cold 0 --only "$scope"
expect_counts 4 0
expect_trace "${all[@]}"
expect_row V-230245 live 2023-11-14T22:13:20Z
cold_id=$(sed -n 's/^{"run_id":"\([^"]*\)".*/\1/p' "$output")
[[ $cold_id ]] || fail 'cold run id missing'
for id in "${all[@]:0:3}"; do
    [[ $(stat -c '%u:%a:%h' "$cache/$id") == 0:600:1 ]] || fail "$id cache permissions"
done
[[ $(stat -c '%u:%a' "$cache") == 0:700 ]] || fail 'cache directory permissions'
[[ ! -e $cache/$live ]] || fail 'dynamic result stored'

observation='1700000010 2023-11-14T22:13:30Z'
run_case warm 0 --status --only "$scope"
expect_counts 1 3
expect_trace "$live"
expect_row V-230245 reused 2023-11-14T22:13:20Z
expect_row "$live" live 2023-11-14T22:13:30Z

run_case narrowed 0 --only V-230245,V-230248
expect_counts 0 2
expect_trace
expect_row V-230245 reused 2023-11-14T22:13:20Z
if grep -Fq '"id":"V-230247"' "$output"; then fail 'cache broadened the selected scope'; fi

# Tightening or loosening metadata changes the full dependent group, while an
# independently observed directory remains eligible for reuse.
chmod 0660 "$messages"
run_case changed 2 --only "$scope"
expect_counts 3 1
expect_trace V-230245 V-230247 "$live"
grep -Fq '"assessment":"FAIL"' "$output" || fail 'permissive mode was accepted'

run_case still-failing 2 --only "$scope"
expect_counts 2 2
expect_trace V-230245 "$live"
chmod 0640 "$messages"

run_case fresh 0 --status --only "$scope" --fresh
expect_counts 4 0
expect_trace "${all[@]}"
expect_row V-230245 live 2023-11-14T22:13:30Z

# A newer live Review supersedes a Pass even when the fingerprint is the same.
force_review=1
run_case superseded 2 --status --only "$scope" --fresh
expect_counts 4 0
expect_trace "${all[@]}"
grep -Fq '"assessment":"NEEDS_REVIEW"' "$output" || fail 'forced live Review was not recorded'
force_review=0
run_case retry-review 0 --only "$scope"
expect_counts 2 2
expect_trace V-230245 "$live"

# An uncached check modifies the shared fixture after the first cache lookups
# and before the final dependency verification. Both reused rows must be live.
drift_during_scan=1
run_case drift 2 --only "$scope"
expect_counts 3 1
expect_trace "$live" V-230245 V-230247
expect_row V-230245 live 2023-11-14T22:13:30Z
grep -Fq '"assessment":"FAIL"' "$output" || fail 'drift concealed the new failure'
drift_during_scan=0
chmod 0640 "$messages"
run_case warm-after-drift 0 --only "$scope"
expect_counts 3 1
expect_trace V-230245 V-230247 "$live"

run_case skipped 2 --status --only "$scope" --skip V-230245
expect_counts 1 2
expect_trace "$live"
grep -Fq '"assessment_source":"skipped"' "$output" || fail 'skipped result was reused'

run_case resume 0 --status --resume "$cold_id"
expect_counts 4 0
expect_trace "${all[@]}"

run_case dry-run 0 --dry-run --only "$scope"
expect_trace "${all[@]}"

# These are the same invalidation inputs a reviewed grouped transaction uses.
(
    REPORT_BASE=$reports
    register_rules
    status_cache_forget 'V-230245 V-230247'
)
run_case after-transaction-invalidation 0 --only "$scope"
expect_counts 3 1
expect_trace V-230245 V-230247 "$live"

boot=22222222-2222-2222-2222-222222222222
run_case different-boot 0 --only "$scope"
expect_counts 4 0
expect_trace "${all[@]}"

checksum=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
run_case different-build 0 --only "$scope"
expect_counts 4 0
expect_trace "${all[@]}"

chmod 0644 "$cache/V-230245"
run_case public-record 0 --only "$scope"
expect_counts 2 2
expect_trace V-230245 "$live"
[[ $(stat -c '%a' "$cache/V-230245") == 600 ]] || fail 'public record was not safely replaced'

target=$fixture/copy
cp -- "$cache/V-230245" "$target"
saved=$(sha256sum "$target")
rm -- "$cache/V-230245"
ln -s -- "$target" "$cache/V-230245"
run_case linked-record 0 --only "$scope"
expect_counts 2 2
expect_trace V-230245 "$live"
[[ ! -L $cache/V-230245 && $(sha256sum "$target") == "$saved" ]] || fail 'linked target was modified'

printf 'unrecognized extra record\n' >> "$cache/V-230245"
run_case malformed-record 0 --only "$scope"
expect_counts 2 2
expect_trace V-230245 "$live"

mv -- "$cache" "$fixture/real-cache"
ln -s -- "$fixture/real-cache" "$cache"
run_case linked-directory 0 --only "$scope"
expect_counts 4 0
expect_trace "${all[@]}"

printf 'PASS Classic cache timestamps and scope, dependent drift, live failures, grouped invalidation, identity and unsafe cache records.\n'
