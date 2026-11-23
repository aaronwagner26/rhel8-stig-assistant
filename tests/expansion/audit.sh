#!/bin/bash
# Run only in the disposable fixture container. No daemon or kernel actions.
# Pass the assembled CLI, or a classic backend followed by an audit fragment.
set -u
set -o pipefail
[[ -f /.dockerenv && $(findmnt -n -o FSTYPE -T /etc/audit) == tmpfs ]] || exit 1
(( $# == 1 || $# == 2 )) || exit 64
source "$1" || exit 1
if (( $# == 2 )); then source "$2" || exit 1; fi

fixture=$(mktemp -d /var/tmp/stig-audit-test.XXXXXXXX) || exit 1
function fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
function equal() { [[ $1 == "$2" ]] || fail "expected $2 but saw $1"; }
function rule_result() { ASSESSMENT=$1 EVIDENCE=$2; }
function edit_fail() { PLAN_REASON=$1; return 1; }
function have_tools() { return 0; }

exec_payload=$(expansion_audit_payload V-230462)
watch_payload=$(expansion_audit_payload V-230410)
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload")" present
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< \
    '-a exit,always -S all -F auid!=-1 -F auid>=1000 -F perm=x -F key=priv_cmd -F path=/usr/bin/sudo')" present
equal "$(expansion_audit_rule_state watch /etc/sudoers.d identity <<< "$watch_payload")" present
equal "$(expansion_audit_rule_state watch /etc/sudoers.d identity <<< '-w /etc/sudoers.d -p aw -F key=identity')" present
equal "$(expansion_audit_rule_state watch /etc/shadow identity <<< '# -w /etc/shadow -p wa -k identity')" missing
equal "$(expansion_audit_rule_state watch /etc/shadow identity <<< '-w /etc -p wa -k parent')" review
equal "$(expansion_audit_rule_state watch /etc/sudoers.d identity <<< '-w /etc/sudoers.d/local -p wa -k nested')" review
equal "$(expansion_audit_rule_state watch /etc/shadow identity <<< '-w /etc/passwd -p wa -k identity')" missing
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload"$'\n'"$exec_payload")" review
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload"$'\n''-A never,exit -F uid=0')" review
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload"$'\n''-a always,exclude -F msgtype=SYSCALL')" review
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload"$'\n-D')" review
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< "$exec_payload -F uid=0")" review
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< $'-D\n'"$exec_payload")" present
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< '-a always,exit -F path=/usr/bin/sudoedit -F perm=x -k priv_cmd')" missing
equal "$(expansion_audit_rule_state exec /usr/bin/sudo priv_cmd <<< '-a always,exit -F path=/bin/sudo -F perm=x -k priv_cmd')" review
printf '%s\n' "$exec_payload" > "$fixture/rule"
expansion_audit_validate_dropin "$fixture/rule" /etc/audit/rules.d/90-rhel8-stig-v230462.rules || fail 'known rule rejected'
if expansion_audit_validate_dropin "$fixture/rule" /etc/audit/rules.d/90-rhel8-stig-v230418.rules; then
    fail 'payload for different ID was accepted'
fi

source_rules='' generated_rules='' runtime_rules='' object_present=yes fixture_enabled=1 loader_ok=yes
function expansion_audit_watched_object() { [[ $object_present == yes ]]; }
function expansion_audit_kernel_status() { printf '%s\n' "$fixture_enabled"; }
function expansion_audit_loader() { [[ $loader_ok == yes ]] && printf 'stock audit loader\n'; }
function audit_rule_source_inventory() { printf 'fixture-source\n'; }
function audit_rule_source_contents() { printf '%s\n' "$source_rules"; }
function expansion_audit_generated_rules() { printf '%s\n' "$generated_rules"; }
function active_audit_rules() { printf '%s\n' "$runtime_rules"; }
function stat() {
    if [[ $* == '-c %d:%i:%u:%g:%a -- /usr/bin/sudo' ]]; then
        printf '1:2:0:0:4755\n'
    else
        command stat "$@"
    fi
}
function check_sudo() { CHECK_PENDING=0; rule_V_230462_check || fail 'sudo check errored'; }
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" FAIL/0
source_rules=$exec_payload
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" NEEDS_REVIEW/1
generated_rules=$exec_payload
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" NEEDS_REVIEW/1
runtime_rules=$exec_payload
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" PASS/0
source_rules=''
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" FAIL/0
object_present=no
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" NEEDS_REVIEW/0
object_present=yes
fixture_enabled=0
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" FAIL/0
fixture_enabled=1 loader_ok=no
check_sudo; equal "$ASSESSMENT/$CHECK_PENDING" NEEDS_REVIEW/0
loader_ok=yes

planned_path='' planned_mode='' planned_diff='' EDIT_GROUPED='' EDIT_RELATED=''
EDIT_TEMP=$fixture
declare -A EFFECTIVE=()
function edit_content() {
    planned_path=$1 planned_mode=$2 planned_diff=$3
    cat > "$fixture/planned"
    "$4" "$fixture/planned" "$1"
}
rule_V_230462_plan || fail 'eligible sudo audit plan failed'
equal "$planned_path/$planned_mode/$EDIT_DISPOSITION" /etc/audit/rules.d/90-rhel8-stig-v230462.rules/0600/pending
equal "$(< "$fixture/planned")" "$exec_payload"
before_context=$EDIT_CONTEXT
fixture_enabled=2
rule_V_230462_plan || fail 'immutable policy could not stage a pending change'
[[ $EDIT_ACTIVATION == *reboot* && $EDIT_CONTEXT != "$before_context" ]] || fail 'immutable audit did not require separate reboot activation'
source_rules='# Ansible managed'
if rule_V_230462_plan; then fail 'managed audit source was eligible'; fi
source_rules=$exec_payload
if rule_V_230462_plan; then fail 'duplicate existing source was eligible'; fi
source_rules=''
runtime_rules="$exec_payload"$'\n''-a never,task'
if rule_V_230462_plan; then fail 'runtime suppressions were ignored'; fi
fixture_enabled=1 runtime_rules=''

# Audit configuration plans use the isolated /etc/audit fixture mount.
function attended_policy_source() { [[ $1 == /etc/audit/auditd.conf && -f $1 ]]; }
function text_input_file() { [[ -f $1 ]]; }
function audit_log_object() { printf '/fixture/audit.log\n'; }
function audit_writer_context() { printf 'fixture-writer\n'; }
function expansion_audit_daemon_started() { printf '%s\n' "$fixture_started"; }
printf '%s\n' 'log_file = /fixture/audit.log' 'local_events = no' 'log_format = RAW' > /etc/audit/auditd.conf
initial=$(< /etc/audit/auditd.conf)
rule_V_230393_check; equal "$ASSESSMENT" FAIL
rule_V_230393_plan || fail 'single option plan failed'
equal "$planned_path/$planned_mode/$EDIT_DISPOSITION" /etc/audit/auditd.conf/keep/pending
equal "$(expansion_audit_config_observe local_events "$fixture/planned")" yes
equal "$(expansion_audit_config_observe log_format "$fixture/planned")" RAW
EFFECTIVE[V-230395]=1
rule_V_230393_plan || fail 'grouped option plan failed'
equal "$EDIT_GROUPED/$EDIT_RELATED" V-230395/V-230395
equal "$(expansion_audit_config_observe log_format "$fixture/planned")" ENRICHED
equal "$(< /etc/audit/auditd.conf)" "$initial"
cat "$fixture/planned" > /etc/audit/auditd.conf
modified=$(stat -c '%Y' -- /etc/audit/auditd.conf)
CHECK_PENDING=0 fixture_started=$modified
rule_V_230395_check; equal "$ASSESSMENT/$CHECK_PENDING" NEEDS_REVIEW/1
CHECK_PENDING=0 fixture_started=$((modified + 1))
rule_V_230395_check; equal "$ASSESSMENT/$CHECK_PENDING" PASS/0
printf '%s\n' 'log_format = RAW' >> /etc/audit/auditd.conf
rule_V_230395_check; equal "$ASSESSMENT" NEEDS_REVIEW
if rule_V_230395_plan; then fail 'duplicate option was eligible'; fi

# Metadata planning reads a synthetic executable and records proposed values.
EDIT_GROUPED='' EDIT_RELATED=''
unset 'EFFECTIVE[V-230395]'
tool=$fixture/auditctl
printf '%s\n' 'synthetic binary' > "$tool"
chmod 0777 -- "$tool"
chgrp 1 -- "$tool"
function expansion_audit_tool_paths() { printf '%s\n' "$tool"; }
verified=yes
function expansion_audit_tool_integrity() { [[ $verified == yes ]]; }
function edit_metadata() { planned_path=$1 planned_mode=$2 planned_group=$3; }
rule_V_230472_check; equal "$ASSESSMENT" FAIL
rule_V_230472_plan || fail 'audit tool permissions plan failed'
equal "$planned_path/$planned_mode/$planned_group" "$tool/0755/keep"
EFFECTIVE[V-230474]=1
rule_V_230472_plan || fail 'grouped audit tool plan failed'
equal "$planned_mode/$planned_group/$EDIT_GROUPED/$EDIT_RELATED" 0755/0/V-230474/V-230474
verified=no
if rule_V_230472_plan; then fail 'unverified executable was eligible'; fi
equal "$(stat -c '%a:%g' -- "$tool")" 777:1

printf 'PASS audit rule parser, staged and loaded status, guarded plans, configuration grouping, and trusted metadata fixtures\n'
