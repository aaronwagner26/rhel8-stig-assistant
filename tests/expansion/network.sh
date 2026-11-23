#!/bin/bash
# Review-only fixtures. All config sources and the planned copy are private
# temporary files. Mock observations and activation commands.
set -euo pipefail
[[ -f /.dockerenv && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]]
[[ $# -eq 1 ]]
source "$1"

fixture=$(mktemp -d -- /var/tmp/stig-network.XXXXXXXX)
mkdir "$fixture/sysctl.d" "$fixture/vendor"
CHECK_PENDING=0
declare -A LIVE=() EFFECTIVE=() DEFAULT_SSH=()

network_sysctl_locations() { printf '%s\n' "$fixture/sysctl.d" "$fixture/vendor"; }
network_sysctl_main() { printf '%s/sysctl.conf\n' "$fixture"; }
network_sysctl_path() { printf '%s/sysctl.d/90-rhel8-stig-%s.conf\n' "$fixture" "$1"; }
network_sysctl_protected_path() { [[ $(realpath -e -- "$1") == "$fixture/"* ]]; }
network_sysctl_live() { printf '%s\n' "${LIVE[$1]-0}"; }
network_sysctl_ipv6_disabled() { [[ -f $fixture/ipv6-off ]]; }
network_ssh_path() { printf '%s/sshd_config\n' "$fixture"; }
network_ssh_authority() { printf 'fixture authority\n'; }
expanded_ssh_loaded_state() { printf 'started\n'; }
edit_safe_path() { [[ $1 == "$fixture/"* && ! -L $1 ]]; }
timeout() { [[ $* == "12 sshd -t -f $fixture/"* ]]; }

expanded_ssh_effective() {
    local result
    result=$(expanded_ssh_values "$1" "$2") || return 1
    if [[ -z $result ]]; then result=${DEFAULT_SSH[$2]}; fi
    printf '%s\n' "$result"
}

edit_content() {
    CAPTURED_PATH=$1 CAPTURED_MODE=$2 CAPTURED_DIFF=$3 CAPTURED_VALIDATOR=$4
    CAPTURED_COPY=$fixture/candidate
    cat > "$CAPTURED_COPY"
    "$4" "$CAPTURED_COPY" "$1"
}

assert_result() {
    local want=$1 handler=$2
    CHECK_PENDING=0
    "$handler"
    if [[ $ASSESSMENT != "$want" ]]; then
        printf '%s expected %s, received %s (%s)\n' "$handler" "$want" "$ASSESSMENT" "$EVIDENCE" >&2
        exit 1
    fi
}

deny() {
    if "$@"; then printf 'Unexpected success: %s\n' "$*" >&2; exit 1; fi
}

assert_result FAIL rule_V_230269_check
rule_V_230269_plan
[[ $CAPTURED_PATH == "$fixture/sysctl.d/90-rhel8-stig-V-230269.conf" && $CAPTURED_MODE == 0644 ]]
[[ ! -e $CAPTURED_PATH && $EDIT_DISPOSITION == pending && $EDIT_ACTIVATION == *'sysctl -w kernel.dmesg_restrict=1'* ]]
grep -Fx 'kernel.dmesg_restrict = 1' "$CAPTURED_COPY"
printf '%s\n' 'kernel.dmesg_restrict = 0' > "$fixture/vendor/50-vendor.conf"
deny "$CAPTURED_VALIDATOR" "$CAPTURED_COPY" "$CAPTURED_PATH"
assert_result NEEDS_REVIEW rule_V_230269_check
deny rule_V_230269_plan
printf '%s\n' 'net/ipv4/conf/*/send_redirects = 0' > "$fixture/vendor/50-vendor.conf"
assert_result NEEDS_REVIEW rule_V_230536_check
ln -s /dev/null "$fixture/sysctl.d/50-vendor.conf"
assert_result FAIL rule_V_230536_check
LIVE[net.ipv4.ip_forward]=1
deny rule_V_230536_plan
LIVE[net.ipv4.ip_forward]=0
rule_V_230536_plan
cp -- "$CAPTURED_COPY" "$CAPTURED_PATH"
"$CAPTURED_VALIDATOR" "$CAPTURED_PATH" "$CAPTURED_PATH"
LIVE[net.ipv4.conf.all.send_redirects]=1
assert_result NEEDS_REVIEW rule_V_230536_check
[[ $CHECK_PENDING == 1 ]]
LIVE[net.ipv4.conf.all.send_redirects]=0
assert_result PASS rule_V_230536_check

LIVE[kernel.perf_event_paranoid]=3 LIVE[kernel.kptr_restrict]=2
assert_result NEEDS_REVIEW rule_V_230270_check
assert_result NEEDS_REVIEW rule_V_230547_check
deny rule_V_230270_plan
deny rule_V_230547_plan
: > "$fixture/ipv6-off"
assert_result NOT_APPLICABLE rule_V_230535_check
deny rule_V_230535_plan

DEFAULT_SSH[ClientAliveCountMax]=3 DEFAULT_SSH[ClientAliveInterval]=0
DEFAULT_SSH[StrictModes]=yes DEFAULT_SSH[IgnoreUserKnownHosts]=no
DEFAULT_SSH[PermitUserEnvironment]=no DEFAULT_SSH[PrintLastLog]=yes DEFAULT_SSH[X11UseLocalhost]=yes
printf '%s\n' '# fixture' 'PermitUserEnvironment yes' > "$fixture/sshd_config"
EDIT_TEMP=$fixture EDIT_RELATED='' EDIT_GROUPED=''
assert_result FAIL rule_V_230288_check
EFFECTIVE[V-230244]=1
deny rule_V_230244_plan
EFFECTIVE[V-244525]=1 EFFECTIVE[V-230288]=1
rule_V_230244_plan
[[ $EDIT_GROUPED == 'V-230288 V-244525' && $EDIT_RELATED == "$EDIT_GROUPED" && $EDIT_DISPOSITION == pending ]]
grep -Fx 'ClientAliveCountMax 1' "$CAPTURED_COPY"
grep -Fx 'ClientAliveInterval 600' "$CAPTURED_COPY"
grep -Fx 'StrictModes yes' "$CAPTURED_COPY"
grep -Fx 'PermitUserEnvironment yes' "$CAPTURED_COPY"
[[ $(< "$fixture/sshd_config") == $'# fixture\nPermitUserEnvironment yes' ]]
printf '%s\n' 'ClientAliveInterval 300' >> "$fixture/sshd_config"
assert_result PASS rule_V_244525_check
EDIT_RELATED='' EDIT_GROUPED=''
unset 'EFFECTIVE[V-244525]'
rule_V_230244_plan
grep -Fx 'ClientAliveInterval 300' "$CAPTURED_COPY"
printf '%s\n' 'Match User example' >> "$fixture/sshd_config"
assert_result NEEDS_REVIEW rule_V_230244_check
deny rule_V_230244_plan
printf '%s\n' 'PASS sysctl role, precedence, masked source, stale source, IPv6 and stricter settings; SSH selected grouping, timing dependency, scope and untouched values.'
