#!/bin/bash
# Run in a disposable, offline Docker container with private /var/tmp.
set -euo pipefail
[[ -f /.dockerenv && $# == 1 ]]
[[ $(findmnt -rn -o TARGET,FSTYPE --target /var/tmp) == '/var/tmp tmpfs' ]]
[[ $(findmnt -rn -o TARGET,FSTYPE --target /etc) == '/ overlay' ]]
source "$1"
export LC_ALL=C

path=/etc/chrony.conf
[[ ! -e $path && ! -L $path ]]
trap 'rm -f -- /etc/chrony.conf' EXIT
EDIT_TEMP=$(mktemp -d /var/tmp/chrony-case.XXXXXXXX)
CHRONY_APPROVED_SERVER=''
CHRONY_RUN_SERVER=''

for value in NTP1.example.org ntp.example.org. chrony01 10.20.30.40; do
    chrony_valid_approved_server "$value"
done
for value in '' 'ntp.example.org iburst' '-bad.example.org' 'example..org' 'localhost.' \
    'server/name' 'ntp.example.org#ignore' '1234' '10.01.0.2' '10.0.0.256' '127.0.0.2' \
    '0.1.0.2' '224.0.0.2' '::1'; do
    if chrony_valid_approved_server "$value"; then
        printf 'Invalid approved source accepted: %q\n' "$value" >&2
        exit 1
    fi
done

site_file=$EDIT_TEMP/site.conf
printf '%s\n' 'CHRONY_APPROVED_SERVER=ntp.example.org' > "$site_file"
chmod 0600 "$site_file"
read_site_config "$site_file"
[[ $(chrony_effective_approved_server) == ntp.example.org ]]
CHRONY_RUN_SERVER=ntp-other.example.org
[[ $(chrony_effective_approved_server) == ntp-other.example.org ]]
CHRONY_RUN_SERVER=''

# Substitute native service responses while exercising the real parser and rendering.
unit_state=inactive
unit_start='2030-01-01 00:00:00 UTC'
live_activity='0,0,0,0,0'
live_sources='^,*,ntp.example.org,2,16,377,40,0,0,0'
leap_status=Normal
chronyd() { [[ $1 == -p && $2 == -f && -f $3 ]]; }
systemctl() {
    [[ $1 == show ]] || return 1
    if [[ $* == *ExecMainStartTimestamp* ]]; then
        printf 'ActiveState=%s\nExecMainStartTimestamp=%s\n' "$unit_state" "$unit_start"
    else
        [[ $* == *'ActiveState --value' ]] || return 1
        printf '%s\n' "$unit_state"
    fi
}
chronyc() {
    case $* in
        '-c activity') printf '%s\n' "$live_activity" ;;
        '-c -N sources -a') printf '%s\n' "$live_sources" ;;
        '-n tracking') printf 'Leap status     : %s\n' "$leap_status" ;;
        *) return 1 ;;
    esac
}
timeout() { shift; "$@"; }
chrony_authority() { printf 'trusted-service\n'; }
local_filesystem() { [[ $1 == /etc || $1 == "$path" ]]; }
edit_content() {
    proposal=$3
    staged_validator=$4
    cat > "$EDIT_TEMP/proposal"
}

expect_result() {
    rule_V_230484_check
    if [[ $ASSESSMENT != "$1" ]]; then
        printf 'Expected %s, got %s (%s)\n' "$1" "$ASSESSMENT" "$EVIDENCE" >&2
        exit 1
    fi
}

expect_block() {
    PLAN_REASON=''
    rule_V_230484_plan || :
    if [[ $PLAN_REASON != *"$1"* ]]; then
        printf 'Expected plan blocker %s, got %s\n' "$1" "$PLAN_REASON" >&2
        exit 1
    fi
}

printf '# Configuration fixture\nmakestep 1.0 3\n# EOF without final newline' > "$path"
cp -- "$path" "$EDIT_TEMP/original"
expect_result FAIL
rule_V_230484_plan
[[ $EDIT_CONTEXT == *'approved time source=ntp.example.org' && $EDIT_DISPOSITION == pending ]]
[[ $proposal == '+ server ntp.example.org iburst maxpoll 16' && $staged_validator == chrony_approved_source_validate ]]
[[ $(cat "$EDIT_TEMP/proposal") == $'# Configuration fixture\nmakestep 1.0 3\n# EOF without final newline\nserver ntp.example.org iburst maxpoll 16' ]]
[[ $(sha256sum < "$path") == "$(sha256sum < "$EDIT_TEMP/original")" ]]
"$staged_validator" "$EDIT_TEMP/proposal" "$path"
cp -- "$EDIT_TEMP/proposal" "$EDIT_TEMP/altered"
printf '%s\n' '# unrelated change' >> "$EDIT_TEMP/altered"
if "$staged_validator" "$EDIT_TEMP/altered" "$path"; then exit 1; fi
unit_state=active
live_activity='1,0,0,0,0'
expect_block 'existing live time sources'
if "$staged_validator" "$EDIT_TEMP/proposal" "$path"; then exit 1; fi
live_activity='0,0,0,0,0'
rule_V_230484_plan
cp -- "$EDIT_TEMP/proposal" "$path"
"$staged_validator" "$path" "$path"

expect_result PASS
unit_start='2000-01-01 00:00:00 UTC'
expect_result NEEDS_REVIEW
unit_start='2030-01-01 00:00:00 UTC'
leap_status='Not synchronised'
expect_result NEEDS_REVIEW
leap_status=Normal
live_sources='^,*,unapproved.example.org,2,16,377,40,0,0,0'
expect_result NEEDS_REVIEW

for directive in 'pool other.example.org' 'peer other.example.org' 'include /etc/chrony.d/*' \
    'refclock SHM 0' 'local stratum 10' 'manual' 'authselectmode require' 'minsources 2'; do
    printf '%s\n' "$directive" > "$path"
    expect_block 'existing or alternate sources'
done
printf '%s\n' '# managed by configuration management' > "$path"
expect_block 'appears to be externally managed'
chmod 0666 "$path"
expect_block 'trusted regular chrony.conf'
chmod 0644 "$path"
CHRONY_APPROVED_SERVER=''
cp -- "$EDIT_TEMP/original" "$path"
expect_block 'supply one approved time server'
printf '%s\n' 'server existing.example.org iburst maxpoll 20' > "$path"
expect_result FAIL
rule_V_230484_plan
[[ $staged_validator == chrony_poll_validate && $proposal == 'server directive at line 1: maxpoll 20 -> 16' ]]
grep -Fxq 'server existing.example.org iburst maxpoll 16' "$EDIT_TEMP/proposal"
printf '%s\n' 'PASS approved chrony input, bounded plans, and observed synchronization.'
