#!/bin/bash
# Run only with a private temporary directory in the disposable fixture.
set -euo pipefail
[[ $# == 1 && -f /.dockerenv && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]] || exit 64
source "$1"

EDIT_TEMP=$(mktemp -d /var/tmp/stig-audit-preview.XXXXXXXX)
candidate=$EDIT_TEMP/edit-0
original=$EDIT_TEMP/site.conf
trap 'rm -f -- "$candidate" "$original"; rmdir -- "$EDIT_TEMP"' EXIT

check_diff() {
    local path=$1 validator=$2 input=$3
    EDIT_KINDS=(content)
    EDIT_PATHS=("$path")
    EDIT_PRE=(absent)
    EDIT_VALIDATOR=("$validator")
    printf '%s\n' "$input" > "$candidate"
    preview=$(edit_public_diff 0)
}

assert_visible() {
    if [[ $preview != *"$1"* ]]; then
        printf 'Expected visible preview line: %s\n%s\n' "$1" "$preview" >&2
        exit 1
    fi
}

assert_hidden() {
    if [[ $preview == *"$1"* ]]; then
        printf 'Unexpected visible preview line: %s\n' "$1" >&2
        exit 1
    fi
}

redaction='[source line omitted; see reviewed change above]'
useradd='-a always,exit -F path=/usr/sbin/useradd -F perm=x -F auid>=1000 -F auid!=unset -k privileged-useradd'
watch='-w /etc/shadow -p wa -k identity'
cron='-w /etc/cron.d/ -p wa -k cronjobs'
useradd_path=/etc/audit/rules.d/90-rhel8-stig-v288831.rules

check_diff "$useradd_path" audit_rule_dropin_validate "$useradd"
assert_visible "+ $useradd"
assert_hidden "$redaction"

check_diff /etc/audit/rules.d/90-rhel8-stig-v274877.rules audit_rule_dropin_validate "$cron"
assert_visible "+ $cron"
assert_hidden '/var/spool/cron/'

check_diff /etc/audit/rules.d/90-rhel8-stig-v230404.rules expansion_audit_validate_dropin "$watch"
assert_visible "+ $watch"
assert_hidden "$redaction"

secret='-a always,exit -F path=/site/token -F perm=x -k private-name'
check_diff "$useradd_path" audit_rule_dropin_validate "$useradd"$'\n'"$secret"
assert_visible "+ $useradd"
assert_visible "$redaction"
assert_hidden "$secret"

check_diff "$useradd_path" - "$useradd"
assert_visible "$redaction"
assert_hidden "$useradd"

check_diff /etc/audit/rules.d/90-rhel8-stig-v230405.rules expansion_audit_validate_dropin "$watch"
assert_visible "$redaction"
assert_hidden "$watch"

check_diff "$original" audit_rule_dropin_validate "$useradd"
assert_visible "$redaction"
assert_hidden "$useradd"

printf 'site_secret=old-value\n' > "$original"
printf 'site_secret=new-value\n' > "$candidate"
EDIT_PRE=(existing)
preview=$(edit_public_diff 0)
assert_visible "$redaction"
assert_hidden old-value
assert_hidden new-value

printf 'PASS safe audit additions and existing secret redaction\n'
