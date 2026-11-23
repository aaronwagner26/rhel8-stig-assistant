#!/bin/bash
# Exercise parser and staged plans against root-owned fixtures in a disposable container.
set -euo pipefail
[[ -f /.dockerenv && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]]
(( $# == 1 || $# == 2 )) || exit 64
source "$1"
if (( $# == 2 )); then source "$2"; fi

fixture=$(mktemp -d -- /var/tmp/stig-accounts.XXXXXXXX)
mkdir "$fixture/pam.d" "$fixture/quality.conf.d" "$fixture/staging"
EDIT_TEMP=$fixture/staging
declare -A EFFECTIVE=()

account_policy_path() { printf '%s/%s.conf\n' "$fixture" "$1"; }
account_policy_pam_directory() { printf '%s/pam.d\n' "$fixture"; }
edit_safe_path() { [[ $1 == "$fixture/"* && ! -L $1 ]]; }
rule_result() { ASSESSMENT=$1 CHECK_DETAIL=$2; }
edit_content() {
    CAPTURED_PATH=$1 CAPTURED_MODE=$2 CAPTURED_DIFF=$3 CAPTURED_VALIDATOR=$4
    CAPTURED_COPY=$fixture/candidate
    cat > "$CAPTURED_COPY"
    "$4" "$CAPTURED_COPY" "$1"
}

result() {
    local expected=$1 check=$2
    "$check"
    if [[ $ASSESSMENT != "$expected" ]]; then
        printf 'Expected %s for %s. Got %s (%s)\n' "$expected" "$check" "$ASSESSMENT" "$CHECK_DETAIL" >&2
        return 1
    fi
}

stack() {
    printf 'password requisite pam_pwquality.so try_first_pass local_users_only retry=3 %s\n' "${1:-}"
    printf '%s\n' 'password sufficient pam_unix.so sha512 shadow use_authtok' 'password required pam_deny.so'
}

printf '%s\n' 'password substack system-auth' > "$fixture/pam.d/passwd"
stack > "$fixture/pam.d/system-auth"
stack > "$fixture/pam.d/password-auth"
cat > "$fixture/quality.conf" <<'EOF'
# Keep existing evidence.
ucredit = 1
lcredit = -2
minlen = 10
maxrepeat = 0
EOF

result FAIL rule_V_230357_check
result PASS rule_V_230358_check
result FAIL rule_V_230369_check
result FAIL rule_V_230361_check
result FAIL rule_V_251716_check
EFFECTIVE=([V-230357]=1 [V-230358]=1 [V-230369]=1 [V-230361]=1 [V-251716]=1)
rule_V_230357_plan
[[ $EDIT_GROUPED == 'V-230361 V-230369 V-251716' && $CAPTURED_MODE == keep ]]
grep -q '^lcredit = -2$' "$CAPTURED_COPY"
grep -q '^minlen = 15$' "$CAPTURED_COPY"
grep -q '^retry = 3$' "$CAPTURED_COPY"
grep -q '^# Keep existing evidence.$' "$CAPTURED_COPY"
grep -q '^minlen = 10$' "$fixture/quality.conf"

printf '%s\n' '# New drop-in while an approval was pending' > "$fixture/quality.conf.d/10-policy.conf"
if "$CAPTURED_VALIDATOR" "$CAPTURED_COPY" "$CAPTURED_PATH" 2>/dev/null; then
    printf '%s\n' 'A change to a supporting drop-in should invalidate authorization.' >&2
    exit 1
fi
printf '%s\n' 'lcredit=-1' > "$fixture/quality.conf.d/10-policy.conf"
result FAIL rule_V_230358_check
[[ $CHECK_DETAIL == *'conflicting explicit settings'* ]]
stack 'maxrepeat=9' > "$fixture/pam.d/password-auth"
result FAIL rule_V_230361_check
[[ $CHECK_DETAIL == *'Effective PAM arguments'* ]]
EFFECTIVE=([V-230361]=1)
if rule_V_230361_plan; then exit 1; fi

stack > "$fixture/pam.d/password-auth"
printf '%s\n' 'ucredit=1' 'minlen=18' > "$fixture/quality.conf"
EFFECTIVE=([V-230357]=1 [V-230369]=1)
rule_V_230357_plan
[[ $EDIT_GROUPED == V-230369 && $CAPTURED_DIFF == *'stays at 18'* ]]
grep -q '^minlen=18$' "$CAPTURED_COPY"
EFFECTIVE=([V-230369]=1)
if rule_V_230369_plan; then exit 1; fi

rm -- "$fixture/quality.conf.d/10-policy.conf"
printf '%s\n' '# Start with no explicit policy.' > "$fixture/quality.conf"
EFFECTIVE=([V-230357]=1 [V-230358]=1 [V-230359]=1 [V-230360]=1 [V-230361]=1 \
           [V-230362]=1 [V-230363]=1 [V-230369]=1 [V-230375]=1 [V-230377]=1 [V-251716]=1)
for id in "${!EFFECTIVE[@]}"; do result FAIL "rule_V_${id#V-}_check"; done
rule_V_230357_plan
[[ ${#ACCOUNT_VALIDATE_IDS[@]} == 11 ]]
cp -- "$CAPTURED_COPY" "$fixture/quality.conf"
for id in "${!EFFECTIVE[@]}"; do result PASS "rule_V_${id#V-}_check"; done

cat > "$fixture/login.conf" <<'EOF'
CREATE_HOME no
PASS_MIN_DAYS 1
PASS_MAX_DAYS 99999
FAIL_DELAY 6
UMASK 027
EOF
result FAIL rule_V_230324_check
result PASS rule_V_230365_check
result FAIL rule_V_230366_check
result PASS rule_V_230378_check
result FAIL rule_V_230383_check
EFFECTIVE=([V-230324]=1 [V-230365]=1 [V-230366]=1 [V-230378]=1 [V-230383]=1)
rule_V_230324_plan
[[ $EDIT_GROUPED == 'V-230366 V-230383' ]]
grep -q '^CREATE_HOME yes$' "$CAPTURED_COPY"
grep -q '^FAIL_DELAY 6$' "$CAPTURED_COPY"
grep -q '^PASS_MAX_DAYS 180$' "$CAPTURED_COPY"
grep -q '^UMASK 077$' "$CAPTURED_COPY"

printf '%s\n' '# Local account defaults' > "$fixture/login.conf"
for id in "${!EFFECTIVE[@]}"; do result FAIL "rule_V_${id#V-}_check"; done
rule_V_230324_plan
[[ ${#ACCOUNT_VALIDATE_IDS[@]} == 5 ]]
cp -- "$CAPTURED_COPY" "$fixture/login.conf"
for id in "${!EFFECTIVE[@]}"; do result PASS "rule_V_${id#V-}_check"; done

printf '%s\n' 'PASS_MIN_DAYS 200' 'PASS_MAX_DAYS 365' 'UMASK 177' > "$fixture/login.conf"
result FAIL rule_V_230383_check
[[ $CHECK_DETAIL == *'stricter custom mask'* ]]
EFFECTIVE=([V-230366]=1 [V-230383]=1)
if rule_V_230366_plan 2>/dev/null; then exit 1; fi
if rule_V_230383_plan; then exit 1; fi

printf '%s\n' '[main]' 'gpgcheck=1' 'clean_requirements_on_remove=False' > "$fixture/dnf.conf"
result FAIL rule_V_230281_check
EFFECTIVE=([V-230281]=1)
rule_V_230281_plan
grep -q '^gpgcheck=1$' "$CAPTURED_COPY"
grep -q '^clean_requirements_on_remove=True$' "$CAPTURED_COPY"
grep -q '^clean_requirements_on_remove=False$' "$fixture/dnf.conf"
printf '%s\n' '[main]' 'gpgcheck=1' 'clean_requirements_on_remove=yes' > "$fixture/dnf.conf"
result PASS rule_V_230281_check
printf '%s\n' '[main]' 'include=example.conf' > "$fixture/dnf.conf"
result NEEDS_REVIEW rule_V_230281_check
printf '%s\n' 'Account, password-quality, and DNF fixtures passed.'
