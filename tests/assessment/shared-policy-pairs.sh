#!/bin/bash
# Run inside a disposable offline container with signed RHEL 8.10 DVD RPMs.
set -e -o pipefail
[[ -f /.dockerenv && $EUID == 0 && $# == 2 ]] || exit 64
[[ $(findmnt -rn -o TARGET,FSTYPE --target /var/tmp) == '/var/tmp tmpfs' ]] || exit 64
for path in /etc /usr/sbin /var/spool /var/lib/rpm; do
    [[ $(findmnt -rn -o TARGET,FSTYPE --target "$path") == '/ overlay' ]] || exit 64
done
while IFS= read -r mounted; do
    case $mounted in
        /etc/resolv.conf|/etc/hostname|/etc/hosts) ;;
        /etc|/etc/*|/usr|/usr/*|/var|/var/spool|/var/spool/*|/var/lib|/var/lib/rpm|/var/lib/rpm/*) exit 64 ;;
    esac
done < <(findmnt -rn -o TARGET)

rpm_root=$2
packages=("$rpm_root"/BaseOS/Packages/authselect-*.rpm "$rpm_root"/BaseOS/Packages/attr-*.rpm)
rpm --import "$rpm_root/RPM-GPG-KEY-redhat-release"
rpm --checksig "${packages[@]}"
rpm -U --oldpackage --noscripts --nodeps --replacepkgs --replacefiles "${packages[@]}"

source "$1"
export LC_ALL=C
umask 077
register_rules
identify_script
fingerprint=$SCRIPT_HASH
fixture=$(mktemp -d -- /var/tmp/stig-policy-pairs.XXXXXXXX)
backup_root=$(mktemp -d -- /var/lib/stig-policy-pairs.XXXXXXXX)
HOST_ID=fixture OPERATOR=fixture RUN_ID=20261123T120000Z.Fixture1
read -r BOOT_ID < /proc/sys/kernel/random/boot_id

# Keep native authselect but substitute observational audit commands, since
# this container must not talk to the host kernel's audit subsystem.
mkdir "$fixture/bin"
cat > "$fixture/bin/systemctl" <<'SYSTEMCTL'
#!/bin/bash
[[ $* == 'show auditd.service -p ExecStartPost --value' ]] || exit 64
printf '%s\n' '{ path=/usr/sbin/augenrules ; argv[]=/usr/sbin/augenrules --load ; ignore_errors=yes ; }'
SYSTEMCTL
cat > "$fixture/bin/auditctl" <<'AUDITCTL'
#!/bin/bash
case $1 in
    -s) printf '%s\n' 'enabled 1' ;;
    -l) printf '%s\n' 'No rules' ;;
    *) exit 64 ;;
esac
AUDITCTL
cat > "$fixture/bin/augenrules" <<'AUGENRULES'
#!/bin/bash
exit 64
AUGENRULES
chmod 0700 "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"

verify_script() { [[ $(sha256_file "$SCRIPT_PATH") == "$fingerprint" ]]; }
local_filesystem() { [[ $(findmnt -n -o FSTYPE -T "$1") =~ ^(overlay|tmpfs)$ ]]; }
getenforce() { printf '%s\n' Disabled; }

configure_scope() {
    init_options
    init_results
    parse_args "$@"
    BACKUP_BASE=$(mktemp -d -- "$backup_root/run.XXXXXXXX")
    BACKUP_RUN=''
    RUN_DIR=$(mktemp -d -- "$fixture/run.XXXXXXXX")
    : > "$RUN_DIR/run.log"
    : > "$RUN_DIR/changes.txt"
}

build_preview() {
    local item
    resolve_scope
    for item in "${SCOPE[@]}"; do assess_one "$item"; done
}

approve() { [[ $1 == "restore-$leader" ]]; }
apply_choice() {
    [[ $1 == "$leader" && $2 == high && $3 == 0 && $4 == 0 ]] || exit 1
    (( approval_count += 1 ))
    return "$answer"
}

exercise_approval_and_rollback() {
    local leader=$1 peer=$2 before_a=$3 before_b=$4 path_a=$5 path_b=$6 result
    local answer=1 approval_count=0
    [[ ${#PREVIEW_KEY[@]} == 1 && ${PREVIEW_GROUP[$leader]} == "$peer" &&
        ${PLANNED_BY[$peer]} == "$leader" && ${DISPLAY_PLAN[$leader]} == *"$path_a"* &&
        ${DISPLAY_PLAN[$leader]} == *"$path_b"* ]]
    do_apply
    [[ $approval_count == 1 && ${ACTIONS[$leader]} == SKIPPED && ${ACTIONS[$peer]} == SKIPPED &&
        $(edit_identity content "$path_a") == "$before_a" && $(edit_identity content "$path_b") == "$before_b" ]]
    answer=0 approval_count=0
    do_apply
    [[ $approval_count == 1 && ${ACTIONS[$leader]} == PENDING_ACTIVATION &&
        ${ACTIONS[$peer]} == PENDING_ACTIVATION && ${AFTER[$peer]} == NEEDS_REVIEW &&
        $(wc -l < "$RUN_DIR/changes.txt") == 2 && ! -e $BACKUP_RUN/$peer.edits ]]
    result=$BACKUP_RUN/$leader.edits
    verify_digest "$result/grouped" && [[ $(< "$result/grouped") == "$peer" ]]
    verify_digest "$result/operations" && [[ $(wc -l < "$result/operations") == 2 ]]
    verify_digest "$BACKUP_RUN/manifest"
    grep -Fxq "select"$'\t'"$leader" "$BACKUP_RUN/manifest"
    grep -Fxq "select"$'\t'"$peer" "$BACKUP_RUN/manifest"
    rollback_file_plan "$leader" "$BACKUP_RUN"
    [[ ${GROUPED_BY[$peer]} == "$leader" ]]
}

touch "$fixture/approval-output"
exec {TTY_FD}<> "$fixture/approval-output"
authselect create-profile stig-pairs -b sssd --symlink-meta
authselect select custom/stig-pairs --force
authselect check
password_auth=/etc/authselect/custom/stig-pairs/password-auth
system_auth=/etc/authselect/custom/stig-pairs/system-auth

configure_scope --apply --only V-244541
build_preview
[[ ${#SCOPE[@]} == 1 && ${#PREVIEW_KEY[@]} == 1 && ! ${PREVIEW_GROUP[V-244541]} ]]

configure_scope --apply --only V-244541,V-268322 --skip V-268322
build_preview
[[ ${#PREVIEW_KEY[@]} == 1 && ${ACTIONS[V-268322]} == SKIPPED && ! ${PREVIEW_GROUP[V-244541]} ]]

configure_scope --apply --only V-244541,V-268322 --review-each
build_preview
[[ ${#PREVIEW_KEY[@]} == 2 && ! ${PREVIEW_GROUP[V-244541]} && ! ${PREVIEW_GROUP[V-268322]} ]]

configure_scope --apply --only V-244541,V-268322
build_preview
reviewed_key=${PREVIEW_KEY[V-244541]}
cp -p -- "$system_auth" "$fixture/system-auth"
printf '\n%s\n' '# nullok directive requires authoritative review' >> "$system_auth"
authselect apply-changes
refresh_apply_plan V-244541
[[ $PLAN_KEY != "$reviewed_key" && ! $PLAN_GROUP && ${#EDIT_PATHS[@]} == 1 ]]
edit_reset
cp -p -- "$fixture/system-auth" "$system_auth"
authselect apply-changes

configure_scope --apply --only V-244541,V-268322
build_preview
password_live=$(sha256_file /etc/pam.d/password-auth)
system_live=$(sha256_file /etc/pam.d/system-auth)
password_source=$(sha256_file "$password_auth")
system_source=$(sha256_file "$system_auth")
exercise_approval_and_rollback V-244541 V-268322 "$(edit_identity content "$password_auth")" \
    "$(edit_identity content "$system_auth")" "$password_auth" "$system_auth"
[[ $(sha256_file "$password_auth") == "$password_source" && $(sha256_file "$system_auth") == "$system_source" &&
    $(sha256_file /etc/pam.d/password-auth) == "$password_live" && $(sha256_file /etc/pam.d/system-auth) == "$system_live" ]]

mkdir -p /etc/audit/rules.d /etc/cron.d /var/spool/cron
: > /etc/audit/audit.rules
cron_rule=/etc/audit/rules.d/90-rhel8-stig-v274877.rules
useradd_rule=/etc/audit/rules.d/90-rhel8-stig-v288831.rules
[[ ! -e $cron_rule && ! -e $useradd_rule ]]
printf '%s\n' '-w /usr/sbin/useradd -p x -k alternate' > /etc/audit/rules.d/15-stig-fixture.rules
configure_scope --apply --only V-274877,V-288831
build_preview
[[ ${#PREVIEW_KEY[@]} == 1 && ! ${PREVIEW_GROUP[V-274877]} && ${ACTIONS[V-288831]} == BLOCKED ]]
rm -- /etc/audit/rules.d/15-stig-fixture.rules

configure_scope --apply --only V-274877,V-288831 --review-each
build_preview
[[ ${#PREVIEW_KEY[@]} == 2 && ! ${PREVIEW_GROUP[V-274877]} && ! ${PREVIEW_GROUP[V-288831]} ]]

configure_scope --apply --only V-274877,V-288831
build_preview
exercise_approval_and_rollback V-274877 V-288831 absent absent "$cron_rule" "$useradd_rule"
[[ ! -e $cron_rule && ! -e $useradd_rule && ! -s /etc/audit/audit.rules ]]
printf '%s\n' 'PASS shared PAM and audit policy plans, single approvals, drift check, preserved active state, and rollback.'
