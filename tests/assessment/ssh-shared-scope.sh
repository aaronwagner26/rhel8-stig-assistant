#!/bin/bash
# Run with signed RHEL 8.10 DVD crypto-policies RPMs in an offline container.
set -e -o pipefail
[[ -f /.dockerenv && $EUID == 0 && $# == 2 ]] || exit 64
[[ $(findmnt -rn -o TARGET,FSTYPE --target /var/tmp) == '/var/tmp tmpfs' ]] || exit 64
for path in /etc/crypto-policies /usr/share/crypto-policies /etc/pki/tls /var/lib/rpm; do
    [[ $(findmnt -rn -o TARGET,FSTYPE --target "$path") == '/ overlay' ]] || exit 64
done
mounts=$(findmnt -rn -o TARGET)
if grep -Eq '^(/etc|/var|/var/lib)$|^(/etc/crypto-policies|/etc/pki|/usr|/var/lib/rpm)(/|$)' <<< "$mounts"; then
    exit 64
fi

rpm_root=$2
packages=("$rpm_root"/BaseOS/Packages/crypto-policies-*.rpm "$rpm_root"/BaseOS/Packages/attr-*.rpm)
rpm --import "$rpm_root/RPM-GPG-KEY-redhat-release"
rpm --checksig "${packages[@]}"
rpm -U --oldpackage --noscripts --nodeps --replacepkgs --replacefiles "${packages[@]}"

source "$1"
export LC_ALL=C
umask 077
register_rules
identify_script
fingerprint=$SCRIPT_HASH
fixture=$(mktemp -d -- /var/tmp/stig-ssh-scope.XXXXXXXX)
backup_root=$(mktemp -d -- /var/lib/stig-ssh-scope.XXXXXXXX)
RUN_DIR=$fixture/report BACKUP_RUN=
mkdir -m 0700 -- "$RUN_DIR"
HOST_ID=fixture OPERATOR=fixture RUN_ID=20261123T120000Z.Fixture1
read -r BOOT_ID < /proc/sys/kernel/random/boot_id

# The production preflight rejects containers and verifies the executing inode.
# The sourced fixture accepts only the unchanged artifact and its Docker overlay.
verify_script() { [[ $(sha256_file "$SCRIPT_PATH") == "$fingerprint" ]]; }
local_filesystem() { [[ $(findmnt -n -o FSTYPE -T "$1") =~ ^(tmpfs|overlay)$ ]]; }
getenforce() { printf '%s\n' Disabled; }

configure_scope() {
    init_options
    init_results
    parse_args "$@"
    BACKUP_BASE=$backup_root
    : > "$RUN_DIR/run.log"
    : > "$RUN_DIR/changes.txt"
}

build_preview() {
    local item
    resolve_scope
    include_ssh_scope
    for item in "${SCOPE[@]}"; do assess_one "$item"; done
}

openssl_config=/etc/pki/tls/openssl.cnf
module="/etc/crypto-policies/policies/modules/$ATTENDED_SSH_MODULE.pmod"
crypto_config=/etc/crypto-policies/config
active_policy=/etc/crypto-policies/state/current
update-crypto-policies --set DEFAULT --no-reload
cat > "$openssl_config" <<'OPENSSL'
openssl_conf = default_modules
[default_modules]
ssl_conf = ssl_module
[ssl_module]
system_default = crypto_policy
[crypto_policy]
OPENSSL

config_before=$(sha256_file "$crypto_config")
openssl_before=$(sha256_file "$openssl_config")
server_backend=/etc/crypto-policies/back-ends/opensshserver.config
server_before=$(sha256_file "$server_backend")

configure_scope --apply --only V-230251 --skip V-230252
build_preview
[[ ${#SCOPE[@]} == 1 && ${ACTIONS[V-230251]} == BLOCKED && ${#PREVIEW_KEY[@]} == 0 ]]
[[ ${DISPLAY_PLAN[V-230251]} == *V-230252* ]]

configure_scope --apply --only V-230251,V-230252,V-272482,V-272483 --skip V-288829
build_preview
[[ ${#SCOPE[@]} == 4 && ${ACTIONS[V-230251]} == BLOCKED && ${#PREVIEW_KEY[@]} == 0 ]]
[[ ${DISPLAY_PLAN[V-230251]} == *V-288829* ]]

configure_scope --apply --only V-230251
CKL_PATH=$fixture/imported.ckl CKL_MAPPED[V-230251]=1
build_preview
[[ ${#SCOPE[@]} == 1 && ${ACTIONS[V-230251]} == BLOCKED ]]

configure_scope --apply --resume 20261123T120000Z.ABCDEFGH
SELECT_EXPLICIT=1 REQUESTED[V-230251]=1
build_preview
[[ ${#SCOPE[@]} == 1 && ${ACTIONS[V-230251]} == BLOCKED ]]

configure_scope --apply --only V-230251 --max-risk medium
build_preview
[[ ${#SCOPE[@]} == 1 && ${ACTIONS[V-230251]} == BLOCKED ]]

configure_scope --status --only V-230251
build_preview
[[ ${#SCOPE[@]} == 1 && ${#PREVIEW_KEY[@]} == 0 ]]

configure_scope --apply --only V-230251
IMPLEMENT_DIFF=1
build_preview
[[ ${#SCOPE[@]} == 5 && ${#PREVIEW_KEY[@]} == 1 && ${PREVIEW_RISK[V-230251]} == high ]]
for id in V-230252 V-272482 V-272483; do
    [[ ${SSH_SCOPE_ADDED[$id]+added} && ${PLANNED_BY[$id]} == V-230251 ]]
done
[[ ${SSH_SCOPE_ADDED[V-288829]+added} && ${BEFORE[V-288829]} == FAIL && ! ${PREVIEW_KEY[V-288829]+planned} ]]
[[ ${DISPLAY_PLAN[V-230251]} == *V-288829* && ${DISPLAY_DIFF[V-230251]} == *'mac@OpenSSH = HMAC-SHA2-256 HMAC-SHA2-512'* ]]
write_manifest "$RUN_DIR/manifest"
grep -Fxq $'ssh_impact\tV-288829' "$RUN_DIR/manifest"

configure_scope --apply --resume "$RUN_ID"
load_manifest "$RUN_DIR/manifest" "$RUN_ID"
build_preview
[[ ${#SCOPE[@]} == 5 && ${#PREVIEW_KEY[@]} == 1 &&
    ${SSH_SCOPE_ADDED[V-288829]} == impact && ! ${PREVIEW_KEY[V-288829]+planned} ]]

configure_scope --apply --only V-230251
build_preview

confirm_original() {
    [[ ! -e $module && $(sha256_file "$crypto_config") == "$config_before" &&
        $(sha256_file "$openssl_config") == "$openssl_before" &&
        $(sha256_file "$server_backend") == "$server_before" && $(< "$active_policy") == DEFAULT ]]
}

confirm_original
touch "$fixture/approval-output"
exec {TTY_FD}<> "$fixture/approval-output"
approval_count=0
apply_choice() {
    [[ $1 == V-230251 && $2 == high && $3 == 0 && $4 == 0 ]] || exit 1
    confirm_original || exit 1
    (( approval_count += 1 ))
    return "$answer"
}

answer=1
do_apply
[[ $approval_count == 1 && ${ACTIONS[V-230251]} == SKIPPED ]]
confirm_original
[[ ! -s $RUN_DIR/changes.txt ]]

configure_scope --apply --only V-230251
build_preview
approval_count=0 answer=0
do_apply
[[ $approval_count == 1 && ${ACTIONS[V-230251]} == PENDING_ACTIVATION &&
    ${ACTIONS[V-230252]} == PENDING_ACTIVATION && ${ACTIONS[V-272482]} == PENDING_ACTIVATION &&
    ${ACTIONS[V-272483]} == PENDING_ACTIVATION ]]
[[ $(sha256_file "$openssl_config") == "$openssl_before" &&
    $(sha256_file "$server_backend") == "$server_before" && $(< "$active_policy") == DEFAULT &&
    $(attended_crypto_config_value "$crypto_config") == "FIPS:$ATTENDED_SSH_MODULE" ]]
[[ $(wc -l < "$RUN_DIR/changes.txt") == 2 && ! -e $BACKUP_RUN/V-288829.edits ]]
verify_digest "$BACKUP_RUN/manifest"
grep -Fxq $'ssh_impact\tV-288829' "$BACKUP_RUN/manifest"

# Activate only in this disposable container. A fresh native generation must
# independently verify both client/server cipher and MAC settings.
update-crypto-policies --no-reload
attended_crypto_validate_generated /etc/crypto-policies/back-ends
configure_scope --apply --only V-230251
build_preview
[[ ${#SCOPE[@]} == 1 && ${BEFORE[V-230251]} == NEEDS_REVIEW && ${#PREVIEW_KEY[@]} == 0 ]]
[[ ${DETAIL[V-230251]} == *'contains only approved algorithms'* ]]

configure_scope --rollback "$RUN_ID"
load_manifest "$BACKUP_RUN/manifest" "$RUN_ID"
resolve_scope
approve() { [[ $1 == restore-V-230251 ]]; }
rollback_file_plan V-230251 "$BACKUP_RUN"
[[ ! -e $module && $(sha256_file "$crypto_config") == "$config_before" ]]

update-crypto-policies --set FIPS --no-reload
configure_scope --diff --only V-272482
build_preview
[[ ${#SCOPE[@]} == 4 && ${#PREVIEW_KEY[@]} == 1 && ! ${EFFECTIVE[V-288829]+affected} ]]
for id in $ATTENDED_SSH_SCOPE; do [[ ${EFFECTIVE[$id]+selected} ]]; done
printf '%s\n' 'PASS native SSH grouped scope, guarded preview, single approval, and activation verification.'
