#!/bin/bash
# Start this fixture only in a disposable network-disabled Linux container.
set -e -o pipefail
[[ -f /.dockerenv && $EUID == 0 && $# == 2 ]] || exit 64
[[ $(findmnt -rn -o TARGET,FSTYPE --target /var/tmp) == '/var/tmp tmpfs' ]] || exit 64
mounts=$(findmnt -rn -o TARGET)
if grep -Eq '^(/etc|/var|/var/lib|/var/log)$|^(/usr|/etc/aide\.conf|/etc/stig-evidence-fixture|/var/lib/aide|/var/lib/rpm|/var/log/aide)(/|$)' <<< "$mounts"; then
    exit 64
fi
[[ $(findmnt -rn -o TARGET,FSTYPE --target /etc) == '/ overlay' ]] || exit 64

rpm_root=$2
packages=("$rpm_root"/BaseOS/Packages/e2fsprogs-libs-*.rpm "$rpm_root"/AppStream/Packages/aide-*.rpm)
rpm --import "$rpm_root/RPM-GPG-KEY-redhat-release"
rpm --checksig "${packages[@]}"
rpm -U --oldpackage --noscripts --nodeps "${packages[@]}"

source "$1"
export LC_ALL=C
umask 077
init_options
register_rules
init_results
SCRIPT_PATH=$1
SCOPE=(V-251710)
local_filesystem() { [[ $(findmnt -n -o FSTYPE -T "$1") == overlay ]]; }

fixture=$(mktemp -d -- /var/tmp/stig-aide-fixture.XXXXXXXX)
trap 'rm -f -- "$fixture"/{initialize.conf,initialize.log,resolve.txt,admin.txt}; rmdir -- "$fixture"' EXIT

config=/etc/aide.conf
baseline=/var/lib/aide/aide.db.gz
log=/var/log/aide/aide.log
[[ ! -e $baseline && ! -L $baseline && ! -e $log && ! -L $log ]]
rule_dispatch V-251710
[[ $ASSESSMENT == NEEDS_REVIEW ]]
AFTER[V-251710]=$ASSESSMENT ACTIONS[V-251710]=MANUAL_REQUIRED DETAIL[V-251710]=$EVIDENCE
resolution_aide_check
[[ $RESOLUTION_AIDE_RESULT == *'baseline is missing'* ]]
resolution_text V-251710 > "$fixture/resolve.txt"
grep -Fq 'Installed package: aide-' "$fixture/resolve.txt"
grep -Fq 'Default AIDE paths' "$fixture/resolve.txt"

# Initialize only this disposable fixture. Production always runs --check.
awk '!/^[[:space:]]*report_url[[:space:]]*=/ {print} END {print "report_url=stdout"}' \
    "$config" > "$fixture/initialize.conf"
/usr/sbin/aide "--config=$fixture/initialize.conf" --init > "$fixture/initialize.log"
mv -- /var/lib/aide/aide.db.new.gz "$baseline"
config_before=$(sha256_file "$config")
baseline_before=$(sha256_file "$baseline")
resolution_aide_check
[[ $RESOLUTION_AIDE_RESULT == *'AIDE reported no differences'* ]]
[[ ${AFTER[V-251710]} == NEEDS_REVIEW ]]
render_admin_action V-251710 > "$fixture/admin.txt"
grep -Fq 'V-251710 read-only AIDE evidence:' "$fixture/admin.txt"
grep -Fq 'NEEDS_REVIEW / MANUAL_REQUIRED' "$fixture/admin.txt"

[[ ! -e /etc/stig-evidence-fixture ]]
printf '%s\n' 'fixture-only content' > /etc/stig-evidence-fixture
resolution_aide_check
[[ $RESOLUTION_AIDE_RESULT == *'Added 1 | Removed 0 | Changed 0'* ]]
[[ $RESOLUTION_AIDE_RESULT != *'stig-evidence-fixture'* ]]
[[ $(sha256_file "$baseline") == "$baseline_before" && $(sha256_file "$config") == "$config_before" ]]
[[ ! -e $log && ! -e /var/lib/aide/aide.db.new.gz ]]
if compgen -G '/var/tmp/rhel8-stig-aide.*' >/dev/null; then exit 1; fi

chmod g+w "$baseline"
resolution_aide_check
[[ $RESOLUTION_AIDE_RESULT == *'outside a protected local path'* ]]
chmod g-w "$baseline"
printf '\n# Modified fixture configuration\n' >> "$config"
resolution_aide_check
[[ $RESOLUTION_AIDE_RESULT == *'differs from the installed RPM'* ]]
printf '%s\n' 'PASS read-only AIDE evidence, preserved assessment, protected inputs and fixed-format summary.'
