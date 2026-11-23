#!/bin/bash
# The only writable configuration targets in this test are private tmpfs files.
set -u
set -o pipefail
[[ -f /.dockerenv && $EUID == 0 ]] || exit 1
for path in /var/tmp /var/log; do
    [[ $(findmnt -n -o FSTYPE -T "$path") == tmpfs ]] || exit 1
done
[[ $# == 1 ]] || exit 64
source "$1" || exit 1
init_options
register_rules || exit 1
fixture=$(mktemp -d /var/tmp/stig-local.XXXXXXXX) || exit 1

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
equal() { [[ $1 == "$2" ]] || fail "expected '$2'; saw '$1'"; }
rule_result() { ASSESSMENT=$1; }

notice=$(expansion_console_notice)
[[ $notice == 'You are accessing a U.S. Government'* && $notice != *\" ]] || fail 'invalid pinned notice'
printf '%s\n' "$notice" > "$fixture/issue"
expansion_notice_validate "$fixture/issue" || fail 'pinned notice rejected'
printf '\nAnother line.\n' >> "$fixture/issue"
if expansion_notice_validate "$fixture/issue"; then fail 'unexpected notice was accepted'; fi

printf '[Manager]\nCtrlAltDelBurstAction=none\n' > "$fixture/system.conf"
expansion_burst_validate "$fixture/system.conf" || fail 'valid systemd section rejected'
printf '\nCtrlAltDelBurstAction=reboot\n' >> "$fixture/system.conf"
if expansion_burst_validate "$fixture/system.conf"; then fail 'duplicate systemd directive accepted'; fi
printf '[Other]\nCtrlAltDelBurstAction=none\n' > "$fixture/system.conf"
if expansion_burst_validate "$fixture/system.conf"; then fail 'wrong systemd section accepted'; fi

expansion_screen_value_compliant lock-delay 'uint32 3' || fail 'valid GNOME lock delay rejected'
if expansion_screen_value_compliant lock-delay 'uint32 6'; then fail 'long GNOME lock delay accepted'; fi
if expansion_screen_value_valid lock-delay 'uint32 4294967296'; then fail 'overflow accepted'; fi
if expansion_screen_value_compliant lock-enabled false; then fail 'disabled GNOME lock accepted'; fi

# Exercise the native UID transaction on a private inode.
log=/var/log/messages
printf 'native ownership fixture\n' > "$log" || exit 1
chmod 0664 -- "$log" || exit 1
chown 12345:12346 -- "$log" || exit 1
rule_V_230246_check
equal "$ASSESSMENT" FAIL
original=$(rule_V_230246_observe "$log") || fail 'native log observation failed'
desired="0:${original#*:}"
if rule_V_230246_change "$log" "0:${original#*:}" "$desired"; then fail 'stale native state accepted'; fi
rule_V_230246_change "$log" "$original" "$desired" || fail 'native change failed'
equal "$(rule_V_230246_observe "$log")" "$desired"
rule_V_230246_check
equal "$ASSESSMENT" PASS

edit_metadata() { staged="$1 $2 $3"; }
EFFECTIVE[V-230247]=1
rule_V_230245_plan || fail 'grouped metadata preview failed'
equal "$staged" "$log 0640 0"
equal "$EDIT_GROUPED" V-230247
rule_V_230246_restore "$log" "$original" "$desired" || fail 'native restore failed'
equal "$(rule_V_230246_observe "$log")" "$original"
equal "$(cat -- "$log")" 'native ownership fixture'
ln -- "$log" /var/log/fixture-link || exit 1
if rule_V_230246_observe "$log" >/dev/null; then fail 'multiply linked log accepted'; fi
rm -- /var/log/fixture-link "$log"

printf '%s\n' 'PASS console banner, systemd and GNOME bounds, grouped log metadata, and native UID change and rollback.'
