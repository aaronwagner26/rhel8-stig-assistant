#!/bin/bash
# Run in an offline Docker fixture with private /boot and /etc/dconf tmpfs.
set -euo pipefail
[[ -f /.dockerenv && $# == 1 ]] || exit 1
for mountpoint in /boot /etc/dconf; do
    [[ $(findmnt -rn -o TARGET,FSTYPE --target "$mountpoint") == "$mountpoint tmpfs" ]]
done
source "$1"
export LC_ALL=C

mkdir -p /boot/grub2 /etc/dconf/db/local.d
cfg=/boot/grub2/user.cfg
keyfile=/etc/dconf/db/local.d/00-media-keys

check_result() {
    local rule=$1 expected=$2
    rule_dispatch "$rule"
    if [[ $ASSESSMENT != "$expected" ]]; then
        printf '%s expected %s, got %s (%s)\n' "$rule" "$expected" "$ASSESSMENT" "$EVIDENCE" >&2
        exit 1
    fi
}

BOOT_MODE=UEFI
printf '%s\n' 'GRUB2_PASSWORD=grub.pbkdf2.sha512.synthetic' > "$cfg"
check_result V-230234 PASS
printf '%s\n' 'GRUB2_PASSWORD=grub.pbkdf2.sha512.second' >> "$cfg"
check_result V-230234 NEEDS_REVIEW
[[ $EVIDENCE == *'duplicate definitions'* ]]
printf '%s\n' 'GRUB2_PASSWORD=unsupported' > "$cfg"
check_result V-230234 FAIL
printf '%s\n' '# Empty fixture' > "$cfg"
check_result V-230234 FAIL
BOOT_MODE=BIOS
check_result V-230234 NOT_APPLICABLE

# Stub platform discovery so both checks exercise the real awk readers.
ARCH=x86_64
expanded_gui_state() { printf 'gnome\n'; }
printf '%s\n' '[org/gnome/settings-daemon/plugins/media-keys]' "logout=''" > "$keyfile"
check_result V-230530 NEEDS_REVIEW
[[ $EVIDENCE == *'confirm the loaded database'* ]]
printf '%s\n' "logout=''" >> "$keyfile"
check_result V-230530 NEEDS_REVIEW
[[ $EVIDENCE == *'multiple GNOME logout definitions'* ]]
printf '%s\n' '[org/gnome/settings-daemon/plugins/media-keys]' "logout='synthetic'" > "$keyfile"
check_result V-230530 FAIL
printf '%s\n' 'PASS GRUB and GNOME duplicate, present, and absent setting assessments.'
