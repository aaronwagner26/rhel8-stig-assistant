#!/bin/bash
set -euo pipefail
[[ -f /.dockerenv && $# == 1 && $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs ]]
source "$1"
init_options
register_rules

fail() { printf 'FAIL %s\n' "$*" >&2; exit 1; }
different() { [[ $1 != "$2" ]] || fail "$3"; }
same() { [[ $1 == "$2" ]] || fail "$3"; }
valid_hash() { [[ $1 =~ ^[0-9a-f]{64}$ ]] || fail "$2"; }

eligibles=0
for id in "${RULE_IDS[@]}"; do
    if cache_probe_for "$id" >/dev/null; then eligibles=$((eligibles+1)); fi
done
[[ $eligibles == 75 ]] || fail "wanted 75 supported reads, got $eligibles"
same "$(cache_probe_for V-230267)" 'sysctl-policy sysctl-live-V-230267' 'sysctl mapping'
same "$(cache_probe_for V-230405)" 'audit-rules audit-watch-V-230405' 'audit mapping'
if cache_probe_for V-230224; then fail 'dynamic disk encryption was cacheable'; fi

fixture=$(mktemp -d /var/tmp/stig-cache-dependencies.XXXXXXXX)
mkdir "$fixture/sysctl.d"
network_sysctl_main() { printf '%s/sysctl.conf\n' "$fixture"; }
network_sysctl_locations() { printf '%s/sysctl.d\n' "$fixture"; }
network_sysctl_protected_path() { [[ $1 == "$fixture/"* ]]; }

first=$(cache_observe_source sysctl-policy)
valid_hash "$first" 'no valid fingerprint for empty source set'
printf 'fs.protected_symlinks=1\n' > "$fixture/sysctl.conf"
second=$(cache_observe_source sysctl-policy)
different "$first" "$second" 'new persistent source failed to invalidate'
printf 'net.ipv4.ip_forward=1\n' > "$fixture/sysctl.d/99-role.conf"
third=$(cache_observe_source sysctl-policy)
different "$second" "$third" 'new drop-in failed to invalidate'
printf 'net.ipv4.ip_forward=0\n' > "$fixture/sysctl.d/99-role.conf"
fourth=$(cache_observe_source sysctl-policy)
different "$third" "$fourth" 'edited drop-in failed to invalidate'
ln -s "$fixture/sysctl.conf" "$fixture/sysctl.d/95-ambiguous.conf"
if cache_observe_source sysctl-policy; then fail 'ambiguous symlink did not disable cache'; fi

live=1 fixture_ipv6_disabled=0
network_sysctl_live() { printf '%s\n' "$live"; }
network_sysctl_ipv6_disabled() { [[ $fixture_ipv6_disabled == 1 ]]; }
live_before=$(cache_observe_source sysctl-live-V-230267)
live=0
different "$live_before" "$(cache_observe_source sysctl-live-V-230267)" 'runtime change failed to invalidate'
v6_before=$(cache_observe_source sysctl-live-V-230535)
fixture_ipv6_disabled=1
different "$v6_before" "$(cache_observe_source sysctl-live-V-230535)" 'IPv6 applicability failed to invalidate'

fixture_kernel_enabled=1 fixture_unit='enabled unit' fixture_files='01-base.rules'
fixture_generated='generated policy' fixture_active='live policy' fixture_source_policy='source policy'
expansion_audit_kernel_status() { printf '%s\n' "$fixture_kernel_enabled"; }
expansion_audit_loader() { printf '%s\n' "$fixture_unit"; }
audit_rule_source_inventory() { printf '%s\n' "$fixture_files"; }
audit_rule_source_contents() { printf '%s\n' "$fixture_source_policy"; }
expansion_audit_generated_rules() { printf '%s\n' "$fixture_generated"; }
active_audit_rules() { printf '%s\n' "$fixture_active"; }
have_tools() { return 0; }
audit_before=$(cache_observe_source audit-rules)
valid_hash "$audit_before" 'no valid audit fingerprint'
for input in fixture_unit fixture_files fixture_generated fixture_active fixture_source_policy; do
    let_saved=${!input}
    printf -v "$input" '%s' 'different retained state'
    different "$audit_before" "$(cache_observe_source audit-rules)" "$input failed to invalidate audit cohort"
    printf -v "$input" '%s' "$let_saved"
done
fixture_kernel_enabled=0
if cache_observe_source audit-rules; then fail 'audit disabled must require a fresh result'; fi

printf 'text\n' > "$fixture/file"
chmod 0644 "$fixture/file"
before=$(cache_probe_metadata "$fixture/file" file)
printf 'ordinary log append\n' >> "$fixture/file"
same "$before" "$(cache_probe_metadata "$fixture/file" file)" 'routine log append caused ownership scan'
chmod 0600 "$fixture/file"
different "$before" "$(cache_probe_metadata "$fixture/file" file)" 'mode update failed to invalidate permissions'
before=$(cache_text_file_state "$fixture/file" 1024)
printf 'new file contents\n' > "$fixture/file"
different "$before" "$(cache_text_file_state "$fixture/file" 1024)" 'byte update failed to invalidate text source'
ln -s "$fixture/file" "$fixture/link"
if cache_text_file_state "$fixture/link" 1024; then fail 'a linked text source was cached'; fi
if cache_probe_metadata "$fixture/link" file; then fail 'a linked log source was cached'; fi

printf '%s\n' 'PASS source invalidation for sysctl files/live values, audit inputs, log metadata, and text content.'
