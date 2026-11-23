#!/bin/bash
# Fixture-local module evidence with the native file staging and rollback engine.
set -e -o pipefail
[[ -f /.dockerenv && $EUID == 0 && $# == 1 ]] || exit 64
[[ $(findmnt -n -o FSTYPE -T /var/tmp) == tmpfs && $(findmnt -n -o SOURCE,FSTYPE -T /etc) == 'overlay overlay' ]] || exit 64
source "$1"
export LC_ALL=C
umask 077
init_options
register_rules
parse_args --guided
resolve_scope
[[ ${#SCOPE[@]} == 22 && ${EFFECTIVE[V-251710]+present} && ! ${EFFECTIVE[V-288829]+present} ]]

fixture=$(mktemp -d -- /etc/rhel8-stig-module-fixture.XXXXXXXX)
trap 'rm -r -- "$fixture"' EXIT
mkdir -- "$fixture/bin" "$fixture/results" "$fixture/backups"
export PATH="$fixture/bin:$PATH"
cat > "$fixture/bin/modinfo" <<'MODULE'
#!/bin/bash
printf '/usr/lib/modules/fixture/%s.ko\n' "${@: -1}"
MODULE
printf '#!/bin/bash\nexit 0\n' > "$fixture/bin/modprobe"
chmod 0700 -- "$fixture/bin/modinfo" "$fixture/bin/modprobe"
RUN_DIR=$fixture/results BOOT_ID=3ae3c0fd-a42b-4b03-a34e-68421d67836d
RUN_ID=20261123T143000Z.Guided01 HOST_ID=fixture SCRIPT_HASH=fixture SCRIPT_PATH=/opt/stig.sh
OPERATOR=fixture

module_path() { printf '%s/90-rhel8-stig-%s.conf\n' "$fixture" "${MODULE[$1]}"; }
module_settings() {
    local path="$fixture/90-rhel8-stig-$1.conf"
    if [[ -f $path ]]; then inspect_module_settings "$1" < "$path"; fi
}
module_runtime() {
    if [[ $1 == "${loaded_module-}" ]]; then printf 'active\n'; else printf 'absent\n'; fi
}
inspect_local_module_policy() {
    if [[ -f $fixture/90-rhel8-stig-$1.conf ]]; then printf 'present\n'; else printf 'missing\n'; fi
}
settings_from_stage() {
    inspect_module_settings "$2" < "$1" | awk 'END {exit NR != 2}'
}
trusted_module_directory() { [[ -d $fixture && ! -L $fixture ]]; }
module_signature() { printf '%s %s\n' "$1" "${policy_generation:-1}" | sha256sum; }
local_filesystem() { [[ $(findmnt -n -o FSTYPE -T "$1") =~ ^(tmpfs|overlay)$ ]]; }
verify_script() { return 0; }
getenforce() { printf 'Disabled\n'; }

mods=V-230494,V-230495,V-230496,V-230497,V-230498,V-230499
build_preview() {
    local id
    init_options && init_results && parse_args "$@" && resolve_scope
    BACKUP_BASE=$fixture/backups BACKUP_RUN=''
    : > "$RUN_DIR/run.log"
    : > "$RUN_DIR/changes.txt"
    for id in "${SCOPE[@]}"; do assess_one "$id"; done
}

build_preview --apply --only "$mods" --max-risk medium --skip V-230497
[[ ${#PREVIEW_KEY[@]} == 1 && ${PREVIEW_RISK[V-230494]} == medium &&
   ${PREVIEW_GROUP[V-230494]} == 'V-230495 V-230496 V-230498' &&
   ${ACTIONS[V-230499]} == BLOCKED && ${ACTIONS[V-230497]} == SKIPPED ]]
loaded_module=can build_preview --apply --only V-230494,V-230495
[[ ${#PREVIEW_KEY[@]} == 1 && ! ${PREVIEW_GROUP[V-230494]} &&
   ${ACTIONS[V-230495]} == BLOCKED ]]
build_preview --apply --only "$mods" --review-each
[[ ${#PREVIEW_KEY[@]} == 6 && ! ${PREVIEW_GROUP[V-230494]} ]]
build_preview --apply --only "$mods"
[[ ${#PREVIEW_KEY[@]} == 1 && ${PREVIEW_RISK[V-230494]} == high &&
   ${PREVIEW_GROUP[V-230494]} == 'V-230495 V-230496 V-230497 V-230498 V-230499' ]]
[[ ${DISPLAY_PLAN[V-230494]} == *'install cramfs /bin/false'* ]]
reviewed_key=${PREVIEW_KEY[V-230494]}
policy_generation=2 prepare_rule_plan V-230494
[[ $PLAN_KEY != "$reviewed_key" ]]
edit_reset

original_files() {
    local id
    for id in "${SCOPE[@]}"; do [[ ! -e $(module_path "$id") ]] || return 1; done
}

approvals=0 answer=1
apply_choice() {
    [[ $1 == V-230494 && $2 == high && $3 == 0 && $4 == 0 ]] && original_files || exit 1
    (( approvals += 1 ))
    return "$answer"
}
touch "$fixture/approval-output"
exec {TTY_FD}<> "$fixture/approval-output"
do_apply
[[ $approvals == 1 ]] && original_files
build_preview --apply --only "$mods"
approvals=0 answer=0
write_manifest "$RUN_DIR/manifest"
do_apply
[[ $approvals == 1 && $(wc -l < "$RUN_DIR/changes.txt") == 6 ]]
for id in "${SCOPE[@]}"; do
    [[ ${ACTIONS[$id]} == PENDING_ACTIVATION ]]
    [[ $(< "$(module_path "$id")") == "$(module_bytes "$id" "$BOOT_ID")" ]]
done
render_resolution_next_steps > "$fixture/queue"
grep -Fx 'Boot and kernel modules | V-230494 V-230495 V-230496 V-230497 V-230498 V-230499' "$fixture/queue"
grep -F -- "--status --fresh --resume $RUN_ID" "$fixture/queue"

old=$BACKUP_RUN
init_options
init_results
MODE=rollback
load_manifest "$old/manifest" "$RUN_ID"
resolve_scope
approve() { [[ $1 == restore-V-230494 ]]; }
do_rollback "$old"
original_files
for id in "${SCOPE[@]}"; do [[ ${ACTIONS[$id]} == ROLLED_BACK ]]; done
printf '%s\n' 'PASS guided scope, verified module grouping, independent review, approved staging, next steps, and rollback.'
