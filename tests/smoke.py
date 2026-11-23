"""Check the standalone build without assessing or modifying a host."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "tools" / "build.py"
CLASSIC_SOURCE = ROOT / "src" / "classic" / "rhel8-stig.sh"
CLASSIC = ROOT / "dist" / "rhel8-stig.sh"
RELEASE = ROOT / "dist" / "rhel8-stig-urwid.sh"
EXPANSION = ROOT / "docs" / "expansion-rules.md"
ENGINE_SNAPSHOT = r"""
set -eo pipefail
source "$1"
while IFS= read -r name; do
    case $name in
        rule_V_*|register_rules|rule_dispatch|prepare_rule_plan|assess_one|refresh_apply_plan|\
        commit_reviewed_plan|prepare_backup|write_manifest|load_manifest|record_digest|verify_digest|\
        do_rollback|do_apply|finish_grouped_review|open_attended_terminal|lock_mutation|\
        ckl_verify_source|resolve_scope)
            declare -f "$name" ;;
    esac
done < <(compgen -A function | LC_ALL=C sort)
"""
EXPANSION_REGISTRY = r"""
set -eo pipefail
source "$1"
shift
init_options
register_rules
resolve_scope
for id in "$@"; do
    prefix=rule_${id//-/_}
    kinds="_check _admin"
    case ${HANDLING[$id]-} in
        attended-file) kinds+=" _plan" ;;
        attended-action) kinds+=" _plan _observe _change _restore" ;;
        assessment|evidence-review|attended-module) ;;
        *) printf '%s has invalid handling.\n' "$id" >&2; exit 1 ;;
    esac
    for suffix in $kinds; do
        if ! declare -F "$prefix$suffix" >/dev/null; then
            printf 'Missing handler %s%s.\n' "$prefix" "$suffix" >&2
            exit 1
        fi
    done
    if [[ ${DEFAULT_RULE[$id]-} != yes || ! ${EFFECTIVE[$id]+selected} ]]; then
        printf '%s is absent from the default scope.\n' "$id" >&2
        exit 1
    fi
done
"""


def run(*command):
    env = dict(os.environ, LC_ALL="C", NO_COLOR="1")
    result = subprocess.run([str(arg) for arg in command], cwd=ROOT, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=60)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise SystemExit("{} exited with status {}\n{}".format(command[0], result.returncode, detail))
    return result.stdout


def bash(*args):
    return run("bash", "--noprofile", "--norc", "-p", *args)


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def artifact_state(path, expected_digest):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    sidecar = path.with_suffix(".sh.sha256").read_bytes()
    expected = "{}  {}\n".format(digest, path.name).encode("ascii")
    require(sidecar == expected, "Checksum sidecar does not identify {}.".format(path.name))
    if expected_digest:
        require(digest == expected_digest, "{} differs from the published digest.".format(path.name))
    return data, digest, sidecar


def check_registry(actual):
    lines = actual.decode("utf-8").splitlines()
    require(lines and lines[0] == "ID\tCAT\tHANDLING\tTITLE", "CLI rule registry header changed.")
    rows = [line.split("\t", 3) for line in lines[1:]]
    require(len(rows) == 164 and all(len(row) == 4 for row in rows), "Expected 164 well-formed CLI rules.")
    findings = [row[0] for row in rows]
    require(findings == sorted(set(findings)) and all(re.fullmatch(r"V-[0-9]{6}", item) for item in findings),
            "CLI rule IDs must be distinct and listed in ID order.")
    entries = re.findall(r"^\|\s*(V-[0-9]{6})\s*\|\s*[^|\n]+\|\s*(I{1,3})\s*\|\s*([a-z-]+)\s*\|",
                         EXPANSION.read_text(encoding="utf-8"), re.MULTILINE)
    golden = {rule: (category, kind) for rule, category, kind in entries}
    require(len(entries) == len(golden) == 96, "Expected 96 distinct rules in the expansion catalog.")
    registered = {rule: (category, kind) for rule, category, kind, _ in rows}
    for rule, values in golden.items():
        require(registered.get(rule) == values, "{} is missing or differs from the expansion catalog.".format(rule))
    return findings, sorted(golden)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha256", help="Verify the Urwid build against a published digest.")
    parser.add_argument("--expected-classic-sha256", help="Verify the Classic build against a published digest.")
    args = parser.parse_args()
    artifacts = {CLASSIC: args.expected_classic_sha256, RELEASE: args.expected_sha256}
    for flag, value in (("--expected-sha256", args.expected_sha256),
                        ("--expected-classic-sha256", args.expected_classic_sha256)):
        if value and not re.fullmatch(r"[0-9a-f]{64}", value):
            parser.error("{} requires 64 lowercase hexadecimal digits".format(flag))

    run(sys.executable, BUILDER)
    built = {path: artifact_state(path, digest) for path, digest in artifacts.items()}
    require(built[CLASSIC][0] == CLASSIC_SOURCE.read_bytes(), "Classic build differs from its source.")
    run(sys.executable, BUILDER)
    require({path: artifact_state(path, digest) for path, digest in artifacts.items()} == built,
            "The second build did not reproduce both artifacts and checksums byte for byte.")

    for artifact, (_, digest, _) in built.items():
        bash("-n", artifact)
        self_hash = bash(artifact, "--self-hash").split(maxsplit=1)[:1]
        require(self_hash == [digest.encode("ascii")], "CLI self-hash differs for {}.".format(artifact.name))
    version = runpy.run_path(str(BUILDER))["VERSION"]
    cli_version = bash(RELEASE, "--version").decode("utf-8")
    require(cli_version.startswith("{} {} | ".format(RELEASE.name, version)),
            "CLI version does not match the builder version.")
    cli_help = bash(RELEASE, "--help").decode("utf-8")
    for option in ("--ui-check", "--gui", "--status", "--dry-run", "--diff", "--apply",
                   "--review-each", "--only", "--group-by", "--resume", "--rollback"):
        require(option in cli_help, "CLI help does not describe {}.".format(option))
    registry = bash(RELEASE, "--list")
    require(registry == bash(CLASSIC, "--list"), "Urwid rule registry differs from the Classic edition.")
    findings, expansion = check_registry(registry)
    for artifact in built:
        bash("-c", EXPANSION_REGISTRY, "expansion-registry", artifact, *expansion)
    classic_engine = bash("-c", ENGINE_SNAPSHOT, "engine-snapshot", CLASSIC)
    require(bool(classic_engine) and classic_engine == bash("-c", ENGINE_SNAPSHOT, "engine-snapshot", RELEASE),
            "A rule, approval, mutation, or recovery function differs from the Classic edition.")
    print("Verified {} and {} findings across both editions, including {} new default rules."
          .format(version, len(findings), len(expansion)))
    for artifact, (_, digest, _) in built.items():
        print("{} SHA-256 {}".format(artifact.name, digest))


if __name__ == "__main__":
    main()
