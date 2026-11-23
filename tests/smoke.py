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
CLASSIC = ROOT / "src" / "classic" / "rhel8-stig.sh"
RELEASE = ROOT / "dist" / "rhel8-stig-urwid.sh"
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-sha256", help="Verify against the digest of a published release.")
    args = parser.parse_args()
    if args.expected_sha256 and not re.fullmatch(r"[0-9a-f]{64}", args.expected_sha256):
        parser.error("--expected-sha256 requires 64 lowercase hexadecimal digits")

    run(sys.executable, BUILDER)
    original = RELEASE.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    sidecar = RELEASE.with_suffix(".sh.sha256")
    expected_sidecar = "{}  {}\n".format(digest, RELEASE.name).encode("ascii")
    require(sidecar.read_bytes() == expected_sidecar, "Checksum sidecar does not identify the build.")
    if args.expected_sha256:
        require(digest == args.expected_sha256, "Build differs from the published release digest.")
    run(sys.executable, BUILDER)
    require(RELEASE.read_bytes() == original and sidecar.read_bytes() == expected_sidecar,
            "The second build did not reproduce the first build byte for byte.")

    bash("-n", CLASSIC)
    bash("-n", RELEASE)
    version = runpy.run_path(str(BUILDER))["VERSION"]
    cli_version = bash(RELEASE, "--version").decode("utf-8")
    require(cli_version.startswith("{} {} | ".format(RELEASE.name, version)),
            "CLI version does not match the builder version.")
    cli_help = bash(RELEASE, "--help").decode("utf-8")
    for option in ("--ui-check", "--gui", "--status", "--dry-run", "--diff", "--apply",
                   "--review-each", "--only", "--group-by", "--resume", "--rollback"):
        require(option in cli_help, "CLI help does not describe {}.".format(option))
    self_hash = bash(RELEASE, "--self-hash").split(maxsplit=1)[:1]
    require(self_hash == [digest.encode("ascii")], "CLI self-hash does not identify the build.")

    registry = bash(RELEASE, "--list")
    require(registry == bash(CLASSIC, "--list"), "Urwid rule registry differs from the pinned classic registry.")
    findings = set(re.findall(rb"^V-[0-9]+\b", registry, re.MULTILINE))
    require(bool(findings), "CLI did not list any findings.")
    classic_engine = bash("-c", ENGINE_SNAPSHOT, "engine-snapshot", CLASSIC)
    require(bool(classic_engine) and classic_engine == bash("-c", ENGINE_SNAPSHOT, "engine-snapshot", RELEASE),
            "A rule, approval, mutation, or recovery function differs from the pinned classic implementation.")
    print("Verified {} and {} findings against the pinned classic backend.".format(version, len(findings)))
    print("SHA-256 {}".format(digest))


if __name__ == "__main__":
    main()
