# Releasing a development build

## Change history

Make changes in a topic branch. Keep each commit focused so its behavior and validation can be reviewed together. Use commit subjects that describe the behavior, such as `Keep the active finding focused after resize`. Record the change, the affected path, and the checks run in the pull request. Add or revise tests when behavior changes and record operator-facing changes in the changelog.

Keep the published tag on its verified commit. Publish later changes under a new version and tag. The older source commit, script, and checksum help operators reopen and verify reports made by that build.

## Build and verify

1. Set the Classic version in the backend and the Urwid version in the assembler. Update the embedded and Markdown changelogs, and record any change to the pinned baseline, registry, or backend digest.
2. Generate both standalone artifacts with `python3 tools/build.py`. Run `bash -n dist/rhel8-stig.sh` and `bash -n dist/rhel8-stig-urwid.sh`. From `dist/`, run `sha256sum --check rhel8-stig.sh.sha256 rhel8-stig-urwid.sh.sha256`.
3. Run `python3 tests/smoke.py`. Use a disposable supported guest or an isolated fixture for paths that need to write. Record the exact platform, runtime, artifact hash, test coverage, and open acceptance items.
4. Review the working tree and staged snapshot. Keep generated files under `dist/`. Use synthetic examples and screenshots.
5. Create an annotated tag matching the Urwid development version on the verified commit, such as `v0.6.4-urwid-dev`. Use the pre-release designation for development builds.
6. Attach both scripts and their corresponding checksum files to the GitHub release. Link to the validation record and verify the public tag target and all asset digests. Identify the supported host, the fixture evidence, and any remaining live guest checks in the release notes.

The original lab and vendor installation media are managed separately from the GitHub release assets. See the [operator prerequisites](operator-guide.md#target-and-dependencies).

## Account policy fixtures

Build both scripts first. From a Bash shell at the repository root, run the account policy suite against either built script. This example mounts the repository read-only in the Rocky Linux 8.10 test image and gives the test a temporary filesystem.

```bash
docker run --rm --network none --read-only --cap-drop ALL \
  --tmpfs /var/tmp:rw,nosuid,nodev,noexec,mode=1777 \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  rockylinux/rockylinux:8.10 \
  bash /src/tests/expansion/accounts.sh /src/dist/rhel8-stig.sh
```

Use `/src/dist/rhel8-stig-urwid.sh` as the last argument to check the assembled Urwid engine. The fixture exercises parsing and stages changes in temporary files using the image's native libpwquality and DNF libraries. It performs no login or package transaction.
