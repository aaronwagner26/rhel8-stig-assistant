# Releasing a development build

## Change history

Make changes in a topic branch. Keep each commit focused so its behavior and validation can be reviewed together. Use commit subjects that describe the behavior, such as `Keep the active finding focused after resize`. Record the change, the affected path, and the checks run in the pull request. Add or revise tests when behavior changes and record operator-facing changes in the changelog.

Keep the published tag on its verified commit. Publish later changes under a new version and tag. The older source commit, script, and checksum help operators reopen and verify reports made by that build.

## Build and verify

1. Set the release version in the assembler and update the embedded and Markdown changelogs. Record any change to the pinned baseline, registry, or backend digest explicitly.
2. Generate the standalone artifact with `python3 tools/build.py`. Check it with `bash -n dist/rhel8-stig-urwid.sh` and verify its checksum from `dist/`.
3. Run `python3 tests/smoke.py`. Use a disposable supported guest or an isolated fixture for paths that need to write. Record the exact platform, runtime, artifact hash, test coverage, and open acceptance items.
4. Review the working tree and staged snapshot. Keep generated files under `dist/` and attach the verified script and checksum as GitHub release assets. Use synthetic examples and screenshots.
5. Create an annotated tag of the form `v0.6.3-urwid-dev` on the verified commit. Use the pre-release designation for development builds.
6. Publish the script and its checksum and link to the validation record. Verify the public tag target and asset digests. Keep release notes clear about the exact supported host and the difference between fixture and live guest results.

The original lab and vendor installation media are managed separately from the GitHub release assets. See the [operator prerequisites](operator-guide.md#target-and-dependencies).
