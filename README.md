# RHEL 8 STIG Assistant

An independent, attended STIG assessment and remediation tool for RHEL 8.10 x86_64. Use the Urwid terminal interface to select findings, review each change, and recheck the host afterward. The Classic edition provides the same rule engine through the CLI and a `dialog` interface. Each edition runs as a standalone Bash script.

**Current development versions** Urwid `0.6.9-urwid-dev` and Classic `0.5.9-dev`

**Pinned baseline** DISA RHEL 8 STIG Version 2 Release 9 (Sunset), with 164 of 371 rules registered in both editions. [DISA STIG announcements](https://www.cyber.mil/stigs/stig-announcements)

The catalog records which registered rules support attended remediation and which provide evidence or administrator guidance. Eligible changes require approval. Check your organization's approved baseline before using results as compliance evidence. [Rule coverage](docs/rule-coverage.md)

## Get started

Download the script and its checksum for the edition you want, or build both from source. Use a disposable RHEL 8.10 guest for the first run. [GitHub release](https://github.com/aaronwagner26/rhel8-stig-assistant/releases/tag/v0.6.9-urwid-dev) · [Build instructions](#build-from-source)

| Edition | Script | SHA-256 |
| --- | --- | --- |
| Urwid `0.6.9-urwid-dev` | [rhel8-stig-urwid.sh](https://github.com/aaronwagner26/rhel8-stig-assistant/releases/download/v0.6.9-urwid-dev/rhel8-stig-urwid.sh) | [rhel8-stig-urwid.sh.sha256](https://github.com/aaronwagner26/rhel8-stig-assistant/releases/download/v0.6.9-urwid-dev/rhel8-stig-urwid.sh.sha256) |
| Classic `0.5.9-dev` | [rhel8-stig.sh](https://github.com/aaronwagner26/rhel8-stig-assistant/releases/download/v0.6.9-urwid-dev/rhel8-stig.sh) | [rhel8-stig.sh.sha256](https://github.com/aaronwagner26/rhel8-stig-assistant/releases/download/v0.6.9-urwid-dev/rhel8-stig.sh.sha256) |

Run the Urwid quick start from the directory containing its script and checksum.

```bash
(
  set -e
  sha256sum --check rhel8-stig-urwid.sh.sha256
  chmod 0755 rhel8-stig-urwid.sh
  ./rhel8-stig-urwid.sh --version
  ./rhel8-stig-urwid.sh --ui-check
  ./rhel8-stig-urwid.sh --gui --status
)
```

For the Classic CLI, run the equivalent read-only check after verifying its checksum.

```bash
(
  set -e
  sha256sum --check rhel8-stig.sh.sha256
  chmod 0755 rhel8-stig.sh
  ./rhel8-stig.sh --version
  ./rhel8-stig.sh --status --only V-230494,V-230498
)
```

**Status** assesses settings and saves protected reports. **Apply** requires an explicit `--apply`, root, an interactive terminal, and attended approval. Classic Status automatically reuses eligible observations from the same host and boot. Use `--fresh` to check the whole selected scope live. Interactive acceptance on a genuine RHEL 8.10 guest is pending. [Automatic rechecks](docs/operator-guide.md#automatic-rechecks-in-classic-status) · [Validation record](docs/validation-0.6.9.md)

| To do this | Start here |
| --- | --- |
| Preview the catalog | `./rhel8-stig-urwid.sh --list` |
| Read the policy and local handling for a rule | `./rhel8-stig-urwid.sh --explain V-230494` |
| Assess a limited scope from the command line | `./rhel8-stig-urwid.sh --status --only V-230494,V-230498` |
| Preview eligible changes | `./rhel8-stig-urwid.sh --diff --only V-230494,V-230498` |
| Review saved work | Launch `--gui --status` and press `F9` in **Run settings** |

The Urwid interface uses Python 3 and Urwid. The Classic interface uses `dialog`. Legacy CKL import requires Python 3 with Expat, and full file-content diffs use `diffutils`. In the Urwid edition, `--ui-check` reports what the guest can use. Both editions support ordinary CLI modes without their interface packages. [Operator guide](docs/operator-guide.md)

## Interface

**Findings** shows the selected IDs, active filters, current assessment, and a detail panel. Search by ID or text, use the headers to sort, or paste a batch of IDs and inspect what the selection will include.

![Urwid Findings screen with selected rows, sort headings, and a focused evidence panel](docs/images/findings.png)

**Results** records what passed, what changed, what remains open, and what needs activation or another verification. Open per-finding evidence, review administrator actions, or compare a new read-only recheck with the original report.

![Urwid saved outcomes screen listing assessments, change outcomes, and selected findings](docs/images/outcomes.png)

The screenshots use synthetic fixture data.

## Build from source

```bash
python3 tools/build.py
bash -n dist/rhel8-stig.sh
bash -n dist/rhel8-stig-urwid.sh
(cd dist && sha256sum --check rhel8-stig.sh.sha256 rhel8-stig-urwid.sh.sha256)
python3 tests/smoke.py
```

The build checks the Classic source digest, emits that source unchanged as `dist/rhel8-stig.sh`, and embeds the Urwid sources in `dist/rhel8-stig-urwid.sh`. Each script has a SHA-256 sidecar. The smoke check uses Bash and the Python standard library. [Optional Urwid fixture tests](tests/urwid/README.md)

| Path | Contents |
| --- | --- |
| `src/classic/` | Pinned assessment, remediation, and recovery engine |
| `src/urwid/` | Terminal views, runtime, and Bash bridge |
| `tools/` | Build and release utilities |
| `tests/` | Regression tests and synthetic fixtures |
| `examples/` | Sample scope and site settings |
| `docs/` | Operator guide, screenshots, and validation notes |
| `dist/` | Locally generated scripts and checksums |

## Project records

- [Architecture](docs/architecture.md) explains the source layout and how the terminal interface uses the Bash engine.
- [Changelog](CHANGELOG.md) describes the development versions.
- [Validation](docs/validation-0.6.9.md) records fixture evidence and the remaining RHEL guest checks for this release.
- [Release process](docs/releasing.md) covers changes, versioning, verification, and publication.
- [Contributing](CONTRIBUTING.md) covers source changes and operator feedback.
- [Security](SECURITY.md) explains how to share a concern privately.
- [Third-party notices](THIRD_PARTY_NOTICES.md) identifies the DISA baseline and runtime dependency. A project license has yet to be selected.
