# Validation for 0.6.3

The development release was validated on November 20, 2026. The hexadecimal digests identify the exact inputs and tested output.

| Item | SHA-256 |
| --- | --- |
| DISA `U_RHEL_8_V2R9_STIG.zip` baseline | `620bdff4d4a5b07b58817297dd5255a3f8f981a7227405c07b098588fe55cdee` |
| Pinned classic 0.5.4 backend | `1cd53bc1474de9c23b8bcc1ccd91e004c101fa6b393be8556514c7bf4ddf4333` |
| Assembled `rhel8-stig-urwid.sh` | `ed026f380891f85b833435568e6bd1f99594e3b47782aba8c929eaba3e3aaed0` |

The DISA RHEL 8 STIG V2R9 archive is the reference for the selected 68-rule registry. [DISA benchmark archive](https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_8_V2R9_STIG.zip)

## Test environment

The offline suite used a disposable Rocky Linux 8.10 container with Bash 4.4.20 and Red Hat-signed packages for Platform Python 3.6.8, Urwid 1.3.1, and diffutils 3.6. The container had network access disabled and read-only source and release mounts. Synthetic filesystem changes and backup checks ran in private temporary filesystems. The mutation scenarios supplied fixture host identity and rule observations.

| Area | Verified behavior |
| --- | --- |
| Build identity | Reassembly reproduced the tested bytes. Bash syntax and ShellCheck passed. The classic and Urwid 68-ID catalogs matched. |
| Readiness and selection | Dependency and path diagnostics, keyboard and mouse sorting, paste preview, duplicates, hidden selections, undo, and keyboard focus through resize. |
| Legacy CKL | Section and asset identity, explicit host acknowledgment, namespaced and malformed content, revision boundaries, source changes, and exclusion of imported evidence. |
| Approval and cancellation | Back and Skip defaults, exact reviewed scope, individually reviewed sensitive and revised changes, and low-risk eligibility for `A`. A site-file edit stopped a pending synthetic write. |
| Results and recheck | Text, CSV, and JSON output. Report search, handoff summary, read-only resume using the exact saved scope, and comparison of verified reports without modifying the original. |
| Recovery | Isolated file restoration, metadata and ACL preservation, later edits and drift, terminal cleanup, and report retention after failure. |
| Terminal behavior | Compact and wide layouts, monochrome output, alternate terminal capabilities, and refusal of Apply before host assessment when an interactive terminal is unavailable. |

The exact build completed 27 minutes of terminal holds with `TMOUT=2`. It spent nine minutes each in Review, Approval, and Results. The fixture verified the reviewed scope and report state every 30 seconds, required an explicit Skip, and verified that the lock was released before Results closed. The synthetic change never ran.

The measured median search update fell from about 214 ms to 22 ms in a 1,280-row synthetic fixture over seven repetitions at 160 columns by 40 rows. This measures the offscreen input-to-render path. Live assessments and display transport have separate costs.

## Remaining guest acceptance

Interactive acceptance is still pending on a genuine RHEL 8.10 x86_64 guest. Representative boot and service actions, physical activation, post-reboot verification, and live-system rollback need guest-specific testing before relying on those workflows. The published screenshots use synthetic data.

## Reproduce the artifact check

```bash
python3 tools/build.py
bash -n dist/rhel8-stig-urwid.sh
(cd dist && sha256sum --check rhel8-stig-urwid.sh.sha256)
sha256sum src/classic/rhel8-stig.sh dist/rhel8-stig-urwid.sh
```

Compare the digests against the table above. Running the source checks verifies the repository and generated artifact. The dated fixture record documents the extended evaluation of the release bytes.

The repository provides `python3 tests/smoke.py` and [optional Urwid tests](../tests/urwid/README.md). The smoke test can verify the exact release with `--expected-sha256` and the assembled script digest from the table. The portable checks cover source assembly, command metadata, catalog parity, and selected interface behavior. The full offline acceptance run described above included additional local fixture infrastructure.
