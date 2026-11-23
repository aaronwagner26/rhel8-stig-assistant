# Validation for Classic 0.5.6 and Urwid 0.6.5

Both editions retain 164 rules from the pinned DISA RHEL 8 STIG V2R9 benchmark. Classic Status can reuse verified observations for 75 of those rules. Every other rule still runs live. The Urwid edition uses the shared GRUB and GNOME parser corrections and continues to use live assessments.

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `5eada3181356e55ef7a0cbeecc450dda7c179878cdd2ea902648f44f9f461a69` |
| `rhel8-stig-urwid.sh` | `71fb1b19c9cf7cf74be977fb561d5de7a471ad036ceb1ed38ce6f80d7ceabbff` |

## Verification

Testing used a network-disabled Rocky Linux 8.10 container with Bash 4.4 and GNU awk 4.2.1. The terminal fixtures used the signed RHEL dialog and Urwid packages. The fixtures write only to disposable locations. Host acceptance on a genuine RHEL 8.10 guest is pending.

| Check | Evidence |
| --- | --- |
| Reproducibility | Both artifacts rebuild byte for byte, pass Bash syntax checks, and expose the same 164-rule catalog and remediation logic. |
| Classic incremental Status | Cold and warm runs, original observation time, selected scope, forced live refresh, changed or unreadable inputs, boot or executable identity changes, cache file validation, and refresh when inputs change during the scan. |
| Dependency proofs | All 75 eligible mappings. Fixtures cover changes to live and persistent kernel settings, audit policy, log ownership and permissions, source contents, and symbolic links. |
| GNU awk fixes | Reproduced the older parser error with a caret at the second `?`. The corrected V-230234 and V-230530 checks parse valid, duplicate and absent settings. |
| Terminal workflows | Classic Findings opens with live and reused counts, and Urwid approvals and report workflows passed offline. |

The cache keeps only Pass and Not Applicable observations with verified dependencies. Open, pending, or unresolved findings get another live check. An observation expires after 24 hours, and a different boot or executable build invalidates the cache. [Operator guide](operator-guide.md#automatic-rechecks-in-classic-status)

## Reproduce the checks

Run `python3 tests/smoke.py` from the repository root. Build the scripts before starting the assessment fixtures in this example.

```bash
docker run --pull=never --rm --network none --read-only \
  --tmpfs /var/tmp:rw,nosuid,nodev \
  --tmpfs /boot:rw,nosuid,nodev \
  --tmpfs /etc/dconf:rw,nosuid,nodev \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  rockylinux/rockylinux:8.10 bash -c '
    set -e
    edition=/src/dist/rhel8-stig.sh
    bash /src/tests/assessment/cache.sh "$edition"
    bash /src/tests/assessment/dependencies.sh "$edition"
    bash /src/tests/assessment/grub-password.sh "$edition"
  '
```
