# Validation for Classic 0.5.11 and Urwid 0.6.11

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `721078a8795afb23d5af348759d82926f0cccdd5c42ad16fe73fccae84b89071` |
| `rhel8-stig-urwid.sh` | `a8e926bc72d28f3d19a9cee2a5d8c3fd5c8f4e8fb52bf6a1a00974b2d6646bb8` |

- Build smoke tests reproduced the two standalone files and verified the 164-rule catalog. The menu, protocol and terminal tests covered the direct approval flow, low-risk bulk approval, avoiding writes on Back or Skip, evidence actions, site-setting drift, checklist import, and read-only rechecks.
- The module fixture verified all 22 guided IDs, risk and skip limits, drift, a single approval for six selected modules, the grouped follow-up report, and rollback. It used simulated kernel evidence and real protected file writes in a private container directory.
- Signed RHEL 8.10 DVD packages verified native authselect rendering, the stock nullok conditional, exact SSH plan staging and rollback, and AIDE against an existing disposable database without changing it. The audit fixture simulated the live kernel policy while exercising the file transaction and rollback.
- Native activation and live login, reboot, audit, and time-service behavior need verification on an actual target host. The offline workflow fixtures do not establish compliance on those hosts.

[Guided workflow](operator-guide.md#review-eligible-changes-together) · [All 22 findings](resolution-guide.md)
