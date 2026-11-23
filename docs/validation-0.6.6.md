# Validation for Classic 0.5.7 and Urwid 0.6.6

Both editions assess the same 164 rules in the pinned DISA RHEL 8 STIG V2R9 benchmark. This release removes the change-ticket workflow from settings, command-line options, and new reports.

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `c346ad42f744f76833e0c87586a70278ee42600402e5601ff1158c92d1c9134a` |
| `rhel8-stig-urwid.sh` | `d29d8d2fa8d7fc6e426a75c15e4820ef75c32c22629177fddd0b434b745be588` |

Testing used offline Rocky Linux 8.10 fixtures with Bash 4.4. The terminal fixtures used Red Hat Platform Python 3.6.8 and Urwid 1.3.1. Live acceptance on RHEL 8.10 remains pending.

| Check | Evidence |
| --- | --- |
| Build and CLI | Reproducible bytes, Bash syntax, matching 164-rule catalogs, and rejection of the removed CLI flag. |
| Reports | Text, JSON, and CSV omit the ticket field from new reports. Operator and outcome evidence remain available. |
| Results and history | An older report containing ticket fields could be opened and compared with a new report. Administrator actions still include grouped outcomes and the read-only verification command. |
| Terminal workflow | Readiness, selected Status, focused Apply, approval decisions, and follow-up rechecks through the assembled Urwid script. |
| Classic Status | Cold and warm assessment, scoped recheck, and dependency invalidation through the retained incremental Status fixture. |

Run `python3 tests/smoke.py` from the repository root for checks against both generated scripts. [Urwid fixtures](../tests/urwid/README.md) · [Classic assessment fixtures](validation-0.6.5.md#reproduce-the-checks)
