# Validation for Urwid 0.6.7

This release fixes returning from a plan or diff to Findings. Back restores the preceding browse view, including its selection, filters, sort order, and focused finding. A new review checks that scope against the live host. Back discards the preview's approval token.

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig-urwid.sh` | `bcd14330f90db0201cbe85b9b4059c3c37a6ddd33f3c3f174de26f0e49d2311f` |
| `rhel8-stig.sh` | `c346ad42f744f76833e0c87586a70278ee42600402e5601ff1158c92d1c9134a` |

Tests ran offline in Rocky Linux 8.10 with Bash 4.4, Red Hat Platform Python 3.6.8, and Urwid 1.3.1. Live acceptance on a RHEL 8.10 guest remains pending.

- A terminal session against the assembled Urwid script counted checks as it opened Details, returned, opened a focused preview, returned again, and explicitly reassessed with **F8**. The two Back actions added zero checks. The preview checked one finding, and **F8** checked the full fixture scope.
- The 51 Urwid tests include five navigation regressions. The bridge fixture also checks unrelated finding details after Back, a failed preview, rejection of an abandoned token, and acceptance of a freshly reviewed scope.
- The existing terminal scenarios verified scoped reports, read-only follow-up, site settings drift, and individual and bulk approvals.
- The build smoke tests verified reproducible script bytes, Bash syntax, and parity across the 164-rule catalog.

Run `python3 tests/smoke.py` from the repository root. [Urwid fixture instructions](../tests/urwid/README.md) · [Operator guide](operator-guide.md#read-only-walkthrough)
