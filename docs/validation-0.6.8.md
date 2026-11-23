# Validation for Classic 0.5.8 and Urwid 0.6.8

Both editions contain 164 rules from the pinned DISA RHEL 8 STIG V2R9 benchmark.

| Artifact | SHA-256 |
| --- | --- |
| `rhel8-stig.sh` | `a538106dff71c056d9b3c86e2efc9e7421d8c3017c24fcee40a9d6306630a8bc` |
| `rhel8-stig-urwid.sh` | `8dc03e8429fb91ab56b87945e857c94896b08ff26650e93ae8301cdc7e2c1230` |

Tests ran in a network-disabled Rocky Linux 8.10 container with Bash 4.4, signed Red Hat Platform Python 3.6.8, Urwid 1.3.1, and diffutils 3.6. Live acceptance on a RHEL 8.10 guest remains pending.

| Check | Evidence |
| --- | --- |
| Explicit Apply startup | An assembled Urwid Apply session with explicit IDs opened assessed Findings. The fixture recorded eligible changes only after review and approval. |
| Batch review | Urwid tests exercised all 22 selected IDs, including IDs hidden by filters, and the separate focused action. The Classic fixture confirmed grouped outcomes, the full selected scope, and Back as the confirmation default. |
| Audit previews | Both artifacts showed exact authored additions for V-288831, V-274877, and other supported audit drop-ins. Untrusted candidate text and existing protected values remained redacted. |
| Approval flow | Tests covered the initial diff view, evidence, default Skip, Stop, per-change decisions, revised plans, and rules for bulk approval of eligible low-risk changes. |
| Build and other workflows | Both artifacts rebuilt reproducibly and passed the 164-rule parity check. The 59 Urwid tests and terminal scenarios also exercised Status, CKL import, site drift, and follow-up reports. |

Run `python3 tests/smoke.py` from the repository root. [Urwid fixture instructions](../tests/urwid/README.md) · [Operator guide](operator-guide.md#attended-changes)
