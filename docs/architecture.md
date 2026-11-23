# Architecture

The release is a standalone Bash executable. Bash owns the rule catalog, host checks, scope resolution, remediation proposals, approvals, backups, writes, verification, and report generation. The terminal interface presents that state and returns operator input through a private command channel.

| Source | Responsibility |
| --- | --- |
| [`src/classic/rhel8-stig.sh`](../src/classic/rhel8-stig.sh) | Pinned classic engine and rule definitions |
| [`src/urwid/workbench.py`](../src/urwid/workbench.py) | Run settings, selection, Findings, and Review |
| [`src/urwid/attended.py`](../src/urwid/attended.py) and [`outcomes.py`](../src/urwid/outcomes.py) | Individual decisions, immediate Results, evidence, and follow-up views |
| [`src/urwid/history.py`](../src/urwid/history.py) | Saved-run browsing, protected artifact access, and report comparisons |
| [`src/urwid/bridge.sh`](../src/urwid/bridge.sh), [`hooks.sh`](../src/urwid/hooks.sh), and [`runtime.py`](../src/urwid/runtime.py) | Backend integration, protocol, and terminal supervision |
| [`tools/build.py`](../tools/build.py) | Build pipeline that verifies the classic source digest and assembles the standalone executable |

The backend prepares eligible changes from the current system and verifies the reviewed scope, source inputs, and change signatures before writing. The CLI and terminal interface use the same backend. A recheck is a separate read-only Status run linked to the original report.

Treat report schema, manifest identity, complete review, and approval semantics as compatibility requirements. When updating the pinned source, review the backend delta explicitly and keep test results with the new build. [Release process](releasing.md) · [Validation record](validation.md)
