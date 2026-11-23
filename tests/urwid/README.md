# Urwid fixture tests

Run these tests on Linux from the repository root with Python and a compatible Urwid version installed. The RHEL 8.10 reference runtime is Python 3.6.8 with Urwid 1.3.1. When the package is installed for Platform Python on RHEL, use `/usr/libexec/platform-python` in place of `python3`.

```bash
PYTHONPATH=src/urwid python3 -B -m unittest discover -s tests/urwid -v
```

The tests use synthetic reports, temporary directories under `/var/tmp`, and an isolated pseudoterminal to check report history, path browsing, event handling, and terminal restoration. Running the fixtures needs no elevated privileges. The standard GitHub smoke job uses only Python and Bash.
