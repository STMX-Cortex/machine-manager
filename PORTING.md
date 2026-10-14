# Porting machine-manager

A port (for example to Rust) is correct when it passes every vector in `vectors/` and writes records that match the
schemas in `schemas/`. The Python code is the reference; the vectors and schemas are the contract.

## Layers

| Layer | Python modules | Port rule |
| --- | --- | --- |
| Pure decisions | `core/mmdecide.py`, `core/mmalerts.py`, `core/mmreplay.py`, parsers in `core/mmread.py` and `adapters/` | Same inputs, same outputs: pass the vectors |
| Records and files | `core/mmcore.py` (settings, alert store, masking, atomic writes, line formats) | Match `schemas/`; atomic rename writes |
| Readings | `core/mmread.py` (system calls; the macOS commands as a cross-check) | Any method; `mm check` compares with the commands |
| Jobs and loop | `core/mmsuper.py`, `core/mmwatch.py`, `core/mmrecover.py`, `core/mmdelete.py`, `core/mmdrill.py`, `bin/cachetrim.py` | Same behaviour; tests in `tests/` describe it |
| Adapters | `adapters/ad_queue_fifo.py`, `adapters/ad_ci_github.py`, `adapters/ad_deliver_claude.py` | One per kind; chosen by the profile's `adapter` value |
| Command line | `bin/mm`, `core/mminstall.py`, `core/mmplace.py` | Same verbs, output lines and exit codes (`tests/test_cli.py`) |

## Vectors

One file per case: `vectors/<function>/<case>.json`:

```json
{"function": "slot_decide", "case": "red-to-floor", "settings": "base", "settings_over": {},
 "input": {...}, "expected": {...}}
```

Settings are `vectors/_settings/base.json` (a flat `section.key` map) with `settings_over` applied. Compare the
expected value after a JSON round trip (tuples are lists). A crash is a failure.
`tests/run_vectors.py` is the reference runner; `tests/vector_functions.py` shows how each function takes its input.
`python3 -I tests/run_vectors.py --list` prints the count per function.

Functions with vectors: `classify`, `slot_decide`, `alert_raise`, `alert_absent`, `alert_line`, `conditions`
(`mmalerts.evaluate`), `delete_guard`, `place`, `expected_wait`, `drill_stop`, `replay` (whole incidents minute by
minute), `mask`, `compare_readings`, `parse_load_line`, `parse_history_line`, `parse_kernel_line`, `parse_billing`,
`parse_delete_line`, and for self-recovery `sample_problems`, `self_check`, `crash_loop`, `resume_targets`,
`reboot_check`.

## Schemas

JSON Schema (2020-12) files: `reading`, `status` (kind `machine` or `pool`), `alert`, `placement-request`,
`placement`, `delete-line`, `off`, `override`, `profile`, `settings`. `settings.schema.json` is generated from the
code's table (`mmcore.settings_json_schema()`); `tests/test_vectors.py` fails when they differ.

Every record carries `machine_id` and `schema_version` (now 1). A reader refuses a record with a newer major version.
Several machines and pools are several status records; placement takes a list of candidates.

## Rules a port keeps

1. Readings never block a tick for long: every outside command has a time limit.
2. Mask secrets before anything reaches an alert, evidence, status or output (`mask` vectors).
3. Observe mode and the off switch turn every action into a `WOULD` line.
4. The launch gate fails open: no fresh status, no valid settings, or the off switch means no denial.
5. Deletes re-check their guard right before the delete; a forbidden part of a path is never entered.
6. The tool never pushes, dispatches or runs a placement command; it prints them.
