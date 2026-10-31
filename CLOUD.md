# Development in Codex Cloud

Use Cloud for code changes, reviews, documentation, decision tests, and Linux tests.
Keep the live supervisor on the machine it watches. Run the final macOS checks on a Mac.

## Project context

1. Read [AGENTS.md](AGENTS.md) for the rules and command limits.
2. Read [README.md](README.md) for behavior, platforms, settings, and the current roadmap.
3. Read [PORTING.md](PORTING.md) for the decision vectors, schemas, and contracts.
4. Ask the owner to select the next feature. The roadmap does not authorize all its work at once.

Multiple GitHub pools, general `command`/`static` adapters, and read-only fleet collection/placement are implemented.
Live systemd and peer-host validation still require the owner's target machines. Monitoring integration remains.
Use the README roadmap as the source when its details change.

## Tools

Use Python 3.11 or newer. The project uses the Python standard library only.
Ensure `git`, `ps`, and `lsof` are available. On Ubuntu, `procps` provides `ps`.
Some tests use `/usr/bin/git`; check that path during setup.
No project service must run before the tests.

## Setup request

Paste this request into the Cloud environment setup chat:

```text
Prepare this repository for Linux development.
Read AGENTS.md, CLOUD.md, README.md, and PORTING.md.
Use Python 3.11 or newer. Ensure git, ps, and lsof are available.
Check that /usr/bin/git exists.
Use the existing test fixtures and temporary data folders.
Do not copy a live machine profile, credentials, queue, or runtime data.
Do not install or start machine-manager as a persistent service.
Run these commands from the repository root:
  python3 -I tests/run_tests.py
  python3 -I tests/run_vectors.py
Record the commit, Python version, platform, commands, exit codes, and summaries.
List skipped tests and their reasons from tests/results/.
Report failures. Keep all safety guards and test assertions in place.
Report the Mac checks that still remain.
```

The tests use temporary `HOME`, `MM_BASE`, and `MM_DATA` folders.
Test service commands use fixtures. They do not authorize commands against a real install.
The suite writes one report per group in `tests/results/`. Git ignores these reports.
Copy useful reports into the task result before its saved state expires.

## Owner steps

1. Commit and push these instructions before Cloud needs to read them from GitHub.
2. In Codex, select **Work in > Cloud > Select environment > Create environment**.
3. Select this GitHub repository. Complete any required account connection.
4. Select **Get started**, then paste the setup request above.
5. Review failures, skipped tests, installed tools, and access settings.
6. Resolve setup failures, save the setup, then select **Publish**.
7. After **Environment published** appears, select **Start a new task**.
8. Ask the first task to confirm its commit and repeat both test commands.

These steps follow the [official Cloud environment guide](https://learn.chatgpt.com/docs/environments/cloud-environments).
Publish captures the prepared setup. A new task has its own working files.
Keep source changes in Git branches and pull requests.
Local personal skills and private project notes need separate preparation if a task requires them.

## Checks that need a Mac

Linux skips tests that need real macOS readings or services.
Some optional checks also skip when their required inputs are absent.
Report these skips. A Linux pass does not prove that the Mac checks passed.

1. Check out the proposed change in an isolated Mac worktree.
2. Ask the installed `mm` where tests can run. Follow its placement result.
3. Run the full test suite and vectors on the Mac.
4. Check the live readings, power readings, and service behavior relevant to the change.
5. Report test results and any checks that did not run.
6. Use a separate owner-authorized procedure to update the live service.

Keep the installed profile, settings, queue, and runtime data in place.
Do not clear safe mode or restart the live supervisor as part of Cloud setup.
