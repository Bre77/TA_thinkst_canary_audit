# Project agent memory

This file is the project's committed home for project-intrinsic agent knowledge: build, test, release, architecture, and sharp-edge notes that should travel with the code.

- This app runs on `splunk_input_runtime` (https://github.com/Bre77/splunk-input-runtime), not `splunklib`/`splunk-sdk`. `lib/requirements.txt` pins it to an exact commit archive URL with a `sha256:` hash recorded in a comment above it (no PyPI package exists yet, so there is no `==version` line to pin against). Bump both the commit and the recorded hash together when the runtime releases a new version; never point at a branch.
- Credential handling goes through `self.context.credentials.protect_input_fields(...)` (see `bin/thinkst_canary_audit.py`), not manual `storage_passwords` list/delete/create calls. This preserves the credential identity `(owner=nobody, app=TA_thinkst_canary_audit, realm=<stanza name>, username=auth_token)` that existing installs already have — do not change that tuple without a captain-level decision; it strands users' stored secrets.
- `.build.sh` vendors `lib/` fresh on every build (`pip install -t lib -r lib/requirements.txt --no-dependencies`); `lib/` is gitignored except `lib/requirements.txt`. Do not commit vendored packages into `lib/` — an old vendored `lib/splunklib/` tree was committed by mistake early in this repo's history and removed as part of the `splunk_input_runtime` migration.
- The runner (`Script.run_script`) owns `EventWriter.close()`; app code must not call it explicitly. `splunk_input_runtime`'s `close()` is idempotent by design, but an explicit extra call is redundant and was removed from this app.
- `Bre77/SplunkUI-devcontainer`'s `test-harness/verify-splunklib-app.sh` is app-agnostic — point it at this repo to get a `dependency=splunk_input_runtime` build+import check on both Python 3.9 and 3.13. Its `test-harness/credential-continuity-gate.sh`, however, is hardcoded to its own fixture app id/kind (`cc_fixture`) and cannot be pointed at this app's real `thinkst_canary_audit` modular-input kind without editing that script (a different repo) — it only proves the shared `protect_input_fields` mechanism, not this app's stanza specifically. Verify credential continuity for this app by building `--old-app`/`--new-app` copies of two real commits of this repo, which fails fast and loudly (`wait_modinput_kind` FAIL) if you don't first rename the kind, rather than by assuming a pass.

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
