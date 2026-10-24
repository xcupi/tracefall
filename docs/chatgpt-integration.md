# ChatGPT / Codex integration

Optional AI summaries remain separate from deterministic analysis. Open **Settings → Integrations → ChatGPT / Codex** as an administrator (the local loopback operator is the administrator when authentication is off).

The same provider also supports a separate [bounded AI Case Review](ai-case-review.md). This does not expand Summary's input or report appendix: review selection, caps, preview, consent, coverage and persistence are independent. A separate [parsed-case batch workflow](ai-case-review-batches.md) is available with explicit bounded budgets, persisted packet coverage and a separately approved start. Budget-limited/failed work remains partial; this is not exhaustive raw-image review.

## Authorize, select, and verify are different actions

1. Install the official OpenAI Codex CLI on the Tracefall server. Tracefall searches `PATH`, then `/usr/lib/chatgpt/resources/codex`; `TRACEFALL_CODEX_BIN` can specify an executable. Use an absolute executable path. This process-control implementation is Unix-only; other platforms report the integration unavailable rather than launch an uncontrolled process.
2. Click **Authorize ChatGPT**. Tracefall starts only the official `codex login --device-auth` flow. It does not accept a password, API key, access token, OAuth callback or custom issuer. Follow the displayed official HTTPS link and enter the one-time code on OpenAI's page, not in Tracefall. Continue only if you started this authorization yourself.
3. The card shows preparing/waiting, signed in, failed, expired or cancelled. **Cancel authorization** terminates the login process group and removes the displayed code. The maximum deadline is 15 minutes. A retry gets a new official flow; no device code is written by Tracefall to disk or the case database.
4. **Signed in** means a bounded `codex login status` subprocess reported exactly the ChatGPT status line with a successful exit. File existence is not a sign-in check. This local CLI status does **not** prove token freshness, model availability, subscription entitlement or successful model access.
5. Choose **ChatGPT via Codex CLI** and **Save provider** to use it for new AI summaries. Authorizing alone does not change the selected provider. Saving a provider makes no model request.
6. Optionally acknowledge **Verify one synthetic request**, then click **Verify request**. This separate action sends the fixed text below through the existing hardened Codex model client. It sends **no case data**, may use account quota and is subject to provider/account limits. Only a real successful, nonempty client response sets **Request verified**. Failure leaves it unverified even when still signed in. Verification is in-memory and resets on new authorization, disconnect, failed/lost sign-in status, verification retry, and server restart. It is not a guarantee for future requests or a check of provider data controls.
7. **Disconnect** requires UI confirmation. It runs the official CLI logout only against Tracefall's isolated home and checks CLI status afterwards. Stored case drafts and personal Codex/Hermes sessions are unchanged. Wait for ongoing summaries or verification; cancel a pending login first.

The fixed synthetic user message is:

```text
Reply exactly TRACEFALL_TEST_OK. This is a synthetic Tracefall connection test. No case data is included.
```

The hardened client also prefixes its existing instruction not to use tools. Verification does not store the model's answer in a case or audit record. A nonempty successful response verifies that one request, not that the model followed the requested wording or that a particular model identity was independently established.

## Storage and privacy

- Every login, status, logout and model subprocess uses an explicit absolute `CODEX_HOME` at `<data-dir>/.integrations/codex`. Its `HOME` is isolated too. Tracefall does not fall back to the operator's `~/.codex` or inherited `CODEX_HOME`, copy personal credentials, or open credential contents. The official CLI owns credential storage and refreshing.
- The integration root and Codex home are mode 0700. Symlink integration roots/homes are refused at startup. Protect this entire directory and the server OS account. Owner-only permissions are **not encryption**; administrators, backups and snapshots may retain credentials. Disconnect does not erase backups or snapshots.
- The non-secret selection is atomically saved as mode 0600 in `<data-dir>/.integrations/llm-provider`, outside all cases. `.integrations` is gitignored even under custom data directories. Credentials, CLI output and the one-time code are not copied to report exports, case database rows or audit summaries. CLI-owned files remain sensitive and should not be included in case exports/backups shared with others.
- Authentication output is bounded to 16 KiB, held in memory and never reflected or logged. Only the validated link and a bounded code are exposed while waiting; status GET uses `Cache-Control: no-store`. The UI stores neither credentials nor device codes in local/session storage.
- Allowed authorization URL is **exactly** `https://auth.openai.com/codex/device`: HTTPS, exact host/path, no userinfo, query, explicit port, fragment or encoded path. Unexpected CLI formats/issuers fail closed. This route and prompt structure were inspected in OpenAI's [official device-auth source](https://github.com/openai/codex/blob/main/codex-rs/login/src/device_code_auth.rs), along with [CLI status output](https://github.com/openai/codex/blob/main/codex-rs/cli/src/login.rs); the installed `0.163.0-alpha.10.2` binary's help and route/prompt strings were checked. Future CLI changes may require a parser update. No custom OAuth implementation is involved.
- Commands get a reduced environment, no server keys or inherited access tokens, no stdin credentials, an isolated working directory, a deadline and whole-process-group cancellation. Auth and model commands explicitly select file credential storage and ChatGPT login mode (not the operator's OS keychain). Local CLI status is bounded to four seconds, logout to eight seconds and synthetic verification to 90 seconds. These are not retries against the provider.
- Existing model isolation is preserved: read-only sandbox, ephemeral runs, all existing tool-giving features disabled, ignore user configuration/rules, approvals never, prompt on stdin, empty temporary directory, bounded response, discarded stdout and no stderr in logs/errors/database.
- Check current provider terms and account data controls for the intended data. Tracefall cannot inspect these settings or promise entitlement, quota, retention, training policy, or suitability for sensitive casework.

## Provider precedence and case requests

`TRACEFALL_LLM_PROVIDER`, when explicitly nonempty, overrides the saved UI preference. Supported explicit values are `openai-compatible` and `codex-cli`; an unrecognized explicit value disables summaries rather than falling back. The UI explains the override and refuses selection changes with 409 until the variable is removed and the server restarted. Authorization/verification remain separate account operations, even when an environment-selected API provider is effective.

Without an explicit provider variable, the saved preference selects `codex-cli`, `openai-compatible`, or `none`. With no saved preference, the legacy API route is the default. Its settings remain `TRACEFALL_LLM_API_KEY`, `TRACEFALL_LLM_MODEL`, and optionally `TRACEFALL_LLM_BASE_URL`; no API key/model entry form is added. `TRACEFALL_LLM_MODEL` is also the optional Codex model override; empty lets the CLI choose its own default. A displayed model label is not independent model verification.

A shared synchronized configuration survives `Service.WithActor`/`WithRequest` copies. Each narrative pins one provider client from preparation through retries/completion. Provider/account changes are refused while a summary is active; an authorization/verification operation also blocks new summaries. The startup-only `SetLLM` path and existing API-client tests remain supported.

For case summaries, all existing gates still apply: non-local destinations require per-case `pseudonymized` egress **and a new per-request acknowledgement**. Pseudonymization, leak checks, anchored-answer validation, audit records and report labeling are unchanged. Setup, sign-in and verification never grant case egress or automatically generate a summary. The case's **Outside services** card links back to Settings.

## Administrative API

All routes below inherit centralized roles, forced-password-change restrictions, same-origin/request-source checks and authenticated-mode CSRF checks. Writes in local no-auth mode require `X-Tracefall-Client: dashboard` and a loopback Host. Authenticated requests also need the existing session and `X-Tracefall-CSRF` header. JSON bodies use the strict 4096-byte integration decoder with unknown fields rejected and generic parse errors.

| Method / path | Behavior |
|---|---|
| `GET /api/admin/integrations/chatgpt` | Bounded CLI status, availability, state/progress, ephemeral request verification, saved preference, effective provider and environment override. Link/code/deadline only while waiting. No raw output, account identity, token, key or credential path. |
| `PUT /api/admin/integrations/chatgpt` | `{"provider":"codex-cli"}` (also `openai-compatible`, `none`). Save non-secret preference; no model request. 409 on explicit environment override or active operation. |
| `POST .../authorize` | Start official device authorization, 202; 409 if active/busy, 503 when CLI/storage unavailable. No request body or credentials required. |
| `POST .../cancel` | Cancel pending authorization and wait for process termination, 204 (idempotent when idle). Not a synthetic-verification cancellation endpoint. |
| `DELETE /api/admin/integrations/chatgpt` | Disconnect isolated CLI session, verify local status, return status. 409 while busy. UI supplies confirmation; API callers deliberately choose DELETE. |
| `POST .../verify` | Requires `{"acknowledge":true}` or 403. Exactly the fixed synthetic prompt; arbitrary prompts/case identifiers rejected. 409 when disconnected/busy, 502 on failure, 200 with `{"request_verified":true}` only on successful client response. Request cancellation/deadline terminates the subprocess group; a failed/cancelled request may still have consumed quota. |

## Synthetic verification recipe (no real authorization or model calls)

No new npm dependencies are needed in the repository. The browser test requires the preinstalled external Playwright module and Chrome. **Never run it against a real CLI/server.** The test refuses writes unless a synthetic marker and fresh local stand-in status log confirm the disposable server actually used the fake CLI.

```bash
export GOCACHE=/home/udalah/.hermes/cache/scratch/gocache
export PLAYWRIGHT_MODULE=/home/udalah/.hermes/cache/scratch/tracefall-ux-tools/node_modules/playwright
# Choose a new empty scratch directory for each initial run.
export TF_BROWSER=/home/udalah/.hermes/cache/scratch/tf-chatgpt-browser-new
python3 -c 'import os,pathlib,re; d=pathlib.Path(os.environ["TF_BROWSER"]); d.mkdir(); s=pathlib.Path("internal/api/chatgpt_test.go").read_text(); (d/"codex").write_text(re.search(r"const settingsCodex = `(.+?)`",s,re.S).group(1)); (d/"codex").chmod(0o700); (d/"synthetic-only").write_text("tracefall-browser-synthetic-codex")'
go build -o "$TF_BROWSER/tracefall" ./cmd/tracefall
# Start this foreground command in a separate managed terminal; stop it by PID/session.
env -u TRACEFALL_LLM_API_KEY -u TRACEFALL_LLM_MODEL -u TRACEFALL_LLM_PROVIDER -u TRACEFALL_VT_API_KEY \
  TRACEFALL_CODEX_BIN="$TF_BROWSER/codex" "$TF_BROWSER/tracefall" \
  -host 127.0.0.1 -port 18937 -data-dir "$TF_BROWSER/data" -db "$TF_BROWSER/browser.db"
# In another terminal:
node tests/chatgpt.browser.cjs http://127.0.0.1:18937 "$TF_BROWSER/screenshots" "$TF_BROWSER"
# Actually stop/restart the exact server with the same data/db, then:
node tests/chatgpt.browser.cjs http://127.0.0.1:18937 "$TF_BROWSER/screenshots" "$TF_BROWSER" restart
```

The browser runner covers actual integration endpoints with a synthetic CLI: waiting link/code, cancellation, no automatic model call, separate provider selection, explicit synthetic verification, cleared acknowledgement, reload, real restart/preference persistence, confirmation/disconnect, and desktop/390px screenshots. The initial waiting focus assertion was observed failing before polling was fixed. Inspect screenshots rather than treating a DOM-only assertion as visual QA.

Existing `tests/integrations.browser.cjs` save/restart/remove and `tests/external-ux.browser.cjs` should also run. The external-UX runner requires a separate fresh/unconfigured disposable server, not the signed-in/selected server left by this new runner. Its populated provider responses are browser-mocked. VT test-connection remains mocked; no automated real VT calls occur.

Scoped gates:

```bash
go build ./...
go vet ./...
go test -race ./internal/enrich/llm ./internal/api \
  -run 'TestDevice|TestCodex|TestChatGPT|TestSetLLM|TestNarrative|TestUI_|TestVTIntegration' -count=1 -timeout=5m
go test -race ./internal/api -run TestChatGPTCancel -count=15 -timeout=2m
node --check internal/web/static/app.js
node --check tests/chatgpt.browser.cjs
# Optional installed CLI inspection in a fresh isolated home: help/status ONLY.
TRACEFALL_TEST_CODEX_BIN=/usr/lib/chatgpt/resources/codex \
  go test ./internal/enrich/llm -run TestInstalledCodexIsolatedNegativeControl -v
```

Not established by synthetic tests: a real device authorization, real account/token validity or refresh, real model/plan access or billing, a real model identity, current provider contractual/privacy eligibility, or Windows process isolation. Do not claim these from a synthetic green result. The full repository suite is separate from these scoped gates.
