cd C:\Users\ymukk\projects\trustvault
@'
# PROMPTS.md

AI-assistance log for TrustVault. Each entry records a prompt, what came back, a specific problem I found, what I changed, and the fixing commit.

## Entry 1: Deactivated user kept a working session (2026-10-24)

**Prompt (summary):** I asked Claude for integration tests covering login, CSRF, lockout and sessions.

**Output:** Integration tests for auth, CSRF, lockout and session handling (commit afcd3cd).

**Mistake or limitation I found:** A test I added for deactivated users failed: a user whose account was deactivated could keep using a session that was already issued (commit 3bfc30c, a deliberately failing test). The existing session was accepted without checking that the account was still active.

**What I changed:** The session is now rejected on every request when the account is inactive, so deactivation takes effect immediately.

**Commit:** https://github.com/Yaswitha2005-15/Trust-Vault-/commit/a840f26

**Area:** authorisation

## Entry 2: Audit events had no request/correlation identifier (2026-10-24)

**Prompt (summary):** I asked Claude to write a hash-chained audit service with fail-closed writes (commit f1f3f7f).

**Output:** `AuditService` with an advisory lock on the chain and audit writes inside the caller's transaction.

**Mistake or limitation I found:** When I asked Claude to review the audit code against the project spec, the review found that audit rows had no request or correlation identifier, which the spec requires. The chain could say what happened but not which request caused it.

**What I changed:** Added a `CorrelationId` column, set from a per-request ID that is also returned in the `X-Correlation-Id` header, and included it in the row hash. It is only hashed when present, so older rows still verify. All 32 tests still passed. There is not yet a test that checks the header matches the audit row.

**Commit:** https://github.com/Yaswitha2005-15/Trust-Vault-/commit/3a958f4

**Area:** audit integrity

## Entry 3: Proving the authorisation tests actually matter (2026-10-24)

**Prompt (summary):** I asked how to show that removing a critical authorisation check makes a test fail, as the spec requires.

**Output:** A controlled run with the `no_grant` check removed from the central authorisation service.

**Mistake or limitation I found:** With the check removed, 9 of the 31 tests failed, which shows the checks are covered. The limitation is that I only removed one check, by hand, so other checks have not been mutated. The saved output file also had the wrong encoding, so I re-saved it as UTF-8 (commit 903bccb).

**What I changed:** Recorded the run in `mutation-output.txt` and referenced it in THREATS.md, with the count stated as "9 of the 31 tests that existed at the time" since the suite has since grown to 32.

**Commit:** https://github.com/Yaswitha2005-15/Trust-Vault-/commit/9f62bd7

**Area:** authorisation

## Entry 4: Global CSRF filter made every request return 500 (2026-10-23)

**Prompt (summary):** I asked Claude for CSRF protection on every POST/PUT/PATCH/DELETE with cookie authentication.

**Output:** `Program.cs` registering an antiforgery filter on all controllers with `AddControllers`.

**Mistake or limitation I found:** The csrf endpoint returned HTTP 500. The server