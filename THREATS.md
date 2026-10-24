# TrustVault: threat model

## Assets and trust boundaries

- **Assets:** document contents, who-can-access-what (grants), the audit log, user sessions.
- **Browser to API:** everything from the client is hostile: IDs, file names, content types, JSON fields.
- **API to database:** parameterised EF Core queries only.
- **API to file store:** private folder, only reachable by the API process.
- **Administrator:** can read the audit log and verify the chain, and has no access to document contents. Users are created by the seeder only; there are no user-management endpoints. A compromised admin account is treated as a realistic threat.

## Threats, mitigations and evidence

| Threat | Mitigation | Evidence (test) |
|---|---|---|
| Reading another user's document by ID (BOLA/IDOR) | All access goes through `DocumentAuthorizationService.AuthorizeAsync`, deny by default | `User_without_a_grant_cannot_read_metadata_or_download` |
| Probing which IDs exist | No access and "does not exist" both return 404 | `Guessed_document_id_gets_the_same_answer_as_an_unauthorised_one` |
| Administrator reading or sharing documents | No admin bypass in the authorisation service | `Administrator_cannot_read_or_download_someone_elses_document`, `Administrator_cannot_grant_access_to_someone_elses_document` |
| Access surviving after revoke | No signed URLs, grants re-read from the database on every request | `Revoked_grant_stops_access_on_the_very_next_request`, `Owner_can_grant_and_revoke_through_the_api` |
| Non-owners changing permissions | `ManagePermissions` is owner-only; 403 if you can see the document, 404 if you cannot | `Only_the_owner_can_manage_permissions` |
| Role escalation (Viewer uploading, non-admin reading audit) | Role checks; audit endpoints restricted | `Viewer_role_cannot_upload`, `Viewer_cannot_read_the_audit_log_or_verify_it` |
| Deactivated user keeping an old session | Account status and security stamp checked on every request | `SessionTests.cs` (found by a failing test, commit `3bfc30c`, fixed in `a840f26`) |
| Disguised executable or wrong file type | Extension allowlist plus file-signature check, server-chosen content type | `Executable_disguised_as_pdf_is_rejected`, `Disallowed_extension_is_rejected` |
| Browser rendering uploaded content | Always `attachment`, `application/octet-stream`, `nosniff`, `no-store` | `Owner_can_upload_and_download_their_own_document` |
| Audit log tampering | Hash chain; `GET /api/audit/verify` reports the first broken row | `Tampering_with_an_audit_row_is_detected`, `Verify_reports_an_intact_chain` |
| Actions without an audit record | Success rows are written in the same transaction as the change (fail closed) | `Successful_upload_and_download_are_audited` |
| Probing without a trace | Denied attempts are audited with the real reason | `Denied_download_is_audited_with_the_real_reason`, `Upload_by_a_viewer_is_denied_and_audited`, `Grants_revokes_and_denied_attempts_are_audited` |
| Owners seeing other people's audit events | Owner view filtered to documents they own | `Owner_sees_only_audit_events_for_their_own_documents` |
| Unauthenticated access | Controllers require authentication | `Anonymous_request_gets_401` |
| Granting to nonexistent users or invalid levels | Input validation | `Unknown_user_or_invalid_level_is_rejected` |

Evidence that the authorisation tests matter: with the `no_grant` check removed, 9 of 31 tests failed (see `mutation-output.txt`). All 31 pass with the check restored.

## Controls in place but not directly tested

- **Path traversal:** storage names are generated GUIDs and the user's file name is never used in a path. There is no dedicated test with a name like `../../x`.
- **Mass assignment:** upload binds only `file`, `title` and `category`; the owner always comes from the session. No dedicated test.
- **CSRF:** an antiforgery filter is applied to every controller in `Program.cs`. VERIFY: check `AuthTests.cs` for a test that sends a POST without the token. If there is none, keep this line as it is.
- **SQL injection:** all queries use EF Core LINQ, with one fixed raw SQL statement for the audit lock. There are no search endpoints, so there is no user-controlled query text.
- **Request size limits:** the upload endpoint sets a size limit. The test server logs that it cannot apply the limit, so this is not exercised by tests. It would apply under Kestrel.
- **Audit table permissions:** `deploy/audit-permissions.sql` restricts the app's database role to SELECT and INSERT on the audit table. It has not been run or tested.

## Known limitations (unfinished or accepted)

1. **No web UI.** The app is API-only.
2. **Missing endpoints:** edit/replace, delete and search are not implemented. Soft delete exists in the data model, but no endpoint uses it.
3. **Audit detail lives in the action text.** There is no separate detail column. Grant and revoke events carry level and target in the action string, which is covered by the hash.
4. **No external anchor for the audit chain.** Anyone with full control of the database could rewrite every row and recompute the chain. Deleting the newest rows is not detected without an externally stored head hash. `GET /api/audit/verify` returns `headHash` so it can be stored somewhere write-once.
5. **Anonymous requests (401) are not audited.**
6. **Denied-attempt audit failures are logged, not fail-closed.** Access is still denied. Successful actions are fail-closed. DECIDE: write your own reasoning for this split here.
7. **Metadata views are audited,** so the audit table grows quickly at scale. Appends are serialised with a database advisory lock, which limits write throughput.
8. **In-flight downloads:** a download that has already started can finish after a revoke. The check happens at stream start.
9. **`.txt` signature check** only looks at the first 512 bytes for NUL characters. DECIDE: write whether this matters, given that every download is an attachment with `nosniff`.
10. **Deactivated owner:** grants are not removed when an owner's account is deactivated, so grantees keep access. DECIDE: write whether that is the behaviour you want, and why.
11. **No rate limiting** beyond Identity account lockout.
12. **No purge job, backup or retention policy.**
13. **"Edit" grants give nothing beyond "Read" yet.** The Edit level exists and is validated, but there is no edit endpoint.
14. **No user-management endpoints.** Accounts are created by the seeder; there is no registration, role-change or deactivation endpoint. Deactivation and role changes are enforced if made directly in the database (see `SessionTests`).
15. **Container demo setup:** the Compose file lets the login cookie work over plain HTTP, connects to PostgreSQL as the database owner (so `deploy/audit-permissions.sql` is not applied), and does not persist the ASP.NET data-protection keys, so sessions end when the container is recreated. A real deployment needs HTTPS and a separate, restricted database role.
16. **Uploaded content is not scanned for malware.** Files are only type-checked, size-limited and served as attachments.# Threat model
