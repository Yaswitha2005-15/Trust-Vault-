\# TrustVault project context



Secure document sharing with a real audit trail. Stack: ASP.NET Core (.NET 10) controllers, EF Core, PostgreSQL, Identity with cookie auth, xUnit integration tests.



\## Security rules (never break these)

\- Authorise on the server for every route. Hidden buttons are not security.

\- All document access goes through DocumentAuthorizationService. Deny by default.

\- A user with no access to a document gets 404, not 403.

\- Never trust client input: IDs, filenames, content types, roles, owner fields.

\- Use explicit DTOs. Never bind request bodies directly to entities.

\- Files are stored under server-generated GUID names in a private directory. Never serve from the web root, and never use signed URLs.

\- Every download streams through the API and re-checks the database.

\- Audit every sensitive action and every denied attempt. The audit row is written in the same transaction as the action.

\- Never log passwords, tokens or document contents.

\- Never claim a test passed unless the real output was shown.



\## Roles

\- Administrator: manages users and roles, reads the audit log. Cannot read document contents. Cannot grant access.

\- Owner: uploads documents, grants and revokes access on their own documents.

\- Viewer: reads or downloads documents shared with them.

\- Per-document permissions: Read, Edit (Edit includes Read).

