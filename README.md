# TrustVault

Secure document sharing with a tamper-evident audit trail.

The wrong person can never read a file, and every read, denial and permission change is recorded in a hash-chained log that an administrator can verify.

## What it does

- Owners upload documents (PDF, PNG, JPEG, TXT, up to 10 MB) and share them with other users as **Read** or **Edit**.
- Every download is streamed through the API and re-checks permissions in the database, so revoking access takes effect on the very next request. There are no signed or long-lived URLs.
- Every action, including every **denied** attempt, is written to an append-only audit table. Each row stores the hash of the previous row, so editing or deleting a middle row is detected by `GET /api/audit/verify`.
- Administrators manage the audit log. They cannot read, download or share anyone's documents.

## Roles

| Role | Can do |
|---|---|
| Administrator | Read the whole audit log and verify the audit chain. No access to document contents. |
| Owner | Upload documents, grant and revoke access to their own documents, see audit events for their own documents. |
| Viewer | Read documents that have been shared with them. Cannot upload. |

Document-level access is separate from role. The owner has full rights on their document; anyone else needs an active grant (Read or Edit). Anything not explicitly allowed is denied.

A user with no access to a document gets **404**, the same answer as for a document that does not exist, so IDs cannot be probed. A user who can see a document but may not manage it gets **403**.

## Tech stack

- ASP.NET Core Web API (.NET 10) with ASP.NET Core Identity and HttpOnly cookie sessions
- Entity Framework Core with PostgreSQL 16
- Antiforgery (CSRF) token required on every POST, PUT, PATCH and DELETE
- xUnit integration tests through real HTTP endpoints, using a throwaway PostgreSQL container (Testcontainers)

## Run it with Docker Compose

Prerequisite: Docker Desktop (or Docker Engine with the Compose plugin).

```powershell
git clone https://github.com/Yaswitha2005-15/Trust-Vault-.git
cd Trust-Vault-
Copy-Item .env.example .env      # Linux/macOS: cp .env.example .env
# Edit .env and set your own DB_PASSWORD and SEED_DEMO_PASSWORD
docker compose up --build -d
```

The first build takes several minutes. On start, the API applies the database migrations and seeds three demo accounts. Wait about 15 seconds, then check it:

```powershell
curl.exe -i http://localhost:8080/api/auth/csrf
```

You should get `200 OK` and a JSON token. To stop it, run `docker compose down`. To also delete the database and uploaded files, run `docker compose down -v`.

`SEED_DEMO_PASSWORD` must be at least 12 characters with upper case, lower case, a digit and a symbol.

### Demo accounts

| Email | Role |
|---|---|
| `admin@trustvault.local` | Administrator |
| `owner@trustvault.local` | Owner |
| `viewer@trustvault.local` | Viewer |

The password for all three is the `SEED_DEMO_PASSWORD` value in your `.env`. Passwords are never committed to the repository.

### About HTTPS

The login cookie is marked `Secure` in production, which browsers only accept over HTTPS. The Compose file sets `Security__AllowHttpCookies=true` so the demo works on plain `http://localhost`. A real deployment should sit behind an HTTPS reverse proxy and leave that setting off.

## Using the API

There is no web UI and no Swagger page. Use the API directly. State-changing requests need a CSRF token: call `GET /api/auth/csrf`, keep the cookies, and send the returned token in the `X-XSRF-TOKEN` header.

| Method and path | Who | Purpose |
|---|---|---|
| `GET /api/auth/csrf` | Anyone | Get a CSRF token |
| `POST /api/auth/login` | Anyone | Log in with `email` and `password` (JSON) |
| `POST /api/auth/logout` | Signed in | Log out |
| `GET /api/auth/me` | Signed in | Current user and roles |
| `POST /api/documents` | Owner | Upload a document (multipart: `file`, `title`, optional `category`) |
| `GET /api/documents/{id}` | Owner or grantee | Document metadata |
| `GET /api/documents/{id}/content` | Owner or grantee | Download (always an attachment, `nosniff`, `no-store`) |
| `POST /api/documents/{id}/permissions` | Document owner | Grant `Read` or `Edit` to a user by email (JSON: `userEmail`, `level`) |
| `DELETE /api/documents/{id}/permissions/{userId}` | Document owner | Revoke access |
| `GET /api/audit` | Administrator, Owner | Audit events (owners see only their own documents) |
| `GET /api/audit/verify` | Administrator | Recompute the hash chain and report whether it is intact |

## Run the tests

Docker must be running, because the tests start a fresh PostgreSQL container.

```powershell
dotnet test
```

Last verified result: **31 passed, 0 failed.**

### Mutation check

To show that the tests really protect the authorisation logic, the `no_grant` deny line in `DocumentAuthorizationService.AuthorizeAsync` was commented out. With that single check removed, **9 of the 31 tests failed**, and any logged-in user could read other people's documents. The full output is saved in `mutation-output.txt`. The code was then restored and all 31 tests pass again.

## Security design (short version)

- **One decision point.** `DocumentAuthorizationService.AuthorizeAsync` is the only place access is decided. It returns an `AuthorizedDocument` that only that service can create, and file storage will only open a file for an `AuthorizedDocument`. No authorisation, no bytes.
- **Deny by default, no caching.** Grants are re-read from the database on every request.
- **Private storage.** Files are stored as `{random-guid}.bin` in a private folder. The user's file name is never used as a path.
- **Upload checks.** Extension allowlist, size limit, file-signature check, server-chosen content type.
- **Audit in the same transaction.** For successful actions the business change and its audit row commit together, or neither does. Denied attempts are always denied; if recording the denial fails, the failure is logged.
- **Sessions.** Account status and the security stamp are checked on every request, so a deactivated user loses access immediately.

See `THREATS.md` for the threat model, the tests behind each threat, and the known limitations.

## Known limitations

Listed honestly in `THREATS.md`. The main ones: no web UI, no edit, delete or search endpoints, and the audit chain has no external anchor. In the Compose setup the API connects to PostgreSQL as the database owner, so the append-only database permissions in `deploy/audit-permissions.sql` are not applied. Tamper detection there relies on the hash chain only.# TrustVault
