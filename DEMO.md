# Five-minute demo plan
Run: `docker compose up --build -d`, wait about 15 seconds, then `powershell -ExecutionPolicy Bypass -File .\demo.ps1` (press Enter between steps).
| Time | Step | Say |
|---|---|---|
| 0:00 | Goal | Documents only reach people explicitly authorised, and every action, including denials, is audited. |
| 0:30 | Step 1-2 | Cookie login with a CSRF token; the owner uploads a PDF, which is validated and stored under a generated ID outside any public folder. |
| 1:30 | Step 3 | A viewer with no grant gets 404 for the real ID and for a made-up ID, so IDs cannot be probed. |
| 2:15 | Step 4 | The owner grants Read to one named user; the viewer downloads (200). |
| 2:45 | Step 5 | Revocation applies on the next request, because grants are read from the database each time and there are no signed URLs. |
| 3:30 | Step 6 | An administrator cannot read file contents; there is no admin bypass. |
| 4:00 | Step 7-8 | The audit log shows the upload, the denied attempts, the grant and the revoke, and the hash chain verifies. |
| 4:40 | Close | Show THREATS.md: removing the `no_grant` check fails 9 of 31 tests. Then state the gaps: no UI, no delete/search/edit endpoints, no external anchor for the audit chain. |
