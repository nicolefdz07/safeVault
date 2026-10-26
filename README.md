# SafeVault

A small ASP.NET Core 8 web application that demonstrates secure coding practices:
**input validation, SQL-injection prevention, XSS prevention, authentication (JWT) and role-based access control (RBAC)**,
with an automated NUnit test suite that verifies each protection.

## Project layout

```
src/SafeVault/
  Controllers/   AuthController (register/login), VaultController (any logged-in user), AdminController (admin only)
  Data/          UserRepository (parameterized SQL, SQLite), User, Roles
  Services/      InputValidator, PasswordService (BCrypt), TokenService (JWT)
  wwwroot/       index.html + app.js (web form; output written with textContent)
tests/SafeVault.Tests/
  TestInputValidation.cs   allow-list validation + malicious payloads
  TestSqlInjection.cs      SQL injection against the real repository + SQLite
  TestXss.cs               HTML encoding of XSS payloads
  TestAuthorization.cs     end-to-end auth + RBAC through the real HTTP pipeline
.github/workflows/dotnet.yml   CI: build + run tests on every push
```

## Run it

```bash
dotnet restore
dotnet test                                   # run the security test suite

# run the app (Development: a random JWT key is generated per run)
export Seed__AdminPassword='Choose-A-Strong-Passw0rd'   # optional: creates user "admin" with role admin
dotnet run --project src/SafeVault
```

Outside Development you **must** set `Jwt__Key` (>= 32 bytes) via environment variables or a secret store.
No keys or passwords are committed to the repository.

## API

| Endpoint | Access | Purpose |
|---|---|---|
| `POST /api/auth/register` | public (rate limited) | create a user (always role `user`) |
| `POST /api/auth/login` | public (rate limited) | returns a JWT |
| `GET /api/vault/me`, `/api/vault/profile` | any authenticated user | identity / HTML-encoded profile page |
| `GET /api/admin/users`, `/api/admin/users/search?q=` | role `admin` only | list / search users |

## Summary: vulnerabilities, fixes and Copilot assistance

### Vulnerabilities identified and fixes applied

| # | Vulnerability | Typical vulnerable pattern | Fix applied | Where |
|---|---|---|---|---|
| 1 | **SQL injection** | `"SELECT * FROM Users WHERE Username = '" + input + "'"` | Parameterized queries (`@username`) everywhere; `LIKE` wildcards escaped; DB role constrained with `CHECK` | `UserRepository.cs` |
| 2 | **Missing / weak input validation** | accepting any string for username, email, password | Allow-list regexes anchored with `\z`, length limits, password complexity; validation on the server even though the form also validates | `InputValidator.cs`, `AuthController.cs` |
| 3 | **Cross-site scripting (XSS)** | writing user input into HTML / `innerHTML` unencoded | `WebUtility.HtmlEncode` on every value echoed in HTML; client uses `textContent`; CSP `script-src 'self'`; `X-Content-Type-Options` | `InputValidator.SanitizeForHtml`, `VaultController`, `app.js`, `Program.cs` |
| 4 | **Plain-text / weak password storage** | storing the password as typed | BCrypt (work factor 12) with per-password salt | `PasswordService.cs` |
| 5 | **Broken authentication** | revealing whether a username exists; unlimited guesses | identical generic 401 for unknown user and wrong password, dummy hash verification to even out timing, rate limiting on auth endpoints | `AuthController.cs`, `Program.cs` |
| 6 | **Broken access control / privilege escalation** | any logged-in user can reach admin data; role taken from request body | JWT auth + `[Authorize(Roles = "admin")]`; registration ignores any `role` field; password hashes never returned | `AdminController.cs`, `AuthController.cs` |
| 7 | **Secrets in source** | hard-coded JWT key / admin password | key and seed password come only from configuration / environment | `Program.cs` |

### How the fixes were verified
Every item above has automated tests (see `tests/`). Examples: `' OR '1'='1` and `'; DROP TABLE Users; --` return no rows and leave the
table intact; `<script>` payloads are rejected at registration and encoded on output; a normal user gets **403** on `/api/admin/*`,
an anonymous caller gets **401**, and only an admin gets **200**. CI runs the suite on each push.

### How Copilot assisted
> ✏️ **Edit this section so it reflects your real Copilot sessions** (what you asked, what it produced, what you changed).
> Suggested prompts to run in Copilot and then describe here:

* **Secure code (input validation + SQL injection):** *"Write C# code that validates username and email from a web form using allow-list rules and stores them in a database using parameterized queries to prevent SQL injection."*
* **Authentication / RBAC:** *"Implement JWT authentication and role-based access control with `admin` and `user` roles in ASP.NET Core, hashing passwords with BCrypt."*
* **Debugging:** *"Review this code for SQL injection and XSS vulnerabilities and suggest fixes."* → note which findings Copilot reported and which fixes you accepted or rejected.
* **Tests:** *"Generate NUnit tests that send SQL injection and XSS payloads and verify they are rejected/encoded, plus tests that a normal user cannot access admin endpoints."*

## Possible future work
Account lockout after repeated failures, refresh tokens / revocation, audit logging, HTTPS-only cookies if sessions replace JWT, and a CSRF
token if cookie-based authentication is ever added.
