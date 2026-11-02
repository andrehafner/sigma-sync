# CLAUDE.md — AAP App Development Reference (Oracle Linux 9 / Apache / Shibboleth)

This is the reference for AAP Perl CGI apps on the **new** Linux stack. The old
Windows/IIS/NTLM box is gone; everything below assumes Oracle Linux 9 + Apache
(httpd) + Shibboleth SP + MariaDB. If you are migrating an app off the old IIS
server, this doc plus `DEPLOY.md` is the full picture.

## Environment

- **Hosts:** two vhosts, **identical setup behind both** — only the audience differs:
  - `private.aap.cornell.edu` — internal Cornell networks only
  - `public.aap.cornell.edu` — externally reachable
  Same app root, same Apache/Shibboleth/MariaDB config, same `/apps/APP` paths on each. The
  app is told which host it's building for; write host-agnostic code (relative URLs, or
  `BASE_URL`/`cfg()` from the env file) so the same checkout serves either vhost unchanged.
- **URL:** `https://private.aap.cornell.edu/apps/APP/` or `https://public.aap.cornell.edu/apps/APP/`
- **App root:** `/data/AAP_Storage/apps/APP/` (URL-served at `/apps/APP`)
- **Stack:** Perl CGI + MariaDB + vanilla HTML/JS/CSS on Oracle Linux 9, Apache httpd
- **OS facts:** SELinux **ENFORCING**, suEXEC enabled, Apache runs CGI as user `apache` (uid 48)
- **Auth:** Cornell **Shibboleth SP**. IdP releases `eppn` (= `netid@cornell.edu`) and
  usually `affiliation`/`entitlement`. Do **not** assume `uid`/`displayName`/`mail` are released.
- **Users identified by:** Cornell NetID (lowercase bare netid, e.g. `abc123`)
- **SMTP:** `appsmtp.mail.cornell.edu`, addresses are `{netid}@cornell.edu`
- **Secrets:** one env file per app at `/data/AAP_Storage/secrets/APP.env` (outside the app tree)
- **Uploads:** external, at `/data/AAP_Storage/apps/uploads/APP` (outside the app tree)
- **Logs:** the HTTPS vhost writes to `/var/log/httpd/ssl_error_log` — **NOT** `error_log`.
  When debugging, always read the SSL log.

## The Golden Rule (read this first)

**Any operation that WRITES a file in the app tree — `git pull`, editor save, `sed -i`,
`cp` — resets that file's SELinux label and ownership, and httpd then fails to read/exec
it (403/500).** After EVERY pull or edit on the server:

```bash
cd /data/AAP_Storage/apps/APP && sudo ./redeploy.sh
```

- **Corollary 1:** `restorecon` only applies fcontext rules that already exist. If you run
  `redeploy.sh` before the one-time `semanage fcontext` rules are installed, it prints
  "Done" while leaving every file `default_t` (httpd can't read/exec `default_t`).
  `redeploy.sh` must verify the resulting `.pl` label and warn loudly when it's wrong.
- **Corollary 2:** this same "pulls clobber the tree" hazard is why **user uploads live
  OUTSIDE the app tree**. `redeploy.sh` must NOT manage the upload dir.

Never hand-run `chown`/`restorecon` piecemeal — `redeploy.sh` does it correctly and idempotently.

## Layout & Per-App Deliverables

Flat app directory, no build tools, no frameworks, no bundlers:

```
api.pl              # ALL backend logic — single file, action-routed
app.js              # ALL frontend JS — state, API calls, rendering
style.css           # Shared styles using CSS custom properties
index.html          # Main page
AppConfig.pm        # Shared module: current_netid(), db_creds(), cfg(), is_admin()/require_admin(), exec helpers
redeploy.sh         # Re-applies owner/perms/SELinux labels — run after every write to the tree
deploy/APP.conf     # Apache include (aliases, Shibboleth Location, admin LocationMatch)
APP.env.example     # Template for /data/AAP_Storage/secrets/APP.env (NO real secrets)
DEPLOY.md           # Exact server-side steps + verification GATES + troubleshooting tree
.gitattributes      # Enforce LF: *.pl text eol=lf (and .pm/.cgi/.py/.sh)
```

- Work on the designated git branch, normalize to **LF**, commit with clear messages, push.
  Do not open a PR unless asked.
- **Bundled assets** (logos, icons shipped with the app) stay in the app tree with their
  own relative path — they are deployed content, not user uploads.

## Secrets / Config

- One secrets file per app: `/data/AAP_Storage/secrets/APP.env` (`KEY=VALUE` lines).
- Apache passes its path to the app: `SetEnv APP_ENV_FILE /data/AAP_Storage/secrets/APP.env`
- Keys: `DB_HOST`, `DB_USER`, `DB_PASSWORD`, plus app-specific (`BASE_URL`, `ADMINS`,
  `UPLOAD_DIR`, `UPLOAD_URL`, and Oracle keys if applicable).
- The secrets file lives **outside** the app tree, so it needs its **own** fcontext rule and
  its own `restorecon`. An in-place edit resets its label — re-run `restorecon` on it.
- Provide a generic accessor in the shared module: `cfg(KEY, default)` reads any env key, so
  new app-specific config needs no new code.
- **Never** slurp a Windows password file (`E:\dbaccess\...txt`). A bare-password file will
  NOT work; the parser looks for `DB_PASSWORD=`.

## Backend Rules (api.pl)

**The JSON header MUST print before ANY other output.** Still the #1 bug source. If anything
prints first (warnings, errors, debug), Apache returns 500 ("End of script output before headers").

```perl
my $cgi = CGI->new;
print $cgi->header(-type => 'application/json', -charset => 'utf-8');
```

**Shared module** — load once, use everywhere, so all scripts stay consistent:

```perl
use FindBin;
use lib $FindBin::Bin;
use AppConfig qw(current_netid db_creds cfg is_admin require_admin);
```

**Action router** — all requests hit `api.pl` with an `action` param via a dispatch hash:

```perl
my $action = $cgi->param('action') || '';
my %actions = ( 'get_items' => \&get_items, 'create_item' => \&create_item, ... );
$actions{$action}->() if exists $actions{$action};
```

**Every response:** `{ success: 1, ... }` or `{ success: 0, error: "..." }`

```perl
sub die_json    { print encode_json({ success => 0, error => $_[0] }); exit; }
sub success_json { $_[0]->{success} = 1; print encode_json($_[0]); }
```

**Auth pattern (Shibboleth)** — read the env vars; strip the domain; lowercase. There is NO
`Win32`/NTLM anymore. Remove all `use Win32`, `eval { require Win32 }`, `Win32::*` calls.

```perl
sub current_netid {
    my $u = $ENV{REMOTE_USER} || $ENV{uid} || $ENV{eppn} || '';
    $u =~ s/\@.*$//;     # eppn is netid@cornell.edu -> bare netid
    return lc $u;        # existing DB rows store bare lowercase netids
}
```

Domain-stripping + lowercasing is **mandatory** or ownership checks and name lookups silently fail.

**DB connection** — connect over TCP as the per-app user (never root). Wrap in `eval`, return
JSON error on failure:

```perl
my $c = db_creds();   # parses APP_ENV_FILE for DB_HOST/DB_USER/DB_PASSWORD
$dbh = DBI->connect(
    "DBI:mysql:database=$c->{db};host=$c->{host}",   # host=127.0.0.1 forces TCP
    $c->{user}, $c->{pass},
    { RaiseError => 1, AutoCommit => 1, mysql_enable_utf8 => 1 });
```

DSN stays `DBI:mysql:` — `perl-DBD-MySQL` works against MariaDB. Use `host=127.0.0.1` (an IP
forces TCP and avoids the unix-socket permission trap); never `host=localhost`, never root.

**Always normalize NetIDs:** `$netid = lc($netid); $netid =~ s/\s+//g;`

**Empty dates:** HTML date inputs send `""` not NULL. Convert before SQL:
`$date = undef if !$date || $date eq '';`

### Authorization (this is now harder than on IIS — read carefully)

On IIS the intranet was the trust boundary. **Under Shibboleth, EVERYONE at Cornell is
authenticated**, so an ungated page or an unscoped query is now a university-wide hole.

- **Enforce authorization server-side on every action** — every API call, record lookup,
  export, delete. Checking permission on page load is not enough.
- **Stop trusting submitted identity.** Never trust hidden `netid` fields, `?netid=` params,
  or numeric record IDs. Scope EVERY read/write to the authenticated netid (e.g. keep
  `AND netid=?` on updates) or you have an IDOR.
- **Admin pages need a real gate.** Add an allowlist check (`require_admin`) in code AND
  restrict the URL at Apache/Shibboleth (`Require shib-attr eppn ...@cornell.edu`). An admin
  page with no role check is exposed to all of Cornell.
- **DBI placeholders everywhere.** No string interpolation in SQL — replace
  `"...WHERE id='$id'"` with placeholders + `execute($id)`. No exceptions.

## Frontend Rules (app.js)

**All API calls use POST with FormData** — never GET, never JSON body. CGI.pm reads POST form data.

```javascript
async function apiCall(action, params = {}) {
    const formData = new FormData();
    formData.append('action', action);
    Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== null) formData.append(k, v);
    });
    const response = await fetch('api.pl', { method: 'POST', body: formData });
    const data = await response.json();
    if (!data.success) throw new Error(data.error || 'Unknown error');
    return data;
}
```

**Init flow:** check_permission → update header with username → load data → setup listeners → handle URL deep-links

**Always escape user content before innerHTML:** `escapeHtml(text)` replacing `& < > " '`.
The old IIS app may have echoed input raw — escape it for its rendering context (HTML body/attr, URL, JS).

**Render pattern:** map arrays to HTML template-literal strings, `.join('')`, assign to `container.innerHTML`.

**Hardcoded URLs:** replace any baked-in host (e.g. `share.aap.cornell.edu`) with a value from
the env file or a relative URL. Search the whole tree for the old host.

## CSS

Use CSS custom properties. Cornell red is `#b31b1b`. System font stack. Semantic color tokens
for success/warning/error/info. Full variable set is in `style.css` — copy from any working app.

## Database (MariaDB)

- Primary key: `id INT AUTO_INCREMENT`
- Booleans: `TINYINT(1) DEFAULT 0` with `is_` prefix
- Always have: `permissions` table (netid + access_level), `users` table (netid + firstname + lastname)
- Change tracking: `*_history` table with record_id, field_name, old_value, new_value, changed_by, changed_at
- **Each app gets its OWN MariaDB user**, granted ONLY on the app's DBs, connecting over TCP
  `127.0.0.1`. Create **BOTH** host forms — `@'127.0.0.1'` AND `@'localhost'` — with the same
  password, because MariaDB may reverse-resolve a `127.0.0.1` TCP connection to `localhost`:

```sql
CREATE DATABASE IF NOT EXISTS APP CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'APP_app'@'127.0.0.1' IDENTIFIED BY 'STRONG_PW';
CREATE USER IF NOT EXISTS 'APP_app'@'localhost' IDENTIFIED BY 'STRONG_PW';
GRANT SELECT,INSERT,UPDATE,DELETE ON APP.* TO 'APP_app'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE,DELETE ON APP.* TO 'APP_app'@'localhost';
FLUSH PRIVILEGES;
```

- **GATE** (run before any browser test): `mysql -u APP_app -p -h 127.0.0.1 APP -e 'SELECT 1;'`
- `root@localhost` uses `unix_socket` auth (apache can't use it). Use the per-app user.

## Oracle Data Mart (include ONLY if the app reads the Student Data Mart / Oracle)

None of the old IIS Oracle setup (DBD::Oracle + full client + LDAP/tnsnames `ORACLE_ALIAS`)
exists on a fresh EL9 box. Full steps + troubleshooting subtree go in `DEPLOY.md`.

1. **Driver is not packaged.** `perl-DBD-Oracle` is not in stock/EPEL — build it against the
   Oracle Instant Client (version-pinned in the package name; there is no bare `-basic`):

   ```bash
   sudo dnf install -y oracle-instantclient-release-el9
   dnf list available 'oracle-instantclient*'        # pick newest 19.x basic + devel
   sudo dnf install -y oracle-instantclient19.NN-basic oracle-instantclient19.NN-devel
   sudo dnf install -y perl-DBI perl-devel gcc make libaio
   sudo ORACLE_HOME=/usr/lib/oracle/19.NN/client64 \
        LD_LIBRARY_PATH=/usr/lib/oracle/19.NN/client64/lib \
        PERL_MM_USE_DEFAULT=1 cpan -i DBD::Oracle
   perl -MDBD::Oracle -e 'print "ok\n"'              # VERIFY
   ```

2. **No runtime `LD_LIBRARY_PATH`.** The RPM registers `libclntsh.so` with ldconfig, so httpd,
   timers, and cron find the libs automatically. Do NOT add `LD_LIBRARY_PATH` to the env file,
   Apache conf, or crontab. If `libclntsh.so: cannot open shared object file` appears, the
   ldconfig registration is missing — drop `/etc/ld.so.conf.d/oracle.conf` and run `ldconfig`.

3. **Resolve the alias once, then go file-free.** The old `ORACLE_ALIAS` won't resolve on EL9
   (ORA-12154). Don't reproduce `ldap.ora`/`tnsnames.ora`. On a box that still has the working
   client, run `tnsping ORACLE_ALIAS`, read the `(DESCRIPTION ...)`, and convert host/port into
   a DBD::Oracle attribute DSN. **Check SID vs SERVICE_NAME — different syntax:**

   ```
   SID:          ORACLE_DSN=dbi:Oracle:host=HOST;sid=SID;port=1521
   SERVICE_NAME: ORACLE_DSN=dbi:Oracle:host=HOST;service_name=NAME;port=1521
   ```

   Using `sid=` for a service (or vice-versa) yields ORA-12505 / ORA-12514.

4. **Secrets via the env file.** Add `ORACLE_DSN`, `ORACLE_USER`, `ORACLE_PASSWORD`; read with
   `cfg()` in the shared module (`oracle_creds()`). After editing the secrets file, re-run
   `restorecon` on it (the edit resets its label and httpd can't read it).

5. **Network + SELinux.** The Oracle host is often an AWS RDS endpoint; the box needs outbound
   reach on 1521 (`nc -zv HOST 1521`). A timeout is a security-group/firewall gap (add this
   host's IP), not a DSN bug. For the web path: `sudo setsebool -P httpd_can_network_connect_db 1`.

6. **Safety.** Keep the Oracle account **READ-ONLY** and validate any admin-supplied query is
   `SELECT`/`WITH` only. Any datamart/read error must ABORT the run with ZERO writes (never
   treat a failed query as "remove everyone").

**GATE** (proves driver + DSN + creds + 1521, before any browser/cron test):

```bash
APP_ENV_FILE=/data/AAP_Storage/secrets/APP.env perl -MAppConfig -MDBI -e '
  my $c=AppConfig::oracle_creds();
  my $d=DBI->connect($c->{dsn},$c->{user},$c->{pass},{RaiseError=>1});
  print "Oracle OK: ", $d->selectrow_array("select 1 from dual"), "\n";'
```

## File Uploads (if applicable)

- **Storage location:** write uploads OUTSIDE the app tree (a `git pull`/`redeploy.sh` resets
  labels and can wipe in-tree dirs). Read the location from the env:

  ```perl
  use AppConfig qw(... cfg);
  my $upload_dir = cfg('UPLOAD_DIR', "$FindBin::Bin/uploads");        # fs write path
  my $upload_url = cfg('UPLOAD_URL', 'uploads'); $upload_url =~ s{/+$}{};  # URL prefix
  ```

  Defaults keep in-tree behavior for dev; production points `UPLOAD_DIR` at
  `/data/AAP_Storage/apps/uploads/APP` and `UPLOAD_URL` at `uploads` (the Apache alias).
- **Store only the filename** in the DB; build the URL at render time as `"$upload_url/$filename"`.
  Never store absolute server paths or the old `E:\` path.
- **Validate on write:** allowlist the extension/content-type (and signature where practical),
  enforce a size limit, and RENAME server-side (e.g. `<netid>_<epoch>.<ext>`). Never trust the
  client filename.
- The uploads Apache alias is static (`Options None`, no `ExecCGI`), so an uploaded `.pl` can't
  run — but validate anyway. The **more-specific `/apps/APP/uploads` alias must come BEFORE the
  app alias**, or Apache matches `/apps/APP` first and the upload 404s.

## Common Gotchas

1. **Header before output** — any print/warn/die before `$cgi->header()` = 500 ("End of script
   output before headers").
2. **`@` in `qq{}`** — CSS `@media` in Perl strings interpolates as an array. Use `\@media` or
   a heredoc `<<'HTML'`.
3. **`=>` in `qq{}`** — CSS fat arrows confuse Perl. Use heredocs for embedded CSS.
4. **CRLF line endings** — a CRLF shebang makes Apache fail with `exec ... No such file or
   directory`. Convert all `.pl/.pm/.cgi/.py/.sh` to LF (`sed -i 's/\r$//' *.pl` then
   `sudo ./redeploy.sh`, since sed drops the label). Ship `.gitattributes` with `eol=lf`.
5. **`.pl` downloads as text / Permission denied on exec** — SELinux label wrong
   (`content_t`/`default_t`, not `httpd_sys_script_exec_t`). Fix fcontext overlap, ensure the
   `.pl` rule exists, `sudo ./redeploy.sh`, confirm with `ls -Z`.
6. **403 ambiguity** — the httpd "search permissions are missing on a component of the path"
   message appears for BOTH a real DAC perm bit AND an SELinux `default_t` denial. Decisive
   test: `sudo setenforce 0` + reload. Works → SELinux (put back `setenforce 1`, apply fcontext
   rules, redeploy). Fails → DAC (`namei -l <path>` for a parent dir missing `o+x`).
7. **500 right after a git pull / edit** — the written file lost its SELinux label/owner. Run
   `sudo ./redeploy.sh`.
8. **"redeploy said Done but still 403/500"** — `restorecon` no-opped because the one-time
   `semanage fcontext` rules don't exist (or `semanage` itself fails — install
   `policycoreutils-python-utils`). Apply the rules, re-run.
9. **DB socket error (`/var/lib/mysql/mysql.sock`)** — you used `host=localhost`. Use
   `host=127.0.0.1` (TCP) + the per-app user.
10. **`Access denied 'APP_app'@'localhost'`** (DSN says `host=127.0.0.1`) — MariaDB resolved
    `127.0.0.1` → `localhost`. Create the `@'localhost'` user too (same PW), or add
    `skip-name-resolve`.
11. **Blank page (200, no body)** — script died AFTER printing headers; usually DB connect.
    Read `ssl_error_log`.
12. **POST not GET** — frontend must use POST + FormData, not GET params or JSON body.
13. **Auto-create users** — insert into `users` when referencing a new netid (foreign key safety).
14. **Binary output** — set `binmode(STDOUT)` before serving file downloads.
15. **Shell-outs** — convert Windows cmdlines to shell-free list-form `exec` that CAPTURES
    stdout (so it can't leak into the CGI response); resolve paths via `FindBin`, never hardcode.
    Old `... >nul 2>&1` → `... >/dev/null 2>&1`.

### Key debug moves

```bash
perl -c <script>.pl                                   # syntax / missing modules
sudo -u apache perl <script>.pl 2>&1 | head           # runs as apache, bypasses SELinux:
                                                      #   prints HTML  -> SELinux/label issue
                                                      #   prints error -> code/DB issue
mysql -u APP_app -p -h 127.0.0.1 APP -e 'SELECT 1;'   # DB credential GATE
sudo tail -30 /var/log/httpd/ssl_error_log            # the REAL errors (HTTPS vhost)
sudo ausearch -m avc -ts recent | grep -i httpd       # SELinux denials
ls -Z <file>                                          # confirm SELinux label
namei -l <full/path/to/file>                          # find the parent dir missing o+x
getenforce ; grep -E '^SELINUX=' /etc/selinux/config  # runtime vs persisted must agree
```

## First-Deploy Order (do in THIS sequence; do not browser-test until GATES pass)

1. `dnf install` (incl. `policycoreutils-python-utils` — `semanage` won't exist without it).
2. Create DB + per-app user (BOTH host forms: `@'127.0.0.1'` AND `@'localhost'`).
3. Write `/data/AAP_Storage/secrets/APP.env` (real values, incl. `UPLOAD_DIR`/`UPLOAD_URL`) + perms.
4. (uploads) create `/data/AAP_Storage/apps/uploads/APP` (apache-writable, `2770`).
5. Install `deploy/APP.conf`; `httpd -t`; restart httpd.
6. One-time `semanage fcontext` rules (.pl exec, content, secret, uploads rw, venv) + `setsebool`
   + shibd module.
7. `sudo ./redeploy.sh` (NOW `restorecon` has rules to apply).
8. **GATE:** `ls -Z index.pl` shows `httpd_sys_script_exec_t` (NOT `default_t`).
9. **GATE:** `mysql -u APP_app -p -h 127.0.0.1 APP -e 'SELECT 1;'` succeeds.
10. (uploads) **GATE:** a test upload writes to `/data/AAP_Storage/apps/uploads/APP` AND renders
    back at `/apps/APP/uploads/<file>`.

Skipping step 6 before step 7 is the #1 cause of "redeploy said Done but still 403". Skipping
step 9 is the #1 cause of "500 right after SELinux was finally fixed". Full commands +
troubleshooting decision tree live in `DEPLOY.md`.

## Security Policy (Cornell Policy 5.10)

**Mandatory** for all apps. The Shibboleth threat model makes server-side authz and admin
gating non-optional (see Authorization above).

### Data Classification
- Classify data before development. Most student/staff/business data is **moderate-risk** minimum.
- FERPA-protected student data = moderate-risk. SSNs, bank/payment data = **high-risk**.
- Collect as little sensitive data as possible. If you don't need it, don't store it.

### Auth & Authorization
- Authentication via Cornell Shibboleth SP.
- **Authorization enforced server-side on every action** — re-check on every API call, record
  lookup, export, delete. Page-load checks are not enough.
- Never trust hidden form fields, URL params, or numeric IDs alone. Verify the current user has
  access to the specific record (scope to `current_netid()`).
- Admin pages: allowlist gate in code AND `Require shib-attr eppn ...` at Apache.
- No shared accounts. Role-based, minimal-privilege by default.

### Input & Query Safety
- **DBI placeholders everywhere.** No string interpolation in SQL. No exceptions.
- Validate input with allowlists where practical (NetIDs match `/^[a-z]{2,3}\d{1,4}$/`).
- Escape all output for its rendering context (HTML, URL, JS).
- Protect state-changing requests against CSRF.
- User-facing errors must be generic. Detailed errors go to server logs only.

### Secrets Management
- DB passwords, API keys, SMTP/Oracle creds: **never** in source, templates, JS, or web dirs.
- Store in `/data/AAP_Storage/secrets/APP.env` (outside web root), `640 root:apache`, rotate periodically.
- Separate credentials for dev vs. production.

### Sessions & Transport
- HTTPS only (enforced by Apache + Shibboleth).
- If using custom sessions: long random IDs, HttpOnly + Secure + SameSite cookies, rotate after
  login, expire on inactivity.
- Admin actions (permission changes, bulk exports, deletes) require confirmation or re-auth.

### Logging & Incident Response
- Log security events: logins, failed auth, admin changes, exports, deletes, unusual errors.
- **Never log passwords, session tokens, or sensitive field values.**
- If a breach or exposure is suspected, report immediately to `itsecurity@cornell.edu` and
  preserve evidence.

### File Uploads (if applicable)
- Validate extension, content type, and file signature. Enforce size limits.
- Rename files server-side. Store outside web root (`/data/AAP_Storage/apps/uploads/APP`).
  Scan for malware where practical.

---

## Required: Generate App_Summary.md

After the app is functionally complete, generate **`App_Summary.md`** in the app root, suitable
for an auditor or a new developer. Keep it factual and concise — bullet points, not paragraphs:

1. **App overview** — what it does, who uses it, in 2–3 sentences
2. **Roles & permissions** — every role, what each can do, how access is granted
3. **Data inventory** — every table, what it stores, classification (low/moderate/high), FERPA fields
4. **Data flow** — user action → frontend → API endpoint → database, with specifics for create/submit/approve/delete
5. **Authentication & authorization** — how users are identified (Shibboleth), how every API action verifies permission
6. **External integrations** — SMTP, Oracle data mart, any external APIs/data sources
7. **File locations** — app dir, secrets file, uploads dir, where logs go
8. **Security controls** — input validation, SQL parameterization, output escaping, CSRF, secrets management
9. **Backup & recovery** — database backup approach, restore steps
10. **Known limitations & risks** — anything an auditor should know

Generate this at the end of the final build phase.
