# Deploying Sigma Sync

Target: Oracle Linux 9, Apache httpd, MariaDB, SELinux **enforcing**, on the
`public.aap.cornell.edu` vhost.

| | |
|---|---|
| URL | `https://public.aap.cornell.edu/apps/sigmasync/` |
| App root | `/data/AAP_Storage/apps/sigmasync/` |
| Secrets | `/data/AAP_Storage/secrets/sigmasync.env` |
| Uploads | none |
| Logs | `/var/log/httpd/ssl_error_log` (not `error_log`) |
| Auth | **No Shibboleth.** Wallet-signature sign-in inside the app |

Do the steps **in order** and do not test in a browser until the gates pass.

## 1. Packages

```bash
sudo dnf install -y epel-release            # CryptX and Math::BigInt::GMP come from EPEL
sudo dnf install -y httpd mod_ssl mariadb-server policycoreutils-python-utils \
    perl-CGI perl-DBI perl-DBD-MySQL perl-JSON-PP perl-Digest-SHA perl-MIME-Base64 \
    perl-CryptX perl-Math-BigInt-GMP
perl -MCGI -MDBI -MDBD::mysql -MCryptX -MMath::BigInt::GMP -e 'print "perl modules OK\n"'
```

`Math::BigInt::GMP` is optional but recommended: without it sign-in verification falls back to
pure Perl (~0.9 s instead of ~0.1 s).

## 2. Code

```bash
sudo mkdir -p /data/AAP_Storage/apps
cd /data/AAP_Storage/apps
sudo git clone https://github.com/andrehafner/sigma-sync.git sigmasync
sudo chown -R "$USER" sigmasync            # you maintain the checkout; apache gets group read
```

## 3. Database and per-app user

```bash
sudo mysql < /data/AAP_Storage/apps/sigmasync/schema.sql
sudo mysql <<'SQL'
CREATE USER IF NOT EXISTS 'sigmasync_app'@'127.0.0.1' IDENTIFIED BY 'STRONG_PW';
CREATE USER IF NOT EXISTS 'sigmasync_app'@'localhost' IDENTIFIED BY 'STRONG_PW';
GRANT SELECT,INSERT,UPDATE,DELETE ON sigmasync.* TO 'sigmasync_app'@'127.0.0.1';
GRANT SELECT,INSERT,UPDATE,DELETE ON sigmasync.* TO 'sigmasync_app'@'localhost';
FLUSH PRIVILEGES;
SQL
```

Both host forms are needed: MariaDB may resolve a `127.0.0.1` connection to `localhost`.

## 4. Secrets file

```bash
sudo mkdir -p /data/AAP_Storage/secrets
sudo cp /data/AAP_Storage/apps/sigmasync/sigmasync.env.example /data/AAP_Storage/secrets/sigmasync.env
openssl rand -hex 32                        # paste the output as DATA_KEY
sudo vi /data/AAP_Storage/secrets/sigmasync.env   # DB_PASSWORD, DATA_KEY, ADMIN_ADDRESSES, SITE_HOST
sudo chown root:apache /data/AAP_Storage/secrets/sigmasync.env
sudo chmod 640 /data/AAP_Storage/secrets/sigmasync.env
```

- `ADMIN_ADDRESSES`: comma-separated **wallet addresses** (P2PK) of the people who may disable
  accounts and read the audit log. Anyone can sign in; admins get no access to other people's
  transactions.
- `SITE_HOST`: `public.aap.cornell.edu`, the host the browser shows. The Nautilus wallet signs it
  into every sign-in and the server accepts no other. Leave it empty to turn Nautilus sign-in off.
- **Back up `DATA_KEY` separately** (password manager / sealed envelope). Without it, encrypted
  data in the database and in every backup is unreadable.

## 5. Apache

```bash
sudo cp /data/AAP_Storage/apps/sigmasync/deploy/sigmasync.conf /etc/httpd/conf.d/sigmasync.conf
```

The `Alias` and `<Directory>` must apply to the **public** HTTPS vhost. If conf.d files are not
included in that vhost, add `Include conf.d/sigmasync.conf` inside its `<VirtualHost *:443>`.
The include requires `mod_headers` (loaded by default on EL9).

```bash
sudo httpd -t && sudo systemctl reload httpd
```

## 6. One-time SELinux rules

```bash
sudo semanage fcontext -a -t httpd_sys_content_t     "/data/AAP_Storage/apps/sigmasync(/.*)?"
sudo semanage fcontext -a -t httpd_sys_script_exec_t "/data/AAP_Storage/apps/sigmasync/.*\.pl"
sudo semanage fcontext -a -t httpd_sys_content_t     "/data/AAP_Storage/secrets/sigmasync\.env"
sudo setsebool -P httpd_can_network_connect_db 1     # httpd -> MariaDB on 127.0.0.1:3306
```

(Use `-m` instead of `-a` if a rule already exists.) Outbound HTTP from httpd is **not**
needed: GitHub and the Ergo explorer are called from the browser.

## 7. Apply labels and permissions

```bash
cd /data/AAP_Storage/apps/sigmasync && sudo ./redeploy.sh
```

`redeploy.sh` stops with an error if `api.pl` does not end up `httpd_sys_script_exec_t`.

## 8. Gates

```bash
# GATE 1 - labels
ls -Z /data/AAP_Storage/apps/sigmasync/api.pl          # httpd_sys_script_exec_t
ls -Z /data/AAP_Storage/secrets/sigmasync.env          # httpd_sys_content_t

# GATE 2 - database credentials
mysql -u sigmasync_app -p -h 127.0.0.1 sigmasync -e 'SELECT 1;'

# GATE 3 - the API answers as apache, with the real config
cd /data/AAP_Storage/apps/sigmasync
printf 'action=session' | sudo -u apache env APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env \
  REQUEST_METHOD=POST CONTENT_TYPE=application/x-www-form-urlencoded CONTENT_LENGTH=14 perl api.pl
# -> ...{"nautilus":1,"signed_in":0,"success":1}   (nautilus is 0 while SITE_HOST is empty)

# GATE 4 - over HTTPS
curl -s -X POST -d action=session https://public.aap.cornell.edu/apps/sigmasync/api.pl
curl -sI https://public.aap.cornell.edu/apps/sigmasync/AppConfig.pm | head -1   # 403
curl -sI https://public.aap.cornell.edu/apps/sigmasync/ | grep -i content-security-policy
```

Then sign in with your wallet. Fellow signers simply sign in with theirs.

## Updating

```bash
cd /data/AAP_Storage/apps/sigmasync
git pull
sudo ./redeploy.sh               # ALWAYS - a pull resets labels/ownership of changed files
```

If a release changes `schema.sql`, it ships a migration in `tools/` - see below.

### Migration 001 - key-scoped access (databases created before open sign-in)

```bash
sudo mysqldump sigmasync > ~/sigmasync-before-001.sql     # backup
cd /data/AAP_Storage/apps/sigmasync
git pull && sudo ./redeploy.sh
sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-001-key-scoping.pl --dry-run
sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-001-key-scoping.pl
```

Keeps every account, name, admin flag, transaction, comment and session; moves addresses
to `member_keys` and reads each transaction's signer keys from its stored request. Transactions
without Minotaur signer keys (the old "Other / not Minotaur" mode) are cancelled. Re-running it
is harmless. To undo: `sudo mysql -e 'DROP DATABASE sigmasync; CREATE DATABASE sigmasync'` then
`sudo mysql sigmasync < ~/sigmasync-before-001.sql` and check out the previous release.

### Migration 002 - batch transactions

```bash
sudo mysqldump sigmasync > ~/sigmasync-before-002.sql     # backup
cd /data/AAP_Storage/apps/sigmasync
git pull && sudo ./redeploy.sh
sudo mysql sigmasync < tools/migrate-002-batches.sql
```

Adds the `batches` table and two columns on `transactions`. Safe to run twice. Fresh installs get
it from `schema.sql`.

### Migration 003 - sign-in method of a challenge

```bash
sudo mysqldump sigmasync > ~/sigmasync-before-003.sql     # backup
cd /data/AAP_Storage/apps/sigmasync
git pull && sudo ./redeploy.sh
sudo mysql sigmasync < tools/migrate-003-auth-method.sql
```

Adds `auth_challenges.method`; every existing challenge stays a Minotaur challenge. Safe to run
twice. Fresh installs get it from `schema.sql`. Then set `SITE_HOST` in the env file to offer
Nautilus sign-in.

## Backups

- `mysqldump --single-transaction sigmasync > sigmasync-$(date +%F).sql` on the usual DB backup
  schedule. Encrypted columns stay encrypted in the dump.
- Keep `DATA_KEY` with the backups' recovery instructions, **not** in the same place as the dump.
- Restore: `mysql sigmasync < dump.sql`, put the same `DATA_KEY` in the env file, `restorecon` it.

## Troubleshooting

```
Browser shows an error / blank page
├─ Read the log: sudo tail -30 /var/log/httpd/ssl_error_log
├─ 403 on /apps/sigmasync/
│  ├─ sudo setenforce 0 && retry
│  │  ├─ works  -> SELinux: sudo setenforce 1; step 6 rules missing; sudo ./redeploy.sh
│  │  └─ fails  -> DAC: namei -l /data/AAP_Storage/apps/sigmasync/index.html (a parent dir lacks o+x)
│  └─ "client denied by server configuration" -> the conf is not in the public vhost (step 5)
├─ 500 "End of script output before headers"
│  ├─ right after a pull/edit -> sudo ./redeploy.sh
│  ├─ perl -c api.pl            -> missing module? (step 1)
│  └─ "exec ... No such file"  -> CRLF line endings: sed -i 's/\r$//' api.pl *.pm; sudo ./redeploy.sh
├─ API says "Something went wrong on the server"
│  ├─ "Cannot read config file"         -> env file label/perms: sudo restorecon <env>; chown root:apache; chmod 640
│  ├─ "DATA_KEY must be 64 hex"         -> fix DATA_KEY in the env file
│  ├─ "Can't connect ... mysql.sock"    -> DB_HOST must be 127.0.0.1, not localhost
│  ├─ "Access denied ...@'localhost'"   -> create the @'localhost' user too (step 3)
│  └─ "Can't connect ... (13)"          -> setsebool -P httpd_can_network_connect_db 1
├─ Sign-in: "Signature check failed"
│  └─ The address entered is not the wallet that signed. Use the signing wallet's own address.
├─ Signed in but a transaction is missing
│  └─ None of your addresses is one of its signer keys. Link the address you sign that
│     multi-sig with (Account tab). Multi-sig address #N uses each signer's address #N.
└─ Sign-in works but you are immediately signed out
   └─ Cookie not stored: COOKIE_PATH must be /apps/sigmasync/ and COOKIE_SECURE=1 over HTTPS.
```

Other useful commands:

```bash
sudo ausearch -m avc -ts recent | grep -i httpd       # SELinux denials
getenforce ; grep -E '^SELINUX=' /etc/selinux/config  # runtime vs persisted must agree
sudo -u apache perl -c /data/AAP_Storage/apps/sigmasync/api.pl
```
