# Sigma Sync - Application Summary

## 1. App overview

- Coordinates Ergo blockchain multi-signature transactions made with the Minotaur wallet:
  signers take turns adding commitments and then signatures to a shared transaction request.
- Used by the signers of community-controlled multi-sig wallets (e.g. Sigmanauts treasuries).
- Hosted at `https://public.aap.cornell.edu/apps/sigmasync/`, open to the internet, with no
  Shibboleth. Users sign in by signing a one-time request with their own Ergo wallet.

## 2. Roles & permissions

| Role | Can | Granted by |
|---|---|---|
| Visitor (not signed in) | See the sign-in page; request and complete a sign-in challenge | - |
| Signer | View all transactions; start transactions; lock, submit, release locks; vote to force-unlock someone else's lock; comment; mark complete transactions as broadcast; cancel transactions they created; view the signer list | An admin adds their wallet address on the Signers tab |
| Admin | Everything a signer can, plus add/rename/disable signers, grant/revoke admin, cancel any transaction, view the activity log | `ADMIN_ADDRESSES` in the env file (cannot be removed in the app), or the admin flag set by another admin |

- Disabled members cannot sign in, and their sessions are deleted immediately.
- Admins cannot remove their own access, and config-file admins cannot be demoted in the app.

## 3. Data inventory

| Table | Stores | Classification |
|---|---|---|
| `members` | Wallet address, display name, admin/active flags, last sign-in | Low (addresses are public on-chain; names are pseudonyms) |
| `auth_challenges` | One-time sign-in challenges: SHA-256 of token, address, unsigned challenge tx, IP, expiry | Low; purged after 1 day |
| `sessions` | SHA-256 of session token, CSRF token, member, IP, expiry | Moderate (session secrets; only hashes of the cookie value are stored) |
| `transactions` | Title*, description*, wallet name, Minotaur version, threshold, Ergo tx ID, status, counts, lock holder | Moderate (treasury plans before they are public) |
| `submissions` | Each pasted payload*, its SHA-256, round, counts, detected signer slot | Moderate (partially signed transactions; no private keys or secret nonces) |
| `comments` | Comment text* | Moderate |
| `unlock_votes` | Who voted to force-unlock which lock | Low |
| `events` | Audit log: sign-ins, failed sign-ins, locks, submissions, admin changes, with IP | Moderate (IP addresses) |

\* encrypted at rest with AES-256-GCM.

- No FERPA data, SSNs, payment card or bank data. No private keys: Minotaur keeps signing
  secrets and commitment nonces on the signer's device; payloads contain only public
  commitments and signature proofs, which end up on-chain anyway.

## 4. Data flow

- **Sign-in**: address entered -> `auth_start` validates it (Base58 + checksum, P2PK, network),
  rate-limits by IP (20 per 15 min), stores a challenge and returns a Minotaur `CSR` request
  spending a fictional box -> user signs in Minotaur -> `auth_finish` checks the signed
  transaction equals the issued one and verifies the Schnorr proof against the address's key ->
  if the address is an active member, a session is created (HttpOnly, Secure, SameSite=Strict
  cookie) and the challenge is marked used.
- **Create**: Start Transaction form -> `create_transaction` -> payload analysed (must be a valid
  Minotaur multi-sig request with at least one commitment; threshold must match the wallet's) ->
  `transactions` + first `submissions` row (+ optional `comments`) inserted in one DB transaction.
- **Lock**: `lock` atomically sets the lock holder only if unlocked and open
  (`UPDATE ... WHERE lock_member_id IS NULL`).
- **Submit**: lock holder pastes output -> `submit` (row locked with `SELECT ... FOR UPDATE`) ->
  payload must match the Ergo tx ID, keep every earlier commitment/signature, and add at least
  one -> new `submissions` row, counts/status updated, lock released, event logged.
- **Force-unlock**: `vote_unlock` by members other than the holder, only after the grace
  period; the lock is released once `UNLOCK_VOTES` distinct votes exist for that lock.
- **Complete / broadcast**: status becomes `complete` when signatures reach the threshold or a
  fully signed `CSTX` is submitted; any signer can then `mark_broadcast`.
- **Cancel**: creator or admin, reason required, logged. Nothing is deleted.

## 5. Authentication & authorization

- Identity = control of an Ergo wallet key, proven by a Schnorr signature over a one-time
  challenge transaction. The challenge box does not exist on-chain, so the signed result cannot
  be broadcast or move funds. Challenges expire after 15 minutes and are single-use.
- Every API action except `session`, `auth_start`, `auth_finish` and `logout` calls
  `require_member()`: a valid, unexpired, non-idle session for an **active** member **and** a
  matching CSRF token. Admin actions additionally check the admin flag.
- Record-level rules are enforced server-side: only the lock holder may submit or release;
  the holder cannot vote on their own lock; only the creator or an admin may cancel.
- All requests must be POST.

## 6. External integrations

- None from the server. The server makes no outbound connections besides MariaDB on 127.0.0.1.
- From the browser: `api.github.com` (list of Minotaur releases, cached 6 h, with a built-in
  fallback list) and `api.ergoplatform.com` (on-chain status of completed transactions). Both are
  allowed explicitly in the Content-Security-Policy `connect-src`.
- No SMTP and no Oracle.

## 7. File locations

- App: `/data/AAP_Storage/apps/sigmasync/` (URL `/apps/sigmasync/`)
- Secrets: `/data/AAP_Storage/secrets/sigmasync.env` (root:apache, 640)
- Uploads: none
- Logs: `/var/log/httpd/ssl_error_log` (server errors, without payloads or secrets) and the
  `events` table (security/audit events, viewable by admins on the Activity tab)

## 8. Security controls

- **SQL**: DBI placeholders for every query; no SQL string interpolation of input.
- **Input validation**: addresses Base58/checksum/type/network validated; IDs numeric; version
  allowlist pattern; text length limits (title 120, description 10,000, comment 4,000, payload
  1 MB); control characters stripped; payloads parsed and checked before storage.
- **Output escaping**: all user content is HTML-escaped before rendering; payloads are shown in
  read-only textareas and copied via the Clipboard API as plain text.
- **CSRF**: per-session token required on every authenticated action, plus SameSite=Strict
  cookies.
- **Headers**: strict CSP (`script-src 'self'`, `style-src 'self'`, no inline script/style),
  `frame-ancestors 'none'`, `X-Frame-Options DENY`, `nosniff`, `Referrer-Policy no-referrer`,
  `Permissions-Policy` limiting camera to this origin (used only for QR scanning).
- **Secrets**: DB password and `DATA_KEY` only in the env file outside the web root; never in the
  repository. Session cookies stored only as SHA-256 hashes.
- **Encryption at rest**: AES-256-GCM, random 96-bit nonce per value, column context bound as
  associated data (a ciphertext cannot be moved to another column undetected).
- **Errors**: users get generic messages for server faults; details go to `ssl_error_log`.
- **Access to source files**: Apache refuses `.pm`, `.sql`, `.md`, `.sh`, `.py`, dotfiles and the
  `deploy/`, `t/`, `tools/`, `.git/` directories.
- **Rate limiting**: sign-in challenges limited per IP.
- **Third-party code**: two vendored, version-pinned libraries with recorded SHA-256 hashes
  (`vendor/README.md`); no CDNs at runtime.

## 9. Backup & recovery

- Database: `mysqldump --single-transaction sigmasync` on the standard schedule.
- `DATA_KEY` must be backed up separately and securely; without it the encrypted columns in the
  database and backups are unrecoverable.
- Restore: create the DB and user (DEPLOY.md step 3), load the dump, restore the env file with
  the same `DATA_KEY`, `restorecon` it, `sudo ./redeploy.sh`.

## 10. Known limitations & risks

- Open to the internet by design (no Shibboleth). The sign-in page and challenge endpoint are
  public; everything else requires a member session.
- `DATA_KEY` lives on the same server as the database, so encryption at rest protects database
  dumps, backups and DB-level access, not a full compromise of the web server.
- Payload checks understand Minotaur's current (`hints`) and older (`commitments`) formats;
  "Other / not Minotaur" transactions are stored without validation.
- Output decoding is best effort: outputs carrying registers are not decoded (flagged in the UI).
- "Mark as broadcast" is trusted from any signer; the page shows the explorer's on-chain status
  next to it but the server does not verify it.
- Force-unlock relies on the honesty of two members; votes and overrides are logged.
- Display names are chosen by admins and are not verified identities.
