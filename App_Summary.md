# Sigma Sync - Application Summary

## 1. App overview

- Coordinates Ergo blockchain multi-signature transactions made with the Minotaur wallet:
  signers take turns adding commitments and then signatures to a shared transaction request.
- Used by the signers of community-controlled multi-sig wallets (e.g. Sigmanauts treasuries).
- Hosted at `https://public.aap.cornell.edu/apps/sigmasync/`, open to the internet, with no
  Shibboleth. Anyone can sign in by signing a one-time request with their own Ergo wallet; what
  they can see is limited to transactions their wallet keys are signers of.

## 2. Roles & permissions

| Role | Can | Granted by |
|---|---|---|
| Visitor (not signed in) | See the sign-in page; request and complete a sign-in challenge | - |
| Account | Choose a display name; link/unlink extra wallet addresses (each proven by signature); start a transaction for a multi-sig wallet one of its keys signs for | Automatic on first wallet sign-in |
| Signer of a transaction (an account holding one of that transaction's signer keys) | View it; lock, submit, release the lock; vote to force-unlock another signer's lock; comment; mark it broadcast once complete; cancel it if they started it | Derived from the transaction itself: the public keys in its multi-sig proposition |
| Admin | Everything an account can, plus disable/enable accounts, grant/revoke admin, read the audit log, cancel transactions **they are a signer of** | `ADMIN_ADDRESSES` in the env file (cannot be removed in the app), or the admin flag set by another admin |

- Admins have no access to transactions they are not a signer of.
- Disabled accounts cannot sign in, and their sessions are deleted immediately.
- Admins cannot remove their own access, and config-file admins cannot be demoted in the app.

## 3. Data inventory

| Table | Stores | Classification |
|---|---|---|
| `members` | Display name, admin/active flags, last sign-in | Low (names are self-chosen pseudonyms) |
| `member_keys` | Wallet addresses and public keys each account has proven it controls | Low (public on-chain data), but links addresses to one person |
| `transaction_keys` | Signer public keys of each transaction and whether each has committed/signed | Low (public in the transaction) |
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
  the account holding that key is found (or created) and, if active, a session is created
  (HttpOnly, Secure, SameSite=Strict cookie); the challenge is marked used.
- **Link address**: same challenge flow with `purpose=link` while signed in; the proven key is
  added to the current account (refused if another account holds it).
- **Create**: Start Transaction form -> `create_transaction` -> payload analysed (must be a valid
  Minotaur multi-sig request; signer keys must be readable; one of the creator's keys must be a
  signer and already committed; threshold must match the wallet's; 20 per account per day) ->
  `transactions`, its `transaction_keys`, the first `submissions` row (+ optional `comments`)
  inserted in one DB transaction.
- **Lock**: `lock` atomically sets the lock holder only if unlocked and open
  (`UPDATE ... WHERE lock_member_id IS NULL`).
- **Submit**: lock holder pastes output -> `submit` (row locked with `SELECT ... FOR UPDATE`) ->
  payload must match the Ergo tx ID, keep every earlier commitment/signature, and add at least
  one -> new `submissions` row, per-key states, counts and status updated, lock released, event logged.
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
  `require_member()`: a valid, unexpired, non-idle session for an **active** account **and** a
  matching CSRF token. Admin actions additionally check the admin flag.
- **Every transaction read or write** goes through `load_tx()`, whose query only returns the row
  if the account holds one of the transaction's signer keys (`transaction_keys` joined to
  `member_keys`). The list query uses the same condition. Unauthorized and non-existent IDs get
  the same "Transaction not found" answer.
- Record-level rules are enforced server-side: only the lock holder may submit or release;
  the holder cannot vote on their own lock; only the creator or an admin (who is also a signer)
  may cancel.
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

- Open to the internet by design (no Shibboleth), and anyone with an Ergo wallet can create an
  account. Accounts can only see transactions their own keys sign for, so an account by itself
  grants nothing. Spam is limited by per-IP challenge limits and a per-account daily cap on new
  transactions; admins can disable accounts.
- Visibility follows keys, so a signer who uses an address the account has not linked will not
  see the transaction until they link it (the UI explains this).
- Display names are self-chosen and only unique, not verified; the signer list always shows the
  address next to the name.
- The admin audit log shows account addresses and event metadata (not transaction contents).
- `DATA_KEY` lives on the same server as the database, so encryption at rest protects database
  dumps, backups and DB-level access, not a full compromise of the web server.
- Payload checks understand Minotaur's current (`hints`) and older (`commitments`) formats.
  Only Minotaur multi-sig transactions are supported (their keys are what scopes access).
- Output decoding is best effort: outputs carrying registers are not decoded (flagged in the UI).
- "Mark as broadcast" is trusted from any signer; the page shows the explorer's on-chain status
  next to it but the server does not verify it.
- Force-unlock relies on the honesty of two members; votes and overrides are logged.
