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
| Account | Choose a display name; link/unlink extra wallet addresses (each proven by signature); start a transaction for a multi-sig wallet one of its keys signs for; register such a wallet by its address | Automatic on first wallet sign-in |
| Signer of a wallet (an account holding one of the wallet's keys) | View it with its keys; rename it | Derived from the wallet address: the public keys in its multi-sig script |
| Signer of a transaction (an account holding one of that transaction's signer keys) | View it; lock, submit, release the lock; vote to force-unlock another signer's lock; comment; mark it broadcast once complete; cancel it if they started it | Derived from the transaction itself: the public keys in its multi-sig proposition |
| Admin | Everything an account can, plus disable/enable accounts, grant/revoke admin, read the audit log, cancel transactions **they are a signer of** | `ADMIN_ADDRESSES` in the env file (cannot be removed in the app), or the admin flag set by another admin |

- Admins have no access to transactions they are not a signer of.
- Admins can delete an account: its addresses and sessions are removed, any lock it holds is
  released and its open unlock votes dropped. Past activity stays on the transactions, labelled
  "(deleted)"; an account with no history is removed entirely. Signing in again with the same
  address creates a new account (delete is not a ban - Disable is). Deletions are audit-logged.
- Disabled accounts cannot sign in, and their sessions are deleted immediately.
- Admins cannot remove their own access, and config-file admins cannot be demoted in the app.

## 3. Data inventory

| Table | Stores | Classification |
|---|---|---|
| `members` | Display name, admin/active flags, last sign-in | Low (names are self-chosen pseudonyms) |
| `member_keys` | Wallet addresses and public keys each account has proven it controls | Low (public on-chain data), but links addresses to one person |
| `transaction_keys` | Signer public keys of each transaction and whether each has committed/signed | Low (public in the transaction) |
| `auth_challenges` | One-time sign-in challenges: SHA-256 of token, address, sign-in method (Minotaur or Nautilus), unsigned challenge tx (Minotaur only), IP, expiry | Low; purged after 1 day |
| `sessions` | SHA-256 of session token, CSRF token, member, IP, expiry | Moderate (session secrets; only hashes of the cookie value are stored) |
| `transactions` | Title*, description*, wallet name, Minotaur version, threshold, Ergo tx ID, status, counts, lock holder, registered wallet | Moderate (treasury plans before they are public) |
| `batches` | Batch title*, item count, creator, time | Moderate |
| `wallets` | Multi-sig wallet address and its SHA-256 (unique), network, M and N, name*, who registered it (none for the command line and the migration) | Low (public on-chain data), except the name |
| `wallet_keys` | The public keys of each wallet in script order | Low (public in the address) |
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
- **Sign-in with Nautilus** (only when `SITE_HOST` is set): `auth_start` with `method=nautilus`
  stores a challenge marked Nautilus and returns only the token -> the Nautilus wallet signs
  `token;host;seconds;random` -> `auth_finish` reads the method from the stored challenge, checks
  the token, that the host equals `SITE_HOST`, that the time is within 5 minutes of the
  challenge's life, and the Schnorr proof against the address's key -> then as above. An answer
  of one method is refused for a challenge of the other.
- **Link address**: same challenge flow, with either method, with `purpose=link` while signed
  in; the proven key is added to the current account (refused if another account holds it).
- **Wallet**: `register_wallet` takes a multi-sig address (at most 3,000 characters) -> it must be
  a Minotaur M-of-N script on the server's network with 1 < M < N, valid keys in ascending order,
  and rebuild byte for byte -> the account must hold one of its keys (checked against the
  address before any lookup) -> the wallet and its keys are written once, under the unique
  SHA-256 of the address. `rename_wallet` lets any signer of the wallet change its shared name.
  Both log the wallet id only, never the name. `get_wallet` lists the wallet's open
  transactions and its closed ones, 200 at a time, read under the transaction visibility rule.
  `tools/add-wallet.pl` adds a wallet from the command line with the same checks.
- **Create**: Start Transaction form -> `create_transaction` -> payload analysed (must be a valid
  Minotaur multi-sig request; signer keys must be readable; one of the creator's keys must be a
  signer and already committed; threshold must match the wallet's; 20 per account per day) ->
  `transactions`, its `transaction_keys`, the first `submissions` row (+ optional `comments`)
  inserted in one DB transaction. When every input names the same M and keys, the transaction
  is linked to that wallet, which the same DB transaction registers if it is new (named after
  the transaction's wallet name; an existing wallet keeps its name).
- **Batch**: Start Batch form -> `batch_preview` (read-only: every entry checked exactly as a
  single start, plus duplicates within the batch, already-tracked transactions and boxes an open
  transaction already spends; at most 100 entries) -> `create_batch` re-checks everything
  server-side and inserts the batch and one transaction per valid entry in one DB transaction
  (invalid entries only skipped on explicit confirmation; counts against the daily cap, default 200).
- **Lock**: `lock` atomically sets the lock holder only if unlocked and open
  (`UPDATE ... WHERE lock_member_id IS NULL`), and raises the lock count `lock_seq`. With
  `seq`, it locks only while `lock_seq` still equals it. `release_lock` with `seq` first cancels
  a lock at that count that has not arrived yet (raises `lock_seq` if nobody holds the lock and
  the caller may lock, logged as `lock_cancel`), then releases only the caller's lock whose count
  is `seq` + 1, so a late release never clears a newer lock. Without `seq` both work as before.
  The list reply names every lock the account holds (`held_locks`), beyond its 500 rows too.
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
  challenge: a challenge transaction (Minotaur) or a text naming the challenge and the site's
  host (Nautilus). The challenge box does not exist on-chain, so the signed result cannot
  be broadcast or move funds. Challenges expire after 15 minutes and are single-use.
- Every API action except `session`, `auth_start`, `auth_finish` and `logout` calls
  `require_member()`: a valid, unexpired, non-idle session for an **active** account **and** a
  matching CSRF token. Admin actions additionally check the admin flag.
- **Every transaction read or write** goes through `load_tx()`, whose query only returns the row
  if the account holds one of the transaction's signer keys (`transaction_keys` joined to
  `member_keys`). The list query uses the same condition. Unauthorized and non-existent IDs get
  the same "Transaction not found" answer. The Start Batch check looks for box clashes only among
  open transactions the account can see. A duplicate Ergo transaction is always refused, and named
  only when the account can see it.
- **Every wallet read or write** goes through `load_wallet()` or the same condition: the account
  holds one of the wallet's keys (`wallet_keys` joined to `member_keys`). Unauthorized and
  non-existent IDs get the same "Wallet not found" answer.
- Turn rules are enforced server-side: an account can lock only while it owes the current round
  its step (commitment round: none of its keys committed; signing round: committed, not yet
  signed). A submission may only add the submitter's own commitment/signature, in one of the
  submitter's key slots, for the current round. Given commitments and signatures are final.
- Record-level rules are enforced server-side: only the lock holder may submit or release;
  the holder cannot vote on their own lock; only the creator or an admin (who is also a signer)
  may cancel.
- All requests must be POST.

## 6. External integrations

- None from the server. The server makes no outbound connections besides MariaDB on 127.0.0.1.
- From the browser: token names/decimals from `api.ergoplatform.com/api/v1/tokens/` (public
  data, cached per browser); `api.github.com` (list of Minotaur releases, cached 6 h, with a built-in
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
- **Input validation**: addresses Base58/checksum/type/network validated; wallet addresses at
  most 3,000 characters before decoding, and only the Minotaur multi-sig script; IDs numeric;
  version allowlist pattern; text length limits (title 120, description 10,000, comment 4,000,
  wallet name 80, payload 1 MB); control characters stripped; payloads parsed and checked
  before storage.
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
- The decoded view trusts a request's input boxes only when each input has exactly one box whose
  hash is the id the input names; a box that matches no input is ignored. Otherwise the inputs
  are reported as unverified: none are listed, no output is marked as change, and the outputs
  are marked uncertain, because the starter chooses the boxes a request carries.
- "Mark as broadcast" is trusted from any signer; the page shows the explorer's on-chain status
  next to it but the server does not verify it.
- Force-unlock relies on the honesty of two members; votes and overrides are logged.
