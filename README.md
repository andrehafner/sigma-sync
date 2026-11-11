# Sigma Sync

Coordinate Ergo multi-signature transactions with your fellow signers.

[Minotaur](https://github.com/minotaur-ergo/minotaur-wallet) multi-sig works in two rounds: every signer adds a
**commitment**, then every signer adds a **signature**, each time continuing from the
latest request. Passing those requests around a spreadsheet or a chat breaks easily: someone
continues from an old copy and erases another signer's commitment, two people work at the same time,
a paste picks up a stray line break, and nobody is sure whose turn it is.

Sigma Sync is a small web app that keeps one source of truth for each transaction:

- **Wallet sign-in, no passwords, no sign-up.** Anyone proves who they are by signing a one-time
  request with their Minotaur signing wallet (QR code for air-gapped wallets, or copy/paste).
- **You only see your own transactions.** Every multi-sig request lists the public keys of its
  signers. A transaction is visible only to accounts holding one of those keys, so access follows
  the wallet itself, not a list someone maintains.
- **One signer at a time.** Lock a transaction, copy the latest request into Minotaur, paste your
  output back. Submitting releases the lock. If someone walks away, two other signers can vote to
  force-unlock it.
- **Every paste is checked.** It must be the same Ergo transaction, keep every earlier
  commitment and signature, and add yours. A stale or wrong paste is refused with an explanation.
- **Clear progress.** The queue groups every open transaction by the step you owe: *Needs your
  commitment*, *Needs your signature*, *Waiting for others* and *Ready to broadcast*, each with its
  count. Closed transactions stay behind the filter. Cards show commitments and signatures against
  the M-of-N threshold, who holds the lock, and how old the transaction is. The detail lists every
  signer key with its state in each round (not started, committed, signed, not taking part) and says
  whom the transaction waits on. A Minotaur 2.x request does not mark signatures per key, so its
  signing round shows a count only. Each transaction has a description, comments, and a full
  activity history.
- **Review before you sign.** A *Transaction details* panel decodes the transaction itself: every
  payment with its ERG and tokens (names and decimals from the explorer) and destination, the
  fee, the change, and which wallet addresses it spends from, with a warning when it spends from
  more than one. When the request's input boxes do not match the inputs it names, the panel says
  "Inputs unverified" and shows no spending address and no change. It ends with a reminder to verify
  everything again in Minotaur.
- **Minotaur generation check.** Minotaur 3.0+ and 2.x write different request layouts and cannot
  read each other's. Sigma Sync detects the layout (it cannot tell 3.0 from 4.2.1 - those are
  identical) and refuses a paste from the wrong generation for the transaction's chosen version.
- **QR codes both ways.** Requests are shown as paged/animated QR codes in Minotaur's own
  format, and the camera scanner reads Minotaur's paged QR codes back.
- **Encrypted at rest.** Titles, descriptions, payloads and comments are stored with AES-256-GCM.

| Sign in | Transactions | Your turn |
|---|---|---|
| ![Sign-in](docs/screenshots/signin.png) | ![Transaction list](docs/screenshots/list.png) | ![Transaction detail](docs/screenshots/detail.png) |

## How it works

### Sign-in

1. Enter the address of your **signing wallet** (the regular wallet you sign multi-sig with,
   not the multi-sig wallet).
2. Sigma Sync builds a Minotaur *cold signing request* (`{"CSR": ...}`) that spends a box
   owned by that address. The box is **made up**: it does not exist on the blockchain, and its
   ID is derived from a random one-time challenge. The signed result can never be broadcast,
   so no funds can move.
3. Sign it in Minotaur (scan the QR code or paste), then paste or scan the signed result
   (`{"CSTX": ...}`) back.
4. The server checks the signed transaction is exactly the one it issued and verifies the
   Schnorr signature against the address's public key (pure Perl: Blake2b-256, secp256k1 and
   the Ergo Fiat-Shamir proof format; see [`ErgoKit.pm`](ErgoKit.pm)). The first sign-in creates
   an account; you then pick the name your co-signers see.

#### Sign-in with Nautilus

When the env file sets `SITE_HOST`, the server also accepts a sign-in from the Nautilus browser
wallet, for a new account and for linking an address:

1. `auth_start` with `method=nautilus` returns a one-time challenge (64 hex characters) and no
   Minotaur request.
2. Nautilus's `auth(address, challenge)` signs the text `challenge;host;seconds;random` and
   returns the text and its proof.
3. `auth_finish` checks that the stored challenge was issued for Nautilus and for this address,
   that the host in the text is `SITE_HOST`, that the time is no more than 5 minutes outside the
   challenge's life, and verifies the proof with the same Schnorr code. From there it continues
   exactly as the Minotaur sign-in.

Each challenge stores its method, so an answer made for one method is refused for the other.
Without `SITE_HOST` the server refuses the Nautilus method.

The page offers **Sign in with Nautilus** under the address form when the server has `SITE_HOST`
set and the Nautilus connector is in the page, also when the connector arrives after the page
loaded. It connects, lists the wallet's used and unused addresses, lets you choose one and runs
the three steps above. The Account tab links another address the same way. If Nautilus refuses
to connect or to sign, the page shows one fixed message and changes nothing. It never shows
text that the wallet returned, except the addresses you choose from.

### Who sees what

- When a transaction is started, Sigma Sync reads the signer public keys out of the transaction
  (the `atLeast(M, keys)` proposition of each input) and stores them with it.
- An account sees, locks, signs, comments on or cancels a transaction **only if one of its proven
  addresses is one of those keys**. Anyone else gets "Transaction not found". Admins are no exception.
- Only a signer of the wallet can start a transaction for it. The request may already carry
  commitments (yours or another signer's); anyone whose key has not committed adds theirs in turn.
- Minotaur derives each multi-sig key from every signer's wallet at the same address index, so a
  multi-sig's first address uses each signer's first address. If you sign with several wallets,
  or a multi-sig uses a later address, link those addresses on the **Account** tab (each one is
  proven with its own signature).
- Signers who have not signed in yet are listed as "Not on Sigma Sync yet"; the transaction appears
  for them the moment they do.

Admins (from `ADMIN_ADDRESSES`, or promoted by another admin) can disable accounts and read the
audit log. That is all.

### Wallets

The server keeps a registry of multi-sig wallets, and the page has a **Wallets** tab for it.

- The Wallets tab lists the wallets your keys sign for and registers one from its address and an
  optional name. A wallet's own page shows its name (any signer can change it), its address with
  a copy button, M of N, every key with its owner's name or "Not on Sigma Sync yet", the open
  transactions, and below them the closed ones, 200 at a time with a "Show older" button.
  The transaction list and the detail view show the wallet's name, or "No wallet" for a
  transaction whose inputs disagree. The list's search matches that name.
- `register_wallet` takes the wallet's Minotaur address and a name. The server reads M and the
  keys from the address and takes it only when it is a Minotaur M-of-N script on the server's
  network, with 1 < M < N, valid keys in ascending order, at most 3,000 characters, and when one
  of your proven addresses is one of its keys. A wallet is stored once: a second registration
  returns the same wallet.
- `list_wallets` and `get_wallet` show a wallet only to an account that holds one of its keys,
  with every key and its owner's name. Anyone else gets "Wallet not found". `get_wallet` also
  lists the wallet's open transactions and its closed ones, newest first, 200 at a time
  (`before` takes the last id shown).
- The name is shared by the wallet's signers and encrypted at rest. Any of them can change it
  with `rename_wallet`. The audit log records the wallet id and the account, never the name.
- Starting a transaction links it to its wallet when every input is a box of the same M-of-N
  wallet, and registers the wallet if nobody has, named after the transaction's wallet name.
  A start never renames a registered wallet. A transaction whose inputs disagree has no wallet.
  Every transaction carries its wallet's id and name, or none.
- An operator can add a wallet before any signer does:
  `APP_ENV_FILE=... perl tools/add-wallet.pl '<address>' '<name>'` prints its id.

### Select and run

The queue offers run actions only while a connected wallet supports them: its context has `multisig`
as its own property with `version` 1, and one of its addresses is one of yours. Without that the same
queue leads into the paste flow, one transaction at a time. When Nautilus is in the page but the site
is not allowed yet, the queue shows a **Connect Nautilus** button. The page never opens the connect
window by itself.

- A row where you owe a step has a checkbox, and each group has **Select all**. A selection holds
  rows of one group and at most 20. A row you cannot select says why. A refresh of the list keeps
  the selection.
- **Review** lists every selected transaction with what it pays, to whom, the fee, the wallet, M of N
  and the Ergo transaction ID. An item with unverified inputs, a partial or uncertain reading or a
  payment to a contract has its own tick. **Confirm** is off until every such tick is given, and it
  is the only confirm.
- A run handles one item after another: the page reads it, takes its lock (an item whose lock you
  already hold keeps it and uses the request the server gave for it), then makes one wallet call
  with the requests as the server returned them. It submits each answer through `submit`, so the
  server's checks decide what is stored. Each row shows waiting, lock taken, in the wallet,
  submitted, done, or failed with the server's or the wallet's reason. One failure does not stop the
  rest. A lock that did not lead to a stored step is released. A lock counts as released only when the
  server says so. If a release fails any other way, the row and the summary say the lock may still be
  held, and **Release** asks the server again without calling the wallet.
- The page compares what the server decoded from each request with what you reviewed. An item that
  changed since the review never goes to the wallet. Its row fails, its lock is released and you
  review it again.
- The summary offers **Retry** for the failed rows. A retry takes the lock again. It sends the
  wallet's kept answer when the stored request is the one the wallet got, and asks the wallet again
  when it is not.
- The list does not refresh while a run is open, and the queue offers no new selection or review
  until it ends. Leaving the run page does not stop the run, and the queue links back to it.
- Everything the wallet returns shows as text. An answer that is not a signed request (`MSR`) is never
  submitted. A wallet call that fails, or whose answer has the wrong length, order or ids, submits
  nothing and releases the locks of the call. When your session ends the run stops and the sign-in
  screen shows; the locks stay until you return.
- Every lock of a run names the lock count the page read, and every release names its item's count. A page that is
  closed during a run sends one release for each lock the run holds and each lock it asked for and has no answer
  to, so no lock stays. A tab that is only hidden keeps its locks, because a wallet review can take minutes.
- When the queue loads it shows every lock you hold, also one on a transaction beyond the 500 rows of the list, and
  one **Release** action frees them. It releases by count, so it never clears a lock you took after the view was
  drawn. It does not show while your own run is open.

### Rounds and statuses

| Status | Meaning |
|---|---|
| Commitment round | Signers add commitments until M are in |
| Signing round | Signers who committed add signatures until M are in |
| Ready to broadcast | The final payload is complete; publish it from Minotaur |
| Broadcast | Someone confirmed it was published (the page also checks the explorer) |
| Cancelled | The creator or an admin stopped it, with a reason |

M (signatures required) and N (keys in the wallet) are read from the first request, as is the
final Ergo transaction ID, so the explorer link works from the start.

### Checks on every paste

| Problem | What happens |
|---|---|
| Line breaks, zero-width characters, smart quotes, BOM | Removed automatically; nothing else is changed |
| Truncated or invalid JSON | Refused ("it may be cut off") |
| A different Ergo transaction | Refused |
| A commitment or signature from an earlier paste is missing or replaced | Refused ("you probably started from an older request") |
| Nothing new added (the request pasted back) | Refused |
| One page of a multi-page QR code | Refused, with a hint to scan every page |
| A commitment or signature for someone else's key | Refused: each signer submits their own |
| A new commitment after signing has started | Refused: commitments are closed |

Each stored payload has a short SHA-256 fingerprint so signers can tell versions apart.

### Your step is final

Once your commitment (or signature) is in, the next signers build on it, so it cannot be redone.
You can only lock a transaction while it still needs **your** step: in the commitment round if
none of your keys has committed, in the signing round if you committed and have not signed.
Signers who did not commit cannot join once signing has started.

### Batches

**Start Batch** takes tens of requests at once - pasted one after another, as a JSON array, or
uploaded as `.json`/`.txt` files. Each may be an unsigned cold signing request (`{"CSR":…}`,
nobody committed yet) or a multi-sig request (`{"MSR":…}`), with or without commitments already in it.

1. **Check** reads every entry and shows what it sends, its M-of-N wallet and its Ergo TX ID,
   and flags duplicates, transactions already tracked, and wallets you do not sign for. Nothing
   is written.
   It also checks how the entries relate on-chain: two entries spending the same box (or a box an
   open transaction already spends) can never both confirm, so the later one is flagged; an entry
   that spends another entry's output is marked "after entry N".
2. **Start** creates one transaction per valid entry, named `<batch name> 1`, `<batch name> 2`, …
   **in broadcast order** (an entry always comes after the ones it spends from), sharing the
   wallet name, Minotaur version, description and note. Chained transactions get a comment saying
   which one must be broadcast first.
3. Signers work through them as usual; after each submit, **Next in batch** jumps to the next one
   waiting for them.

For a transaction started from a CSR, the first committer opens it with Minotaur's
**home-screen** scanner (or paste there): Minotaur files it under the multi-sig wallet, where they
press Commit. Everyone after that uses the multi-sig wallet's Multi-sig Communication page.

### Locks

Only the lock holder sees the latest request and can submit. Submitting or releasing frees
the lock. If a lock is abandoned, `UNLOCK_VOTES` other signers (default 2) can vote to force it
open, at different times, once it has been held for `UNLOCK_GRACE_MINUTES` (default 10).

## Stack

Perl CGI + MariaDB + vanilla HTML/CSS/JS, no build step. Two small libraries are vendored in
[`vendor/`](vendor/README.md) (QR generation and a QR decoder fallback).

| File | Purpose |
|---|---|
| `api.pl` | All API actions (`action=...`, POST only) |
| `ErgoKit.pm` | Ergo addresses, sign-in request/verification, payload analysis |
| `AppConfig.pm` | Config file, database connection, encryption at rest |
| `app.js`, `index.html`, `style.css` | The single-page frontend |
| `schema.sql` | Database schema |
| `deploy/sigmasync.conf` | Apache include (CSP and security headers, access rules) |
| `redeploy.sh` | Re-applies ownership, permissions and SELinux labels after a pull |
| `DEPLOY.md` | Server setup, verification gates, troubleshooting |
| `App_Summary.md` | Security and data summary for auditors |

## Development

Requirements: Perl with `CGI`, `DBI`, `DBD::mysql`, `CryptX` (and ideally `Math::BigInt::GMP`),
plus MariaDB.

```bash
mysql -u root < schema.sql            # then create a user as shown at the end of schema.sql
cp sigmasync.env.example dev.env      # fill in DB_*, DATA_KEY, ADMIN_ADDRESSES;
                                      # set COOKIE_SECURE=0 and COOKIE_PATH=/ for local HTTP,
                                      # and SITE_HOST=127.0.0.1:8080 for Nautilus sign-in
APP_ENV_FILE=$PWD/dev.env python3 tools/dev-server.py 8080
prove -I. t/                          # unit tests
```

The sign-in fixture in `t/fixtures/login.json` was signed with a throwaway key by sigma-rust
(`ergo-lib`), so the tests check the Perl verifier against the reference implementation.

## Deployment

See [DEPLOY.md](DEPLOY.md). In short: create the database and user, write
`/data/AAP_Storage/secrets/sigmasync.env`, install `deploy/sigmasync.conf`, add the one-time
SELinux rules, then run `sudo ./redeploy.sh` after every pull.
