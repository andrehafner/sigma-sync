-- Sigma Sync schema (MariaDB 10.5+). Run once as an admin:
--   mysql -u root < schema.sql
-- Secret-bearing text columns (*_enc) hold AES-256-GCM ciphertext produced by
-- AppConfig::seal(); they are never readable without DATA_KEY from the env file.

CREATE DATABASE IF NOT EXISTS sigmasync CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE sigmasync;

-- Accounts. Anyone who proves control of an Ergo wallet key gets one; what they can see
-- is decided by the keys they hold (see member_keys / transaction_keys).
CREATE TABLE IF NOT EXISTS members (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    display_name   VARCHAR(64)  NOT NULL,
    name_chosen    TINYINT(1)   NOT NULL DEFAULT 0,
    is_admin       TINYINT(1)   NOT NULL DEFAULT 0,
    is_active      TINYINT(1)   NOT NULL DEFAULT 1,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at  DATETIME     NULL
) ENGINE=InnoDB;

-- Wallet addresses (P2PK) an account has proven it controls, by signing a challenge.
CREATE TABLE IF NOT EXISTS member_keys (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    member_id      INT          NOT NULL,
    address        VARCHAR(64)  NOT NULL,
    pk             CHAR(66)     NOT NULL,          -- compressed public key, hex
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_key_address (address),
    UNIQUE KEY uq_key_pk (pk),
    KEY ix_key_member (member_id),
    CONSTRAINT fk_key_member FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- One-time sign-in challenges: a Minotaur cold-signing request, or a token Nautilus signs.
CREATE TABLE IF NOT EXISTS auth_challenges (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    token_hash     CHAR(64)     NOT NULL,
    address        VARCHAR(64)  NOT NULL,
    member_id      INT          NULL,              -- set when linking an extra address
    method         VARCHAR(10)  NOT NULL DEFAULT 'minotaur',   -- minotaur or nautilus
    message_hex    TEXT         NOT NULL,          -- empty for nautilus
    ip             VARCHAR(45)  NOT NULL,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     DATETIME     NOT NULL,
    used_at        DATETIME     NULL,
    UNIQUE KEY uq_challenge_token (token_hash),
    KEY ix_challenge_ip (ip, created_at)
) ENGINE=InnoDB;

-- Browser sessions. Only a SHA-256 of the cookie value is stored.
CREATE TABLE IF NOT EXISTS sessions (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    token_hash     CHAR(64)     NOT NULL,
    csrf_token     CHAR(64)     NOT NULL,
    member_id      INT          NOT NULL,
    ip             VARCHAR(45)  NOT NULL,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at     DATETIME     NOT NULL,
    UNIQUE KEY uq_session_token (token_hash),
    KEY ix_session_member (member_id),
    CONSTRAINT fk_session_member FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Transactions started together (e.g. tens of requests uploaded at once). Each item is
-- named "<batch title> <n>".
CREATE TABLE IF NOT EXISTS batches (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    title_enc      TEXT         NOT NULL,
    item_count     SMALLINT UNSIGNED NOT NULL,
    created_by     INT          NOT NULL,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_batch_creator FOREIGN KEY (created_by) REFERENCES members(id)
) ENGINE=InnoDB;

-- A multi-sig transaction moving through the commitment and signing rounds.
-- status: commit -> sign -> complete -> broadcast   (or cancelled)
CREATE TABLE IF NOT EXISTS transactions (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    title_enc         TEXT         NOT NULL,
    description_enc   MEDIUMTEXT   NOT NULL,
    wallet_name       VARCHAR(80)  NOT NULL DEFAULT '',
    minotaur_version  VARCHAR(40)  NOT NULL,
    signers_required  TINYINT UNSIGNED NOT NULL,
    signers_total     TINYINT UNSIGNED NOT NULL,
    ergo_tx_id        CHAR(64)     NOT NULL,
    status            VARCHAR(12)  NOT NULL DEFAULT 'commit',
    commits           TINYINT UNSIGNED NOT NULL DEFAULT 0,
    signatures        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_by        INT          NOT NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at         DATETIME     NULL,
    lock_member_id    INT          NULL,
    lock_seq          INT          NOT NULL DEFAULT 0,
    locked_at         DATETIME     NULL,
    batch_id          INT          NULL,
    batch_seq         SMALLINT UNSIGNED NULL,
    KEY ix_tx_status (status, updated_at),
    KEY ix_tx_batch (batch_id, batch_seq),
    CONSTRAINT fk_tx_creator FOREIGN KEY (created_by) REFERENCES members(id),
    CONSTRAINT fk_tx_lock FOREIGN KEY (lock_member_id) REFERENCES members(id)
) ENGINE=InnoDB;

-- The signer keys of each transaction, read from the transaction itself, with the
-- latest state of each key's slot: 0 empty, 1 committed, 2 signed, 3 not participating.
-- An account can see a transaction only if it holds one of these keys.
CREATE TABLE IF NOT EXISTS transaction_keys (
    transaction_id  INT          NOT NULL,
    pk              CHAR(66)     NOT NULL,
    slot            TINYINT UNSIGNED NOT NULL,
    state           TINYINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (transaction_id, pk),
    KEY ix_txkey_pk (pk),
    CONSTRAINT fk_txkey_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id)
) ENGINE=InnoDB;

-- Every payload pasted into a transaction, in order. The newest row is the one the
-- next signer must continue from.
CREATE TABLE IF NOT EXISTS submissions (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id  INT          NOT NULL,
    member_id       INT          NOT NULL,
    round           VARCHAR(8)   NOT NULL,           -- start | commit | sign | final
    payload_enc     MEDIUMTEXT   NOT NULL,
    payload_sha256  CHAR(64)     NOT NULL,
    commits         TINYINT UNSIGNED NOT NULL DEFAULT 0,
    signatures      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_sub_tx (transaction_id, id),
    CONSTRAINT fk_sub_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id),
    CONSTRAINT fk_sub_member FOREIGN KEY (member_id) REFERENCES members(id)
) ENGINE=InnoDB;

-- Notes visible to every signer.
CREATE TABLE IF NOT EXISTS comments (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id  INT          NOT NULL,
    member_id       INT          NOT NULL,
    submission_id   INT          NULL,
    body_enc        TEXT         NOT NULL,
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_comment_tx (transaction_id, id),
    CONSTRAINT fk_comment_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id),
    CONSTRAINT fk_comment_member FOREIGN KEY (member_id) REFERENCES members(id)
) ENGINE=InnoDB;

-- Override votes to release a lock someone forgot to release. A lock is released once
-- UNLOCK_VOTES distinct members (other than the holder) have voted on the same lock_seq.
CREATE TABLE IF NOT EXISTS unlock_votes (
    transaction_id  INT          NOT NULL,
    lock_seq        INT          NOT NULL,
    member_id       INT          NOT NULL,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (transaction_id, lock_seq, member_id),
    CONSTRAINT fk_vote_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id),
    CONSTRAINT fk_vote_member FOREIGN KEY (member_id) REFERENCES members(id)
) ENGINE=InnoDB;

-- Append-only audit trail (sign-ins, locks, submissions, admin changes, ...).
CREATE TABLE IF NOT EXISTS events (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id  INT          NULL,
    member_id       INT          NULL,
    event           VARCHAR(32)  NOT NULL,
    detail          VARCHAR(255) NOT NULL DEFAULT '',
    ip              VARCHAR(45)  NOT NULL DEFAULT '',
    created_at      DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    KEY ix_event_tx (transaction_id, id),
    KEY ix_event_time (created_at)
) ENGINE=InnoDB;

-- Per-app database user (create both host forms; see DEPLOY.md). Example:
--   CREATE USER IF NOT EXISTS 'sigmasync_app'@'127.0.0.1' IDENTIFIED BY 'STRONG_PW';
--   CREATE USER IF NOT EXISTS 'sigmasync_app'@'localhost' IDENTIFIED BY 'STRONG_PW';
--   GRANT SELECT,INSERT,UPDATE,DELETE ON sigmasync.* TO 'sigmasync_app'@'127.0.0.1';
--   GRANT SELECT,INSERT,UPDATE,DELETE ON sigmasync.* TO 'sigmasync_app'@'localhost';
--   FLUSH PRIVILEGES;
