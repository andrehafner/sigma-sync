-- Migration 004 - the wallet registry.
-- Adds the wallets and wallet_keys tables and transactions.wallet_id. Safe to run twice.
--   sudo mysqldump sigmasync > ~/sigmasync-before-004.sql
--   sudo mysql sigmasync < tools/migrate-004-wallets.sql

CREATE TABLE IF NOT EXISTS wallets (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    network           VARCHAR(8)   NOT NULL,
    address           TEXT         NOT NULL,
    address_sha256    CHAR(64)     NOT NULL,
    signers_required  TINYINT UNSIGNED NOT NULL,
    signers_total     TINYINT UNSIGNED NOT NULL,
    name_enc          TEXT         NOT NULL,
    created_by        INT          NULL,
    created_at        DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_wallet_address (address_sha256)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS wallet_keys (
    wallet_id       INT          NOT NULL,
    pk              CHAR(66)     NOT NULL,
    slot            TINYINT UNSIGNED NOT NULL,
    PRIMARY KEY (wallet_id, pk),
    KEY ix_walletkey_pk (pk),
    CONSTRAINT fk_walletkey_wallet FOREIGN KEY (wallet_id) REFERENCES wallets(id)
) ENGINE=InnoDB;

-- The foreign key gives wallet_id its index. Like the keys MariaDB makes for the other
-- foreign keys of this table, it comes last, so a migrated table matches schema.sql.
ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS wallet_id INT NULL AFTER batch_seq,
    ADD CONSTRAINT fk_tx_wallet FOREIGN KEY IF NOT EXISTS (wallet_id) REFERENCES wallets(id);
