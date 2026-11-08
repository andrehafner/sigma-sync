-- Migration 002 - batch transactions.
-- Adds the batches table and the batch columns on transactions. Safe to run twice.
--   sudo mysqldump sigmasync > ~/sigmasync-before-002.sql
--   sudo mysql sigmasync < tools/migrate-002-batches.sql

CREATE TABLE IF NOT EXISTS batches (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    title_enc      TEXT         NOT NULL,
    item_count     SMALLINT UNSIGNED NOT NULL,
    created_by     INT          NOT NULL,
    created_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_batch_creator FOREIGN KEY (created_by) REFERENCES members(id)
) ENGINE=InnoDB;

ALTER TABLE transactions
    ADD COLUMN IF NOT EXISTS batch_id  INT NULL AFTER locked_at,
    ADD COLUMN IF NOT EXISTS batch_seq SMALLINT UNSIGNED NULL AFTER batch_id,
    ADD INDEX IF NOT EXISTS ix_tx_batch (batch_id, batch_seq);
