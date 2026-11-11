-- Migration 003 - the sign-in method of a challenge.
-- Adds auth_challenges.method: minotaur (every existing row) or nautilus. Safe to run twice.
--   sudo mysqldump sigmasync > ~/sigmasync-before-003.sql
--   sudo mysql sigmasync < tools/migrate-003-auth-method.sql

ALTER TABLE auth_challenges
    ADD COLUMN IF NOT EXISTS method VARCHAR(10) NOT NULL DEFAULT 'minotaur' AFTER member_id;
