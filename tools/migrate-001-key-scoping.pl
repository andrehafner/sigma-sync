#!/usr/bin/perl
#
# Migration 001 - key-scoped access (open sign-in).
#
# Upgrades a database created with the first release of schema.sql:
#   * members.address  ->  member_keys (address + public key), members.name_chosen
#   * signer keys of every transaction  ->  transaction_keys (read from its latest
#     stored request, which is decrypted with DATA_KEY)
#   * auth_challenges.member_id, drops submissions.slot_index
#
# Run on the server as root (connects to MariaDB as root over the local socket):
#
#   sudo mysqldump sigmasync > ~/sigmasync-before-001.sql          # backup first
#   cd /data/AAP_Storage/apps/sigmasync
#   sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-001-key-scoping.pl --dry-run
#   sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-001-key-scoping.pl
#
# Safe to re-run: it stops if the database is already migrated.
#
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/..";

use DBI;
use AppConfig qw(cfg unseal);
use ErgoKit qw(address_decode analyze_payload);

my $DRY = grep { $_ eq '--dry-run' } @ARGV;
die "Set APP_ENV_FILE to the sigmasync env file.\n" unless $ENV{APP_ENV_FILE};

my $db_name = cfg('DB_NAME', 'sigmasync');
my $dbh = DBI->connect("DBI:mysql:database=$db_name;host=localhost", 'root', '',
    { RaiseError => 1, PrintError => 0, AutoCommit => 1, mysql_enable_utf8mb4 => 1 })
    or die "Cannot connect as MariaDB root. Run this script with sudo.\n";

sub has_column {
    my ($table, $column) = @_;
    return $dbh->selectrow_array(q{SELECT COUNT(*) FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? AND COLUMN_NAME = ?}, undef, $db_name, $table, $column);
}

# Schema changes are printed; per-row writes run silently (their rows are listed instead).
sub run {
    my ($sql, @bind) = @_;
    (my $short = $sql) =~ s/\s+/ /g;
    print '  ', ($DRY ? 'would run: ' : ''), substr($short, 0, 100), "\n";
    $dbh->do($sql, undef, @bind) unless $DRY;
}

sub write_row { my ($sql, @bind) = @_; $dbh->do($sql, undef, @bind) unless $DRY }

unless (has_column('members', 'address')) {
    print "Database '$db_name' is already migrated - nothing to do.\n";
    exit 0;
}
print $DRY ? "DRY RUN - nothing will be changed.\n\n" : "Migrating '$db_name'...\n\n";

# --- 1. New tables and columns ------------------------------------------------
print "1. New tables and columns\n";
run(q{CREATE TABLE IF NOT EXISTS member_keys (
    id INT AUTO_INCREMENT PRIMARY KEY, member_id INT NOT NULL, address VARCHAR(64) NOT NULL,
    pk CHAR(66) NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_key_address (address), UNIQUE KEY uq_key_pk (pk), KEY ix_key_member (member_id),
    CONSTRAINT fk_key_member FOREIGN KEY (member_id) REFERENCES members(id) ON DELETE CASCADE
) ENGINE=InnoDB});
run(q{CREATE TABLE IF NOT EXISTS transaction_keys (
    transaction_id INT NOT NULL, pk CHAR(66) NOT NULL, slot TINYINT UNSIGNED NOT NULL,
    state TINYINT UNSIGNED NOT NULL DEFAULT 0, PRIMARY KEY (transaction_id, pk), KEY ix_txkey_pk (pk),
    CONSTRAINT fk_txkey_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id)
) ENGINE=InnoDB});
run('ALTER TABLE auth_challenges ADD COLUMN IF NOT EXISTS member_id INT NULL AFTER address');
run('ALTER TABLE members ADD COLUMN IF NOT EXISTS name_chosen TINYINT(1) NOT NULL DEFAULT 0 AFTER display_name');
write_row('UPDATE members SET name_chosen = 1');    # existing names were set deliberately

# --- 2. Member addresses -> member_keys -------------------------------------------
print "\n2. Member addresses\n";
my $members = $dbh->selectall_arrayref('SELECT id, address, display_name FROM members ORDER BY id', { Slice => {} });
for my $m (@$members) {
    my $info = address_decode($m->{address});
    unless ($info && $info->{pk}) {
        print "  !! #$m->{id} $m->{display_name}: '$m->{address}' is not a P2PK address - skipped\n";
        next;
    }
    my $pk = unpack 'H*', $info->{pk};
    print "  #$m->{id} $m->{display_name}: $m->{address}\n";
    write_row('INSERT IGNORE INTO member_keys (member_id, address, pk) VALUES (?,?,?)', $m->{id}, $m->{address}, $pk);
}

# --- 3. Transaction signer keys -> transaction_keys ---------------------------------
print "\n3. Transaction signer keys\n";
my %member_by_pk = map { (unpack('H*', (address_decode($_->{address}) || {})->{pk} // '')) => $_->{display_name} } @$members;
my $txs = $dbh->selectall_arrayref('SELECT id, status, ergo_tx_id FROM transactions ORDER BY id', { Slice => {} });
for my $tx (@$txs) {
    my $subs = $dbh->selectall_arrayref(
        'SELECT payload_enc FROM submissions WHERE transaction_id = ? ORDER BY id DESC', undef, $tx->{id});
    my $analysis;
    for my $s (@$subs) {
        my $a = analyze_payload(unseal($s->[0], 'submission.payload'));
        if ($a->{input_keys}) { $analysis = $a; last }
    }
    unless ($analysis) {
        print "  !! #$tx->{id}: no Minotaur multi-sig request with readable signer keys"
            . " (a non-Minotaur transaction?) - it will be cancelled\n";
        write_row(q{UPDATE transactions SET status = 'cancelled', closed_at = COALESCE(closed_at, UTC_TIMESTAMP()),
              lock_member_id = NULL, locked_at = NULL, ergo_tx_id = COALESCE(ergo_tx_id, ''),
              signers_total = COALESCE(signers_total, 0) WHERE id = ?}, $tx->{id});
        write_row(q{INSERT INTO events (transaction_id, event, detail) VALUES (?, 'cancel', ?)},
            $tx->{id}, 'Migration 001: no signer keys (non-Minotaur transaction)');
        next;
    }
    my %seen;
    my @keys = grep { !$seen{$_}++ } sort map { @$_ } @{ $analysis->{input_keys} };
    my @known = grep { $member_by_pk{$_} } @keys;
    printf "  #%d: %d signer keys, %d belong to existing members (%s)\n", $tx->{id}, scalar @keys,
        scalar @known, join(', ', map { $member_by_pk{$_} } @known) || 'none - visible once they sign in';
    for my $i (0 .. $#keys) {
        write_row('INSERT IGNORE INTO transaction_keys (transaction_id, pk, slot, state) VALUES (?,?,?,?)',
            $tx->{id}, $keys[$i], $i, $analysis->{key_states}{ $keys[$i] } // 0);
    }
    write_row('UPDATE transactions SET signers_total = ? WHERE id = ?', scalar @keys, $tx->{id});
}

# --- 4. Drop what the new code no longer uses ------------------------------------------
print "\n4. Remove old columns\n";
run('ALTER TABLE members DROP INDEX uq_members_address, DROP COLUMN address, DROP COLUMN created_by');
run('ALTER TABLE submissions DROP COLUMN IF EXISTS slot_index');
run('ALTER TABLE transactions MODIFY signers_total TINYINT UNSIGNED NOT NULL, MODIFY ergo_tx_id CHAR(64) NOT NULL');

print $DRY ? "\nDry run finished. Re-run without --dry-run to apply.\n"
           : "\nDone. Every member keeps their account, name and history.\n";
