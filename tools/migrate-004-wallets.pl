#!/usr/bin/perl
#
# Migration 004, second half - links the existing transactions to their wallets (SPEC W7, W8).
#
# Run after tools/migrate-004-wallets.sql. For every transaction without a wallet it reads
# the first stored request; when every input names the same M and the same keys, and that
# wallet passes the registry's checks, it links the transaction and registers the wallet if
# nobody has. Then it names each wallet that has no name after the newest non-empty wallet
# name among its transactions. It never writes over a name.
#
# It connects with the app's own credentials (SELECT, INSERT and UPDATE are enough):
#
#   cd /data/AAP_Storage/apps/sigmasync
#   sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-004-wallets.pl --dry-run
#   sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/migrate-004-wallets.pl
#
# Safe to re-run: a second run changes nothing. The whole run is one database transaction,
# which --dry-run rolls back.
#
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/..";

use AppConfig qw(cfg dbh seal unseal ensure_wallet);
use ErgoKit qw(analyze_payload wallet_from_request);

my $DRY = grep { $_ eq '--dry-run' } @ARGV;
die "Set APP_ENV_FILE to the sigmasync env file.\n" unless $ENV{APP_ENV_FILE};

my $network = cfg('NETWORK', 'mainnet');
my $db = dbh();
# ponytail: one transaction for the whole run keeps every linked row locked until the end;
# commit per transaction if a large site needs the app to keep working meanwhile.
$db->begin_work;
print $DRY ? "DRY RUN - nothing will be changed.\n\n" : "Linking transactions to wallets...\n\n";

my ($linked, $created, $none) = (0, 0, 0);
my $txs = $db->selectcol_arrayref('SELECT id FROM transactions WHERE wallet_id IS NULL ORDER BY id');
for my $tx_id (@$txs) {
    my ($first) = $db->selectrow_array(
        'SELECT payload_enc FROM submissions WHERE transaction_id = ? ORDER BY id LIMIT 1', undef, $tx_id);
    my $w = defined $first && wallet_from_request(analyze_payload(unseal($first, 'submission.payload')), $network);
    unless ($w) { $none++; next }
    my ($wallet_id, $new) = ensure_wallet($w, '', undef);
    $db->do('UPDATE transactions SET wallet_id = ? WHERE id = ? AND wallet_id IS NULL', undef, $wallet_id, $tx_id);
    $linked++;
    $created += $new;
    print "  #$tx_id -> wallet $wallet_id", ($new ? ' (new)' : ''), "\n";
}
print "\n$linked linked, $created new wallets, $none without a wallet (inputs that disagree or no Minotaur wallet)\n";

# Names are printed by wallet id only: they are encrypted at rest (SPEC W5).
my $wallets = $db->selectall_arrayref('SELECT id, name_enc FROM wallets ORDER BY id');
for my $row (@$wallets) {
    my ($wallet_id, $sealed) = @$row;
    next if length unseal($sealed, 'wallet.name');
    my ($name) = $db->selectrow_array(q{SELECT wallet_name FROM transactions WHERE wallet_id = ? AND wallet_name <> ''
        ORDER BY id DESC LIMIT 1}, undef, $wallet_id);
    next unless defined $name;
    # The old ciphertext in the condition: a rename meanwhile wins.
    $db->do('UPDATE wallets SET name_enc = ? WHERE id = ? AND name_enc = ?', undef,
        seal($name, 'wallet.name'), $wallet_id, $sealed);
    print "  wallet $wallet_id named after its newest transaction with a wallet name\n";
}

if ($DRY) {
    $db->rollback;
    print "\nDry run finished. Re-run without --dry-run to apply.\n";
} else {
    $db->commit;
    print "\nDone.\n";
}
