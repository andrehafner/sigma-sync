#!/usr/bin/perl
#
# Adds a multi-sig wallet to the registry from its Minotaur address, with a name (SPEC W9),
# so its signers see it before any of them registers it or starts a transaction. The
# address passes the same checks as in the app. Prints the wallet id. A wallet that is
# already registered keeps its name: the tool prints its id and changes nothing.
#
#   cd /data/AAP_Storage/apps/sigmasync
#   sudo APP_ENV_FILE=/data/AAP_Storage/secrets/sigmasync.env perl tools/add-wallet.pl '<address>' '<name>'
#
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/..";

use AppConfig qw(cfg dbh ensure_wallet);
use ErgoKit qw(wallet_from_address);

die "Usage: perl tools/add-wallet.pl <address> <name>\n" unless @ARGV == 2;
die "Set APP_ENV_FILE to the sigmasync env file.\n" unless $ENV{APP_ENV_FILE};
my ($address, $name) = @ARGV;
utf8::decode($name);
$name =~ s/[\x00-\x1F\x7F]//g;
$name =~ s/^\s+|\s+$//g;
die "Give the wallet a name of 1 to 80 characters.\n" unless length $name && length $name <= 80;

my ($w, $why) = wallet_from_address($address =~ s/\s+//gr, cfg('NETWORK', 'mainnet'));
die "$why\n" unless $w;
my $db = dbh();
$db->begin_work;
my ($id) = ensure_wallet($w, $name, undef);
$db->commit;
print "$id\n";
