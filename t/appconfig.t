#!/usr/bin/perl
use strict;
use warnings;
use utf8;

use File::Temp qw(tempfile);
use FindBin;
use lib "$FindBin::Bin/..";
use Test::More;

my ($fh, $file) = tempfile(UNLINK => 1);
print $fh "# comment\nDATA_KEY=" . ('ab' x 32) . "\nQUOTED=\"hello world\"\nEMPTY=\n";
close $fh;
$ENV{APP_ENV_FILE} = $file;

require AppConfig;
AppConfig->import(qw(cfg seal unseal));

is(cfg('QUOTED'), 'hello world', 'reads quoted values');
is(cfg('EMPTY', 'fallback'), 'fallback', 'empty values fall back to the default');
is(cfg('MISSING', 7), 7, 'missing keys fall back to the default');

my $text = "Pay 1,000 ERG → treasury\nline two";
my $sealed = seal($text, 'comment.body');
like($sealed, qr/^v1:/, 'ciphertext is versioned');
unlike($sealed, qr/treasury/, 'ciphertext does not contain the plaintext');
isnt(seal($text, 'comment.body'), $sealed, 'each encryption uses a fresh nonce');
is(unseal($sealed, 'comment.body'), $text, 'round-trips UTF-8 text');
ok(!eval { unseal($sealed, 'transaction.title'); 1 }, 'refuses a ciphertext moved to another column');

my $tampered = $sealed;
substr($tampered, -6, 1) = substr($tampered, -6, 1) eq 'A' ? 'B' : 'A';
ok(!eval { unseal($tampered, 'comment.body'); 1 }, 'refuses tampered ciphertext');

done_testing;
