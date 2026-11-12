#!/usr/bin/perl
# Run from the repository root:  prove -I. t/
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/..";
use JSON::PP;
use Test::More;

use ErgoKit qw(address_decode verify_login_response verify_nautilus_auth);

sub fixture {
    open my $fh, '<', "$FindBin::Bin/fixtures/$_[0]" or die $!;
    local $/;
    return decode_json(<$fh>);
}

# Signed by Wallet.sign_message_using_p2pk of ergo-lib-wasm-browser 0.28.0 (sigma-rust
# 0.28.0) with a throwaway key. The file names the address and the public key.
my $fx       = fixture('nautilus-auth.json');
my $minotaur = fixture('login.json');
my $pk       = address_decode($fx->{address})->{pk};
my (undef, undef, $seconds, $rand) = split /;/, $fx->{signed_message};

# A challenge issued at the signed time that lives 15 minutes (CHALLENGE_MINUTES), with
# the 300 seconds of L4 on each side, as auth_finish computes the window.
sub check {
    my (%over) = @_;
    my ($issued, $expires) = (delete $over{issued} // $seconds, delete $over{expires} // $seconds + 900);
    return verify_nautilus_auth(
        signed_message => $fx->{signed_message},
        proof          => $fx->{proof},
        challenge      => $fx->{challenge},
        host           => $fx->{host},
        pk             => $pk,
        not_before     => $issued - 300,
        not_after      => $expires + 300,
        %over,
    );
}

my $FORMAT = qr/not return a Nautilus sign-in text/;
my $PROOF  = qr/Signature check failed/;

# gate: SPEC A1, L9 | the wrapper hashes other bytes than the signed text and refuses every real Nautilus proof | no other test feeds a Nautilus text to the verifier
{
    my $text = $fx->{signed_message};
    utf8::upgrade($text);    # api.pl hands over decoded text
    my ($ok, $why) = check(signed_message => $text);
    ok($ok, 'accepts a Nautilus sign-in signed by sigma-rust 0.28.0') or diag $why;
}

# gate: SPEC L4 field count | a text with our four fields first and more after it passes, so another site relays our challenge | only this file tests the field count
{
    my ($ok, $why) = check(signed_message => $fx->{relayed_signed_message}, proof => $fx->{relayed_proof});
    ok(!$ok, 'refuses a relayed text of seven fields with a valid proof');
    like($why, $FORMAT, '... for its field count');

    (my $short = $fx->{signed_message}) =~ s/.\z//;
    ($ok, $why) = check(signed_message => $short);
    like($why, $FORMAT, 'refuses field 4 of 63 hex characters for its form');
}

# gate: SPEC L4 field 1 | the challenge in the text is not compared, so a proof for one challenge spends another | only this file tests field 1
{
    my ($ok, $why) = check(challenge => 'ab' x 32);
    ok(!$ok, 'refuses a text for another challenge');
    like($why, qr/different sign-in request/, '... as another request');
}

# gate: SPEC L4 field 2, I5 | the host is not compared, or an empty SITE_HOST matches an empty field 2 | only this file tests field 2
{
    my ($ok, $why) = check(host => 'evil.example');
    ok(!$ok, 'refuses a text signed for another site host');
    like($why, qr/another site/, '... as another site');

    ($ok, $why) = check(host => '', signed_message => "$fx->{challenge};;$seconds;$rand");
    ok(!$ok, 'refuses an empty field 2 when the site host is empty');
    like($why, qr/another site/, '... as another site');
}

# gate: SPEC L4 field 3 | the window is skipped or off by one at either edge | only this file tests field 3
{
    my ($ok, $why) = check(issued => $seconds + 301);
    ok(!$ok, 'refuses a time 301 seconds before the challenge was issued');
    like($why, qr/outside the sign-in window/, '... as outside the window');

    ($ok, $why) = check(expires => $seconds - 301);
    ok(!$ok, 'refuses a time 301 seconds after the challenge expired');
    like($why, qr/outside the sign-in window/, '... as outside the window');

    ok((check(issued  => $seconds + 300))[0], 'accepts a time 300 seconds before the challenge was issued');
    ok((check(expires => $seconds - 300))[0], 'accepts a time 300 seconds after the challenge expired');
}

# gate: SPEC L4 proof, L9 | the proof is not checked against the text and the key, or a short proof reaches the verifier | only this file verifies a Nautilus proof
{
    my $text = $fx->{signed_message};
    substr($text, -1, 1) = substr($text, -1, 1) eq '0' ? '1' : '0';
    my ($ok, $why) = check(signed_message => $text);
    ok(!$ok, 'refuses a text with one changed character in field 4');
    like($why, $PROOF, '... as a failed signature check');

    ($ok, $why) = check(pk => address_decode($minotaur->{address})->{pk});
    ok(!$ok, 'refuses the proof checked against another key');
    like($why, $PROOF, '... as a failed signature check');

    ($ok, $why) = check(proof => substr($fx->{proof}, 2));
    ok(!$ok, 'refuses a proof of 110 hex characters');
    like($why, qr/did not produce a signature/, '... as no signature');
}

# gate: SPEC L10 | one method's verifier accepts the other method's answer | only this file crosses the two methods
{
    my ($ok, $why) = check(signed_message => $minotaur->{response});
    ok(!$ok, 'refuses a Minotaur answer for a Nautilus challenge');
    like($why, $FORMAT, '... as not a Nautilus text');

    ($ok, $why) = verify_login_response(response => $fx->{signed_message},
        expected_message => pack('H*', $minotaur->{message_hex}), pk => $pk);
    ok(!$ok, 'refuses a Nautilus answer for a Minotaur challenge');
    like($why, qr/does not look like Minotaur output/, '... as not Minotaur output');
}

done_testing();
