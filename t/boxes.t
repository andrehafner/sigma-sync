#!/usr/bin/perl
# Run from the repository root:  prove -I. t/
# SPEC Q10, A10: a request's boxes are trusted only when each input has exactly one box
# whose Blake2b-256 hash is the id the input names.
use strict;
use warnings;

use FindBin;
use lib "$FindBin::Bin/..";
use JSON::PP;
use MIME::Base64 qw(encode_base64);
use Test::More;

use ErgoKit qw(address_decode analyze_payload blake2b256);

my $vlq    = \&ErgoKit::vlq;
my $sender = address_decode('9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy');
my $payee  = "\x00\x08\xcd\x02" . ("\x44" x 32);    # an output tree only: never decoded as a key
my $fee    = pack 'H*', '1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304';

# A full serialized box, as Minotaur lists it: candidate (no tokens, no registers), then the
# id of the transaction that made it and its output index. Its hash is its box id.
sub box { my ($value, $tree, $parent) = @_; $vlq->($value) . $tree . $vlq->(100) . "\x00\x00" . $parent . $vlq->(0) }
sub out { my ($value, $tree) = @_; $vlq->($value) . $tree . $vlq->(100) . "\x00\x00" }

# An MSR whose transaction spends the boxes @$spends (their hashes are the input ids), pays
# @$outs, and lists @$boxes as its input boxes.
sub analyze {
    my ($spends, $outs, $boxes) = @_;
    my $msg = $vlq->(scalar @$spends) . join('', map { blake2b256($_) . "\x00\x00" } @$spends)
            . $vlq->(0) . $vlq->(0) . $vlq->(scalar @$outs) . join('', @$outs);
    my $reduced = $vlq->(length $msg) . $msg . join('', map { "\xcd" . $sender->{pk} . "\x00" } @$spends) . "\x00";
    return analyze_payload(encode_json({ MSR => encode_json({ tx => encode_base64($reduced, ''),
        boxes => [ map { encode_base64($_, '') } @$boxes ], hints => [ map { [''] } @$spends ] }) }));
}

sub change_marks { return scalar grep { $_->{is_change} } @{ $_[0]{outputs} || [] } }

# Unverified reading: no inputs, no change, every output decoded but uncertain.
sub unverified {
    my ($a, $n_outs, $what) = @_;
    ok($a->{valid} && $a->{inputs_unverified}, "$what: inputs unverified");
    is_deeply($a->{inputs} // [], [], '... no inputs listed');
    ok(!defined $a->{inputs_value}, '... no input total');
    is(scalar @{ $a->{outputs} || [] }, $n_outs, '... every output still decoded');
    is(change_marks($a), 0, '... no output marked as change');
    ok($a->{outputs_uncertain}, '... outputs uncertain');
}

my $spent = box(15_000_000_000, $sender->{tree}, "\x22" x 32);
my @pay   = (out(10_000_000_000, $payee), out(4_998_900_000, $sender->{tree}), out(1_100_000, $fee));

# gate: SPEC Q10, A10 | a hash check that refuses honest boxes, or a verified path that loses the change mark | t/ergokit.t checks change with honest boxes but not the inputs_unverified flag
{
    my $a = analyze([$spent], \@pay, [$spent]);
    ok($a->{valid} && !$a->{inputs_unverified}, 'honest boxes: inputs verified');
    is($a->{inputs_value}, '15000000000', '... input total from the box');
    is_deeply([ map { $_->{address} } @{ $a->{inputs} || [] } ], ['9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy'], '... input address from the box');
    ok($a->{outputs}[1]{is_change} && !$a->{outputs}[0]{is_change}, '... the last output before the fee is change');
    ok(!$a->{outputs_uncertain}, '... outputs certain');
}

# gate: SPEC Q10, A10 | the starter lists a box made up at the payee's address, so the payment shows as change and drops out of the sends | no test lists a box that is not the input
{
    my $all = [ out(14_998_900_000, $payee), out(1_100_000, $fee) ];
    my $made_up = box(15_000_000_000, $payee, "\x22" x 32);
    unverified(analyze([$spent], $all, [$made_up]), 2, 'a box made up at the payee');
}

# gate: SPEC Q10, A10 | boxes trusted when some input has its box and another has none, or when one box is counted twice | no test spends two inputs or repeats a box
{
    my $second = box(5_000_000_000, $sender->{tree}, "\x23" x 32);
    my @two = (out(10_000_000_000, $payee), out(9_998_900_000, $sender->{tree}), out(1_100_000, $fee));
    unverified(analyze([$spent, $second], \@two, [$spent]), 3, 'an input with no box');
    unverified(analyze([$spent], \@pay, [$spent, $spent]), 3, 'one box listed twice');
}

# gate: SPEC Q10 | a box that matches no input is added to the total or the input addresses | no test lists an extra box
{
    my $extra = box(7_000_000_000, $payee, "\x55" x 32);
    my $a = analyze([$spent], \@pay, [$extra, $spent]);
    ok($a->{valid} && !$a->{inputs_unverified}, 'an extra box that matches no input: inputs verified');
    is($a->{inputs_value}, '15000000000', '... the extra box is not counted');
    is(scalar @{ $a->{inputs} || [] }, 1, '... nor listed');
    ok($a->{outputs}[1]{is_change} && !$a->{outputs_uncertain}, '... change and certainty kept');
}

done_testing;
