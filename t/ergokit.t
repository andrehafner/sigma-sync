#!/usr/bin/perl
# Run from the repository root:  prove -I. t/
use strict;
use warnings;
use utf8;

use FindBin;
use lib "$FindBin::Bin/..";
use JSON::PP;
use MIME::Base64 qw(encode_base64 decode_base64);
use Test::More;

use ErgoKit qw(address_decode address_from_tree build_login_request verify_login_response
               sanitize_payload analyze_payload compare_hints);

my $fixture = do {
    open my $fh, '<', "$FindBin::Bin/fixtures/login.json" or die $!;
    local $/;
    decode_json(<$fh>);
};

# --- Addresses ---------------------------------------------------------------
{
    my $addr = '9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy';
    my $info = address_decode($addr);
    ok($info, 'decodes a mainnet P2PK address');
    is($info->{type}, 'P2PK', '... as P2PK');
    is($info->{network}, 'mainnet', '... on mainnet');
    is(length $info->{pk}, 33, '... with a 33-byte public key');
    is(address_from_tree($info->{tree}), $addr, 'ErgoTree round-trips to the same address');

    (my $typo = $addr) =~ s/w/x/;
    ok(!address_decode($typo), 'rejects an address with a bad checksum');
    ok(!address_decode('not an address'), 'rejects garbage');
    ok(!address_decode(''), 'rejects empty input');
}

# --- Sign-in -------------------------------------------------------------------
# The fixture was signed by sigma-rust (ergo-lib) with a throwaway key.
{
    my $info = address_decode($fixture->{address});
    my $req = build_login_request(address => $fixture->{address}, nonce => $fixture->{nonce});
    is($req->{request}, $fixture->{request}, 'sign-in request is deterministic for a given nonce');

    my $csr = decode_json(decode_json($req->{request})->{CSR});
    is($csr->{sender}, $fixture->{address}, 'request names the signing address');
    is(scalar @{ $csr->{inputs} }, 1, 'request spends exactly one (fictional) box');

    my $msg = pack 'H*', $fixture->{message_hex};
    my ($ok) = verify_login_response(response => $fixture->{response}, expected_message => $msg, pk => $info->{pk});
    ok($ok, 'accepts a real signature from the wallet');

    my $other = build_login_request(address => $fixture->{address}, nonce => 'another-nonce-0123456789');
    my ($ok2, $why2) = verify_login_response(response => $fixture->{response}, expected_message => $other->{message}, pk => $info->{pk});
    ok(!$ok2, 'rejects a signature made for a different challenge');
    like($why2, qr/different sign-in request/, '... with a clear reason');

    my $wrong_pk = address_decode('9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy')->{pk};
    ok(!(verify_login_response(response => $fixture->{response}, expected_message => $msg, pk => $wrong_pk))[0],
       'rejects a signature checked against another key');

    my $outer = decode_json($fixture->{response});
    my $raw = decode_base64(decode_json($outer->{CSTX})->{signedTx});
    substr($raw, 40, 1) = chr(ord(substr($raw, 40, 1)) ^ 0x01);    # flip a bit in the proof
    my $tampered = encode_json({ CSTX => encode_json({ signedTx => encode_base64($raw, '') }) });
    ok(!(verify_login_response(response => $tampered, expected_message => $msg, pk => $info->{pk}))[0],
       'rejects a tampered proof');

    ok(!(verify_login_response(response => $fixture->{request}, expected_message => $msg, pk => $info->{pk}))[0],
       'rejects the request pasted back instead of the signed result');
}

# --- Payload hygiene -------------------------------------------------------------
{
    my $dirty = "\x{FEFF} {\x{201C}MSR\x{201D}:\r\n\"a\x{200B}b c\"}\t\n ";
    is(sanitize_payload($dirty), '{"MSR":"ab c"}', 'strips BOM, zero-width, line breaks and smart quotes; keeps real spaces');
}

# --- Multi-sig analysis --------------------------------------------------------------
# Builds a synthetic Minotaur MSR for an M-of-N wallet. States per slot:
# 0 empty, 1 committed, 2 signed, 3 simulated.
sub msr {
    my ($k, $n, $states, $seed) = @_;
    my $addr = '9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy';
    my $req  = build_login_request(address => $addr, nonce => "synthetic-tx-$seed-0123456789");
    my @pks  = map { "\x02" . chr(0x10 + $_) x 32 } 0 .. $n - 1;    # distinct, already sorted
    my $reduced = ErgoKit::vlq(length $req->{message}) . $req->{message}
                . "\x98" . chr($k) . ErgoKit::vlq($n) . join('', map { "\xcd" . $_ } @pks) . "\x00\x00";
    my @row = map {
        my $s = $states->[$_];
        my $commit = "\x02" . chr($_) x 32;
        $s == 0 ? '' : $s == 1 ? encode_base64($commit, '')
          : $s == 2 ? encode_base64($commit . ("\x11" x 56), '')
          : encode_base64($commit . ("\x22" x 56) . "\x01", '');
    } 0 .. $n - 1;
    my $inner = encode_json({ tx => encode_base64($reduced, ''), boxes => [], hints => [\@row] });
    return (encode_json({ MSR => $inner }), $req->{tx_id});
}

{
    my ($payload, $tx_id) = msr(3, 5, [1, 0, 1, 0, 0], 'a');
    my $a = analyze_payload($payload);
    ok($a->{valid}, 'analyses a Minotaur multi-sig request');
    is($a->{format}, 'MSR', '... format');
    is($a->{tx_id}, $tx_id, '... transaction id');
    is($a->{required}, 3, '... threshold M');
    is($a->{signers}, 5, '... signer count N');
    is($a->{committed}, 2, '... commitments');
    is($a->{signed}, 0, '... signatures');
    is_deeply($a->{slots}, [1, 0, 1, 0, 0], '... slot states');
    is(scalar @{ $a->{input_keys}[0] }, 5, '... lists the signer keys of each input');
    is_deeply($a->{input_keys}[0], [ sort @{ $a->{input_keys}[0] } ], '... in sorted (slot) order');
    is(scalar(grep { $_ == 1 } values %{ $a->{key_states} }), 2, '... with a state per key');
    is($a->{outputs}[0]{address}, '9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy', '... decodes outputs');

    my $signing = analyze_payload((msr(3, 5, [2, 3, 2, 3, 1], 'a'))[0]);
    is($signing->{committed}, 3, 'simulated slots are not counted as commitments');
    is($signing->{signed}, 2, 'signed slots are counted');

    my $prev = $a->{hints};
    my $next = analyze_payload((msr(3, 5, [1, 1, 1, 0, 0], 'a'))[0])->{hints};
    my $cmp = compare_hints($prev, $next);
    is($cmp->{lost} + $cmp->{changed}, 0, 'a new commitment loses nothing');
    is($cmp->{new_commits}, 1, '... and adds one commitment');
    is_deeply($cmp->{slots}, [1], '... in slot 1');

    my $stale = analyze_payload((msr(3, 5, [0, 1, 1, 0, 0], 'a'))[0])->{hints};
    is(compare_hints($prev, $stale)->{lost}, 1, 'detects a paste that drops an earlier commitment');

    my $sign = analyze_payload((msr(3, 5, [2, 3, 1, 3, 1], 'a'))[0])->{hints};
    my $cmp2 = compare_hints(analyze_payload((msr(3, 5, [1, 0, 1, 0, 1], 'a'))[0])->{hints}, $sign);
    is($cmp2->{new_signatures}, 1, 'detects a new signature');
    is($cmp2->{lost} + $cmp2->{changed}, 0, '... with simulated slots for non-participants allowed');
}

{
    my $a = analyze_payload('{"MSR":"{\"tx\":\"AAAA');
    ok(!$a->{valid}, 'rejects truncated JSON');
    like($a->{error}, qr/cut off/, '... and says it may be cut off');

    my $page = analyze_payload('{"MSR":"abc","p":1,"n":3}');
    like($page->{error}, qr/multi-page QR/, 'explains a single page of a multi-page QR');

    ok(!analyze_payload('hello')->{valid}, 'rejects plain text');

    my $cstx = analyze_payload($fixture->{response});
    is($cstx->{format}, 'CSTX', 'recognises a fully signed transaction');
    is($cstx->{tx_id}, $fixture->{tx_id}, '... and computes its transaction id');
}

done_testing;
