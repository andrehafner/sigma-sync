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

# Output decoding: a Minotaur multi-sig address, the miner fee, and a P2PK output that
# carries a token and registers must all decode, with amounts and token ids.
{
    my $vlq = \&ErgoKit::vlq;
    my @pks = map { "\x02" . chr(0x30 + $_) x 32 } 0 .. 2;
    my $ms_tree = "\x10" . $vlq->(4) . "\x04" . $vlq->(4)          # 2-of-3 (zig-zag 2 = 4)
                . join('', map { "\x08\xcd" . $_ } @pks)
                . "\x98\x73\x00\x83" . $vlq->(3) . "\x08" . join('', map { "\x73" . $vlq->($_) } 1 .. 3);
    my $fee_tree = pack 'H*', '1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304';
    my $p2pk = address_decode('9f3AaAirSTGYKWqDcw8hEa4Pk4hYiS96VC3Kpcr7CKTuqTiwjCy')->{tree};
    my $token = "\xab" x 32;
    my $registers = "\x03"
        . "\x0e" . $vlq->(3) . 'abc'                              # R4: Coll[Byte]
        . "\x04" . $vlq->(84)                                     # R5: Int 42
        . "\x08\xcd" . $pks[0];                                   # R6: SigmaProp
    my $msg = $vlq->(1) . ("\x11" x 32) . "\x00\x00"              # one input
            . $vlq->(0)                                           # no data inputs
            . $vlq->(1) . $token                                  # token table
            . $vlq->(3)
            . $vlq->(5_000_000_000) . $p2pk . $vlq->(100) . "\x01" . $vlq->(0) . $vlq->(7) . $registers
            . $vlq->(2_000_000_000) . $ms_tree . $vlq->(100) . "\x00\x00"
            . $vlq->(1_100_000) . $fee_tree . $vlq->(100) . "\x00\x00";
    my $reduced = $vlq->(length $msg) . $msg . "\x98\x02" . $vlq->(3) . join('', map { "\xcd" . $_ } @pks) . "\x00\x00";
    my $payload = encode_json({ MSR => encode_json({ tx => encode_base64($reduced, ''), boxes => [], hints => [[ '', '', '' ]] }) });
    my $a = analyze_payload($payload);
    ok(!$a->{outputs_partial}, 'decodes every output (multi-sig, fee, registers)');
    is(scalar @{ $a->{outputs} }, 3, '... all three');
    is($a->{outputs}[0]{value}, '5000000000', '... payment amount');
    is_deeply($a->{outputs}[0]{tokens}, [ { id => unpack('H*', $token), amount => '7' } ], '... payment token');
    ok($a->{outputs}[1]{is_multisig}, '... multi-sig destination recognised');
    like($a->{outputs}[1]{address}, qr/^[1-9A-HJ-NP-Za-km-z]{60,}$/, '... with its P2S address');
    ok($a->{outputs}[2]{is_fee}, '... miner fee recognised');
    is($a->{minotaur_format}, '3', 'hints layout reported as Minotaur 3.0+');
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
