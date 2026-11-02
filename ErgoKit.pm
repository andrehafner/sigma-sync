package ErgoKit;
#
# ErgoKit - the small slice of the Ergo protocol that Sigma Sync needs, in pure Perl.
#
#   * Address encoding (Base58 + Blake2b-256 checksum)
#   * Wallet sign-in: build a Minotaur "Cold Signing Request" (CSR) that spends a
#     made-up box owned by the user's address, then verify the Schnorr signature in
#     the "Cold Signed Transaction" (CSTX) that Minotaur returns. The made-up box does
#     not exist on-chain, so the signed transaction can never be broadcast.
#   * Read-only analysis of Minotaur multi-sig payloads (MSR / CSTX): transaction id,
#     M-of-N threshold, per-signer commitment/signature slots, and a best-effort output
#     summary. Payloads are never modified.
#
# Byte formats follow sigma-rust / sigmastate (ErgoTree, ErgoBox, Transaction,
# ReducedTransaction, Fiat-Shamir proof trees) and Minotaur's QR/JSON envelope.
#
use strict;
use warnings;

use Crypt::Digest::BLAKE2b_256 qw(blake2b_256);
use JSON::PP ();
use MIME::Base64 qw(decode_base64 encode_base64);
use Math::BigInt try => 'GMP';    # pure-Perl fallback works, ~10x slower (~0.9 s per sign-in)

use Exporter 'import';
our @EXPORT_OK = qw(
    blake2b256 address_decode address_from_tree
    build_login_request verify_login_response
    sanitize_payload analyze_payload compare_hints
);

use constant {
    NETWORK_MAINNET => 0x00,
    NETWORK_TESTNET => 0x10,
    TYPE_P2PK       => 0x01,
    TYPE_P2SH       => 0x02,
    TYPE_P2S        => 0x03,
    LOGIN_BOX_VALUE => 1_000_000,   # 0.001 ERG; purely cosmetic, the box is fictional
};

# Miner-fee contract (mainnet and testnet use the same tree).
my $FEE_TREE_HEX = '1005040004000e36100204a00b08cd0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ea02d192a39a8cc7a701730073011001020402d19683030193a38cc7b2a57300000193c2b2a57301007473027303830108cdeeac93b1a57304';

sub blake2b256 { return blake2b_256($_[0]) }

# ---------------------------------------------------------------------------
# Base58 (Bitcoin alphabet)
# ---------------------------------------------------------------------------
my $B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
my %B58_INDEX = map { substr($B58, $_, 1) => $_ } 0 .. 57;

sub base58_encode {
    my ($bytes) = @_;
    my @digits;    # little-endian base-58 digits
    for my $byte (unpack 'C*', $bytes) {
        my $carry = $byte;
        for my $d (@digits) {
            $carry += $d << 8;
            $d = $carry % 58;
            $carry = int($carry / 58);
        }
        while ($carry) { push @digits, $carry % 58; $carry = int($carry / 58); }
    }
    my ($zeros) = $bytes =~ /^(\x00*)/;
    return ('1' x length $zeros) . join '', map { substr($B58, $_, 1) } reverse @digits;
}

sub base58_decode {
    my ($str) = @_;
    return undef unless defined $str && $str =~ /^[1-9A-HJ-NP-Za-km-z]+$/;
    my @bytes = (0);
    for my $ch (split //, $str) {
        my $carry = $B58_INDEX{$ch};
        for my $i (0 .. $#bytes) {
            $carry += $bytes[$i] * 58;
            $bytes[$i] = $carry & 0xff;
            $carry >>= 8;
        }
        while ($carry) { push @bytes, $carry & 0xff; $carry >>= 8; }
    }
    my ($leading) = $str =~ /^(1*)/;
    my $body = pack 'C*', reverse @bytes;
    $body =~ s/^\x00+//;
    return ("\x00" x length $leading) . $body;
}

# ---------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------

# Returns { network => 'mainnet'|'testnet', type => 'P2PK'|'P2SH'|'P2S', content => bytes,
#           pk => 33-byte key (P2PK only), tree => ErgoTree bytes (P2PK/P2S) } or undef.
sub address_decode {
    my ($address) = @_;
    my $raw = base58_decode($address // '');
    return undef unless defined $raw && length $raw > 5;
    my $body     = substr($raw, 0, -4);
    my $checksum = substr($raw, -4);
    return undef unless substr(blake2b256($body), 0, 4) eq $checksum;

    my $prefix  = ord substr($body, 0, 1);
    my $content = substr($body, 1);
    my $net     = $prefix & 0xF0;
    my $type    = $prefix & 0x0F;
    return undef unless $net == NETWORK_MAINNET || $net == NETWORK_TESTNET;

    my %info = (
        network => $net == NETWORK_MAINNET ? 'mainnet' : 'testnet',
        content => $content,
    );
    if ($type == TYPE_P2PK) {
        return undef unless length $content == 33 && $content =~ /^[\x02\x03]/;
        return undef unless ec_decompress($content);
        @info{qw(type pk tree)} = ('P2PK', $content, "\x00\x08\xcd" . $content);
    }
    elsif ($type == TYPE_P2S)  { @info{qw(type tree)} = ('P2S', $content) }
    elsif ($type == TYPE_P2SH) { $info{type} = 'P2SH' }
    else                       { return undef }
    return \%info;
}

sub address_from_tree {
    my ($tree, $network) = @_;
    my $net = ($network // 'mainnet') eq 'testnet' ? NETWORK_TESTNET : NETWORK_MAINNET;
    my $body;
    if (length $tree == 36 && substr($tree, 0, 3) eq "\x00\x08\xcd") {
        $body = chr($net | TYPE_P2PK) . substr($tree, 3);
    } else {
        $body = chr($net | TYPE_P2S) . $tree;
    }
    return base58_encode($body . substr(blake2b256($body), 0, 4));
}

# ---------------------------------------------------------------------------
# VLQ (unsigned LEB128, as used by sigma serialization)
# ---------------------------------------------------------------------------
sub vlq {
    my ($n) = @_;
    my $out = '';
    while (1) {
        my $b = $n & 0x7f;
        $n >>= 7;
        if ($n) { $out .= chr($b | 0x80) } else { $out .= chr($b); last }
    }
    return $out;
}

# A tiny cursor over a byte string. All readers die on truncated input.
sub _reader { my ($bytes) = @_; return { b => $bytes, p => 0 } }

sub _take {
    my ($r, $n) = @_;
    die "truncated data\n" if $n < 0 || $r->{p} + $n > length $r->{b};
    my $s = substr($r->{b}, $r->{p}, $n);
    $r->{p} += $n;
    return $s;
}

sub _u8 { return ord _take($_[0], 1) }

sub _vlq {
    my ($r) = @_;
    my ($n, $shift) = (0, 0);
    while (1) {
        my $b = _u8($r);
        die "VLQ too long\n" if $shift > 63;
        $n |= ($b & 0x7f) << $shift;
        last unless $b & 0x80;
        $shift += 7;
    }
    return $n;
}

# ---------------------------------------------------------------------------
# secp256k1 (just enough for Schnorr verification)
# ---------------------------------------------------------------------------
my $P  = Math::BigInt->from_hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
my $N  = Math::BigInt->from_hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
my $GX = Math::BigInt->from_hex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798');
my $GY = Math::BigInt->from_hex('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8');
my $G  = [$GX, $GY];

sub _mod { my $x = $_[0]->copy->bmod($P); return $x }

sub _bytes_to_int { return Math::BigInt->from_hex(unpack('H*', $_[0]) || '0') }

sub _int_to_bytes {
    my ($n, $len) = @_;
    my $hex = $n->as_hex;
    $hex =~ s/^0x//;
    $hex = ('0' x ($len * 2 - length $hex)) . $hex;
    return pack 'H*', $hex;
}

sub ec_decompress {
    my ($bytes) = @_;
    return undef unless length $bytes == 33;
    my $prefix = ord substr($bytes, 0, 1);
    return undef unless $prefix == 2 || $prefix == 3;
    my $x = _bytes_to_int(substr($bytes, 1));
    return undef if $x >= $P;
    my $rhs = _mod($x->copy->bmodpow(3, $P)->badd(7));
    my $y   = $rhs->copy->bmodpow(($P + 1) / 4, $P);
    return undef unless $y->copy->bmodpow(2, $P) == $rhs;
    $y = $P - $y if ($y->is_odd ? 3 : 2) != $prefix;
    return [$x, $y];
}

sub ec_compress {
    my ($pt) = @_;
    die "cannot encode point at infinity\n" unless $pt;
    return chr($pt->[1]->is_odd ? 3 : 2) . _int_to_bytes($pt->[0], 32);
}

sub _ec_add {
    my ($a, $b) = @_;
    return $b unless $a;
    return $a unless $b;
    my $lambda;
    if ($a->[0] == $b->[0]) {
        return undef if _mod($a->[1] + $b->[1])->is_zero;    # P + (-P)
        my $inv = ($a->[1] * 2)->bmodinv($P);
        $lambda = _mod($a->[0]->copy->bpow(2)->bmul(3)->bmul($inv));
    } else {
        my $inv = _mod($b->[0] - $a->[0])->bmodinv($P);
        $lambda = _mod(($b->[1] - $a->[1]) * $inv);
    }
    my $x = _mod($lambda->copy->bpow(2) - $a->[0] - $b->[0]);
    my $y = _mod($lambda * ($a->[0] - $x) - $a->[1]);
    return [$x, $y];
}

sub _ec_mul {
    my ($pt, $k) = @_;
    my $result;
    my $addend = $pt;
    my $bits = $k->copy->bmod($N)->as_bin;
    $bits =~ s/^0b//;
    for my $bit (reverse split //, $bits) {
        $result = _ec_add($result, $addend) if $bit;
        $addend = _ec_add($addend, $addend);
    }
    return $result;
}

sub _ec_neg { my ($pt) = @_; return $pt ? [$pt->[0], _mod($P - $pt->[1])] : undef }

# ---------------------------------------------------------------------------
# Sign-in: Cold Signing Request (CSR) -> Cold Signed Transaction (CSTX)
# ---------------------------------------------------------------------------

# ErgoBoxCandidate body (no tokens, no registers). Identical in a standalone box and in
# a transaction output when the box has no tokens.
sub _box_candidate_bytes {
    my ($value, $tree, $height) = @_;
    return vlq($value) . $tree . vlq($height) . "\x00" . "\x00";
}

# Builds the sign-in request for a P2PK address.
#   $nonce: random bytes (>= 16) unique to this challenge.
# Returns { request => '{"CSR":"..."}' text for Minotaur, message => bytes the wallet
#           signs (stored server-side), box_id => hex id of the fictional input box }.
sub build_login_request {
    my (%arg) = @_;
    my $info = address_decode($arg{address}) or die "invalid address\n";
    die "only P2PK wallet addresses can sign in\n" unless $info->{type} eq 'P2PK';
    die "nonce too short\n" unless length($arg{nonce} // '') >= 16;

    my $tree   = $info->{tree};
    my $height = $arg{height} // 1_000_000;

    # The fictional input box: its parent "transaction id" commits to the nonce, so the
    # box id (and therefore the signed message) is unique to this challenge.
    my $parent_tx_id = blake2b256("Sigma Sync sign-in\x00" . $arg{nonce});
    my $box_bytes    = _box_candidate_bytes(LOGIN_BOX_VALUE, $tree, $height)
                     . $parent_tx_id . vlq(0);
    my $box_id       = blake2b256($box_bytes);

    # Unsigned transaction: 1 input (empty proof, empty extension), no data inputs,
    # no tokens, 1 output returning the same value to the same address.
    my $message = vlq(1) . $box_id . "\x00" . "\x00"
                . vlq(0)
                . vlq(0)
                . vlq(1) . _box_candidate_bytes(LOGIN_BOX_VALUE, $tree, $height);

    # ReducedTransaction: len-prefixed unsigned tx, then per input the reduced sigma
    # proposition (ProveDlog = 0xcd || pk) and its cost, then the total cost.
    my $reduced = vlq(length $message) . $message
                . "\xcd" . $info->{pk} . vlq(0)
                . vlq(0);

    my $csr = JSON::PP->new->canonical->encode({
        reducedTx => encode_base64($reduced, ''),
        sender    => $arg{address},
        inputs    => [ encode_base64($box_bytes, '') ],
    });
    return {
        request => JSON::PP->new->canonical->encode({ CSR => $csr }),
        message => $message,
        box_id  => unpack('H*', $box_id),
        tx_id   => unpack('H*', blake2b256($message)),
    };
}

# Parses a signed transaction's input section and returns
#   (bytes_to_sign, [ { box_id, proof, ext_count } ... ]).
# The remainder of the transaction (data inputs, tokens, outputs) is copied verbatim.
# Context extensions are only supported when empty.
sub _signed_tx_split {
    my ($signed) = @_;
    my $r = _reader($signed);
    my $count = _vlq($r);
    die "transaction has no inputs\n" unless $count;
    my (@inputs, $unsigned);
    $unsigned = vlq($count);
    for (1 .. $count) {
        my $box_id = _take($r, 32);
        my $proof  = _take($r, _vlq($r));
        my $ext    = _u8($r);
        die "context extensions are not supported\n" if $ext;
        push @inputs, { box_id => $box_id, proof => $proof };
        $unsigned .= $box_id . "\x00" . "\x00";
    }
    $unsigned .= substr($signed, $r->{p});
    return ($unsigned, \@inputs);
}

# Verifies the CSTX text Minotaur returned for a sign-in request.
#   expected_message: the unsigned transaction bytes from build_login_request
#   pk: the 33-byte public key of the address that is signing in
# Returns (1) on success or (0, reason).
sub verify_login_response {
    my (%arg) = @_;
    my $doc = eval { _decode_envelope(sanitize_payload($arg{response})) };
    return (0, 'That does not look like Minotaur output. Paste the signed result (it starts with {"CSTX":).')
        unless $doc && $doc->{type} eq 'CSTX' && ref $doc->{data} eq 'HASH' && $doc->{data}{signedTx};

    my $signed = decode_base64($doc->{data}{signedTx});
    my ($message, $inputs) = eval { _signed_tx_split($signed) };
    return (0, 'The signed transaction could not be read.') unless $message;
    return (0, 'This signature is for a different sign-in request. Start again and use the newest request.')
        unless $message eq $arg{expected_message} && @$inputs == 1;

    my $proof = $inputs->[0]{proof};
    return (0, 'The wallet did not produce a signature.') unless length $proof == 56;

    return schnorr_verify($arg{pk}, $message, $proof)
        ? (1)
        : (0, 'Signature check failed. Make sure you signed with the wallet for this address.');
}

# Verifies a Fiat-Shamir proof for a single ProveDlog(pk) leaf, as produced by Ergo
# wallets: proof = challenge (24 bytes) || z (32 bytes).
sub schnorr_verify {
    my ($pk_bytes, $message, $proof) = @_;
    my $h = ec_decompress($pk_bytes) or return 0;
    my $e_bytes = substr($proof, 0, 24);
    my $e = _bytes_to_int($e_bytes);
    my $z = _bytes_to_int(substr($proof, 24, 32));

    # Commitment a = g^z * h^-e
    my $a = _ec_add(_ec_mul($G, $z), _ec_neg(_ec_mul($h, $e)));
    return 0 unless $a;

    # Fiat-Shamir tree bytes for one leaf: prefix 1, then the proposition as an ErgoTree
    # with constant segregation, then the commitment; each length-prefixed (int16 BE).
    my $prop = "\x10\x01\x08\xcd" . $pk_bytes . "\x73\x00";
    my $commitment = ec_compress($a);
    my $tree = "\x01" . pack('n', length $prop) . $prop
                      . pack('n', length $commitment) . $commitment;
    my $expected = substr(blake2b256($tree . $message), 0, 24);
    return $expected eq $e_bytes ? 1 : 0;
}

# ---------------------------------------------------------------------------
# Multi-sig payloads
# ---------------------------------------------------------------------------

# Removes characters that clipboards, chat apps and office tools add but that can never
# be part of a Minotaur payload. Nothing is re-encoded; the payload is otherwise untouched.
sub sanitize_payload {
    my ($text) = @_;
    $text //= '';
    $text =~ s/[\x{200B}-\x{200D}\x{2060}\x{FEFF}\x{00AD}]//g;   # zero-width & soft hyphen
    $text =~ s/[\x{201C}\x{201D}\x{201E}\x{201F}\x{2033}]/"/g;  # smart double quotes
    $text =~ s/[\x{2018}\x{2019}\x{201A}\x{201B}\x{2032}]/'/g;  # smart single quotes
    $text =~ s/\x{00A0}/ /g;                                     # non-breaking space
    $text =~ s/[\r\n\t]+//g;                                     # line breaks never belong
    $text =~ s/^\s+|\s+$//g;
    return $text;
}

# Splits '{"MSR":"<json>"}' into { type => 'MSR', data => {...} }.
sub _decode_envelope {
    my ($text) = @_;
    my $json  = JSON::PP->new->allow_nonref;
    my $outer = $json->decode($text);
    die "not an object\n" unless ref $outer eq 'HASH';
    my @keys = grep { $_ ne 'p' && $_ ne 'n' && $_ ne 'a' } keys %$outer;
    die "unexpected envelope\n" unless @keys == 1;
    my ($type) = @keys;
    my $data = $outer->{$type};
    $data = $json->decode($data) if !ref $data && $data =~ /^\s*[\{\[]/;
    die "partial QR page\n" if defined $outer->{n} && $outer->{n} > 1;
    return { type => $type, data => $data };
}

# Older Minotaur builds stored nested lists as Python-style strings: "[['a', '']]".
sub _as_list {
    my ($v) = @_;
    return $v if ref $v eq 'ARRAY';
    return [] unless defined $v && !ref $v && $v =~ /^\s*\[/;
    (my $j = $v) =~ s/'/"/g;
    my $parsed = eval { JSON::PP->new->decode($j) };
    return ref $parsed eq 'ARRAY' ? $parsed : [];
}

# Slot states. A hint is a 33-byte commitment, optionally followed by a 56-byte proof;
# a 90th byte marks a simulated proof (generated for signers who did not take part).
use constant { SLOT_EMPTY => 0, SLOT_COMMITTED => 1, SLOT_SIGNED => 2, SLOT_SIMULATED => 3 };

sub _hint_state {
    my ($hint) = @_;
    return SLOT_EMPTY unless defined $hint && !ref $hint && length $hint;
    my $len = length decode_base64($hint);
    return $len >= 90 ? SLOT_SIMULATED : $len >= 89 ? SLOT_SIGNED : SLOT_COMMITTED;
}

# Reads an ErgoTree from a stream. Supports trees carrying the size flag and plain
# P2PK trees; anything else stops the (best-effort) walk.
sub _read_tree {
    my ($r) = @_;
    my $header = _u8($r);
    if ($header & 0x08) {
        my $size = _vlq($r);
        return chr($header) . vlq($size) . _take($r, $size);
    }
    if ($header == 0x00 && substr($r->{b}, $r->{p}, 2) eq "\x08\xcd") {
        return chr($header) . _take($r, 35);
    }
    die "unsupported tree layout\n";
}

sub _parse_reduced {
    my ($bytes) = @_;
    my $r   = _reader($bytes);
    my $len = _vlq($r);
    my $msg = _take($r, $len);

    my %tx = (message => $msg, tx_id => unpack('H*', blake2b256($msg)));

    my $m = _reader($msg);
    my $n_in = _vlq($m);
    for (1 .. $n_in) {
        push @{ $tx{input_ids} }, unpack 'H*', _take($m, 32);
        _take($m, _vlq($m));
        die "context extensions are not supported\n" if _u8($m);
    }

    # Each input's reduced proposition: a threshold atLeast(M, keys) for multi-sig boxes,
    # or a single key. Keys are listed in sorted order, which is also the order of
    # Minotaur's hint slots.
    my @input_keys;
    my $readable = 1;
    for my $i (1 .. $n_in) {
        my $op = _u8($r);
        my @keys;
        if ($op == 0x98) {
            my $k = _u8($r);
            my $n = _vlq($r);
            for (1 .. $n) {
                if (_u8($r) != 0xcd) { $readable = 0; last }
                push @keys, unpack 'H*', _take($r, 33);
            }
            last unless $readable;
            @tx{qw(required signers)} = ($k, $n) if $i == 1;
        } elsif ($op == 0xcd) {
            push @keys, unpack 'H*', _take($r, 33);
            @tx{qw(required signers)} = (1, 1) if $i == 1;
        } else {
            $readable = 0;
            last;
        }
        _vlq($r);    # cost
        push @input_keys, [ sort @keys ];
    }
    $tx{input_keys} = \@input_keys if $readable;

    # Outputs (best effort - stops quietly on layouts we do not decode).
    eval {
        my $n_data = _vlq($m);
        _take($m, 32 * $n_data);
        my $n_tok = _vlq($m);
        my @token_ids = map { unpack 'H*', _take($m, 32) } 1 .. $n_tok;
        my $n_out = _vlq($m);
        for (1 .. $n_out) {
            my %o = (value => '' . _vlq($m));    # strings: amounts can exceed JS safe integers
            my $tree = _read_tree($m);
            $o{tree}    = unpack 'H*', $tree;
            $o{address} = address_from_tree($tree);
            $o{is_fee}  = $o{tree} eq $FEE_TREE_HEX ? 1 : 0;
            _vlq($m);    # creation height
            my $nt = _u8($m);
            for (1 .. $nt) {
                my $idx = _vlq($m);
                push @{ $o{tokens} }, { id => $token_ids[$idx], amount => '' . _vlq($m) };
            }
            push @{ $tx{outputs} }, \%o;
            die "registers\n" if _u8($m);    # cannot skip registers safely
        }
        1;
    } or $tx{outputs_partial} = 1;

    return \%tx;
}

sub _parse_box_summary {
    my ($b64) = @_;
    my $r = _reader(decode_base64($b64));
    my %b = (value => _vlq($r));
    my $tree = _read_tree($r);
    $b{address} = address_from_tree($tree);
    return \%b;
}

# Read-only analysis of a pasted payload. Never throws; returns a hashref:
#   format   => 'MSR' | 'CSTX' | 'text'
#   valid    => 1 if the payload is a well-formed format we understand
#   tx_id, required, signers, committed, signed, hints (matrix of strings),
#   outputs, inputs_value, error
sub analyze_payload {
    my ($text) = @_;
    my %res = (format => 'text', valid => 0);
    $text = sanitize_payload($text);
    unless (length $text) { $res{error} = 'Empty payload.'; return \%res }
    unless ($text =~ /^\{/) {
        $res{error} = 'This is not a Minotaur payload (expected text starting with {"MSR": or {"CSTX":).';
        return \%res;
    }
    my $doc = eval { _decode_envelope($text) };
    unless ($doc) {
        $res{error} = 'The payload is not valid JSON. It may be cut off - copy it again in full.';
        $res{error} = 'This is a single page of a multi-page QR code. Scan every page, or copy the text instead.'
            if ($@ // '') =~ /partial/;
        return \%res;
    }
    $res{format} = $doc->{type};
    my $d = $doc->{data};

    if ($doc->{type} eq 'CSTX') {
        unless (ref $d eq 'HASH' && $d->{signedTx}) { $res{error} = 'CSTX payload has no signedTx.'; return \%res }
        my ($msg) = eval { _signed_tx_split(decode_base64($d->{signedTx})) };
        if ($msg) {
            $res{tx_id} = unpack 'H*', blake2b256($msg);
        } else {
            $res{warning} = 'Signed transaction is in a layout Sigma Sync cannot fully read; it was not checked against the original.';
        }
        $res{valid} = 1;
        return \%res;
    }

    unless ($doc->{type} eq 'MSR' && ref $d eq 'HASH' && $d->{tx}) {
        $res{error} = "Unrecognised payload type '$doc->{type}'.";
        return \%res;
    }

    my $tx = eval { _parse_reduced(decode_base64($d->{tx})) };
    unless ($tx) { $res{error} = 'The transaction inside the payload could not be read. It may be truncated.'; return \%res }
    @res{qw(tx_id required signers outputs outputs_partial input_keys)}
        = @$tx{qw(tx_id required signers outputs outputs_partial input_keys)};

    # Hints: current builds use "hints" (matrix input x signer slot); the oldest builds
    # used "commitments" + "signed".
    my $matrix = _as_list(exists $d->{hints} ? $d->{hints} : $d->{commitments});
    my @hints = map { [ map { defined $_ && !ref $_ ? $_ : '' } @{ _as_list($_) } ] } @$matrix;
    $res{hints} = \@hints;

    # Every input carries one slot per signer key; count the least-complete input.
    my ($committed, $signed);
    for my $row (@hints) {
        my @state = map { _hint_state($_) } @$row;
        my $c = grep { $_ == SLOT_COMMITTED || $_ == SLOT_SIGNED } @state;
        my $s = grep { $_ == SLOT_SIGNED } @state;
        $committed = $c if !defined $committed || $c < $committed;
        $signed    = $s if !defined $signed    || $s < $signed;
    }
    $res{slots} = [ map { _hint_state($_) } @{ $hints[0] || [] } ];

    # State per signer key (hex): slot j of input i belongs to the j-th key of that input.
    if ($res{input_keys}) {
        my %state;
        for my $i (0 .. $#{ $res{input_keys} }) {
            my $keys = $res{input_keys}[$i];
            for my $j (0 .. $#$keys) {
                $state{ $keys->[$j] } //= _hint_state($hints[$i][$j]);
            }
        }
        $res{key_states} = \%state;
    }
    if (!exists $d->{hints} && ref $d->{signed} eq 'ARRAY') {
        $signed = scalar @{ $d->{signed} };
    }
    $res{committed} = $committed // 0;
    $res{signed}    = $signed // 0;
    $res{signers} //= scalar @{ $hints[0] // [] } || undef;

    # Input value (best effort) from the serialized input boxes.
    my $boxes = _as_list($d->{boxes});
    my ($total, @in_addr) = (0);
    for my $b (@$boxes) {
        my $s = eval { _parse_box_summary($b) } or do { $total = undef; last };
        $total += $s->{value};
        push @in_addr, $s->{address};
    }
    if (defined $total && @$boxes) {
        $res{inputs_value} = "$total";
        my %mine = map { $_ => 1 } @in_addr;
        $_->{is_change} = $mine{ $_->{address} } ? 1 : 0 for @{ $res{outputs} || [] };
    }

    $res{valid} = 1;
    return \%res;
}

# Compares the hint matrices of the previous and the new payload.
# Returns { lost, changed, new_commits, new_signatures, slots => [indices that progressed] }.
#   lost/changed are counted over every input; progress is reported for the first input
#   (all inputs move together, so that equals "per signer").
sub compare_hints {
    my ($old, $new) = @_;
    my %r = (lost => 0, changed => 0, new_commits => 0, new_signatures => 0, slots => []);
    my $rows = @$old > @$new ? @$old : @$new;
    for my $i (0 .. $rows - 1) {
        my $o = $old->[$i] || [];
        my $n = $new->[$i] || [];
        my $cols = @$o > @$n ? @$o : @$n;
        for my $j (0 .. $cols - 1) {
            my ($ov, $nv) = ($o->[$j] // '', $n->[$j] // '');
            next if $ov eq $nv;
            my ($os, $ns) = (_hint_state($ov), _hint_state($nv));
            my $progress;
            if ($os == SLOT_EMPTY) {
                $progress = $ns == SLOT_SIMULATED ? undef : $ns;
            } elsif ($ns == SLOT_EMPTY) {
                $r{lost}++;
            } elsif (substr(decode_base64($ov), 0, 33) ne substr(decode_base64($nv), 0, 33)) {
                $r{changed}++;                       # slot overwritten with a new commitment
            } elsif ($os == SLOT_COMMITTED && $ns == SLOT_SIGNED) {
                $progress = SLOT_SIGNED;
            } elsif ($os == SLOT_COMMITTED && $ns == SLOT_SIMULATED) {
                # a committed signer that is left out of the final signature: allowed
            } else {
                $r{lost}++;                          # a proof was removed or replaced
            }
            next unless $progress && $i == 0;
            $r{new_commits}++    if $os == SLOT_EMPTY;
            $r{new_signatures}++ if $progress == SLOT_SIGNED;
            push @{ $r{slots} }, $j;
        }
    }
    return \%r;
}

1;
