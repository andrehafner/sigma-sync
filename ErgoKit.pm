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
    build_login_request verify_login_response verify_nautilus_auth
    wallet_from_address wallet_from_request wallet_tree
    sanitize_payload analyze_payload compare_hints payload_input_ids
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

# Base58 is slow in pure Perl and a large transaction repeats the same few trees, so
# addresses are cached per process.
my %ADDRESS_CACHE;
sub address_from_tree {
    my ($tree, $network) = @_;
    my $cached = \$ADDRESS_CACHE{ ($network // 'mainnet') . ':' . $tree };
    return $$cached //= _address_from_tree($tree, $network);
}

sub _address_from_tree {
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
# Returns (1) on success or (0, reason[, signed_message]).
sub verify_login_response {
    my (%arg) = @_;
    my $doc = eval { _decode_envelope(sanitize_payload($arg{response})) };
    return (0, 'That does not look like Minotaur output. Paste the signed result (it starts with {"CSTX":).')
        unless $doc && $doc->{type} eq 'CSTX' && ref $doc->{data} eq 'HASH' && $doc->{data}{signedTx};

    my $signed = decode_base64($doc->{data}{signedTx});
    my ($message, $inputs) = eval { _signed_tx_split($signed) };
    return (0, 'The signed transaction could not be read.') unless $message;
    # On a mismatch the signed message is returned too, so the caller can tell the user
    # *which* request was signed (e.g. an old one a wallet re-displayed).
    return (0, 'This signature is for a different sign-in request. Start again and use the newest request.', $message)
        unless $message eq $arg{expected_message} && @$inputs == 1;

    my $proof = $inputs->[0]{proof};
    return (0, 'The wallet did not produce a signature.') unless length $proof == 56;

    return schnorr_verify($arg{pk}, $message, $proof)
        ? (1)
        : (0, 'Signature check failed. Make sure you signed with the wallet for this address.');
}

# Verifies the text and proof that Nautilus's auth(address, challenge) returned, with the
# checks of SPEC L4 in their order. The text is "challenge;host;seconds;random" and the
# proof is the single-key proof verify_login_response checks, over the text's bytes (L9).
#   challenge: the stored token; host: SITE_HOST; pk: 33 bytes of the stored address
#   not_before, not_after: Unix seconds, the challenge's life widened by 300 each side
# Returns (1) on success or (0, reason).
sub verify_nautilus_auth {
    my (%arg) = @_;
    my $text   = $arg{signed_message} // '';
    my @fields = split /;/, $text, -1;
    my $not_nautilus = 'The wallet did not return a Nautilus sign-in text.';
    return (0, $not_nautilus) unless $text =~ /\A[\x20-\x7e]{1,300}\z/ && @fields == 4;
    my ($challenge, $host, $seconds, $rand) = @fields;

    return (0, 'This signature is for a different sign-in request. Start again and use the newest request.')
        unless length $challenge && $challenge eq ($arg{challenge} // '');
    return (0, 'This signature was made for another site.')
        unless length $host && $host eq ($arg{host} // '');
    return (0, 'The time in the signed text is outside the sign-in window. Check the clock of this computer.')
        unless $seconds =~ /\A[0-9]+\z/ && $seconds >= $arg{not_before} && $seconds <= $arg{not_after};
    return (0, $not_nautilus) unless $rand =~ /\A[0-9a-fA-F]{64}\z/;

    my $proof = $arg{proof} // '';
    return (0, 'The wallet did not produce a signature.') unless $proof =~ /\A[0-9a-fA-F]{112}\z/;
    return schnorr_verify($arg{pk}, $text, pack('H*', $proof))
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
    my $start  = $r->{p};
    my $header = _u8($r);
    if ($header & 0x08) {                                   # size flag: length is given
        my $size = _vlq($r);
        return chr($header) . vlq($size) . _take($r, $size);
    }
    if ($header == 0x00 && substr($r->{b}, $r->{p}, 2) eq "\x08\xcd") {    # P2PK
        return chr($header) . _take($r, 35);
    }
    if ($header == 0x10) {
        my $fee = pack 'H*', $FEE_TREE_HEX;
        if (substr($r->{b}, $start, length $fee) eq $fee) {             # miner fee contract
            $r->{p} = $start + length $fee;
            return $fee;
        }
        _skip_minotaur_multisig_body($r);                                 # Minotaur multi-sig wallet
        return substr($r->{b}, $start, $r->{p} - $start);
    }
    die "unsupported tree layout\n";
}

# Minotaur multi-sig address (constant-segregated, no size flag):
#   10 <n+1> 04 <M> (08 cd <key>) x n  98 73 00  83 <n> 08  (73 <i>) for i = 1..n
sub _skip_minotaur_multisig_body {
    my ($r) = @_;
    my $count = _vlq($r);
    die "not a multi-sig tree\n" unless $count >= 2 && _u8($r) == 0x04;
    _vlq($r);                                               # M (zig-zag int)
    for (2 .. $count) {
        die "not a multi-sig tree\n" unless _take($r, 2) eq "\x08\xcd";
        _take($r, 33);
    }
    my $n = $count - 1;
    die "not a multi-sig tree\n" unless _take($r, 4) eq "\x98\x73\x00\x83" && _vlq($r) == $n && _u8($r) == 0x08;
    for my $i (1 .. $n) {
        die "not a multi-sig tree\n" unless _u8($r) == 0x73 && _vlq($r) == $i;
    }
}

# ---------------------------------------------------------------------------
# Multi-sig wallets (SPEC W2)
# ---------------------------------------------------------------------------

# The Minotaur wallet script from M and the 33-byte keys, which it sorts as Minotaur does
# (../minotaur-wallet/apps/wallet/src/action/address.ts:22-38). M is a zig-zag int: 2 * M.
sub wallet_tree {
    my ($m, $keys) = @_;
    my @keys = sort @$keys;
    my $n = @keys;
    return "\x10" . vlq($n + 1) . "\x04" . vlq(2 * $m) . join('', map { "\x08\xcd$_" } @keys)
         . "\x98\x73\x00\x83" . vlq($n) . "\x08" . join('', map { "\x73" . vlq($_) } 1 .. $n);
}

my $NOT_A_WALLET = 'This address is not a Minotaur multi-sig wallet.';

# The longest wallet address (SPEC W2). It is Base58 of a prefix byte, the script and a 4-byte
# checksum, and Base58 carries log(256)/log(58) characters per byte, so a script longer than
# this cannot fit in it.
my $MAX_ADDRESS     = 3000;
my $MAX_WALLET_TREE = int($MAX_ADDRESS * log(58) / log(256)) + 1 - 5;

# Reads M and the keys from a wallet address on $network. Returns
# { network, address, m, keys => [hex, in script order] }, or (undef, reason).
sub wallet_from_address {
    my ($address, $network) = @_;
    # Base58 decoding is quadratic here, so the length is checked first. 3,000 characters
    # hold a wallet of 50 keys and not one of 60.
    return (undef, "That address is too long (max $MAX_ADDRESS characters).") if length $address > $MAX_ADDRESS;
    my $info = address_decode($address) or return (undef, 'That is not a valid Ergo address.');
    return (undef, 'This is the address of a single key. Use the address of the multi-sig wallet.')
        if $info->{type} eq 'P2PK';
    return (undef, 'This is a pay-to-script-hash (P2SH) address, which hides its script. Use the address of the multi-sig wallet.')
        if $info->{type} eq 'P2SH';
    return (undef, "Use a $network address.") if $info->{network} ne $network;

    my ($m, @keys);
    eval {
        my $r = _reader($info->{tree});
        die "layout\n" unless _u8($r) == 0x10;
        my $count = _vlq($r);
        die "layout\n" unless $count >= 2 && _u8($r) == 0x04;
        my $zigzag = _vlq($r);
        die "layout\n" if $zigzag & 1;
        $m = $zigzag / 2;
        for (2 .. $count) {
            die "layout\n" unless _take($r, 2) eq "\x08\xcd";
            push @keys, _take($r, 33);
        }
        1;
    } or return (undef, $NOT_A_WALLET);
    my $why = _wallet_refusal($m, \@keys);
    return (undef, $why) if $why;
    # Whatever follows the keys, and the form of every number, must be what Minotaur writes.
    return (undef, $NOT_A_WALLET) unless wallet_tree($m, \@keys) eq $info->{tree};
    return { network => $network, address => $address, m => $m, keys => [ map { unpack 'H*', $_ } @keys ] };
}

# The checks of W2 on M and the 33-byte keys in script order. Returns a reason, or undef.
sub _wallet_refusal {
    my ($m, $keys) = @_;
    return 'Sigma Sync takes a wallet that needs more than one and fewer than all of its signatures. '
        . "With M = 1 or M = N it cannot read the signer keys of the wallet's transactions." unless $m > 1 && $m < @$keys;
    return 'A key in this wallet is not a valid public key.' if grep { !ec_decompress($_) } @$keys;
    my %seen;
    return 'A key appears twice in this wallet.' if grep { $seen{$_}++ } @$keys;
    return 'The keys of this wallet are not in ascending order.' if grep { $keys->[$_] lt $keys->[$_ - 1] } 1 .. $#$keys;
    return undef;
}

# The wallet of a request (SPEC W7): every input names the same M and the same keys, and
# that wallet passes W2. $a is what analyze_payload returns. Returns what
# wallet_from_address returns for the wallet's address, or undef.
sub wallet_from_request {
    my ($a, $network) = @_;
    my ($keys, $required) = @$a{qw(input_keys input_required)};
    return undef unless $keys && @$keys;
    # The script is 10 bytes plus at least 37 per key, so the key count alone refuses a wallet
    # too long for an address before any key is checked or any address encoded.
    return undef if 10 + 37 * @{ $keys->[0] } > $MAX_WALLET_TREE;
    my $shape = join ',', $required->[0], @{ $keys->[0] };
    return undef if grep { join(',', $required->[$_], @{ $keys->[$_] }) ne $shape } 1 .. $#$keys;
    my @keys = map { pack 'H*', $_ } @{ $keys->[0] };
    return undef if _wallet_refusal($required->[0], \@keys);
    my $address = address_from_tree(wallet_tree($required->[0], \@keys), $network);
    return undef if length $address > $MAX_ADDRESS;
    return { network => $network, address => $address, m => $required->[0], keys => [ @{ $keys->[0] } ] };
}

# --- Register values (sigma constants), read only to skip over them -------------
# Type codes follow sigmastate's TypeSerializer: primitives 1-9, then Coll, nested
# Coll, Option, Option[Coll] and pair constructors in blocks of 12, tuples at 96.
sub _read_type {
    my ($r) = @_;
    my $c = _u8($r);
    return { prim => $c } if $c >= 1 && $c <= 11;
    my ($block, $p) = (int($c / 12), $c % 12);
    my $elem = sub { $p ? { prim => $p } : _read_type($r) };
    return { coll => $elem->() }                          if $block == 1;
    return { coll => { coll => $elem->() } }              if $block == 2;
    return { option => $elem->() }                        if $block == 3;
    return { option => { coll => $elem->() } }            if $block == 4;
    if ($block == 5) {                                    # (prim, T) or (T, T)
        my $first = $p ? { prim => $p } : _read_type($r);
        return { tuple => [ $first, _read_type($r) ] };
    }
    if ($block == 6) {                                    # (T, prim), or a triple
        return { tuple => [ map { _read_type($r) } 1 .. 3 ] } unless $p;
        return { tuple => [ _read_type($r), { prim => $p } ] };
    }
    if ($block == 7) {                                    # (prim, prim), or a quadruple
        return { tuple => [ map { _read_type($r) } 1 .. 4 ] } unless $p;
        return { tuple => [ { prim => $p }, { prim => $p } ] };
    }
    return { tuple => [ map { _read_type($r) } 1 .. _u8($r) ] } if $c == 96;
    return { unit => 1 }   if $c == 98;
    return { string => 1 } if $c == 102;
    die "unsupported register type $c\n";
}

sub _skip_sigma_boolean {
    my ($r) = @_;
    my $op = _u8($r);
    if    ($op == 0xcd) { _take($r, 33) }
    elsif ($op == 0xce) { _take($r, 132) }
    elsif ($op == 0x96 || $op == 0x97) { _skip_sigma_boolean($r) for 1 .. _vlq($r) }
    elsif ($op == 0x98) { _vlq($r); _skip_sigma_boolean($r) for 1 .. _vlq($r) }
    elsif ($op != 0x7e && $op != 0x7f) { die "unsupported sigma proposition\n" }
}

sub _skip_value {
    my ($r, $t) = @_;
    if (defined(my $p = $t->{prim})) {
        if    ($p == 1 || $p == 2) { _take($r, 1) }            # Boolean, Byte
        elsif ($p >= 3 && $p <= 5) { _vlq($r) }                # Short, Int, Long
        elsif ($p == 6 || $p == 9) { _take($r, _vlq($r)) }     # BigInt, UnsignedBigInt
        elsif ($p == 7)            { _take($r, 33) }           # GroupElement
        elsif ($p == 8)            { _skip_sigma_boolean($r) } # SigmaProp
        else                       { die "unsupported primitive $p\n" }
    }
    elsif (my $e = $t->{coll}) {
        my $len = _vlq($r);
        die "collection too long\n" if $len > length($r->{b}) - $r->{p} + 8 || ($e->{unit} && $len);
        if    (($e->{prim} // 0) == 1) { _take($r, int(($len + 7) / 8)) }   # bit-packed
        elsif (($e->{prim} // 0) == 2) { _take($r, $len) }
        else  { _skip_value($r, $e) for 1 .. $len }
    }
    elsif ($t->{option}) { _skip_value($r, $t->{option}) if _u8($r) }
    elsif ($t->{tuple})  { _skip_value($r, $_) for @{ $t->{tuple} } }
    elsif ($t->{string}) { _take($r, _vlq($r)) }
    elsif (!$t->{unit})  { die "unsupported value\n" }
}

sub _skip_registers {
    my ($r) = @_;
    _skip_value($r, _read_type($r)) for 1 .. _u8($r);
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
    # or a single key (M = 1). Keys are listed in sorted order, which is also the order of
    # Minotaur's hint slots.
    my (@input_keys, @input_required);
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
            push @input_required, $k;
        } elsif ($op == 0xcd) {
            push @keys, unpack 'H*', _take($r, 33);
            @tx{qw(required signers)} = (1, 1) if $i == 1;
            push @input_required, 1;
        } else {
            $readable = 0;
            last;
        }
        _vlq($r);    # cost
        push @input_keys, [ sort @keys ];
    }
    @tx{qw(input_keys input_required)} = (\@input_keys, \@input_required) if $readable;

    # Outputs. Contract trees without a size field cannot be measured without a full
    # ErgoTree parser, so for those every possible length is tried and the one after
    # which the rest of the transaction parses exactly to its end is kept.
    eval {
        my $n_data = _vlq($m);
        _take($m, 32 * $n_data);
        my $n_tok = _vlq($m);
        my @token_ids = map { unpack 'H*', _take($m, 32) } 1 .. $n_tok;
        my $n_out = _vlq($m);
        my ($budget, @found) = (200_000);
        _parse_outputs($msg, $m->{p}, $n_out, \@token_ids, \$budget, \@found);
        die "outputs\n" unless @found;
        $tx{output_parses} = \@found;
        1;
    } or $tx{outputs_partial} = 1;

    return \%tx;
}

# Value, address and tokens of a serialized input box (registers are not needed).
# Parses $n outputs from $pos. Every complete parse that ends exactly at the end of
# $bytes is pushed to @$found (at most 32); the caller chooses between them.
sub _parse_outputs {
    my ($bytes, $pos, $n, $token_ids, $budget, $found, @path) = @_;
    if ($n == 0) {
        push @$found, [@path] if $pos == length $bytes && @$found < 32;
        return;
    }
    return if $$budget-- <= 0 || @$found >= 32;

    my $r = { b => $bytes, p => $pos };
    my $value = eval { _vlq($r) };
    return unless $value;
    my $tree_start = $r->{p};

    my $known = eval { _read_tree($r); $r->{p} };
    my @ends = defined $known ? ($known) : ();
    if (!defined $known && !(ord(substr($bytes, $tree_start, 1)) & 0x08)) {
        @ends = ($tree_start + 2 .. length($bytes) - 3);    # unknown contract: try every length
    }
    for my $end (@ends) {
        my $rr = { b => $bytes, p => $end };
        my $o = eval {
            my %o = (value => "$value");
            $o{height} = _vlq($rr);
            die "height\n" if $o{height} > 100_000_000;
            my $nt = _u8($rr);
            die "tokens\n" if $nt > @$token_ids;
            for (1 .. $nt) {
                my $idx = _vlq($rr);
                die "token index\n" if $idx >= @$token_ids;
                my $amount = _vlq($rr);
                die "token amount\n" unless $amount;
                push @{ $o{tokens} }, { id => $token_ids->[$idx], amount => "$amount" };
            }
            die "registers\n" if ord(substr($bytes, $rr->{p}, 1)) > 6;
            my $reg_start = $rr->{p};
            _skip_registers($rr);
            $o{_registers} = substr($bytes, $reg_start, $rr->{p} - $reg_start);
            my $tree = substr($bytes, $tree_start, $end - $tree_start);
            $o{tree}        = unpack 'H*', $tree;
            $o{address}     = address_from_tree($tree);
            $o{is_fee}      = $o{tree} eq $FEE_TREE_HEX ? 1 : 0;
            $o{is_multisig} = defined $known && !$o{is_fee} && substr($tree, 0, 1) eq "\x10" ? 1 : 0;
            $o{is_contract} = !$o{is_fee} && !$o{is_multisig} && $tree !~ /^\x00\x08\xcd/ ? 1 : 0;
            \%o;
        } or next;
        _parse_outputs($bytes, $rr->{p}, $n - 1, $token_ids, $budget, $found, @path, $o);
    }
}

# Box id of each output: Blake2b-256 of the full box (candidate with full token ids,
# then the transaction id and the output index). Lets a batch see which transactions
# spend another's outputs.
sub _set_box_ids {
    my ($outs, $tx_id) = @_;
    for my $i (0 .. $#$outs) {
        my $o = $outs->[$i];
        my $bytes = vlq($o->{value}) . pack('H*', $o->{tree}) . vlq($o->{height})
                  . chr(scalar @{ $o->{tokens} || [] })
                  . join('', map { pack('H*', $_->{id}) . vlq($_->{amount}) } @{ $o->{tokens} || [] })
                  . ($o->{_registers} // "\x00")
                  . pack('H*', $tx_id) . vlq($i);
        $o->{box_id} = unpack 'H*', blake2b256($bytes);
    }
    delete $_->{_registers} for @$outs;
}

# Chooses the parse that makes sense as a transaction: ERG in = ERG out and no token
# created out of nothing (when the input boxes are known), all outputs sharing one
# creation height (wallets build them that way), then the shortest contract trees.
# Returns (outputs, certain) or ().
sub _choose_outputs {
    my ($found, $in_value, $in_tokens, $mint_id) = @_;
    my @ok = @$found;
    if (defined $in_value) {
        @ok = grep {
            my $sum = 0;
            my %tok;
            for my $o (@$_) { $sum += $o->{value}; $tok{ $_->{id} } += $_->{amount} for @{ $o->{tokens} || [] } }
            $sum == $in_value && !grep { $_ ne ($mint_id // '') && $tok{$_} > ($in_tokens->{$_} // 0) } keys %tok;
        } @ok;
    }
    return () unless @ok;
    my @same = grep { my %h = map { $_->{height} => 1 } @$_; keys(%h) == 1 } @ok;
    @ok = @same if @same;
    my %distinct = map { join('|', map { "$_->{address}:$_->{value}" } @$_) => 1 } @ok;
    return ($ok[0], keys(%distinct) == 1 && defined $in_value ? 1 : 0);
}

sub _parse_box_summary {
    my ($b64) = @_;
    my $r = _reader(decode_base64($b64));
    my %b = (value => _vlq($r));
    $b{address} = address_from_tree(_read_tree($r));
    _vlq($r);    # creation height
    for (1 .. _u8($r)) {
        my $id = unpack 'H*', _take($r, 32);
        $b{tokens}{$id} += _vlq($r);
    }
    return \%b;
}

# Box ids a payload's transaction spends (hex), without the full analysis. Undef if
# the payload is not a readable MSR/CSR.
sub payload_input_ids {
    my ($text) = @_;
    my $doc = eval { _decode_envelope(sanitize_payload($text)) } or return;
    my $d = $doc->{data};
    return unless ref $d eq 'HASH';
    my $tx = $doc->{type} eq 'CSR' ? $d->{reducedTx} : $doc->{type} eq 'MSR' ? $d->{tx} : undef;
    return unless $tx;
    return eval {
        my $r = _reader(decode_base64($tx));
        my $m = _reader(_take($r, _vlq($r)));
        my @ids;
        for (1 .. _vlq($m)) { push @ids, unpack 'H*', _take($m, 32); _take($m, _vlq($m)); _u8($m) }
        \@ids;
    };
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

    # A cold signing request (CSR) is the unsigned transaction before anyone committed:
    # the same reduced transaction and input boxes, with no hints yet.
    my $is_csr = $doc->{type} eq 'CSR' && ref $d eq 'HASH' && $d->{reducedTx};
    if ($is_csr) {
        $res{sender} = $d->{sender} if defined $d->{sender} && !ref $d->{sender};
        $d = { tx => $d->{reducedTx}, boxes => $d->{inputs} // [], hints => [] };
    }

    unless (($doc->{type} eq 'MSR' || $is_csr) && ref $d eq 'HASH' && $d->{tx}) {
        $res{error} = "Unrecognised payload type '$doc->{type}'.";
        return \%res;
    }

    my $tx = eval { _parse_reduced(decode_base64($d->{tx})) };
    unless ($tx) { $res{error} = 'The transaction inside the payload could not be read. It may be truncated.'; return \%res }
    @res{qw(tx_id required signers outputs outputs_partial input_keys input_required input_ids)}
        = @$tx{qw(tx_id required signers outputs outputs_partial input_keys input_required input_ids)};

    # Hints: current builds use "hints" (matrix input x signer slot); the oldest builds
    # used "commitments" + "signed".
    # Payload layout reveals the Minotaur generation: 3.0+ writes "hints", 2.x wrote
    # "commitments"/"signed"/"simulated". Versions within a generation are identical.
    $res{minotaur_format} = $is_csr ? undef : exists $d->{hints} ? '3' : '2';
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
    my ($total, %in_tokens, @in_addr, %by_addr) = (0);
    for my $b (@$boxes) {
        my $s = eval { _parse_box_summary($b) } or do { $total = undef; last };
        $total += $s->{value};
        $in_tokens{$_} += $s->{tokens}{$_} for keys %{ $s->{tokens} || {} };
        push @in_addr, $s->{address} unless $by_addr{ $s->{address} };
        my $a = $by_addr{ $s->{address} } ||= { address => $s->{address}, value => 0, boxes => 0, tokens => {} };
        $a->{value} += $s->{value};
        $a->{boxes}++;
        $a->{tokens}{$_} = 1 for keys %{ $s->{tokens} || {} };
    }
    # Pick the output parse that makes sense against the inputs (see _choose_outputs).
    if ($tx->{output_parses}) {
        my $inputs_known = defined $total && @$boxes;
        my ($outs, $certain) = _choose_outputs($tx->{output_parses}, ($inputs_known ? $total : undef),
            \%in_tokens, $tx->{input_ids}[0]);
        if ($outs) {
            _set_box_ids($outs, $tx->{tx_id});
            $res{outputs} = $outs;
            $res{outputs_uncertain} = $certain ? 0 : 1;
        } else {
            $res{outputs_partial} = 1;
        }
    }

    if (defined $total && @$boxes) {
        $res{inputs_value}  = "$total";
        $res{inputs_tokens} = [ map { { id => $_, amount => "$in_tokens{$_}" } } sort keys %in_tokens ];
        $res{inputs} = [ map { { address => $_->{address}, value => "$_->{value}", boxes => $_->{boxes},
                                tokens => scalar keys %{ $_->{tokens} } } } @by_addr{@in_addr} ];
        # Ergo's transaction builder appends the change box after the payments (the fee
        # box comes last), so only the last non-fee output can be change. Earlier outputs
        # to a spending address are deliberate payments to it (e.g. a test send to self).
        my %mine = map { $_ => 1 } @in_addr;
        my @outs = @{ $res{outputs} || [] };
        my ($last) = grep { !$_->{is_fee} } reverse @outs;
        for my $o (@outs) {
            $o->{to_input_address} = $mine{ $o->{address} } ? 1 : 0;
            $o->{is_change} = $last && $o == $last && $o->{to_input_address} ? 1 : 0;
        }
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
