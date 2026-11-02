package AppConfig;
#
# Shared configuration, database and encryption helpers for Sigma Sync.
#
# Configuration comes from the env file named by $ENV{APP_ENV_FILE}
# (set by Apache: SetEnv APP_ENV_FILE /data/AAP_Storage/secrets/sigmasync.env).
#
use strict;
use warnings;

use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG qw(random_bytes);
use DBI;
use MIME::Base64 qw(encode_base64 decode_base64);

use Exporter 'import';
our @EXPORT_OK = qw(cfg db_creds dbh seal unseal random_hex client_ip);

my %CONFIG;
my $LOADED = 0;

sub _load {
    return if $LOADED;
    $LOADED = 1;
    my $file = $ENV{APP_ENV_FILE} or return;
    open my $fh, '<', $file or die "Cannot read config file\n";
    while (my $line = <$fh>) {
        $line =~ s/\r?\n$//;
        next if $line =~ /^\s*(#|$)/;
        my ($k, $v) = $line =~ /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/ or next;
        $v =~ s/^(['"])(.*)\1$/$2/;
        $CONFIG{$k} = $v;
    }
    close $fh;
}

# cfg('KEY', $default) - any key from the env file.
sub cfg {
    my ($key, $default) = @_;
    _load();
    return exists $CONFIG{$key} && length $CONFIG{$key} ? $CONFIG{$key} : $default;
}

sub db_creds {
    return {
        host => cfg('DB_HOST', '127.0.0.1'),
        db   => cfg('DB_NAME', 'sigmasync'),
        user => cfg('DB_USER', 'sigmasync_app'),
        pass => cfg('DB_PASSWORD', ''),
    };
}

my $DBH;
sub dbh {
    return $DBH if $DBH && $DBH->ping;
    my $c = db_creds();
    $DBH = DBI->connect(
        "DBI:mysql:database=$c->{db};host=$c->{host}",
        $c->{user}, $c->{pass},
        { RaiseError => 1, PrintError => 0, AutoCommit => 1, mysql_enable_utf8mb4 => 1 },
    );
    $DBH->do(q{SET time_zone = '+00:00'});
    return $DBH;
}

# --- Encryption at rest -----------------------------------------------------
# AES-256-GCM with a random 96-bit nonce. Stored form: "v1:" . base64(nonce|tag|ct).
# $context is authenticated (not stored) so a ciphertext cannot be moved to another
# column, e.g. seal($text, 'comment.body').

sub _data_key {
    my $hex = cfg('DATA_KEY', '');
    die "DATA_KEY must be 64 hex characters (32 bytes)\n" unless $hex =~ /^[0-9a-fA-F]{64}$/;
    return pack 'H*', $hex;
}

sub seal {
    my ($plain, $context) = @_;
    $plain //= '';
    utf8::encode($plain) if utf8::is_utf8($plain);
    my $iv = random_bytes(12);
    my ($ct, $tag) = gcm_encrypt_authenticate('AES', _data_key(), $iv, $context // '', $plain);
    return 'v1:' . encode_base64($iv . $tag . $ct, '');
}

sub unseal {
    my ($stored, $context) = @_;
    return '' unless defined $stored && length $stored;
    my ($ver, $b64) = split /:/, $stored, 2;
    die "Unknown ciphertext version\n" unless $ver eq 'v1' && defined $b64;
    my $raw = decode_base64($b64);
    die "Ciphertext too short\n" if length $raw < 28;
    my ($iv, $tag, $ct) = (substr($raw, 0, 12), substr($raw, 12, 16), substr($raw, 28));
    my $plain = gcm_decrypt_verify('AES', _data_key(), $iv, $context // '', $ct, $tag);
    die "Ciphertext failed authentication\n" unless defined $plain;
    utf8::decode($plain);
    return $plain;
}

sub random_hex { return unpack 'H*', random_bytes($_[0] // 32) }

sub client_ip { return substr($ENV{REMOTE_ADDR} // '', 0, 45) }

1;
