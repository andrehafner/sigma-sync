#!/usr/bin/perl
#
# Sigma Sync API - every request is a POST with an "action" field.
# Responses: { "success": 1, ... } or { "success": 0, "error": "..." }.
#
# Access model
#   * Anyone can create an account by signing a challenge with an Ergo wallet.
#   * An account holds one or more proven wallet keys (member_keys).
#   * A transaction's signer keys are read from the transaction itself
#     (transaction_keys). An account can see and act on a transaction only if it
#     holds one of those keys. There is no other way in - admins included.
#
use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin;

use CGI qw(-utf8);
use Digest::SHA qw(sha256_hex);
use JSON::PP ();

use AppConfig qw(cfg dbh seal unseal random_hex client_ip ensure_wallet);
use ErgoKit qw(address_decode address_from_tree build_login_request verify_login_response
               verify_nautilus_auth wallet_from_address wallet_from_request
               sanitize_payload analyze_payload compare_hints payload_input_ids);

# Large enough for a full batch of big requests (MAX_BATCH entries of a few hundred KB).
$CGI::POST_MAX = 32 * 1024 * 1024;

my $JSON = JSON::PP->new->utf8->canonical;
my $cgi  = CGI->new;
my @cookies;
my ($ME, $SESSION);
my %WALLET_OF;    # wallet_of_tx's answers, for this request

my %LIMIT = (title => 120, description => 10_000, comment => 4000, payload => 1_000_000,
             wallet => 80, name => 40);

# A transaction is visible to the current account when it holds one of its signer keys.
# Used as "... FROM transactions t WHERE ... AND $VISIBLE" with $ME->{id} bound.
my $VISIBLE = q{EXISTS (SELECT 1 FROM transaction_keys tk JOIN member_keys mk ON mk.pk = tk.pk
                         WHERE tk.transaction_id = t.id AND mk.member_id = ?)};

# A wallet is visible to the current account when it holds one of its keys (SPEC W4).
# Used as "... FROM wallets w WHERE ... AND $WALLET_VISIBLE" with $ME->{id} bound.
my $WALLET_VISIBLE = q{EXISTS (SELECT 1 FROM wallet_keys wk JOIN member_keys mk ON mk.pk = wk.pk
                                WHERE wk.wallet_id = w.id AND mk.member_id = ?)};

# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------
my %PUBLIC = (
    session     => \&act_session,
    auth_start  => \&act_auth_start,
    auth_finish => \&act_auth_finish,
    logout      => \&act_logout,
);
my %MEMBER = (
    list_transactions  => \&act_list_transactions,
    get_transaction    => \&act_get_transaction,
    analyze            => \&act_analyze,
    create_transaction => \&act_create_transaction,
    batch_preview      => \&act_batch_preview,
    create_batch       => \&act_create_batch,
    lock               => \&act_lock,
    release_lock       => \&act_release_lock,
    vote_unlock        => \&act_vote_unlock,
    submit             => \&act_submit,
    add_comment        => \&act_add_comment,
    cancel_transaction => \&act_cancel_transaction,
    mark_broadcast     => \&act_mark_broadcast,
    get_account        => \&act_get_account,
    update_account     => \&act_update_account,
    unlink_address     => \&act_unlink_address,
    register_wallet    => \&act_register_wallet,
    list_wallets       => \&act_list_wallets,
    get_wallet         => \&act_get_wallet,
    rename_wallet      => \&act_rename_wallet,
);
my %ADMIN = (
    admin_members  => \&act_admin_members,
    admin_update   => \&act_admin_update,
    admin_delete   => \&act_admin_delete,
    recent_events  => \&act_recent_events,
);

my $response = eval {
    die { public => 'Use POST.' } unless ($ENV{REQUEST_METHOD} // '') eq 'POST';
    die { public => 'That upload is too large (over 32 MB). Split it into smaller batches.' }
        if ($cgi->cgi_error // '') =~ /^413/;
    my $action = $cgi->param('action') // '';
    if (my $h = $PUBLIC{$action}) { return $h->() }
    my $h = $MEMBER{$action} || $ADMIN{$action} or die { public => 'Unknown action.' };
    require_member();
    die { public => 'Administrator access required.' } if $ADMIN{$action} && !$ME->{is_admin};
    return $h->();
};
if (my $err = $@) {
    if (ref $err eq 'HASH' && $err->{public}) {
        $response = { success => 0, error => $err->{public}, %{ $err->{extra} || {} } };
    } else {
        warn "sigmasync api error: $err";
        $response = { success => 0, error => 'Something went wrong on the server. Please try again.' };
    }
}
$response->{success} //= 1;

print $cgi->header(
    -type          => 'application/json',
    -charset       => 'utf-8',
    -cache_control => 'no-store',
    (@cookies ? (-cookie => \@cookies) : ()),
);
print $JSON->encode($response);
exit;

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
sub fail  { die { public => $_[0], extra => $_[1] } }
sub param { my $v = $cgi->param($_[0]); return defined $v ? $v : '' }

sub int_param {
    my $v = param($_[0]);
    fail('Invalid request.') unless $v =~ /^\d{1,9}$/;
    return $v + 0;
}

# Plain text: normalise newlines, drop control characters, enforce a length limit.
sub clean_text {
    my ($v, $max, $label, $multiline) = @_;
    $v =~ s/\r\n?/\n/g;
    $v =~ s/[\x00-\x08\x0B-\x1F\x7F]//g;
    $v =~ s/\n/ /g unless $multiline;
    $v =~ s/^\s+|\s+$//g;
    fail("$label is too long (max $max characters).") if length $v > $max;
    return $v;
}

sub log_event {
    my ($event, $detail, $tx_id, $member_id) = @_;
    dbh()->do('INSERT INTO events (transaction_id, member_id, event, detail, ip) VALUES (?,?,?,?,?)',
        undef, $tx_id, $member_id // ($ME ? $ME->{id} : undef), $event,
        substr($detail // '', 0, 255), client_ip());
}

sub session_cookie {
    my ($value, $expires) = @_;
    return $cgi->cookie(
        -name     => 'sigmasync_sid',
        -value    => $value,
        -path     => cfg('COOKIE_PATH', '/apps/sigmasync/'),
        -expires  => $expires,
        -secure   => cfg('COOKIE_SECURE', '1') eq '1' ? 1 : 0,
        -httponly => 1,
        -samesite => 'Strict',
    );
}

sub admin_addresses {
    return map { s/^\s+|\s+$//gr } grep { length } split /,/, cfg('ADMIN_ADDRESSES', '');
}

sub member_addresses {
    my ($member_id) = @_;
    return dbh()->selectcol_arrayref('SELECT address FROM member_keys WHERE member_id = ? ORDER BY id', undef, $member_id);
}

sub is_env_admin {
    my ($addresses) = @_;
    my %env = map { $_ => 1 } admin_addresses();
    return (grep { $env{$_} } @$addresses) ? 1 : 0;
}

sub load_session {
    return if $SESSION;
    my $token = $cgi->cookie('sigmasync_sid') // '';
    return unless $token =~ /^[0-9a-f]{64}$/;
    my $idle = cfg('SESSION_IDLE_MINUTES', 2880) + 0;
    my $row = dbh()->selectrow_hashref(q{
        SELECT s.id AS session_id, s.csrf_token, m.id, m.display_name, m.name_chosen, m.is_admin
          FROM sessions s JOIN members m ON m.id = s.member_id
         WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP()
           AND s.last_seen_at > UTC_TIMESTAMP() - INTERVAL ? MINUTE
           AND m.is_active = 1
    }, undef, sha256_hex($token), $idle) or return;
    dbh()->do('UPDATE sessions SET last_seen_at = UTC_TIMESTAMP() WHERE id = ?', undef, $row->{session_id});
    $SESSION = $row;
    $ME = load_member($row->{id});
}

sub load_member {
    my ($id) = @_;
    my $m = dbh()->selectrow_hashref('SELECT id, display_name, name_chosen, is_admin, is_active FROM members WHERE id = ?', undef, $id)
        or return;
    $m->{addresses} = member_addresses($id);
    $m->{env_admin} = is_env_admin($m->{addresses});
    $m->{is_admin}  = 1 if $m->{env_admin};
    $m->{$_} += 0 for qw(id name_chosen is_admin is_active);
    return $m;
}

sub require_member {
    load_session();
    fail('Your session has ended. Please sign in again.', { signed_out => 1 }) unless $ME;
    my $csrf = param('csrf');
    fail('Your session has ended. Please sign in again.', { signed_out => 1 })
        unless length $csrf && $csrf eq $SESSION->{csrf_token};
}

sub public_member {
    my ($m) = @_;
    return { map { $_ => $m->{$_} } qw(id display_name name_chosen is_admin addresses) };
}

sub client_config {
    return {
        unlock_votes         => cfg('UNLOCK_VOTES', 2) + 0,
        unlock_grace_minutes => cfg('UNLOCK_GRACE_MINUTES', 10) + 0,
        explorer_tx_url      => cfg('EXPLORER_TX_URL', 'https://explorer.ergoplatform.com/en/transactions/'),
        explorer_api_url     => cfg('EXPLORER_API_URL', 'https://api.ergoplatform.com/api/v1/transactions/'),
        explorer_token_url   => cfg('EXPLORER_TOKEN_API_URL', 'https://api.ergoplatform.com/api/v1/tokens/'),
        explorer_address_url => cfg('EXPLORER_ADDRESS_URL', 'https://explorer.ergoplatform.com/en/addresses/'),
        nautilus             => nautilus_on(),
    };
}

# SPEC L1, L4: the Nautilus method needs the site's host, the second field of the signed text.
sub nautilus_on { return length cfg('SITE_HOST', '') ? 1 : 0 }

sub site_host {
    fail('Sign-in with Nautilus is not available on this site.') unless nautilus_on();
    return cfg('SITE_HOST');
}

sub valid_address {
    my ($address) = @_;
    my $info = address_decode($address);
    fail('That is not a valid Ergo address.') unless $info;
    fail('Use the regular (P2PK) address of your signing wallet, not a multi-sig or contract address.')
        unless $info->{type} eq 'P2PK';
    fail("Use a $info->{network} address.") if $info->{network} ne cfg('NETWORK', 'mainnet');
    return $info;
}

# ---------------------------------------------------------------------------
# Sign-in and address linking
# ---------------------------------------------------------------------------
sub act_session {
    load_session();
    return { signed_in => 0, nautilus => nautilus_on() } unless $ME;
    return { signed_in => 1, member => public_member($ME), csrf => $SESSION->{csrf_token},
             config => client_config() };
}

# purpose=login (default) starts a sign-in; purpose=link (signed in) proves an extra address.
# method=nautilus asks for a token for Nautilus's auth(); without it the challenge is Minotaur's.
sub act_auth_start {
    my $method = param('method');
    fail('Unknown sign-in method.') unless $method eq '' || $method eq 'nautilus';
    my $nautilus = $method eq 'nautilus';
    site_host() if $nautilus;
    my $address = param('address') =~ s/\s+//gr;
    my $link = param('purpose') eq 'link';
    if ($link) {
        require_member();
        my ($owner) = dbh()->selectrow_array('SELECT member_id FROM member_keys WHERE address = ?', undef, $address);
        fail('That address is already linked to your account.') if $owner && $owner == $ME->{id};
        fail('That address is already linked to another account.') if $owner;
    }
    valid_address($address);

    my $db = dbh();
    $db->do('DELETE FROM auth_challenges WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY');
    my ($recent) = $db->selectrow_array(
        'SELECT COUNT(*) FROM auth_challenges WHERE ip = ? AND created_at > UTC_TIMESTAMP() - INTERVAL 15 MINUTE',
        undef, client_ip());
    fail('Too many sign-in attempts. Wait a few minutes and try again.') if $recent >= 20;

    my $token = random_hex(32);
    my $ttl = cfg('CHALLENGE_MINUTES', 15) + 0;
    if ($nautilus) {
        $db->do(q{INSERT INTO auth_challenges (token_hash, address, member_id, method, message_hex, ip, expires_at)
                  VALUES (?,?,?,'nautilus','',?, UTC_TIMESTAMP() + INTERVAL ? MINUTE)},
            undef, sha256_hex($token), $address, ($link ? $ME->{id} : undef), client_ip(), $ttl);
        return { challenge => $token, method => 'nautilus', expires_minutes => $ttl };
    }
    my $req = build_login_request(address => $address, nonce => pack('H*', random_hex(32)));
    $db->do(q{INSERT INTO auth_challenges (token_hash, address, member_id, message_hex, ip, expires_at)
              VALUES (?,?,?,?,?, UTC_TIMESTAMP() + INTERVAL ? MINUTE)},
        undef, sha256_hex($token), $address, ($link ? $ME->{id} : undef), unpack('H*', $req->{message}),
        client_ip(), $ttl);

    return { challenge => $token, request => $req->{request}, expires_minutes => $ttl };
}

sub act_auth_finish {
    my $token = param('challenge');
    fail('Sign-in request not found. Start again.') unless $token =~ /^[0-9a-f]{64}$/;
    my $db = dbh();
    my $ch = $db->selectrow_hashref(q{
        SELECT id, address, member_id, method, message_hex,
               UNIX_TIMESTAMP(created_at) AS issued, UNIX_TIMESTAMP(expires_at) AS expires
          FROM auth_challenges
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP()
    }, undef, sha256_hex($token));
    fail('This request has expired or was already used. Start again.') unless $ch;

    # The method is the stored challenge's, never the request's (SPEC L4, L10).
    my $info = address_decode($ch->{address});
    my ($ok, $why);
    if ($ch->{method} eq 'nautilus') {
        ($ok, $why) = verify_nautilus_auth(
            signed_message => param('signed_message'), proof => param('proof'), challenge => $token,
            host => site_host(), pk => $info->{pk},
            not_before => $ch->{issued} - 300, not_after => $ch->{expires} + 300);
    } else {
        my $response = param('response');
        fail('Paste the signed result from Minotaur.') unless length $response;
        fail('That is far too long to be a signed result.') if length $response > 200_000;

        my $signed_message;
        ($ok, $why, $signed_message) = verify_login_response(
            response => $response, expected_message => pack('H*', $ch->{message_hex}), pk => $info->{pk});
        if (!$ok && $signed_message) {
            # Minotaur keeps the previous signed result on screen when a new request is scanned
            # in the same session (it then shows no password prompt). Recognise that case.
            my ($old) = $db->selectrow_array(
                'SELECT id FROM auth_challenges WHERE address = ? AND message_hex = ? AND id <> ?',
                undef, $ch->{address}, unpack('H*', $signed_message), $ch->{id});
            $why = 'Minotaur gave you the result of an earlier sign-in instead of signing this new request '
                 . '(it did not ask for your password, right?). This is a Minotaur quirk: fully close and reopen '
                 . 'Minotaur, then scan or paste the request shown here again.' if $old;
        }
    }
    unless ($ok) {
        # A wrong paste (e.g. the request itself) does not burn the challenge.
        log_event('login_failed', "$ch->{address}: $why");
        fail($why);
    }
    $db->do('UPDATE auth_challenges SET used_at = UTC_TIMESTAMP() WHERE id = ? AND used_at IS NULL', undef, $ch->{id}) > 0
        or fail('This request was already used. Start again.');
    my $pk_hex = unpack 'H*', $info->{pk};

    # Linking an extra address to the signed-in account.
    if ($ch->{member_id}) {
        require_member();
        fail('This request belongs to another session. Start again.') unless $ch->{member_id} == $ME->{id};
        my ($owner) = $db->selectrow_array('SELECT member_id FROM member_keys WHERE pk = ?', undef, $pk_hex);
        fail('That address is already linked to another account.') if $owner && $owner != $ME->{id};
        $db->do('INSERT IGNORE INTO member_keys (member_id, address, pk) VALUES (?,?,?)', undef, $ME->{id}, $ch->{address}, $pk_hex);
        log_event('address_linked', $ch->{address});
        return { linked => $ch->{address}, member => public_member(load_member($ME->{id})) };
    }

    # Sign-in: find the account holding this key, or create one.
    my ($member_id) = $db->selectrow_array('SELECT member_id FROM member_keys WHERE pk = ?', undef, $pk_hex);
    my $created = 0;
    unless ($member_id) {
        $db->begin_work;
        $db->do('INSERT INTO members (display_name) VALUES (?)', undef, 'Signer ' . substr($ch->{address}, 0, 8));
        $member_id = $db->last_insert_id(undef, undef, 'members', 'id');
        $db->do('INSERT INTO member_keys (member_id, address, pk) VALUES (?,?,?)', undef, $member_id, $ch->{address}, $pk_hex);
        $db->commit;
        $created = 1;
        log_event('account_created', $ch->{address}, undef, $member_id);
    }
    my $member = load_member($member_id);
    unless ($member->{is_active}) {
        log_event('login_denied', $ch->{address}, undef, $member_id);
        fail('This account has been disabled. Contact an administrator if you think this is a mistake.');
    }

    my $session = random_hex(32);
    my $csrf    = random_hex(32);
    my $hours   = cfg('SESSION_HOURS', 48) + 0;
    $db->do('DELETE FROM sessions WHERE expires_at < UTC_TIMESTAMP()');
    $db->do(q{INSERT INTO sessions (token_hash, csrf_token, member_id, ip, expires_at)
              VALUES (?,?,?,?, UTC_TIMESTAMP() + INTERVAL ? HOUR)},
        undef, sha256_hex($session), $csrf, $member_id, client_ip(), $hours);
    $db->do('UPDATE members SET last_login_at = UTC_TIMESTAMP() WHERE id = ?', undef, $member_id);
    push @cookies, session_cookie($session, "+${hours}h");

    log_event('login', $ch->{address}, undef, $member_id);
    return { signed_in => 1, created => $created, member => public_member($member), csrf => $csrf,
             config => client_config() };
}

sub act_logout {
    load_session();
    if ($SESSION) {
        dbh()->do('DELETE FROM sessions WHERE id = ?', undef, $SESSION->{session_id});
        log_event('logout');
    }
    push @cookies, session_cookie('', '-1d');
    return { signed_in => 0 };
}

# ---------------------------------------------------------------------------
# Account
# ---------------------------------------------------------------------------
sub act_get_account {
    my $keys = dbh()->selectall_arrayref(q{
        SELECT mk.address, mk.created_at,
               (SELECT COUNT(DISTINCT tk.transaction_id) FROM transaction_keys tk WHERE tk.pk = mk.pk) AS transactions
          FROM member_keys mk WHERE mk.member_id = ? ORDER BY mk.id}, { Slice => {} }, $ME->{id});
    $_->{transactions} += 0 for @$keys;
    return { member => public_member($ME), addresses => $keys };
}

sub name_param {
    my $name = clean_text(param('display_name'), $LIMIT{name}, 'Name');
    fail('Use 2 to 40 characters for your name.') if length $name < 2;
    return $name;
}

sub act_update_account {
    my $name = name_param();
    my ($taken) = dbh()->selectrow_array(
        'SELECT id FROM members WHERE LOWER(display_name) = LOWER(?) AND id <> ?', undef, $name, $ME->{id});
    fail('That name is already in use. Pick another so co-signers can tell you apart.') if $taken;
    dbh()->do('UPDATE members SET display_name = ?, name_chosen = 1 WHERE id = ?', undef, $name, $ME->{id});
    log_event('name_changed', $name);
    $ME = load_member($ME->{id});
    return act_get_account();
}

sub act_unlink_address {
    my $address = param('address');
    my $n = dbh()->selectrow_array('SELECT COUNT(*) FROM member_keys WHERE member_id = ?', undef, $ME->{id});
    fail('You cannot remove your only address.') if $n <= 1;
    dbh()->do('DELETE FROM member_keys WHERE member_id = ? AND address = ?', undef, $ME->{id}, $address) > 0
        or fail('That address is not linked to your account.');
    log_event('address_unlinked', $address);
    $ME = load_member($ME->{id});
    return act_get_account();
}

# ---------------------------------------------------------------------------
# Transactions
# ---------------------------------------------------------------------------
sub load_tx {
    my ($id, $for_update) = @_;
    my $tx = dbh()->selectrow_hashref(
        "SELECT t.* FROM transactions t WHERE t.id = ? AND $VISIBLE" . ($for_update ? ' FOR UPDATE' : ''),
        undef, $id, $ME->{id});
    fail('Transaction not found.') unless $tx;    # same answer whether it exists or not
    return $tx;
}

sub latest_submission {
    my ($tx_id) = @_;
    my $row = dbh()->selectrow_hashref(
        'SELECT * FROM submissions WHERE transaction_id = ? ORDER BY id DESC LIMIT 1', undef, $tx_id) or return;
    $row->{payload} = unseal($row->{payload_enc}, 'submission.payload');
    return $row;
}

sub is_open { return $_[0]{status} eq 'commit' || $_[0]{status} eq 'sign' }

sub member_names {
    my ($ids) = @_;
    my %seen;
    my @ids = grep { defined && !$seen{$_}++ } @$ids;
    return {} unless @ids;
    my $rows = dbh()->selectall_arrayref(
        'SELECT id, display_name FROM members WHERE id IN (' . join(',', ('?') x @ids) . ')',
        { Slice => {} }, @ids);
    return { map { $_->{id} => $_->{display_name} } @$rows };
}

# Slot states of the current account's keys, per transaction: { tx_id => [state, ...] }
sub my_key_states {
    my ($tx_id) = @_;
    my $rows = dbh()->selectall_arrayref(q{
        SELECT tk.transaction_id, tk.state FROM transaction_keys tk JOIN member_keys mk ON mk.pk = tk.pk
         WHERE mk.member_id = ?} . ($tx_id ? ' AND tk.transaction_id = ?' : ''),
        undef, $ME->{id}, ($tx_id ? $tx_id : ()));
    my %s;
    push @{ $s{ $_->[0] } }, $_->[1] for @$rows;
    return \%s;
}

# Rounds the current account has submitted in, per transaction: { tx_id => { commit => 1, ... } }
sub my_rounds {
    my ($tx_id) = @_;
    my $rows = dbh()->selectall_arrayref(
        'SELECT DISTINCT transaction_id, round FROM submissions WHERE member_id = ?'
        . ($tx_id ? ' AND transaction_id = ?' : ''), undef, $ME->{id}, ($tx_id ? $tx_id : ()));
    my %r;
    $r{ $_->[0] }{ $_->[1] } = 1 for @$rows;
    return \%r;
}

# Where the current account stands, from the state of its own key slots (and, for old
# Minotaur formats that do not mark signatures per slot, its own submissions).
# A commitment or signature, once given, is final: `can_act` is true only while the
# account still owes the current round its step.
sub my_progress {
    my ($tx, $states, $rounds) = @_;
    my @s = @{ $states || [] };
    $rounds ||= {};
    my %p = (
        committed => (grep { $_ == 1 || $_ == 2 } @s) || $rounds->{commit} ? 1 : 0,
        signed    => (grep { $_ == 2 } @s) || $rounds->{sign} || $rounds->{final} ? 1 : 0,
    );
    $p{can_act} = ($tx->{status} eq 'commit' && !$p{committed} && grep { $_ == 0 } @s)
               || ($tx->{status} eq 'sign' && $p{committed} && !$p{signed}) ? 1 : 0;
    $p{awaiting} = $p{can_act};
    return \%p;
}

# Why the current account cannot take a turn, or undef if it can.
sub turn_refusal {
    my ($tx, $p) = @_;
    return 'This transaction is no longer open for signing.' unless is_open($tx);
    return undef if $p->{can_act};
    if ($tx->{status} eq 'commit') {
        return 'You have already committed. Your commitment is final - the next signers build on it.' if $p->{committed};
        return 'None of your keys has an open commitment slot in this transaction.';
    }
    return 'You have already signed. Your signature is final.' if $p->{signed};
    return 'Signing has started, and only signers who committed can sign. Commitments are closed.';
}

sub tx_brief {
    my ($tx, $names, $states, $comment_count, $rounds) = @_;
    my $wallet = wallet_of_tx($tx->{wallet_id});
    return {
        id               => $tx->{id} + 0,
        title            => unseal($tx->{title_enc}, 'transaction.title'),
        wallet_name      => $tx->{wallet_name},
        minotaur_version => $tx->{minotaur_version},
        status           => $tx->{status},
        signers_required => $tx->{signers_required} + 0,
        signers_total    => $tx->{signers_total} + 0,
        commits          => $tx->{commits} + 0,
        signatures       => $tx->{signatures} + 0,
        ergo_tx_id       => $tx->{ergo_tx_id},
        created_by       => $names->{ $tx->{created_by} },
        created_at       => $tx->{created_at},
        updated_at       => $tx->{updated_at},
        closed_at        => $tx->{closed_at},
        lock             => $tx->{lock_member_id}
            ? { name => $names->{ $tx->{lock_member_id} }, since => $tx->{locked_at},
                mine => $tx->{lock_member_id} == $ME->{id} ? 1 : 0 }
            : undef,
        lock_seq => $tx->{lock_seq} + 0,
        comments => $comment_count // 0,
        me       => my_progress($tx, $states, $rounds),
        batch    => $tx->{batch_id} ? { id => $tx->{batch_id} + 0, seq => $tx->{batch_seq} + 0 } : undef,
        wallet   => $wallet ? { id => $wallet->{id}, name => $wallet->{name} } : undef,
    };
}

# Briefs of transactions the caller already read under the visibility condition.
sub briefs {
    my ($txs) = @_;
    my @ids = map { $_->{id} } @$txs;
    my %comments;
    if (@ids) {
        %comments = map { $_->[0] => $_->[1] } @{ dbh()->selectall_arrayref(
            'SELECT transaction_id, COUNT(*) FROM comments WHERE transaction_id IN (' . join(',', ('?') x @ids)
            . ') GROUP BY transaction_id', undef, @ids) };
    }
    my $states = my_key_states();
    my $rounds = my_rounds();
    my $names = member_names([ map { ($_->{created_by}, $_->{lock_member_id}) } @$txs ]);
    return [ map { tx_brief($_, $names, $states->{ $_->{id} }, $comments{ $_->{id} }, $rounds->{ $_->{id} }) } @$txs ];
}

sub act_list_transactions {
    my $txs = dbh()->selectall_arrayref(qq{
        SELECT t.* FROM transactions t
         WHERE $VISIBLE
           AND (t.status IN ('commit','sign','complete') OR t.closed_at > UTC_TIMESTAMP() - INTERVAL 180 DAY)
         ORDER BY FIELD(t.status,'commit','sign','complete','broadcast','cancelled'), t.updated_at DESC
         LIMIT 500
    }, { Slice => {} }, $ME->{id});
    # Every lock the account holds, also on a transaction beyond the 500 rows above (SPEC B7).
    my $held = dbh()->selectall_arrayref(qq{
        SELECT t.* FROM transactions t WHERE t.lock_member_id = ? AND $VISIBLE ORDER BY t.id
    }, { Slice => {} }, $ME->{id}, $ME->{id});
    my $me = member_names([ $ME->{id} ]);
    my %wallets;
    my @wallets = grep { length && !$wallets{$_}++ } map { $_->{wallet_name} } @$txs;
    return {
        transactions => briefs($txs),
        wallet_names => [ @wallets[0 .. ($#wallets < 19 ? $#wallets : 19)] ],
        held_locks   => [ map { my $b = tx_brief($_, $me); +{ map { $_ => $b->{$_} } qw(id title wallet lock lock_seq) } } @$held ],
    };
}

sub act_get_transaction {
    my $id = int_param('id');
    my $db = dbh();
    my $tx = load_tx($id);

    my $subs = $db->selectall_arrayref(
        'SELECT id, member_id, round, payload_sha256, commits, signatures, created_at FROM submissions WHERE transaction_id = ? ORDER BY id',
        { Slice => {} }, $id);
    my $comments = $db->selectall_arrayref(
        'SELECT id, member_id, submission_id, body_enc, created_at FROM comments WHERE transaction_id = ? ORDER BY id',
        { Slice => {} }, $id);
    my $events = $db->selectall_arrayref(q{
        SELECT id, member_id, event, detail, created_at FROM events
         WHERE transaction_id = ? AND event IN ('lock','release','unlock_vote','lock_override','cancel','broadcast')
         ORDER BY id}, { Slice => {} }, $id);
    my $votes = $tx->{lock_member_id} ? $db->selectall_arrayref(
        'SELECT member_id, created_at FROM unlock_votes WHERE transaction_id = ? AND lock_seq = ? ORDER BY created_at',
        { Slice => {} }, $id, $tx->{lock_seq}) : [];

    # The signers of this transaction: every key, whether or not its owner uses Sigma Sync.
    my $keys = $db->selectall_arrayref(q{
        SELECT tk.pk, tk.slot, tk.state, mk.member_id, mk.address
          FROM transaction_keys tk LEFT JOIN member_keys mk ON mk.pk = tk.pk
         WHERE tk.transaction_id = ? ORDER BY tk.slot}, { Slice => {} }, $id);

    my $names = member_names([ $tx->{created_by}, $tx->{lock_member_id},
        map { $_->{member_id} } @$subs, @$comments, @$events, @$votes, @$keys ]);

    my @timeline;
    my %comment_for = map { $_->{submission_id} ? ($_->{submission_id} => $_) : () } @$comments;
    for my $s (@$subs) {
        my $c = $comment_for{ $s->{id} };
        push @timeline, {
            kind => 'submission', at => $s->{created_at}, member => $names->{ $s->{member_id} },
            round => $s->{round}, commits => $s->{commits} + 0, signatures => $s->{signatures} + 0,
            fingerprint => substr($s->{payload_sha256}, 0, 12),
            ($c ? (comment => unseal($c->{body_enc}, 'comment.body')) : ()),
        };
    }
    for my $c (grep { !$_->{submission_id} } @$comments) {
        push @timeline, { kind => 'comment', at => $c->{created_at}, member => $names->{ $c->{member_id} },
                          comment => unseal($c->{body_enc}, 'comment.body') };
    }
    for my $e (@$events) {
        push @timeline, { kind => 'event', at => $e->{created_at}, member => $names->{ $e->{member_id} // 0 },
                          event => $e->{event}, detail => $e->{detail} };
    }
    @timeline = sort { $a->{at} cmp $b->{at} } @timeline;

    my $brief = tx_brief($tx, $names, my_key_states($id)->{$id}, scalar @$comments, my_rounds($id)->{$id});
    $brief->{description} = unseal($tx->{description_enc}, 'transaction.description');
    $brief->{wallet}{address} = wallet_of_tx($tx->{wallet_id})->{address} if $brief->{wallet};
    $brief->{timeline}    = \@timeline;
    $brief->{signers}     = [ map { {
        slot    => $_->{slot} + 0,
        state   => $_->{state} + 0,
        name    => $_->{member_id} ? $names->{ $_->{member_id} } : undef,
        address => $_->{address} // address_from_tree("\x00\x08\xcd" . pack('H*', $_->{pk}), cfg('NETWORK', 'mainnet')),
        mine    => ($_->{member_id} // 0) == $ME->{id} ? 1 : 0,
    } } @$keys ];

    if ($tx->{lock_member_id}) {
        $brief->{lock}{votes} = [ map { { name => $names->{ $_->{member_id} }, at => $_->{created_at},
                                          mine => $_->{member_id} == $ME->{id} ? 1 : 0 } } @$votes ];
        my ($age) = $db->selectrow_array('SELECT TIMESTAMPDIFF(MINUTE, locked_at, UTC_TIMESTAMP()) FROM transactions WHERE id = ?', undef, $id);
        $brief->{lock}{age_minutes} = $age + 0;
    }

    # What the transaction does, decoded from the latest payload. The payload text itself
    # is only handed to the lock holder (to continue from it) or once the transaction is
    # complete (to broadcast it).
    my $latest = latest_submission($id);
    if ($latest) {
        my $a = analyze_payload($latest->{payload});
        # The latest MSR describes the transaction; a final CSTX does not carry boxes.
        my $d = $a;
        if ($a->{format} ne 'MSR') {
            my ($msr) = grep { $_->{format} eq 'MSR' }
                map { analyze_payload(unseal($_->[0], 'submission.payload')) }
                @{ $db->selectall_arrayref('SELECT payload_enc FROM submissions WHERE transaction_id = ? ORDER BY id DESC LIMIT 5', undef, $id) };
            $d = $msr if $msr;
        }
        $brief->{review} = {
            format          => $a->{format},
            outputs         => $d->{outputs},
            outputs_partial => $d->{outputs_partial} ? 1 : 0,
            outputs_uncertain => $d->{outputs_uncertain} ? 1 : 0,
            inputs_unverified => ($d->{inputs_unverified} // 1) ? 1 : 0,
            inputs          => $d->{inputs},
            inputs_value    => $d->{inputs_value},
            inputs_tokens   => $d->{inputs_tokens},
            minotaur_format => $d->{minotaur_format},
        };
        if (($brief->{lock} && $brief->{lock}{mine}) || $tx->{status} eq 'complete' || $tx->{status} eq 'broadcast') {
            $brief->{payload} = {
                text        => $latest->{payload},
                type        => $a->{format},
                fingerprint => substr($latest->{payload_sha256}, 0, 12),
                at          => $latest->{created_at},
                by          => $names->{ $latest->{member_id} },
            };
        }
    }

    # Batch context: position, and the next item in the batch that needs this account.
    if ($tx->{batch_id}) {
        my ($count) = $db->selectrow_array('SELECT item_count FROM batches WHERE id = ?', undef, $tx->{batch_id});
        $brief->{batch}{count} = $count + 0;
        my $siblings = $db->selectall_arrayref(qq{
            SELECT t.* FROM transactions t WHERE t.batch_id = ? AND t.id <> ? AND t.lock_member_id IS NULL
               AND t.status IN ('commit','sign') AND $VISIBLE ORDER BY t.batch_seq},
            { Slice => {} }, $tx->{batch_id}, $id, $ME->{id});
        my $states = my_key_states();
        my $rounds = my_rounds();
        my @todo = grep { my_progress($_, $states->{ $_->{id} }, $rounds->{ $_->{id} })->{can_act} } @$siblings;
        my ($next) = (grep { $_->{batch_seq} > $tx->{batch_seq} } @todo)[0] // $todo[0];
        $brief->{batch}{next} = { id => $next->{id} + 0, seq => $next->{batch_seq} + 0 } if $next;
        $brief->{batch}{waiting_on_you} = scalar @todo;
    }

    $brief->{can} = {
        lock      => !$tx->{lock_member_id} && !turn_refusal($tx, $brief->{me}) ? 1 : 0,
        cancel    => ($tx->{created_by} == $ME->{id} || $ME->{is_admin}) && $tx->{status} ne 'broadcast' && $tx->{status} ne 'cancelled' ? 1 : 0,
        broadcast => $tx->{status} eq 'complete' ? 1 : 0,
    };
    return { transaction => $brief };
}

# Validates a pasted payload against the transaction's current state.
# Returns (analysis, comparison-or-undef). Fails with a clear message when the paste
# would lose work or belongs to another transaction.
sub check_payload {
    my ($tx, $payload, $latest) = @_;
    my $a = analyze_payload($payload);
    fail($a->{error}) unless $a->{valid};
    if ($a->{tx_id} && $a->{tx_id} ne $tx->{ergo_tx_id}) {
        fail('This payload belongs to a different Ergo transaction (ID ' . substr($a->{tx_id}, 0, 10)
           . '...). Make sure you opened the request from this page in Minotaur.');
    }
    return ($a, undef) unless $latest;

    if (sha256_hex($payload) eq $latest->{payload_sha256}) {
        fail('This is the same request that is already stored. In Minotaur, add your commitment or signature, then paste the NEW output.');
    }
    my $prev = analyze_payload($latest->{payload});
    # A transaction started from a cold signing request (CSR) has no hints yet: the
    # first MSR is compared against an empty matrix, so the usual rules apply.
    $prev->{hints} = [] if $prev->{format} eq 'CSR';
    return ($a, undef) unless $a->{format} eq 'MSR' && ($prev->{format} eq 'MSR' || $prev->{format} eq 'CSR');

    my $cmp = compare_hints($prev->{hints} || [], $a->{hints} || []);
    # Older Minotaur builds keep signatures in a separate list; compare the counts too.
    # (Commitment counts may legitimately drop when an extra committer is simulated.)
    $cmp->{lost}++ if $a->{signed} < $prev->{signed};
    $cmp->{new_signatures} ||= $a->{signed} > $prev->{signed} ? $a->{signed} - $prev->{signed} : 0;
    if ($cmp->{lost} || $cmp->{changed}) {
        fail('This would erase work from other signers (' . ($cmp->{lost} + $cmp->{changed})
           . ' commitment/signature slot(s) missing or replaced). You probably started from an older request. '
           . 'Copy the latest request from this page and try again.');
    }
    unless ($cmp->{new_commits} || $cmp->{new_signatures}) {
        fail('No new commitment or signature found. Did you paste the request instead of the output Minotaur produced after you committed or signed?');
    }
    return ($a, $cmp);
}

# Minotaur 3.0+ writes and reads the "hints" layout; 2.x used another one. The two
# generations cannot continue each other's requests.
sub version_major { my ($v) = @_; return $v =~ /(\d+)\./ ? $1 + 0 : undef }

sub check_generation {
    my ($version, $a) = @_;
    my $major = version_major($version);
    return unless $a->{minotaur_format} && defined $major;
    my $want = $major >= 3 ? '3' : '2';
    return if $a->{minotaur_format} eq $want;
    fail($a->{minotaur_format} eq '2'
        ? "This request was made with Minotaur 2.x, but this transaction uses Minotaur $version. "
          . 'Minotaur 3.0 and later cannot read 2.x requests - update Minotaur and start again from the latest request.'
        : "This request was made with Minotaur 3.0 or later, but this transaction uses Minotaur $version. "
          . 'Use the version the transaction was started with.');
}

sub payload_param {
    my $p = sanitize_payload(param('payload'));
    fail('Paste the payload from Minotaur.') unless length $p;
    fail('The payload is too large.') if length $p > $LIMIT{payload};
    return $p;
}

# Signer keys of a transaction (hex), in display order: sorted and de-duplicated.
sub tx_keys {
    my ($a) = @_;
    my %seen;
    return [ grep { !$seen{$_}++ } sort map { @$_ } @{ $a->{input_keys} || [] } ];
}

sub my_pks {
    return dbh()->selectcol_arrayref('SELECT pk FROM member_keys WHERE member_id = ?', undef, $ME->{id});
}

sub update_key_states {
    my ($tx_id, $a) = @_;
    my $states = $a->{key_states} or return;
    my $sth = dbh()->prepare('UPDATE transaction_keys SET state = ? WHERE transaction_id = ? AND pk = ?');
    $sth->execute($states->{$_}, $tx_id, $_) for keys %$states;
}

sub act_analyze {
    my $payload = sanitize_payload(param('payload'));
    my $a = analyze_payload($payload);
    my %out = map { $_ => $a->{$_} } qw(format valid error warning tx_id required signers committed signed outputs outputs_partial inputs_value inputs_unverified minotaur_format);
    if ($a->{input_keys}) {
        my %mine = map { $_ => 1 } @{ my_pks() };
        my @my_keys = grep { $mine{$_} } @{ tx_keys($a) };
        $out{is_signer} = @my_keys ? 1 : 0;
        $out{my_committed} = (grep { ($a->{key_states}{$_} // 0) =~ /^[12]$/ } @my_keys) ? 1 : 0;
    }
    my $tx_id = param('id');
    if ($tx_id =~ /^\d+$/ && length $payload) {
        my $tx = load_tx($tx_id);
        my $latest = latest_submission($tx_id);
        eval { my (undef, $cmp) = check_payload($tx, $payload, $latest); check_generation($tx->{minotaur_version}, $a);
               $out{compare} = $cmp; 1 }
            or do { my $e = $@; die $e unless ref $e eq 'HASH'; $out{problem} = $e->{public} };
    }
    return { analysis => \%out };
}

sub version_param {
    my $v = param('minotaur_version');
    fail('Choose the Minotaur version everyone should use.')
        unless $v =~ /^(?:[a-z]+-)?v?\d+(?:\.\d+){1,3}(?:-[\w.]+)?$/;
    return $v;
}

# Checks a payload someone wants to start a transaction from. Returns
# (analysis, signer keys) or (undef, undef, reason) so batches can report per item.
# The starter must be a signer. An MSR may already carry commitments from anyone
# (tools such as the Rosen guard scripts generate requests with one in place); a CSR
# is an unsigned request nobody has committed to yet.
sub start_checks {
    my ($payload, $version) = @_;
    my $a = analyze_payload($payload);
    return (undef, undef, $a->{error}) unless $a->{valid};
    return (undef, undef, 'Use a multi-sig request (MSR) from Minotaur, or an unsigned cold signing request (CSR).')
        unless $a->{format} eq 'MSR' || $a->{format} eq 'CSR';
    return (undef, undef, 'Sigma Sync could not read the signer keys from this transaction.') unless $a->{input_keys};
    if ($a->{minotaur_format} && version_major($version) && ($a->{minotaur_format} eq '2') != (version_major($version) < 3)) {
        return (undef, undef, $a->{minotaur_format} eq '2'
            ? 'This request was made with Minotaur 2.x. Pick a 2.x version, or (better) redo it with the latest Minotaur.'
            : 'This request was made with Minotaur 3.0 or later, but you picked a 2.x version. Pick the version you actually used.');
    }
    my $keys = tx_keys($a);
    my %mine = map { $_ => 1 } @{ my_pks() };
    my @my_keys = grep { $mine{$_} } @$keys;
    return (undef, undef, 'None of the addresses on your account is a signer of this multi-sig wallet. If you sign '
        . 'with another wallet or address, link it on the Account tab first.') unless @my_keys;
    return ($a, $keys);
}

sub daily_quota_left {
    my ($recent) = dbh()->selectrow_array(
        'SELECT COUNT(*) FROM transactions WHERE created_by = ? AND created_at > UTC_TIMESTAMP() - INTERVAL 1 DAY',
        undef, $ME->{id});
    return cfg('DAILY_TX_LIMIT', 200) - $recent;
}

# The open transaction of this Ergo transaction id, with whether the account can see it.
# Only a visible one may be named (SPEC I10). Returns nothing when none is tracked.
sub tracked_as {
    my ($ergo_tx_id) = @_;
    my ($dupe, $visible) = dbh()->selectrow_array(
        qq{SELECT t.id, $VISIBLE FROM transactions t WHERE t.ergo_tx_id = ? AND t.status <> 'cancelled'},
        undef, $ME->{id}, $ergo_tx_id);
    return $dupe ? ($dupe, $visible) : ();
}

# Inserts a checked transaction with its signer keys and first submission, and links it to
# the wallet its inputs name, which a start registers when nobody has (SPEC W3, W7). Caller
# holds the DB transaction, so a refused start leaves no wallet behind.
sub insert_transaction {
    my (%t) = @_;
    my ($a, $keys) = @t{qw(analysis keys)};
    my $required = $a->{required};
    my $commits  = $a->{committed} // 0;
    my $status   = $commits >= $required ? 'sign' : 'commit';
    my $db = dbh();
    my ($wallet_id, $created);
    if (my $w = wallet_from_request($a, cfg('NETWORK', 'mainnet'))) {
        # A registered wallet keeps its name; a new one takes the start's (SPEC W3).
        ($wallet_id, $created) = ensure_wallet($w, $t{wallet}, $ME->{id});
        log_event('wallet_registered', $wallet_id) if $created;    # the id only (SPEC W5)
    }
    $db->do(q{INSERT INTO transactions (title_enc, description_enc, wallet_name, minotaur_version,
                signers_required, signers_total, ergo_tx_id, status, commits, created_by, batch_id, batch_seq, wallet_id)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)}, undef,
        seal($t{title}, 'transaction.title'), seal($t{description}, 'transaction.description'), $t{wallet}, $t{version},
        $required, scalar @$keys, $a->{tx_id}, $status, $commits, $ME->{id}, $t{batch_id}, $t{batch_seq}, $wallet_id);
    my $tx_id = $db->last_insert_id(undef, undef, 'transactions', 'id');
    my $sth = $db->prepare('INSERT INTO transaction_keys (transaction_id, pk, slot, state) VALUES (?,?,?,?)');
    $sth->execute($tx_id, $keys->[$_], $_, $a->{key_states}{ $keys->[$_] } // 0) for 0 .. $#$keys;
    # The first submission counts as the starter's commitment only if their own key has
    # committed in it; otherwise they still owe the commitment round their step.
    my %mine = map { $_ => 1 } @{ my_pks() };
    my $own_commit = grep { $mine{$_} && ($a->{key_states}{$_} // 0) =~ /^[12]$/ } @$keys;
    my $sub_id = insert_submission($tx_id, ($own_commit ? 'commit' : 'start'), $t{payload}, $commits, 0);
    insert_comment($tx_id, $t{comment}, $sub_id) if length($t{comment} // '');
    log_event('create', $t{batch_id} ? "batch $t{batch_id} item $t{batch_seq}" : '', $tx_id);
    return $tx_id;
}

sub act_create_transaction {
    my $title = clean_text(param('title'), $LIMIT{title}, 'Title');
    fail('Give the transaction a name.') unless length $title;
    my $desc    = clean_text(param('description'), $LIMIT{description}, 'Description', 1);
    my $wallet  = clean_text(param('wallet_name'), $LIMIT{wallet}, 'Wallet name');
    my $version = version_param();
    my $required = param('signers_required');
    fail('Set how many signatures are required (1-50).') unless $required =~ /^\d{1,2}$/ && $required >= 1 && $required <= 50;
    my $comment = clean_text(param('comment'), $LIMIT{comment}, 'Comment', 1);
    my $payload = payload_param();

    fail('You have started a lot of transactions today. Try again tomorrow.') if daily_quota_left() < 1;
    my ($a, $keys, $why) = start_checks($payload, $version);
    fail($why) unless $a;
    if ($a->{required} && $a->{required} != $required) {
        fail("This multi-sig wallet needs $a->{required} of $a->{signers} signatures. Set \"Signatures required\" to $a->{required}.");
    }
    if (my ($dupe, $visible) = tracked_as($a->{tx_id})) {
        fail('This Ergo transaction is already being tracked' . ($visible ? " (#$dupe)." : '.'));
    }

    my $db = dbh();
    $db->begin_work;
    my $tx_id = insert_transaction(analysis => $a, keys => $keys, payload => $payload, title => $title,
        description => $desc, wallet => $wallet, version => $version, comment => $comment);
    $db->commit;
    return { id => $tx_id + 0 };
}

# --- Batches -----------------------------------------------------------------
# A batch is many requests pasted or uploaded at once: JSON objects one after another
# (any whitespace between them), or a JSON array of them.
use constant MAX_BATCH => 100;

sub split_batch {
    my ($text) = @_;
    $text //= '';
    $text =~ s/^\x{FEFF}//;
    my $json = JSON::PP->new->allow_nonref;
    my @items;
    $text =~ s/^\s+//;
    while (length $text) {
        my ($value, $used) = eval { $json->decode_prefix($text) };
        return (undef, 'Could not read entry ' . (@items + 1) . ' - the text may be cut off or not JSON.') unless $used;
        # Keep each request's text exactly as given; only array elements need re-encoding.
        push @items, ref $value eq 'ARRAY' ? (map { ref $_ ? JSON::PP->new->encode($_) : "$_" } @$value)
                                           : substr($text, 0, $used);
        $text = substr($text, $used);
        $text =~ s/^[\s,]+//;
        return (undef, 'Too many entries: a batch can hold at most ' . MAX_BATCH . '.') if @items > MAX_BATCH;
    }
    return (undef, 'Paste or upload at least one request.') unless @items;
    return \@items;
}

# Checks every item; returns per-item results without writing anything.
sub check_batch {
    my ($text, $version) = @_;
    my ($items, $err) = split_batch($text);
    fail($err) unless $items;
    my (%seen, @out);
    my $i = 0;
    for my $raw (@$items) {
        $i++;
        my $payload = sanitize_payload($raw);
        my %r = (index => $i);
        if (length $payload > $LIMIT{payload}) {
            $r{error} = 'Too large.';
        } else {
            my ($a, $keys, $why) = start_checks($payload, $version);
            if (!$a) {
                $r{error} = $why;
            } else {
                @r{qw(format tx_id required signers committed outputs_uncertain)} =
                    @$a{qw(format tx_id required signers committed outputs_uncertain)};
                my @sends = grep { !$_->{is_fee} && !$_->{is_change} } @{ $a->{outputs} || [] };
                my $sent = 0;
                my %tok;
                for my $o (@sends) { $sent += $o->{value}; $tok{ $_->{id} } += $_->{amount} for @{ $o->{tokens} || [] } }
                $r{sends}  = { outputs => scalar @sends, value => "$sent", tokens => scalar keys %tok,
                               to => [ map { $_->{address} } @sends ] };
                $r{decoded} = @{ $a->{outputs} || [] } ? 1 : 0;
                if (my $first = $seen{ $a->{tx_id} }) {
                    $r{error} = "Same transaction as entry $first.";
                } elsif (my ($dupe, $visible) = tracked_as($a->{tx_id})) {
                    $r{error} = $visible ? "Already tracked as #$dupe." : 'Already tracked.';
                    $r{tracked} = $dupe + 0 if $visible;
                }
                $seen{ $a->{tx_id} } //= $i;
                $r{ok} = $r{error} ? 0 : 1;
                $r{_payload} = $payload;
                $r{_analysis} = $a;
                $r{_keys} = $keys;
            }
        }
        $r{ok} //= 0;
        push @out, \%r;
    }

    # Boxes already being spent by open transactions the account can see (SPEC I10): a second
    # spender can never confirm. A spend of the same box is of the same wallet, so its signers see it.
    my %open_spends;
    my $open = dbh()->selectall_arrayref(qq{
        SELECT t.id, (SELECT s.payload_enc FROM submissions s WHERE s.transaction_id = t.id ORDER BY s.id LIMIT 1)
          FROM transactions t WHERE t.status IN ('commit','sign','complete') AND $VISIBLE}, undef, $ME->{id});
    for my $row (@$open) {
        my $ids = payload_input_ids(unseal($row->[1], 'submission.payload')) or next;
        $open_spends{$_} //= $row->[0] for @$ids;
    }

    # Within the batch: two entries spending one box conflict; an entry spending another
    # entry's output must wait until that one is broadcast.
    my (%spent_by, %output_of);
    for my $r (grep { $_->{ok} } @out) {
        for my $o (@{ $r->{_analysis}{outputs} || [] }) { $output_of{ $o->{box_id} } = $r->{index} if $o->{box_id} }
    }
    for my $r (grep { $_->{ok} } @out) {
        my (%deps, $clash, $tracked_clash);
        for my $in (@{ $r->{_analysis}{input_ids} || [] }) {
            $clash //= $spent_by{$in};
            $tracked_clash //= $open_spends{$in};
            $spent_by{$in} //= $r->{index};
            $deps{ $output_of{$in} } = 1 if $output_of{$in} && $output_of{$in} != $r->{index};
        }
        if ($clash) {
            @$r{qw(ok error)} = (0, "Spends the same box as entry $clash - only one of them can ever confirm.");
        } elsif ($tracked_clash) {
            @$r{qw(ok error tracked)} = (0, "Spends a box that #$tracked_clash already spends - only one can ever confirm.", $tracked_clash + 0);
        }
        $r->{after} = [ sort { $a <=> $b } keys %deps ] if %deps;
    }

    # Number valid entries in broadcast order: an entry always comes after the entries
    # whose outputs it spends (otherwise keep the pasted order).
    my @ready = grep { $_->{ok} } @out;
    my %done;
    my $seq = 0;
    while (my @next = grep { !$done{ $_->{index} } && !grep { !$done{$_} } @{ $_->{after} || [] } } @ready) {
        $done{ $next[0]{index} } = ++$seq;
        $next[0]{seq} = $seq;
    }
    for my $r (grep { !$done{ $_->{index} } } @ready) {       # a cycle cannot confirm at all
        @$r{qw(ok error)} = (0, 'Part of a circular chain of spends - these can never all confirm.');
    }
    return \@out;
}

sub public_items { return [ map { my $r = $_; +{ map { $_ => $r->{$_} } grep { !/^_/ } keys %$r } } @{ $_[0] } ] }

sub act_batch_preview {
    my $version = version_param();
    my $items = check_batch(param('items'), $version);
    return { items => public_items($items), ok => scalar(grep { $_->{ok} } @$items) };
}

sub act_create_batch {
    my $name = clean_text(param('name'), 100, 'Batch name');
    fail('Give the batch a name.') unless length $name;
    my $desc    = clean_text(param('description'), $LIMIT{description}, 'Description', 1);
    my $wallet  = clean_text(param('wallet_name'), $LIMIT{wallet}, 'Wallet name');
    my $version = version_param();
    my $comment = clean_text(param('comment'), $LIMIT{comment}, 'Comment', 1);

    my $items = check_batch(param('items'), $version);
    my @ok = grep { $_->{ok} } @$items;
    fail('None of the entries can be started - check them first.') unless @ok;
    fail('Some entries have problems. Fix or remove them, or confirm to start only the valid ones.')
        if @ok < @$items && !param('skip_invalid');
    fail('That is more transactions than you can start today (limit ' . cfg('DAILY_TX_LIMIT', 200) . ').')
        if daily_quota_left() < @ok;

    my $db = dbh();
    $db->begin_work;
    $db->do('INSERT INTO batches (title_enc, created_by, item_count) VALUES (?,?,?)', undef,
        seal($name, 'batch.title'), $ME->{id}, scalar @ok);
    my $batch_id = $db->last_insert_id(undef, undef, 'batches', 'id');
    @ok = sort { $a->{seq} <=> $b->{seq} } grep { $_->{ok} } @ok;
    my ($seq, @created, %seq_of_index, %id_of_index) = (0);
    $seq_of_index{ $_->{index} } = $_->{seq} for @ok;
    for my $item (@ok) {
        $seq = $item->{seq};
        push @created, insert_transaction(analysis => $item->{_analysis}, keys => $item->{_keys},
            payload => $item->{_payload}, title => "$name $seq", description => $desc, wallet => $wallet,
            version => $version, comment => $comment, batch_id => $batch_id, batch_seq => $seq) + 0;
    }
    $id_of_index{ $ok[$_]{index} } = $created[$_] for 0 .. $#ok;
    # Record the broadcast order on each chained transaction, visible to every signer.
    for my $i (0 .. $#ok) {
        my @after = grep { $id_of_index{$_} } @{ $ok[$i]{after} || [] };
        next unless @after;
        insert_comment($created[$i], 'Broadcast order: this transaction spends an output of '
            . join(', ', map { "$name $seq_of_index{$_} (#$id_of_index{$_})" } @after)
            . (@after == 1 ? '. Broadcast that one first.' : '. Broadcast those first.'), undef);
    }
    log_event('batch_create', "batch $batch_id: " . scalar(@created) . ' transactions');
    $db->commit;
    return { batch_id => $batch_id + 0, created => \@created, skipped => scalar(@$items) - scalar(@ok) };
}

sub insert_submission {
    my ($tx_id, $round, $payload, $commits, $signatures) = @_;
    dbh()->do(q{INSERT INTO submissions (transaction_id, member_id, round, payload_enc, payload_sha256,
                commits, signatures) VALUES (?,?,?,?,?,?,?)}, undef,
        $tx_id, $ME->{id}, $round, seal($payload, 'submission.payload'), sha256_hex($payload),
        $commits, $signatures);
    return dbh()->last_insert_id(undef, undef, 'submissions', 'id');
}

sub insert_comment {
    my ($tx_id, $body, $sub_id) = @_;
    dbh()->do('INSERT INTO comments (transaction_id, member_id, submission_id, body_enc) VALUES (?,?,?,?)',
        undef, $tx_id, $ME->{id}, $sub_id, seal($body, 'comment.body'));
}

# With `seq`, the lock is taken only while the row's lock count is the one the caller read (SPEC B7).
sub act_lock {
    my $id = int_param('id');
    my $seq = length param('seq') ? int_param('seq') : undef;
    my $tx = load_tx($id);
    if (my $why = turn_refusal($tx, my_progress($tx, my_key_states($id)->{$id}, my_rounds($id)->{$id}))) {
        fail($why);
    }
    my $n = dbh()->do(q{
        UPDATE transactions SET lock_member_id = ?, lock_seq = lock_seq + 1, locked_at = UTC_TIMESTAMP()
         WHERE id = ? AND lock_member_id IS NULL AND status IN ('commit','sign')
    } . (defined $seq ? ' AND lock_seq = ?' : ''), undef, $ME->{id}, $id, (defined $seq ? $seq : ()));
    unless ($n > 0) {
        my $now = load_tx($id);
        fail('This transaction is no longer open for signing.') unless is_open($now);
        fail('The lock on this transaction changed since you read it. Refresh and try again.')
            if defined $seq && $now->{lock_seq} != $seq;
        fail('Someone else locked this transaction a moment ago. Refresh to see who.');
    }
    log_event('lock', '', $id);
    return act_get_transaction();
}

# With `seq`, first the cancel of a `lock` at that count that has not arrived yet, then the
# release of the lock it took, whose count is `seq` + 1. Whichever the server handles first,
# no lock of that request stays, and a newer lock of the account is never cleared (SPEC B7).
sub act_release_lock {
    my $id = int_param('id');
    my $seq = length param('seq') ? int_param('seq') : undef;
    my $tx = load_tx($id);
    if (defined $seq && !turn_refusal($tx, my_progress($tx, my_key_states($id)->{$id}, my_rounds($id)->{$id}))
        && dbh()->do(q{UPDATE transactions SET lock_seq = lock_seq + 1
                        WHERE id = ? AND lock_member_id IS NULL AND lock_seq = ? AND status IN ('commit','sign')},
                     undef, $id, $seq) > 0) {
        log_event('lock_cancel', '', $id);
        return act_get_transaction();
    }
    my $n = dbh()->do('UPDATE transactions SET lock_member_id = NULL, locked_at = NULL WHERE id = ? AND lock_member_id = ?'
        . (defined $seq ? ' AND lock_seq = ?' : ''), undef, $id, $ME->{id}, (defined $seq ? $seq + 1 : ()));
    fail('You do not hold the lock on this transaction.') unless $n > 0;
    log_event('release', '', $id);
    return act_get_transaction();
}

sub act_vote_unlock {
    my $id = int_param('id');
    my $db = dbh();
    $db->begin_work;
    my $tx = load_tx($id, 1);
    fail('This transaction is not locked.') unless $tx->{lock_member_id};
    fail('You hold this lock - use "Release lock" instead.') if $tx->{lock_member_id} == $ME->{id};
    my ($age) = $db->selectrow_array('SELECT TIMESTAMPDIFF(MINUTE, ?, UTC_TIMESTAMP())', undef, $tx->{locked_at});
    my $grace = cfg('UNLOCK_GRACE_MINUTES', 10) + 0;
    fail("Give the signer a chance: override votes open $grace minutes after the lock was taken.") if $age < $grace;

    $db->do('INSERT IGNORE INTO unlock_votes (transaction_id, lock_seq, member_id) VALUES (?,?,?)',
        undef, $id, $tx->{lock_seq}, $ME->{id});
    my ($votes) = $db->selectrow_array('SELECT COUNT(*) FROM unlock_votes WHERE transaction_id = ? AND lock_seq = ?',
        undef, $id, $tx->{lock_seq});
    log_event('unlock_vote', "vote $votes", $id);
    if ($votes >= cfg('UNLOCK_VOTES', 2)) {
        $db->do('UPDATE transactions SET lock_member_id = NULL, locked_at = NULL WHERE id = ?', undef, $id);
        log_event('lock_override', "released after $votes votes", $id);
    }
    $db->commit;
    return act_get_transaction();
}

sub act_submit {
    my $id = int_param('id');
    my $payload = payload_param();
    my $comment = clean_text(param('comment'), $LIMIT{comment}, 'Comment', 1);

    my $db = dbh();
    $db->begin_work;
    my $tx = load_tx($id, 1);
    fail('This transaction is no longer open for signing.') unless is_open($tx);
    fail('Lock the transaction before submitting.') unless ($tx->{lock_member_id} // 0) == $ME->{id};

    my ($a, $cmp) = check_payload($tx, $payload, latest_submission($id));
    check_ownership($tx, $a, $cmp);
    check_generation($tx->{minotaur_version}, $a);

    my $required = $tx->{signers_required};
    my ($commits, $signatures, $round, $status);
    if ($a->{format} eq 'CSTX') {
        ($commits, $signatures, $round, $status) = ($tx->{commits}, $required, 'final', 'complete');
    } else {
        ($commits, $signatures) = ($a->{committed}, $a->{signed});
        $round = !$cmp ? $tx->{status} : $cmp->{new_commits} ? 'commit' : 'sign';
        $status = $signatures >= $required ? 'complete' : $commits >= $required ? 'sign' : 'commit';
        update_key_states($id, $a);
    }

    my $sub_id = insert_submission($id, $round, $payload, $commits, $signatures);
    insert_comment($id, $comment, $sub_id) if length $comment;
    $db->do(q{UPDATE transactions SET commits = ?, signatures = ?, status = ?, lock_member_id = NULL,
                locked_at = NULL, updated_at = UTC_TIMESTAMP() WHERE id = ?},
        undef, $commits, $signatures, $status, $id);
    log_event('submit', "$round: commits $commits, signatures $signatures", $id);
    $db->commit;

    my $result = act_get_transaction();
    $result->{submitted} = { round => $round, status => $status, commits => $commits, signatures => $signatures };
    return $result;
}

# A submission may only add the submitter's own step for the current round: a
# commitment in the commitment round, a signature in the signing round, in a slot
# that belongs to one of the submitter's keys.
sub check_ownership {
    my ($tx, $a, $cmp) = @_;
    if ($tx->{status} eq 'commit' && $a->{format} eq 'CSTX') {
        fail('A fully signed transaction cannot be submitted during the commitment round.');
    }
    return unless $cmp;
    if ($tx->{status} eq 'sign' && $cmp->{new_commits}) {
        fail('Signing has started, so commitments are closed. Only signers who committed can sign.');
    }
    if ($tx->{status} eq 'commit' && $cmp->{new_signatures} && $a->{committed} < $tx->{signers_required}) {
        fail('This adds a signature before enough commitments are in. Commit only, then submit.');
    }
    my $keys = $a->{input_keys} ? $a->{input_keys}[0] : undef;
    return unless $keys && @{ $cmp->{slots} };    # old formats: slots cannot be attributed
    my %mine = map { $_ => 1 } @{ my_pks() };
    my @others = grep { !$mine{ $keys->[$_] // '' } } @{ $cmp->{slots} };
    fail('This adds a ' . ($tx->{status} eq 'commit' ? 'commitment' : 'signature') . " for another signer's key. "
       . 'Each signer submits their own - ask them to sign in and take their turn.') if @others;
    fail('This adds more than one step at once. Submit only your own commitment or signature.')
        if @{ $cmp->{slots} } > 1;
}

sub act_add_comment {
    my $id = int_param('id');
    my $body = clean_text(param('comment'), $LIMIT{comment}, 'Comment', 1);
    fail('Write a comment first.') unless length $body;
    load_tx($id);
    insert_comment($id, $body, undef);
    dbh()->do('UPDATE transactions SET updated_at = UTC_TIMESTAMP() WHERE id = ?', undef, $id);
    return act_get_transaction();
}

sub act_cancel_transaction {
    my $id = int_param('id');
    my $reason = clean_text(param('reason'), 255, 'Reason');
    fail('Give a short reason for cancelling.') unless length $reason;
    my $tx = load_tx($id);
    fail('Only the creator or an admin can cancel a transaction.') unless $tx->{created_by} == $ME->{id} || $ME->{is_admin};
    fail('This transaction is already closed.') if $tx->{status} eq 'broadcast' || $tx->{status} eq 'cancelled';
    dbh()->do(q{UPDATE transactions SET status = 'cancelled', lock_member_id = NULL, locked_at = NULL,
                closed_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP() WHERE id = ?}, undef, $id);
    log_event('cancel', $reason, $id);
    return act_get_transaction();
}

sub act_mark_broadcast {
    my $id = int_param('id');
    my $tx = load_tx($id);
    fail('Only a fully signed transaction can be marked as broadcast.') unless $tx->{status} eq 'complete';
    dbh()->do(q{UPDATE transactions SET status = 'broadcast', closed_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP()
                WHERE id = ? AND status = 'complete'}, undef, $id);
    log_event('broadcast', '', $id);
    return act_get_transaction();
}

# ---------------------------------------------------------------------------
# Wallets: what each signer sees of a registered multi-sig wallet. Every refusal
# comes before the first write.
# ---------------------------------------------------------------------------
sub load_wallet {
    my ($id) = @_;
    my $w = dbh()->selectrow_hashref("SELECT w.* FROM wallets w WHERE w.id = ? AND $WALLET_VISIBLE", undef, $id, $ME->{id});
    fail('Wallet not found.') unless $w;    # same answer whether it exists or not (SPEC W4)
    return $w;
}

# The wallet a brief names: id, name and address, read under the wallet visibility
# condition. A transaction's keys are its wallet's keys (SPEC W7), so whoever sees the
# transaction sees its wallet.
sub wallet_of_tx {
    my ($id) = @_;
    return undef unless $id;
    return $WALLET_OF{$id} //= do {
        my $w = dbh()->selectrow_hashref("SELECT w.id, w.name_enc, w.address FROM wallets w WHERE w.id = ? AND $WALLET_VISIBLE",
            undef, $id, $ME->{id});
        $w && { id => $w->{id} + 0, name => unseal($w->{name_enc}, 'wallet.name'), address => $w->{address} };
    };
}

use constant WALLET_PAGE => 200;

# A wallet with its keys, its open transactions and its closed ones newest first, a page
# at a time below the id $before (SPEC W6). Transactions are read under the visibility
# condition (SPEC I2).
sub wallet_reply {
    my ($w, $before) = @_;
    my $db = dbh();
    my $keys = $db->selectall_arrayref(q{
        SELECT wk.pk, wk.slot, mk.member_id, mk.address, m.display_name
          FROM wallet_keys wk LEFT JOIN member_keys mk ON mk.pk = wk.pk LEFT JOIN members m ON m.id = mk.member_id
         WHERE wk.wallet_id = ? ORDER BY wk.slot}, { Slice => {} }, $w->{id});
    my $open = $db->selectall_arrayref(qq{
        SELECT t.* FROM transactions t WHERE t.wallet_id = ? AND t.status IN ('commit','sign','complete') AND $VISIBLE
         ORDER BY t.id DESC}, { Slice => {} }, $w->{id}, $ME->{id});
    my $closed = $db->selectall_arrayref(qq{
        SELECT t.* FROM transactions t WHERE t.wallet_id = ? AND t.status IN ('broadcast','cancelled') AND $VISIBLE}
        . (defined $before ? ' AND t.id < ?' : '') . ' ORDER BY t.id DESC LIMIT ' . (WALLET_PAGE + 1),
        { Slice => {} }, $w->{id}, $ME->{id}, (defined $before ? $before : ()));
    my $more = @$closed > WALLET_PAGE ? 1 : 0;
    splice @$closed, WALLET_PAGE if $more;
    my @briefs = @{ briefs([ @$open, @$closed ]) };
    return { wallet => {
        id               => $w->{id} + 0,
        name             => unseal($w->{name_enc}, 'wallet.name'),
        address          => $w->{address},
        network          => $w->{network},
        signers_required => $w->{signers_required} + 0,
        signers_total    => $w->{signers_total} + 0,
        keys             => [ map { {
            pk      => $_->{pk},
            slot    => $_->{slot} + 0,
            name    => $_->{display_name},
            address => $_->{address} // address_from_tree("\x00\x08\xcd" . pack('H*', $_->{pk}), $w->{network}),
            mine    => ($_->{member_id} // 0) == $ME->{id} ? 1 : 0,
        } } @$keys ],
        open             => [ splice @briefs, 0, scalar @$open ],
        closed           => \@briefs,
        closed_more      => $more,
    } };
}

sub act_register_wallet {
    my $name = clean_text(param('name'), $LIMIT{wallet}, 'Wallet name');
    my ($w, $why) = wallet_from_address(param('address') =~ s/\s+//gr, cfg('NETWORK', 'mainnet'));
    fail($why) unless $w;
    # The keys come from the address, never from a stored wallet, so this answer is the same
    # whether or not the wallet is registered (SPEC W3).
    my %mine = map { $_ => 1 } @{ my_pks() };
    fail('None of the addresses on your account is a signer of this wallet. If you sign with another wallet '
        . 'or address, link it on the Account tab first.') unless grep { $mine{$_} } @{ $w->{keys} };
    my $db = dbh();
    $db->begin_work;
    my ($id, $created) = ensure_wallet($w, $name, $ME->{id});
    log_event('wallet_registered', $id) if $created;    # the id only, never the name (SPEC W5)
    $db->commit;
    my $reply = wallet_reply(load_wallet($id));
    $reply->{created} = $created;
    return $reply;
}

sub act_list_wallets {
    my $rows = dbh()->selectall_arrayref("SELECT w.* FROM wallets w WHERE $WALLET_VISIBLE ORDER BY w.id",
        { Slice => {} }, $ME->{id});
    return { wallets => [ map { {
        id               => $_->{id} + 0,
        name             => unseal($_->{name_enc}, 'wallet.name'),
        signers_required => $_->{signers_required} + 0,
        signers_total    => $_->{signers_total} + 0,
    } } @$rows ] };
}

sub act_get_wallet {
    my $id = int_param('id');
    return wallet_reply(load_wallet($id), length param('before') ? int_param('before') : undef);
}

sub act_rename_wallet {
    my $id = int_param('id');
    my $name = clean_text(param('name'), $LIMIT{wallet}, 'Wallet name');
    fail('Give the wallet a name.') unless length $name;
    load_wallet($id);
    my $db = dbh();
    $db->begin_work;
    $db->do('UPDATE wallets SET name_enc = ? WHERE id = ?', undef, seal($name, 'wallet.name'), $id);
    log_event('wallet_renamed', $id);    # the id only, never the name (SPEC W5)
    $db->commit;
    return wallet_reply(load_wallet($id));
}

# ---------------------------------------------------------------------------
# Administration: account moderation and the audit log. Admins get no extra
# visibility into transactions.
# ---------------------------------------------------------------------------
sub act_admin_members {
    my $db = dbh();
    my $rows = $db->selectall_arrayref(
        'SELECT id, display_name, is_admin, is_active, created_at, last_login_at FROM members ORDER BY is_active DESC, last_login_at DESC',
        { Slice => {} });
    my %addr;
    push @{ $addr{ $_->[0] } }, $_->[1]
        for @{ $db->selectall_arrayref('SELECT member_id, address FROM member_keys ORDER BY id') };
    $rows = [ grep { $addr{ $_->{id} } } @$rows ];    # deleted accounts have no addresses
    for my $m (@$rows) {
        $m->{$_} += 0 for qw(id is_admin is_active);
        $m->{addresses} = $addr{ $m->{id} };
        $m->{env_admin} = is_env_admin($m->{addresses});
        $m->{is_admin}  = 1 if $m->{env_admin};
    }
    return { members => $rows };
}

# Deletes an account: its addresses and sessions go, any lock it holds is released
# and its open unlock votes are dropped. Signing in again with one of those addresses
# creates a fresh account. Past commitments, signatures and comments stay on the
# transactions (labelled "<name> (deleted)"); an account with no history is removed.
sub act_admin_delete {
    my $id = int_param('id');
    my $m = load_member($id) or fail('Account not found.');
    fail('You cannot delete your own account.') if $id == $ME->{id};
    fail('This admin is set in the server config (ADMIN_ADDRESSES); remove it there first.') if $m->{env_admin};
    fail('This account was already deleted.') unless @{ $m->{addresses} };

    my $db = dbh();
    $db->begin_work;
    my $locked = $db->selectcol_arrayref('SELECT id FROM transactions WHERE lock_member_id = ? FOR UPDATE', undef, $id);
    for my $tx_id (@$locked) {
        $db->do('UPDATE transactions SET lock_member_id = NULL, locked_at = NULL WHERE id = ?', undef, $tx_id);
        log_event('release', 'lock released: account deleted by an admin', $tx_id);
    }
    $db->do('DELETE FROM unlock_votes WHERE member_id = ?', undef, $id);
    $db->do('DELETE FROM sessions WHERE member_id = ?', undef, $id);
    $db->do('DELETE FROM member_keys WHERE member_id = ?', undef, $id);

    my ($history) = $db->selectrow_array(q{
        SELECT (SELECT COUNT(*) FROM transactions WHERE created_by = ?)
             + (SELECT COUNT(*) FROM submissions WHERE member_id = ?)
             + (SELECT COUNT(*) FROM comments WHERE member_id = ?)}, undef, $id, $id, $id);
    if ($history) {
        my $name = substr($m->{display_name}, 0, 40) . ' (deleted)';
        my ($taken) = $db->selectrow_array('SELECT id FROM members WHERE LOWER(display_name) = LOWER(?) AND id <> ?', undef, $name, $id);
        $name = substr($m->{display_name}, 0, 30) . " (deleted #$id)" if $taken;
        $db->do('UPDATE members SET display_name = ?, is_admin = 0, is_active = 0 WHERE id = ?', undef, $name, $id);
    } else {
        $db->do('DELETE FROM members WHERE id = ?', undef, $id);
    }
    log_event('member_delete', "#$id $m->{display_name}: " . join(', ', @{ $m->{addresses} }));
    $db->commit;
    return act_admin_members();
}

sub act_admin_update {
    my $id = int_param('id');
    my $m = load_member($id) or fail('Account not found.');
    my $is_admin  = param('is_admin')  eq '' ? $m->{is_admin}  : (param('is_admin')  ? 1 : 0);
    my $is_active = param('is_active') eq '' ? $m->{is_active} : (param('is_active') ? 1 : 0);
    fail('You cannot remove your own access.') if $id == $ME->{id} && (!$is_active || !$is_admin);
    fail('This admin is set in the server config (ADMIN_ADDRESSES); change it there.')
        if $m->{env_admin} && (!$is_active || !$is_admin);
    my $name = param('display_name') eq '' ? $m->{display_name} : name_param();

    dbh()->do('UPDATE members SET display_name = ?, is_admin = ?, is_active = ? WHERE id = ?',
        undef, $name, $is_admin, $is_active, $id);
    dbh()->do('DELETE FROM sessions WHERE member_id = ?', undef, $id) unless $is_active;
    log_event('member_update', "#$id: name=$name admin=$is_admin active=$is_active");
    return act_admin_members();
}

sub act_recent_events {
    my $rows = dbh()->selectall_arrayref(q{
        SELECT e.id, e.transaction_id, e.event, e.detail, e.ip, e.created_at, m.display_name AS member
          FROM events e LEFT JOIN members m ON m.id = e.member_id
         ORDER BY e.id DESC LIMIT 200}, { Slice => {} });
    return { events => $rows };
}
