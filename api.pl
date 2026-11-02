#!/usr/bin/perl
#
# Sigma Sync API - every request is a POST with an "action" field.
# Responses: { "success": 1, ... } or { "success": 0, "error": "..." }.
#
use strict;
use warnings;

use FindBin;
use lib $FindBin::Bin;

use CGI qw(-utf8);
use Digest::SHA qw(sha256_hex);
use JSON::PP ();

use AppConfig qw(cfg dbh seal unseal random_hex client_ip);
use ErgoKit qw(address_decode build_login_request verify_login_response
               sanitize_payload analyze_payload compare_hints);

$CGI::POST_MAX = 4 * 1024 * 1024;

my $JSON = JSON::PP->new->utf8->canonical;
my $cgi  = CGI->new;
my @cookies;
my ($ME, $SESSION);

my %LIMIT = (title => 120, description => 10_000, comment => 4000, payload => 1_000_000,
             wallet => 80, name => 40);

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
    lock               => \&act_lock,
    release_lock       => \&act_release_lock,
    vote_unlock        => \&act_vote_unlock,
    submit             => \&act_submit,
    add_comment        => \&act_add_comment,
    cancel_transaction => \&act_cancel_transaction,
    mark_broadcast     => \&act_mark_broadcast,
    list_members       => \&act_list_members,
);
my %ADMIN = (
    save_member   => \&act_save_member,
    recent_events => \&act_recent_events,
);

my $response = eval {
    die { public => 'Use POST.' } unless ($ENV{REQUEST_METHOD} // '') eq 'POST';
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

sub cookie_path { return cfg('COOKIE_PATH', '/apps/sigmasync/') }

sub session_cookie {
    my ($value, $expires) = @_;
    return $cgi->cookie(
        -name     => 'sigmasync_sid',
        -value    => $value,
        -path     => cookie_path(),
        -expires  => $expires,
        -secure   => cfg('COOKIE_SECURE', '1') eq '1' ? 1 : 0,
        -httponly => 1,
        -samesite => 'Strict',
    );
}

sub admin_addresses {
    return map { s/^\s+|\s+$//gr } grep { length } split /,/, cfg('ADMIN_ADDRESSES', '');
}

sub load_session {
    return if $SESSION;
    my $token = $cgi->cookie('sigmasync_sid') // '';
    return unless $token =~ /^[0-9a-f]{64}$/;
    my $idle = cfg('SESSION_IDLE_MINUTES', 120) + 0;
    my $row = dbh()->selectrow_hashref(q{
        SELECT s.id AS session_id, s.csrf_token, m.id, m.address, m.display_name, m.is_admin
          FROM sessions s JOIN members m ON m.id = s.member_id
         WHERE s.token_hash = ? AND s.expires_at > UTC_TIMESTAMP()
           AND s.last_seen_at > UTC_TIMESTAMP() - INTERVAL ? MINUTE
           AND m.is_active = 1
    }, undef, sha256_hex($token), $idle) or return;
    $row->{is_admin} = 1 if grep { $_ eq $row->{address} } admin_addresses();
    dbh()->do('UPDATE sessions SET last_seen_at = UTC_TIMESTAMP() WHERE id = ?', undef, $row->{session_id});
    $SESSION = $row;
    $ME = { map { $_ => $row->{$_} } qw(id address display_name is_admin) };
}

sub require_member {
    load_session();
    fail('Your session has ended. Please sign in again.', { signed_out => 1 }) unless $ME;
    my $csrf = param('csrf');
    fail('Your session has ended. Please sign in again.', { signed_out => 1 })
        unless length $csrf && $csrf eq $SESSION->{csrf_token};
}

sub public_member { my $m = shift; return { map { $_ => $m->{$_} } qw(id address display_name is_admin) } }

sub client_config {
    return {
        unlock_votes         => cfg('UNLOCK_VOTES', 2) + 0,
        unlock_grace_minutes => cfg('UNLOCK_GRACE_MINUTES', 10) + 0,
        explorer_tx_url      => cfg('EXPLORER_TX_URL', 'https://explorer.ergoplatform.com/en/transactions/'),
        explorer_api_url     => cfg('EXPLORER_API_URL', 'https://api.ergoplatform.com/api/v1/transactions/'),
    };
}

# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------
sub act_session {
    load_session();
    return { signed_in => 0 } unless $ME;
    return { signed_in => 1, member => public_member($ME), csrf => $SESSION->{csrf_token},
             config => client_config() };
}

sub act_auth_start {
    my $address = param('address') =~ s/\s+//gr;
    my $info = address_decode($address);
    fail('That is not a valid Ergo address.') unless $info;
    fail('Use the regular (P2PK) address of your signing wallet, not a multi-sig or contract address.')
        unless $info->{type} eq 'P2PK';
    fail("Use a $info->{network} address.") if $info->{network} ne cfg('NETWORK', 'mainnet');

    my $db = dbh();
    $db->do('DELETE FROM auth_challenges WHERE expires_at < UTC_TIMESTAMP() - INTERVAL 1 DAY');
    my ($recent) = $db->selectrow_array(
        'SELECT COUNT(*) FROM auth_challenges WHERE ip = ? AND created_at > UTC_TIMESTAMP() - INTERVAL 15 MINUTE',
        undef, client_ip());
    fail('Too many sign-in attempts. Wait a few minutes and try again.') if $recent >= 20;

    my $token = random_hex(32);
    my $req = build_login_request(address => $address, nonce => pack('H*', random_hex(32)));
    my $ttl = cfg('CHALLENGE_MINUTES', 15) + 0;
    $db->do(q{INSERT INTO auth_challenges (token_hash, address, message_hex, ip, expires_at)
              VALUES (?,?,?,?, UTC_TIMESTAMP() + INTERVAL ? MINUTE)},
        undef, sha256_hex($token), $address, unpack('H*', $req->{message}), client_ip(), $ttl);

    return { challenge => $token, request => $req->{request}, expires_minutes => $ttl };
}

sub act_auth_finish {
    my $token = param('challenge');
    fail('Sign-in request not found. Start again.') unless $token =~ /^[0-9a-f]{64}$/;
    my $db = dbh();
    my $ch = $db->selectrow_hashref(q{
        SELECT id, address, message_hex FROM auth_challenges
         WHERE token_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP()
    }, undef, sha256_hex($token));
    fail('This sign-in request has expired or was already used. Start again.') unless $ch;

    my $response = param('response');
    fail('Paste the signed result from Minotaur.') unless length $response;
    fail('That is far too long to be a sign-in response.') if length $response > 200_000;

    my $info = address_decode($ch->{address});
    my ($ok, $why) = verify_login_response(
        response => $response, expected_message => pack('H*', $ch->{message_hex}), pk => $info->{pk});
    unless ($ok) {
        # A wrong paste (e.g. the request itself) should not burn the challenge.
        log_event('login_failed', "$ch->{address}: $why");
        fail($why);
    }
    $db->do('UPDATE auth_challenges SET used_at = UTC_TIMESTAMP() WHERE id = ? AND used_at IS NULL', undef, $ch->{id}) > 0
        or fail('This sign-in request was already used. Start again.');

    my $member = $db->selectrow_hashref('SELECT * FROM members WHERE address = ?', undef, $ch->{address});
    if (!$member && grep { $_ eq $ch->{address} } admin_addresses()) {
        $db->do('INSERT INTO members (address, display_name, is_admin) VALUES (?,?,1)',
            undef, $ch->{address}, 'Admin ' . substr($ch->{address}, 0, 6));
        $member = $db->selectrow_hashref('SELECT * FROM members WHERE address = ?', undef, $ch->{address});
    }
    unless ($member && $member->{is_active}) {
        log_event('login_denied', $ch->{address});
        fail('Signature verified, but this wallet is not a registered signer. Send your address to an admin to be added.',
            { verified_address => $ch->{address} });
    }

    my $session = random_hex(32);
    my $csrf    = random_hex(32);
    my $hours   = cfg('SESSION_HOURS', 12) + 0;
    $db->do('DELETE FROM sessions WHERE expires_at < UTC_TIMESTAMP()');
    $db->do(q{INSERT INTO sessions (token_hash, csrf_token, member_id, ip, expires_at)
              VALUES (?,?,?,?, UTC_TIMESTAMP() + INTERVAL ? HOUR)},
        undef, sha256_hex($session), $csrf, $member->{id}, client_ip(), $hours);
    $db->do('UPDATE members SET last_login_at = UTC_TIMESTAMP() WHERE id = ?', undef, $member->{id});
    push @cookies, session_cookie($session, "+${hours}h");

    $member->{is_admin} = 1 if grep { $_ eq $member->{address} } admin_addresses();
    log_event('login', '', undef, $member->{id});
    return { signed_in => 1, member => public_member($member), csrf => $csrf, config => client_config() };
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
# Transactions
# ---------------------------------------------------------------------------
sub load_tx {
    my ($id, $for_update) = @_;
    my $sql = 'SELECT * FROM transactions WHERE id = ?' . ($for_update ? ' FOR UPDATE' : '');
    my $tx = dbh()->selectrow_hashref($sql, undef, $id) or fail('Transaction not found.');
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
    my $rows = dbh()->selectall_arrayref('SELECT id, display_name FROM members', { Slice => {} });
    return { map { $_->{id} => $_->{display_name} } @$rows };
}

# Where a member stands on a transaction: did they commit / sign, is it their turn?
sub my_progress {
    my ($tx, $mine) = @_;
    my %p = (committed => $mine->{commit} ? 1 : 0, signed => $mine->{sign} || $mine->{final} ? 1 : 0);
    $p{awaiting} = ($tx->{status} eq 'commit' && !$p{committed})
                || ($tx->{status} eq 'sign' && $p{committed} && !$p{signed}) ? 1 : 0;
    return \%p;
}

sub tx_brief {
    my ($tx, $names, $mine, $comment_count) = @_;
    return {
        id               => $tx->{id} + 0,
        title            => unseal($tx->{title_enc}, 'transaction.title'),
        wallet_name      => $tx->{wallet_name},
        minotaur_version => $tx->{minotaur_version},
        status           => $tx->{status},
        signers_required => $tx->{signers_required} + 0,
        signers_total    => defined $tx->{signers_total} ? $tx->{signers_total} + 0 : undef,
        commits          => $tx->{commits} + 0,
        signatures       => $tx->{signatures} + 0,
        ergo_tx_id       => $tx->{ergo_tx_id},
        created_by       => $names->{ $tx->{created_by} },
        created_by_id    => $tx->{created_by} + 0,
        created_at       => $tx->{created_at},
        updated_at       => $tx->{updated_at},
        closed_at        => $tx->{closed_at},
        lock             => $tx->{lock_member_id}
            ? { member_id => $tx->{lock_member_id} + 0, name => $names->{ $tx->{lock_member_id} },
                since => $tx->{locked_at}, mine => $tx->{lock_member_id} == $ME->{id} ? 1 : 0 }
            : undef,
        comments => $comment_count // 0,
        me       => my_progress($tx, $mine || {}),
    };
}

sub act_list_transactions {
    my $db = dbh();
    my $txs = $db->selectall_arrayref(q{
        SELECT * FROM transactions
         WHERE status IN ('commit','sign','complete')
            OR closed_at > UTC_TIMESTAMP() - INTERVAL 180 DAY
         ORDER BY FIELD(status,'commit','sign','complete','broadcast','cancelled'), updated_at DESC
         LIMIT 500
    }, { Slice => {} });
    my %mine;
    for my $r (@{ $db->selectall_arrayref(
        'SELECT DISTINCT transaction_id, round FROM submissions WHERE member_id = ?', undef, $ME->{id}) }) {
        $mine{ $r->[0] }{ $r->[1] } = 1;
    }
    my %comments = map { $_->[0] => $_->[1] } @{ $db->selectall_arrayref(
        'SELECT transaction_id, COUNT(*) FROM comments GROUP BY transaction_id') };
    my $names = member_names();
    my $wallets = $db->selectcol_arrayref(
        q{SELECT wallet_name FROM transactions WHERE wallet_name <> '' GROUP BY wallet_name ORDER BY MAX(id) DESC LIMIT 20});
    return {
        transactions => [ map { tx_brief($_, $names, $mine{ $_->{id} }, $comments{ $_->{id} }) } @$txs ],
        wallet_names => $wallets,
    };
}

sub act_get_transaction {
    my $id = int_param('id');
    my $db = dbh();
    my $tx = load_tx($id);
    my $names = member_names();

    my $subs = $db->selectall_arrayref(
        'SELECT id, member_id, round, payload_sha256, commits, signatures, slot_index, created_at FROM submissions WHERE transaction_id = ? ORDER BY id',
        { Slice => {} }, $id);
    my $comments = $db->selectall_arrayref(
        'SELECT id, member_id, submission_id, body_enc, created_at FROM comments WHERE transaction_id = ? ORDER BY id',
        { Slice => {} }, $id);
    my $events = $db->selectall_arrayref(q{
        SELECT id, member_id, event, detail, created_at FROM events
         WHERE transaction_id = ? AND event IN ('lock','release','unlock_vote','lock_override','cancel','broadcast')
         ORDER BY id}, { Slice => {} }, $id);

    my %mine;
    my %participants;
    for my $s (@$subs) {
        $mine{ $s->{round} } = 1 if $s->{member_id} == $ME->{id};
        my $p = $participants{ $s->{member_id} } ||= { member_id => $s->{member_id} + 0, name => $names->{ $s->{member_id} } };
        $p->{ $s->{round} eq 'commit' ? 'committed_at' : 'signed_at' } //= $s->{created_at};
        $p->{slot} //= $s->{slot_index};
    }

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

    my $brief = tx_brief($tx, $names, \%mine, scalar @$comments);
    $brief->{description} = unseal($tx->{description_enc}, 'transaction.description');
    $brief->{timeline}    = \@timeline;
    $brief->{participants} = [ sort { ($a->{committed_at} // '9') cmp ($b->{committed_at} // '9') } values %participants ];

    # Override votes for the current lock.
    if ($tx->{lock_member_id}) {
        my $votes = $db->selectall_arrayref(
            'SELECT member_id, created_at FROM unlock_votes WHERE transaction_id = ? AND lock_seq = ? ORDER BY created_at',
            { Slice => {} }, $id, $tx->{lock_seq});
        $brief->{lock}{votes} = [ map { { name => $names->{ $_->{member_id} }, at => $_->{created_at},
                                          mine => $_->{member_id} == $ME->{id} ? 1 : 0 } } @$votes ];
        my ($age) = $db->selectrow_array('SELECT TIMESTAMPDIFF(MINUTE, locked_at, UTC_TIMESTAMP()) FROM transactions WHERE id = ?', undef, $id);
        $brief->{lock}{age_minutes} = $age + 0;
    }

    # Review data from the latest payload: what the transaction does, and the current
    # slot picture. The payload text itself is only handed to the lock holder (to
    # continue from it) or once the transaction is complete (to broadcast it).
    my $latest = latest_submission($id);
    if ($latest) {
        my $a = analyze_payload($latest->{payload});
        $brief->{review} = {
            format       => $a->{format},
            outputs      => $a->{outputs},
            outputs_partial => $a->{outputs_partial} ? 1 : 0,
            inputs_value => $a->{inputs_value},
            slots        => $a->{slots},
        };
        my $show = ($brief->{lock} && $brief->{lock}{mine}) || $tx->{status} eq 'complete' || $tx->{status} eq 'broadcast';
        if ($show) {
            $brief->{payload} = {
                text        => $latest->{payload},
                type        => $a->{format},
                fingerprint => substr($latest->{payload_sha256}, 0, 12),
                at          => $latest->{created_at},
                by          => $names->{ $latest->{member_id} },
            };
        }
    }

    $brief->{can} = {
        lock   => is_open($tx) && !$tx->{lock_member_id} ? 1 : 0,
        cancel => ($tx->{created_by} == $ME->{id} || $ME->{is_admin}) && ($tx->{status} ne 'broadcast' && $tx->{status} ne 'cancelled') ? 1 : 0,
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
    my $generic = $tx && !$tx->{ergo_tx_id};

    if (!$generic) {
        fail($a->{error}) unless $a->{valid};
    }
    return ($a, undef) if $generic || !$tx;

    if ($a->{tx_id} && $a->{tx_id} ne $tx->{ergo_tx_id}) {
        fail('This payload belongs to a different Ergo transaction (ID ' . substr($a->{tx_id}, 0, 10)
           . '...). Make sure you opened the request from this page in Minotaur.');
    }
    return ($a, undef) unless $latest;

    if (sha256_hex($payload) eq $latest->{payload_sha256}) {
        fail('This is the same request that is already stored. In Minotaur, add your commitment or signature, then paste the NEW output.');
    }
    my $prev = analyze_payload($latest->{payload});
    return ($a, undef) unless $a->{format} eq 'MSR' && $prev->{format} eq 'MSR';

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

sub payload_param {
    my $p = sanitize_payload(param('payload'));
    fail('Paste the payload from Minotaur.') unless length $p;
    fail('The payload is too large.') if length $p > $LIMIT{payload};
    return $p;
}

sub act_analyze {
    my $payload = sanitize_payload(param('payload'));
    my $a = analyze_payload($payload);
    my %out = map { $_ => $a->{$_} } qw(format valid error warning tx_id required signers committed signed slots outputs outputs_partial inputs_value);
    my $tx_id = param('id');
    if ($tx_id =~ /^\d+$/ && length $payload) {
        my $tx = load_tx($tx_id);
        my $latest = latest_submission($tx_id);
        eval { my (undef, $cmp) = check_payload($tx, $payload, $latest); $out{compare} = $cmp; 1 }
            or do { my $e = $@; die $e unless ref $e eq 'HASH'; $out{problem} = $e->{public} };
    }
    return { analysis => \%out };
}

sub version_param {
    my $v = param('minotaur_version');
    fail('Choose the Minotaur version everyone should use.')
        unless $v =~ /^(?:[a-z]+-)?v?\d+(?:\.\d+){1,3}(?:-[\w.]+)?$|^other$/;
    return $v;
}

sub act_create_transaction {
    my $title = clean_text(param('title'), $LIMIT{title}, 'Title');
    fail('Give the transaction a name.') unless length $title;
    my $desc   = clean_text(param('description'), $LIMIT{description}, 'Description', 1);
    my $wallet = clean_text(param('wallet_name'), $LIMIT{wallet}, 'Wallet name');
    my $version = version_param();
    my $required = param('signers_required');
    fail('Set how many signatures are required (1-50).') unless $required =~ /^\d{1,2}$/ && $required >= 1 && $required <= 50;
    my $comment = clean_text(param('comment'), $LIMIT{comment}, 'Comment', 1);
    my $payload = payload_param();

    my ($ergo_tx_id, $total, $commits) = (undef, undef, 1);
    if ($version ne 'other' || $payload =~ /^\{/) {
        my $a = analyze_payload($payload);
        fail($a->{error}) unless $a->{valid};
        fail('Start a transaction with the multi-sig request (MSR) from Minotaur, after you have committed.')
            unless $a->{format} eq 'MSR';
        fail('This request has no commitment yet. In Minotaur, press Commit first, then copy the new request.')
            unless $a->{committed};
        if ($a->{required} && $a->{required} != $required) {
            fail("This multi-sig wallet needs $a->{required} of $a->{signers} signatures. Set \"Signatures required\" to $a->{required}.");
        }
        my ($dupe) = dbh()->selectrow_array(
            q{SELECT id FROM transactions WHERE ergo_tx_id = ? AND status <> 'cancelled'}, undef, $a->{tx_id});
        fail("This Ergo transaction is already being tracked (#$dupe).") if $dupe;
        ($ergo_tx_id, $total, $commits) = ($a->{tx_id}, $a->{signers}, $a->{committed});
    }
    my $status = $commits >= $required ? 'sign' : 'commit';

    my $db = dbh();
    $db->begin_work;
    $db->do(q{INSERT INTO transactions (title_enc, description_enc, wallet_name, minotaur_version,
                signers_required, signers_total, ergo_tx_id, status, commits, created_by)
              VALUES (?,?,?,?,?,?,?,?,?,?)}, undef,
        seal($title, 'transaction.title'), seal($desc, 'transaction.description'), $wallet, $version,
        $required, $total, $ergo_tx_id, $status, $commits, $ME->{id});
    my $tx_id = $db->last_insert_id(undef, undef, 'transactions', 'id');
    my $sub_id = insert_submission($tx_id, 'commit', $payload, $commits, 0, undef);
    insert_comment($tx_id, $comment, $sub_id) if length $comment;
    log_event('create', $ergo_tx_id ? "ergo tx $ergo_tx_id" : 'generic', $tx_id);
    $db->commit;
    return { id => $tx_id + 0 };
}

sub insert_submission {
    my ($tx_id, $round, $payload, $commits, $signatures, $slot) = @_;
    dbh()->do(q{INSERT INTO submissions (transaction_id, member_id, round, payload_enc, payload_sha256,
                commits, signatures, slot_index) VALUES (?,?,?,?,?,?,?,?)}, undef,
        $tx_id, $ME->{id}, $round, seal($payload, 'submission.payload'), sha256_hex($payload),
        $commits, $signatures, $slot);
    return dbh()->last_insert_id(undef, undef, 'submissions', 'id');
}

sub insert_comment {
    my ($tx_id, $body, $sub_id) = @_;
    dbh()->do('INSERT INTO comments (transaction_id, member_id, submission_id, body_enc) VALUES (?,?,?,?)',
        undef, $tx_id, $ME->{id}, $sub_id, seal($body, 'comment.body'));
}

sub act_lock {
    my $id = int_param('id');
    my $n = dbh()->do(q{
        UPDATE transactions SET lock_member_id = ?, lock_seq = lock_seq + 1, locked_at = UTC_TIMESTAMP()
         WHERE id = ? AND lock_member_id IS NULL AND status IN ('commit','sign')
    }, undef, $ME->{id}, $id);
    unless ($n > 0) {
        my $tx = load_tx($id);
        fail('This transaction is no longer open for signing.') unless is_open($tx);
        fail('Someone else locked this transaction a moment ago. Refresh to see who.');
    }
    log_event('lock', '', $id);
    return act_get_transaction();
}

sub act_release_lock {
    my $id = int_param('id');
    my $n = dbh()->do('UPDATE transactions SET lock_member_id = NULL, locked_at = NULL WHERE id = ? AND lock_member_id = ?',
        undef, $id, $ME->{id});
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

    my $latest = latest_submission($id);
    my ($a, $cmp) = check_payload($tx, $payload, $latest);

    my ($commits, $signatures, $round, $status);
    my $required = $tx->{signers_required};
    if ($tx->{ergo_tx_id} && $a->{format} eq 'CSTX') {
        ($commits, $signatures, $round, $status) = ($tx->{commits}, $required, 'final', 'complete');
    } elsif ($tx->{ergo_tx_id}) {
        ($commits, $signatures) = ($a->{committed}, $a->{signed});
        $round = !$cmp ? $tx->{status} : $cmp->{new_commits} ? 'commit' : 'sign';
    } else {
        # Generic (non-Minotaur) transaction: each paste is one step of the current round.
        $round = $tx->{status};
        ($commits, $signatures) = ($tx->{commits}, $tx->{signatures});
        $round eq 'commit' ? $commits++ : $signatures++;
    }
    $status //= $signatures >= $required ? 'complete' : $commits >= $required ? 'sign' : 'commit';

    my $slot = $cmp && @{ $cmp->{slots} } == 1 ? $cmp->{slots}[0] : undef;
    my $sub_id = insert_submission($id, $round, $payload, $commits, $signatures, $slot);
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
    log_event('broadcast', $tx->{ergo_tx_id} // '', $id);
    return act_get_transaction();
}

# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------
sub act_list_members {
    my $rows = dbh()->selectall_arrayref(
        'SELECT id, address, display_name, is_admin, is_active, created_at, last_login_at FROM members ORDER BY is_active DESC, display_name',
        { Slice => {} });
    my %env_admin = map { $_ => 1 } admin_addresses();
    for my $m (@$rows) {
        $m->{$_} += 0 for qw(id is_admin is_active);
        $m->{env_admin} = $env_admin{ $m->{address} } ? 1 : 0;
        $m->{is_admin} = 1 if $m->{env_admin};
    }
    return { members => $rows };
}

sub act_save_member {
    my $id = param('id');
    my $name = clean_text(param('display_name'), $LIMIT{name}, 'Name');
    fail('Enter a display name.') unless length $name;
    my $is_admin  = param('is_admin') ? 1 : 0;
    my $is_active = param('is_active') eq '0' ? 0 : 1;
    my $db = dbh();

    if ($id =~ /^\d+$/) {
        my $m = $db->selectrow_hashref('SELECT * FROM members WHERE id = ?', undef, $id) or fail('Member not found.');
        fail('You cannot remove your own access.') if $m->{id} == $ME->{id} && (!$is_active || !$is_admin);
        fail('This admin is set in the server config (ADMIN_ADDRESSES); change it there.')
            if (!$is_active || !$is_admin) && grep { $_ eq $m->{address} } admin_addresses();
        $db->do('UPDATE members SET display_name = ?, is_admin = ?, is_active = ? WHERE id = ?',
            undef, $name, $is_admin, $is_active, $id);
        $db->do('DELETE FROM sessions WHERE member_id = ?', undef, $id) unless $is_active;
        log_event('member_update', "$m->{address}: name=$name admin=$is_admin active=$is_active");
    } else {
        my $address = param('address') =~ s/\s+//gr;
        my $info = address_decode($address);
        fail('That is not a valid Ergo address.') unless $info;
        fail('Members sign in with a regular (P2PK) wallet address.') unless $info->{type} eq 'P2PK';
        my ($exists) = $db->selectrow_array('SELECT id FROM members WHERE address = ?', undef, $address);
        fail('That address is already a member.') if $exists;
        $db->do('INSERT INTO members (address, display_name, is_admin, is_active, created_by) VALUES (?,?,?,?,?)',
            undef, $address, $name, $is_admin, $is_active, $ME->{id});
        log_event('member_add', "$address: name=$name admin=$is_admin");
    }
    return act_list_members();
}

sub act_recent_events {
    my $rows = dbh()->selectall_arrayref(q{
        SELECT e.id, e.transaction_id, e.event, e.detail, e.ip, e.created_at, m.display_name AS member
          FROM events e LEFT JOIN members m ON m.id = e.member_id
         ORDER BY e.id DESC LIMIT 200}, { Slice => {} });
    return { events => $rows };
}
