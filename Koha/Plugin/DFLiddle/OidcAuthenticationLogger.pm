package Koha::Plugin::DFLiddle::OidcAuthenticationLogger;

# Copyright 2026 David F Liddle
#
# This file is part of koha-plugin-oidc-authentication-logger.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at your
# option) any later version.

use Modern::Perl;

use base qw(Koha::Plugins::Base);

use C4::Context;
use C4::Log qw(logaction);

our $VERSION = '1.3.1';

our $metadata = {
    name            => 'OIDC Authentication Logger',
    class           => 'Koha::Plugin::DFLiddle::OidcAuthenticationLogger',
    author          => 'David F Liddle',
    description     => 'Logs OpenID Connect / OAuth IdP logins and unmatched patrons to Koha Action Logs (AUTH SUCCESS/FAILURE)',
    date_authored   => '2026-10-03',
    date_updated    => '2026-10-05',
    minimum_version => '23.11.07',
    maximum_version => undef,
    version         => $VERSION,
};

# Captured from Koha::Auth::Client::get_user's $params->{interface} for the
# duration of that call. Preferred over %ENV path parsing and Context->interface.
our $CurrentOAuthInterface;
our $_get_user_patched = 0;

=head1 NAME

Koha::Plugin::DFLiddle::OidcAuthenticationLogger - Log OIDC/OAuth IdP auth to action_logs

=head1 DESCRIPTION

Koha's built-in AuthSuccessLog / AuthFailureLog preferences cover password
auth in C4::Auth::checkpw. The OAuth/OIDC REST callback path uses
Koha::Auth::Client instead and does not write those rows.

This plugin implements the auth_client_get_user hook (Bug 36503) so Staff and
OPAC IdP logins write native AUTH / SUCCESS or AUTH / FAILURE rows.

=cut

sub new {
    my ( $class, $args ) = @_;
    $args ||= {};
    $args->{metadata} = $metadata;
    $args->{metadata}->{class} = $class;
    my $self = $class->SUPER::new($args);
    _patch_get_user_interface_capture();
    return $self;
}

=head2 auth_client_get_user

Called from Koha::Auth::Client::get_user after the IdP has authenticated the
user and mapping has been applied. Receives provider, data, config,
mapped_data, patron, and (on 24.11) domain.

Does not mutate mapped_data or patron.

=cut

sub auth_client_get_user {
    my ( $self, $args ) = @_;
    $args ||= {};

    # Ensure capture is installed even if this class was loaded without new().
    _patch_get_user_interface_capture();

    my $patron   = $args->{patron};
    my $provider = $args->{provider};
    my $mapped   = $args->{mapped_data} // {};
    my $domain   = $args->{domain};

    my $provider_code = _provider_code($provider);
    my $oauth_iface   = _oauth_interface();
    my $log_iface     = _log_interface($oauth_iface);
    my $identity      = _identity_label($mapped);

    if ($patron) {
        my $borrowernumber =
              ( ref($patron) && $patron->can('borrowernumber') ) ? $patron->borrowernumber
            : ( ref($patron) && $patron->can('id') )             ? $patron->id
            :                                                     undef;

        # Avoid AUTH SUCCESS with object=0 when the patron object is unexpected.
        return unless defined $borrowernumber && $borrowernumber =~ /^\d+$/ && $borrowernumber > 0;

        # logaction stores action_logs.user from C4::Context->userenv->{number}
        # (Log viewer "Librarian"), not from the object argument. OAuth callbacks
        # run before a session exists, so userenv is unset and Librarian would
        # stay 0 even when object is correct. Set userenv for this call only.
        _logaction_as_user(
            $borrowernumber,
            'AUTH',
            'SUCCESS',
            $borrowernumber,
            "OIDC/OAuth login via provider '$provider_code' ($oauth_iface)",
            $log_iface
        );
    }
    else {
        # Koha::REST::V1::OAuth::Client may auto-register *after* get_user returns
        # when the domain allows it. Logging FAILURE here would create a spurious
        # object=0 row immediately before a successful session. Only log FAILURE
        # for true unmatched patrons (auto-register will not run).
        if ( _will_auto_register( $domain, $oauth_iface ) ) {
            return;
        }

        # FAILURE keeps user=0 (no known patron to attribute as Librarian).
        logaction(
            'AUTH',
            'FAILURE',
            0,
            "OIDC/OAuth authenticated via '$provider_code' but no matching Koha patron for '$identity' ($oauth_iface)",
            $log_iface
        );
    }

    return;
}

sub install {
    _patch_get_user_interface_capture();
    return 1;
}

sub uninstall {
    return 1;
}

=head2 _patch_get_user_interface_capture

Wrap C<Koha::Auth::Client::get_user> so the OAuth route's C<interface>
parameter (C<opac>|C<staff>) is available while C<auth_client_get_user> runs.

Koha passes C<interface> into C<get_user> but does not include it in the hook
C<$args>. Under Plack/Mojolicious, C<%ENV> path parsing is unreliable, and
C<C4::Context-E<gt>interface> can remain C<intranet> after a Staff request
because OAuth skips C<authenticate_api_request> (which would set C<api>) and
C<Koha::Middleware::UserEnv> only clears userenv, not interface.

=cut

sub _patch_get_user_interface_capture {
    return if $_get_user_patched;

    # Soft-fail if Auth::Client is not loadable in this process yet.
    eval { require Koha::Auth::Client; 1 } or return;

    my $orig = \&Koha::Auth::Client::get_user;
    no warnings 'redefine';
    *Koha::Auth::Client::get_user = sub {
        my ( $self, $params ) = @_;
        local $CurrentOAuthInterface =
            ( ref($params) eq 'HASH' ) ? $params->{interface} : undef;
        return $orig->( $self, $params );
    };

    $_get_user_patched = 1;
    return;
}

=head2 _logaction_as_user

Call C4::Log::logaction with userenv temporarily set so action_logs.user
(Librarian column) is $borrowernumber. Restores the previous userenv afterward.
Does not leave a lasting session identity.

=cut

sub _logaction_as_user {
    my ( $borrowernumber, @log_args ) = @_;

    my $previous = C4::Context->userenv;
    my $had_env  = ( ref($previous) eq 'HASH' );

    if ($had_env) {

        # Prefer in-place override so we do not replace other userenv fields.
        my $prev_number = $previous->{number};
        $previous->{number} = $borrowernumber;
        my $ok = eval { logaction(@log_args); 1 };
        my $err = $@;
        $previous->{number} = $prev_number;
        die $err if !$ok;
        return;
    }

    C4::Context->set_userenv($borrowernumber);
    my $ok = eval { logaction(@log_args); 1 };
    my $err = $@;
    C4::Context->unset_userenv;
    die $err if !$ok;
    return;
}

sub _provider_code {
    my ($provider) = @_;
    return $provider->code
        if ref($provider) && $provider->can('code');
    return $provider
        if defined $provider && !ref($provider) && length $provider;
    return 'unknown';
}

sub _identity_label {
    my ($mapped) = @_;
    return 'unknown' unless ref($mapped) eq 'HASH';
    for my $key (qw(userid cardnumber email)) {
        my $value = $mapped->{$key};
        return $value if defined $value && length $value;
    }
    return 'unknown';
}

=head2 _oauth_interface

Resolve the OAuth login interface (C<opac> or C<staff>).

Preferred source: C<$CurrentOAuthInterface> captured from
C<Koha::Auth::Client::get_user>'s C<< $params->{interface} >> (the OpenAPI
path parameter), which is authoritative and independent of session/userenv.

Fallbacks (best-effort): request path, then C</public/> vs non-public OAuth
URL shape. C<C4::Context-E<gt>interface> is B<not> trusted here: after a Staff
login on the same Plack worker it can remain C<intranet> while an OPAC OAuth
callback runs.

=cut

sub _oauth_interface {
    if ( defined $CurrentOAuthInterface && $CurrentOAuthInterface =~ /^(opac|staff)$/ ) {
        return $CurrentOAuthInterface;
    }

    my $path = _request_path();

    # Explicit route suffix (…/oauth/login/<provider>/(opac|staff)).
    if ( $path =~ m{/oauth/login/[^/]+/(opac|staff)(?:\b|\?|$)} ) {
        return $1;
    }

    # Bug 33708: OPAC uses /api/v1/public/oauth/… ; Staff uses /api/v1/oauth/…
    if ( $path =~ m{/public/oauth/} ) {
        return 'opac';
    }
    if ( $path =~ m{/oauth/login/} && $path !~ m{/public/} ) {
        return 'staff';
    }

    if ( $path =~ m{/(opac|staff)(?:\?|$)} ) {
        return $1;
    }

    return 'unknown';
}

=head2 _request_path

Best-effort request path for fallbacks. Prefer non-empty values; under
Mojolicious/Plack these C<%ENV> keys are often unset or stale.

=cut

sub _request_path {
    for my $key (qw(REQUEST_URI PATH_INFO SCRIPT_URL HTTP_X_ORIGINAL_URI HTTP_X_REWRITE_URL)) {
        my $value = $ENV{$key};
        next unless defined $value && length $value;
        return $value;
    }
    return '';
}

=head2 _log_interface

Map OAuth interface to a value accepted by action_logs / the log viewer.
Staff OAuth uses C<staff> in the URL; Koha logs traditionally use C<intranet>.

=cut

sub _log_interface {
    my ($oauth_iface) = @_;
    return 'opac'     if $oauth_iface eq 'opac';
    return 'intranet' if $oauth_iface eq 'staff';

    # Do not fall back to Context->interface: it can be leftover intranet from
    # a prior Staff request on the same Plack worker (OAuth skips setting api).
    return 'api';
}

=head2 _will_auto_register

True when Koha will create a patron after get_user returns with no match.
Matches Koha::REST::Plugin::Auth::IdP::auth.register gating for 24.11
(single C<auto_register>, OPAC only) and newer split OPAC/staff flags.

=cut

sub _will_auto_register {
    my ( $domain, $oauth_iface ) = @_;
    return 0 unless $domain && $oauth_iface;

    if ( $domain->can('auto_register_opac') || $domain->can('auto_register_staff') ) {
        return 1
            if $oauth_iface eq 'opac'
            && $domain->can('auto_register_opac')
            && $domain->auto_register_opac;
        return 1
            if $oauth_iface eq 'staff'
            && $domain->can('auto_register_staff')
            && $domain->auto_register_staff;
        return 0;
    }

    return 1
        if $oauth_iface eq 'opac'
        && $domain->can('auto_register')
        && $domain->auto_register;

    return 0;
}

1;
