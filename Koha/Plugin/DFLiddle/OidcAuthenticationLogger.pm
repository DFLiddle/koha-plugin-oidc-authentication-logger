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

our $VERSION = '1.2.0';

our $metadata = {
    name            => 'OIDC Authentication Logger',
    class           => 'Koha::Plugin::DFLiddle::OidcAuthenticationLogger',
    author          => 'David F Liddle',
    description     => 'Logs OpenID Connect / OAuth IdP logins and unmatched patrons to Koha Action Logs (AUTH SUCCESS/FAILURE)',
    date_authored   => '2026-10-03',
    date_updated    => '2026-10-03',
    minimum_version => '23.11.07',
    maximum_version => undef,
    version         => $VERSION,
};

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

        logaction(
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
    return 1;
}

sub uninstall {
    return 1;
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

C4::Context->interface is unreliable here: OAuth routes skip
authenticate_api_request, so Context often stays at the default C<opac>
for both Staff and OPAC callbacks. The route path ends in /opac or /staff.

=cut

sub _oauth_interface {
    my $path = $ENV{PATH_INFO} // $ENV{REQUEST_URI} // '';
    if ( $path =~ m{/oauth/login/[^/]+/(opac|staff)\b} ) {
        return $1;
    }
    if ( $path =~ m{/(opac|staff)(?:\?|$)} ) {
        return $1;
    }

    # Last resort: Context (often wrong for staff OAuth on 24.11).
    my $ctx = C4::Context->interface // '';
    return 'opac'     if $ctx eq 'opac';
    return 'staff'    if $ctx eq 'intranet' || $ctx eq 'staff';
    return 'unknown';
}

=head2 _log_interface

Map OAuth interface to a value accepted by action_logs / the log viewer.
Staff OAuth uses C<staff> in the URL; Koha logs traditionally use C<intranet>.

=cut

sub _log_interface {
    my ($oauth_iface) = @_;
    return 'opac'     if $oauth_iface eq 'opac';
    return 'intranet' if $oauth_iface eq 'staff';
    return C4::Context->interface // 'api';
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
