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

our $VERSION = '1.1.0';

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

    my $provider_code = _provider_code($provider);
    my $interface     = C4::Context->interface // 'unknown';
    my $identity      = _identity_label($mapped);

    if ($patron) {
        my $borrowernumber =
              ( ref($patron) && $patron->can('borrowernumber') ) ? $patron->borrowernumber
            : ( ref($patron) && $patron->can('id') )             ? $patron->id
            :                                                     0;

        logaction(
            'AUTH',
            'SUCCESS',
            $borrowernumber,
            "OIDC/OAuth login via provider '$provider_code' ($interface)",
            $interface
        );
    }
    else {
        # IdP authenticated, but no Koha patron matched the provider matchpoint.
        # Note: if the domain auto-registers after get_user returns, this FAILURE
        # is still accurate for "no existing patron at hook time."
        logaction(
            'AUTH',
            'FAILURE',
            0,
            "OIDC/OAuth authenticated via '$provider_code' but no matching Koha patron for '$identity' ($interface)",
            $interface
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

1;
