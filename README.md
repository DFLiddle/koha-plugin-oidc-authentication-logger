# Koha OIDC Authentication Logger

Koha plugin that writes **native Action Log** rows (`AUTH` / `SUCCESS` or `AUTH` / `FAILURE`) when patrons authenticate via OpenID Connect / OAuth (for example Google) on **Staff** and **OPAC**.

Target tested against: **Koha 24.11.x** (requires the `auth_client_get_user` hook, available from 23.11.07+ / 24.05+).

## Why this exists

Koha’s `AuthSuccessLog` / `AuthFailureLog` system preferences log password checks in `C4::Auth::checkpw`. The OAuth/OIDC REST callback (`/api/v1/oauth/login/...` and `/api/v1/public/oauth/login/...`) uses `Koha::Auth::Client` and does **not** write those rows. This plugin fills that gap via the supported plugin hook `auth_client_get_user`.

## Layout (required for discovery)

```text
Koha/Plugin/DFLiddle/OidcAuthenticationLogger.pm
```

Package name and path must match exactly:

`Koha::Plugin::DFLiddle::OidcAuthenticationLogger`

→ `pluginsdir/Koha/Plugin/DFLiddle/OidcAuthenticationLogger.pm`

## Build a `.kpz`

From the repository root:

```bash
./scripts/build-kpz.sh
# → dist/koha-plugin-oidc-authentication-logger-v1.1.0.kpz
```

Or manually:

```bash
zip -r dist/OidcAuthenticationLogger-v1.1.0.kpz Koha
```

The archive root must contain `Koha/Plugin/...` (not a wrapper folder).

## Install on Koha 24.11.19

Prerequisites in `koha-conf.xml` for the instance:

- `<enable_plugins>1</enable_plugins>`
- UI upload allowed unless you install from the CLI (`plugins_restricted` off, or use `koha-shell` / `install_plugins.pl`)

### Option A — Staff UI (KPZ)

1. Administration → Plugins → Upload plugin
2. Upload the `.kpz`
3. Confirm **OIDC Authentication Logger** appears in the list and is enabled

### Option B — Copy + scan (CLI)

```bash
# As a user that can write the instance pluginsdir, e.g.:
sudo mkdir -p /var/lib/koha/library/plugins/Koha/Plugin/DFLiddle
sudo cp Koha/Plugin/DFLiddle/OidcAuthenticationLogger.pm \
  /var/lib/koha/library/plugins/Koha/Plugin/DFLiddle/

# Register methods in plugin_methods (required — copy alone is not enough)
sudo koha-shell library -c 'perl /usr/share/koha/misc/devel/install_plugins.pl'
```

Replace `library` with your instance name if different.

### Verify registration

```bash
ls -la /var/lib/koha/library/plugins/Koha/Plugin/DFLiddle/
# Expect: OidcAuthenticationLogger.pm  (exact name)

echo "SELECT DISTINCT plugin_class FROM plugin_methods
      WHERE plugin_class = 'Koha::Plugin::DFLiddle::OidcAuthenticationLogger';" \
  | sudo koha-mysql library
```

If the file is present but the Plugins list is empty for this class, re-run `install_plugins.pl`. The admin page reads `plugin_methods`, not the filesystem alone.

## What gets logged

| Outcome | Module | Action | When |
|---------|--------|--------|------|
| IdP login with matched Koha patron | `AUTH` | `SUCCESS` | `auth_client_get_user` after mapping finds a patron |
| IdP login, no matching patron | `AUTH` | `FAILURE` | Same hook when `patron` is undef |

Staff and OPAC both use `Koha::Auth::Client::get_user`, so both interfaces are covered. The log info string includes provider code and interface (`intranet` / `opac`).

View under Tools → Log viewer (Auth), or:

```sql
SELECT * FROM action_logs
 WHERE module = 'AUTH'
   AND info LIKE 'OIDC/OAuth%'
 ORDER BY action_id DESC
 LIMIT 20;
```

### What this hook cannot see

Failures that never reach `get_user` are **not** logged here, including:

- IdP / token errors and CSRF failures in `Koha::REST::V1::OAuth::Client` (redirect with `auth_error=…`)
- `NoValidDomain` thrown before the hook runs

Those still appear in the Plack/error log and as `auth_error` query params on redirect.

If a domain **auto-registers** a patron after `get_user` returns with no patron, this plugin may still write a `FAILURE` for “no matching patron at hook time.”

## Uninstall

Disable/uninstall from Administration → Plugins, or remove the `.pm` and run `install_plugins.pl` / clear `plugin_methods` / `plugin_data` for the class as appropriate for your ops practice.

## Development notes

- Do **not** use `api_routes` / Mojolicious `after_dispatch` for this; that is the wrong extension point on 24.11.
- Do not rename the `.pm` file or change the package without updating both to match.
