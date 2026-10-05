# Koha OIDC Authentication Logger

Koha plugin that writes **native Action Log** rows (`AUTH` / `SUCCESS` or `AUTH` / `FAILURE`) when patrons authenticate via OpenID Connect / OAuth (for example Google) on **Staff** and **OPAC**.

Target tested against: **Koha 24.11.x** (requires the `auth_client_get_user` hook, available from 23.11.07+ / 24.05+).

Current version: **1.3.0**

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
# → dist/koha-plugin-oidc-authentication-logger-v1.3.0.kpz
```

Or manually:

```bash
zip -r dist/OidcAuthenticationLogger-v1.3.0.kpz Koha
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

| Outcome | Module | Action | Interface column | Librarian (`user`) | When |
|---------|--------|--------|------------------|---------------------|------|
| IdP login with matched Koha patron (OPAC) | `AUTH` | `SUCCESS` | `opac` | borrowernumber | Hook finds patron |
| IdP login with matched Koha patron (Staff) | `AUTH` | `SUCCESS` | `intranet` | borrowernumber | Hook finds patron |
| IdP login, no matching patron, auto-register will **not** run | `AUTH` | `FAILURE` | `opac` / `intranet` | `0` | True unmatched patron |
| IdP login, no patron, domain **will** auto-register | *(no row)* | | | | Avoids false `object=0` FAILURE before successful register |

Info strings include the OAuth interface label (`opac` or `staff`), e.g. `OIDC/OAuth login via provider 'google' (staff)`.

Staff and OPAC both use `Koha::Auth::Client::get_user`. The plugin derives `opac` vs `staff` from the OAuth callback path (not `C4::Context->interface`, which is often stuck at the default `opac` for both routes).

On SUCCESS, both `object` and `user` (Log viewer **Librarian**) are set to the patron’s borrowernumber so the viewer can resolve the display name. `C4::Log::logaction` normally takes `user` from `userenv`, which is empty during OAuth callbacks; the plugin sets it for that call only.

View under Tools → Log viewer (Auth), or:

```sql
SELECT action_id, timestamp, user, module, action, object, info, interface
  FROM action_logs
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

First-time **auto-register** logins intentionally produce **no** AUTH row at hook time (Koha creates the patron only after `get_user` returns). The next login for that patron will log `SUCCESS`. True unmatched patrons (auto-register off) still get `FAILURE` with `object = 0`.

## Uninstall

Disable/uninstall from Administration → Plugins, or remove the `.pm` and run `install_plugins.pl` / clear `plugin_methods` / `plugin_data` for the class as appropriate for your ops practice.

## Development notes

- Do **not** use `api_routes` / Mojolicious `after_dispatch` for this; that is the wrong extension point on 24.11.
- Do not rename the `.pm` file or change the package without updating both to match.
- v1.2.0 fixes: false `FAILURE`/`object=0` before auto-register; Staff vs OPAC interface labeling.
- v1.3.0 fixes: SUCCESS rows set `action_logs.user` (Librarian) to the matched borrowernumber, not `0`.
