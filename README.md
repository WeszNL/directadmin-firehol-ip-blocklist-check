# Sernate FireHOL Blocklist Check

DirectAdmin plugin that checks whether this server's public IPv4 addresses appear in FireHOL IP blocklists, using the Sernate Blocklist API.

The plugin is meant to answer one practical question inside DirectAdmin: is one of this server's public IPs listed in any of the FireHOL-based blocklists we index?

It can help with email delivery issues, blocked outbound connections, abuse investigation and general server hygiene. It is not a firewall tool and it does not try to make reputation claims by itself.

## Credit

FireHOL and the upstream feed maintainers deserve credit for collecting, curating and maintaining the source blocklist data. The Sernate Blocklist API indexes and aggregates FireHOL IP blocklist data, then adds search, history, freshness detection and this DirectAdmin plugin on top.

## Features

- Detects public IPv4 addresses on the DirectAdmin server.
- Checks whether those IPs appear in FireHOL-based blocklists.
- Shows current fresh listings by default.
- Optional investigation mode includes historical removed listings and stale upstream feed sources.
- Supports automatic checks every 4, 6, 8, 12 or 24 hours.
- Uses DirectAdmin admin notifications when new active listings are found.
- Does not modify firewall rules and does not block traffic.

## Install

Build the package:

```sh
./tools/build.sh
```

Upload `dist/sernate_firehol_blocklist_check.tar.gz` in DirectAdmin:

1. Log in as admin.
2. Open Plugin Manager.
3. Add/upload the tar.gz package.
4. Select install after upload.
5. Open **Sernate FireHOL Blocklist Check** from the admin plugin menu.

DirectAdmin plugin packages use a `plugin.conf` file and executable user level entry points. This package includes the expected `admin`, `reseller`, `user`, `hooks`, `images` and `scripts` directories.

## Updates

DirectAdmin supports plugin updates through `update_url` and `version_url` in `plugin.conf`. These are intentionally empty until the public GitHub release URL exists.

When the GitHub repository is public, set:

```ini
update_url=https://github.com/sernate/sernate-firehol-blocklist-check/releases/latest/download/sernate_firehol_blocklist_check.tar.gz
version_url=https://github.com/sernate/sernate-firehol-blocklist-check/releases/latest/download/version.txt
```

## API

- Base URL: https://blocklist.sernate.com
- Health check: https://blocklist.sernate.com/health
- API documentation: https://blocklist.sernate.com/docs
- OpenAPI schema: https://blocklist.sernate.com/openapi.json

The plugin uses `POST /search` with comma-separated IPv4 addresses. Public search defaults to current hits from fresh feeds only. Historical and stale-feed results are opt-in.

## Status Definitions

- **Clean:** No public server IPs were found in current indexed security blocklists.
- **Listed:** One or more public server IPs are currently present in indexed security feeds.
- **History Only:** The IP was previously listed in one or more feeds, but is no longer currently present.
- **Stale Source:** The upstream source feed is older than the configured freshness threshold.
- **API Unavailable:** The Sernate Blocklist API is temporarily unavailable or overloaded. The previous successful result may still be shown in the plugin.

## What This Plugin Does Not Do

- It does not automatically block IP addresses.
- It does not modify CSF or firewall rules.
- It does not replace traditional mail blacklist monitoring systems.
- It does not directly monitor Gmail, Microsoft or mailbox-provider deliverability systems.
- It does not guarantee email deliverability.
- It does not decide whether an IP is "bad"; it shows where the IP appears in the indexed lists.
- It does not manage or remove listings from external blocklists.

If removal is required, contact the relevant upstream feed maintainer or provider.
