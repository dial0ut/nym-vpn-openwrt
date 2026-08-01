# Quick Start

## 1. Import your account

Your account is a 24-word recovery phrase from the [Nym wallet](https://nymtech.net/).

=== "LuCI"

    Open **NymVPN**, expand the **Account** card, paste the phrase, **Login**.

=== "CLI"

    ```bash
    nym-vpnc account set "your twenty four word mnemonic phrase here"
    ```

## 2. Connect

=== "LuCI"

    Hit **Connect**. The status ring pulses while connecting and turns green once the tunnel is up.

=== "CLI"

    ```bash
    nym-vpnc connect-v2
    nym-vpnc status
    ```

First connect takes a few seconds longer than later ones — the daemon has to fetch the gateway
directory before it can pick a pair.

## 3. Verify

From any LAN device:

```bash
curl ifconfig.me
```

The address you get back should be the exit gateway's, not your ISP's.

## Pick a gateway

Gateways are auto-selected by default. To pin an exit country:

=== "LuCI"

    Choose entry and exit countries in the **Gateway** card.

=== "CLI"

    ```bash
    nym-vpnc gateway set --exit-country CH
    ```

## Next

- [CLI Reference](../guide/cli.md) — every `nym-vpnc` subcommand
- [Split Tunneling](../guide/split-tunneling.md) — send specific devices around the VPN
- [Troubleshooting](../troubleshooting.md) — when the above doesn't happen
