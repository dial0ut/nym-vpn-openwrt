# Quick Start

Get connected in under 5 minutes after installation.

## 1. Import Your Account

Get your account mnemonic from the [Nym wallet](https://nymtech.net/) or existing setup, then import it:

=== "LuCI"

    1. Open your router's web interface
    2. Navigate to **NymVPN**
    3. Expand the **Account** card
    4. Paste your mnemonic and click **Save**

=== "CLI"

    ```bash
    nym-vpnc account set "your twenty four word mnemonic phrase here"
    ```

## 2. Connect

=== "LuCI"

    Click the **Connect** button on the NymVPN status page. The status ring will animate while connecting and turn green once the tunnel is established.

=== "CLI"

    ```bash
    nym-vpnc connect-v2
    ```

    Check status:

    ```bash
    nym-vpnc status
    ```

## 3. Verify

From any device on your LAN, check your public IP has changed:

```bash
curl ifconfig.me
```

The returned IP should belong to the exit gateway, not your ISP.

## Optional: Choose a Gateway

By default, NymVPN auto-selects gateways. To pick a specific exit country:

=== "LuCI"

    Use the **Gateway** card to select entry and exit countries from the dropdown.

=== "CLI"

    ```bash
    # Set exit country
    nym-vpnc gateway set --exit-country CH
    ```

## Optional: Enable LAN Policy

By default, all LAN clients are routed through NymVPN. To control which clients use the VPN:

=== "LuCI"

    Expand the **LAN Policy** card to configure per-client routing rules.

=== "CLI"

    ```bash
    # Allow LAN access while connected
    nym-vpnc lan set allow

    # Or block LAN access for isolation
    nym-vpnc lan set block
    ```

## Next Steps

- [CLI Reference](../guide/cli.md) — full command reference
- [Configuration](../guide/configuration.md) — UCI config options
- [Troubleshooting](../troubleshooting.md) — common issues and fixes
