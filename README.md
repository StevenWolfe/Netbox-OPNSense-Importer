# OPNsense Sync Script for NetBox

This script synchronizes network configuration from an OPNsense firewall into NetBox. It is designed to run as a **NetBox Custom Script**.

## Features

1.  **Interface Sync**: Imports all interfaces (LAN, WAN, VLANs, WireGuard, etc.) from OPNsense.
2.  **IP Address Sync**: Assigns the correct IP addresses and subnets to those interfaces.
3.  **ARP Discovery**: Fetches the ARP table from OPNsense and automatically assigns IP addresses to **other** devices/VMs in NetBox based on their MAC address.

## Installation

1.  Copy `opnsense_sync.py` to your NetBox scripts directory (usually `/opt/netbox/netbox/scripts/`).
2.  Ensure the file is readable by the NetBox user.
3.  Restart the NetBox RQ worker (or the entire NetBox service) to pick up the new script.
    ```bash
    sudo systemctl restart netbox
    # OR
    sudo systemctl restart netbox-rq
    ```

## Usage

1.  Log in to NetBox.
2.  Navigate to **Customization** > **Scripts**.
3.  Click on **OPNsense Sync**.
4.  Fill in the configuration form and click **Run Script**.

## Configuration: VM vs. Device

The script asks: **"Is this a Virtual Machine?"**

*   **CHECKED (Default):** Use this if your OPNsense is running as a VM (e.g., on Proxmox).
    *   The script will look for an existing **Virtual Machine** in NetBox with the name you provided.
    *   *Tip:* If you are using the Proxmox Import Plugin, use the exact name of the VM as it appears in Proxmox. The script will attach the OPNsense interfaces and IPs to that existing VM.
*   **UNCHECKED:** Use this if your OPNsense is a physical hardware appliance.
    *   The script will look for a **Device** in NetBox.
    *   If it doesn't exist, it will create a new Device (Manufacturer: OPNsense, Type: OPNsense VM/Appliance).

## How to Create OPNsense API Keys

To allow NetBox to talk to OPNsense, you need an API Key and Secret.

1.  Log in to your OPNsense web interface.
2.  Go to **System** > **Access** > **Users**.
3.  Click the **+** button to create a new user (e.g., `netbox-sync`), or edit an existing user.
4.  Click the **🎟️** button to generate a new key.
5.  A file will automatically download.
    *   This file contains the **key** and **secret**. Keep these safe!
6.  **Permissions:**
    *   Click the **pencil icon** (Edit) on the user again.
    *   Scroll to **Effective Privileges** (or Group Memberships if using groups) and grant:
        *   `Status: Interfaces` — required for interface/IP/MAC sync on OPNsense 23.1+ (backs `api/interfaces/overview/*`, the same endpoint the "Interfaces > Overview" page uses).
        *   `Diagnostics: Logs: Firewall: Live View` — required to resolve interface descriptions (backs `api/diagnostics/interface/get_interface_names`). This is an OPNsense naming quirk, not a typo: as of 25.7 that endpoint isn't covered by any privilege whose name mentions "interfaces"; verify it directly in **Effective Privileges** if descriptions come back blank.
        *   `Diagnostics: ARP Table` — required for ARP table sync (backs `api/diagnostics/interface/get_arp` and `search_arp`).
        *   `VPN: WireGuard: Configuration` (or `VPN: WireGuard: Status`) — optional, only if syncing WireGuard tunnels.
    *   You should **not** need `All Pages`. The one exception is documented below.

### A note on OPNsense 25.7+ and legacy camelCase API URLs

OPNsense 25.7 ("Visionary Viper") re-registered its default ACL patterns against
snake_case API URLs (e.g. `get_arp` instead of `getArp`). The old camelCase URLs
still route to the same controller code, but are no longer reliably covered by
narrow privilege grants — see [opnsense/core#9093](https://github.com/opnsense/core/issues/9093)
and [opnsense/core#7256](https://github.com/opnsense/core/issues/7256), both
still open/closed-not-planned upstream. This script tries the current snake_case
endpoint first and automatically falls back to the legacy camelCase name, so it
works against both pre- and post-25.7 installs without configuration.

One endpoint has no narrow-privilege path at all: `get_interface_config` /
`getInterfaceConfig` is not covered by any ACL pattern in stock OPNsense, at any
privilege short of `All Pages`. This script no longer depends on it for normal
operation — interface/IP/MAC data now comes from the `Status: Interfaces`-scoped
Overview API instead — but it remains as a last-resort fallback for OPNsense
installs older than 23.1 (which predate the Overview API). If your run log shows
it being used, either upgrade OPNsense or grant `All Pages` to the API user.

## Troubleshooting

*   **"Virtual Machine not found"**: Ensure the name in the script form matches the VM name in NetBox exactly.
*   **SSL Errors**: If using self-signed certificates on OPNsense, uncheck the "Verify SSL" box in the script form.
*   **Interfaces sync but have no IP/MAC data**: Check the script's run log for `log_warning` entries — as of this release, every non-200 response from an OPNsense API call is logged with the URL and status code. A 403 almost always means a missing privilege; see the permissions list above.
