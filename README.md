# Wallpad Fee Monitor

Home Assistant add-on for reading Kocom wallpad management-fee packets through a Mango/OpenWrt bridge.

The add-on connects to Mango by SSH, runs `tcpdump` on the wallpad network, parses fee-query responses from `10.254.254.1:15000`, and publishes Home Assistant MQTT sensors.

## Current Status

This is an MVP built from captured traffic. It is read-only: it does not send packets to the apartment network.
The parser currently supports the observed management-fee records that include month markers like `2026-04-00 00:00` followed by five little-endian amount fields.

## Install

1. Push this repository to GitHub.
2. In Home Assistant, go to **Settings > Add-ons > Add-on Store > Repositories**.
3. Add the GitHub repository URL.
4. Install **Wallpad Fee Monitor**.
5. Fill in the add-on options and start it.

Mango/OpenWrt must have `tcpdump` installed:

```sh
opkg update
opkg install tcpdump
```

## Add-on Options

- `mango_host`: Mango/OpenWrt management IP, for example `192.168.0.16`
- `mango_user`: usually `root`
- `mango_password`: OpenWrt SSH password
- `mango_interface`: usually `br-lan`
- `wallpad_ip`: usually `10.109.35.41`
- `server_ip`: observed fee server, usually `10.254.254.1`
- `server_port`: observed service port, usually `15000`
- `mqtt_host`: MQTT broker, for example `core-mosquitto`
- `mqtt_username` / `mqtt_password`: broker credentials if required

## Sensors

The add-on publishes MQTT discovery entities such as:

- `sensor.wallpad_fee_current_total`
- `sensor.wallpad_fee_current_common`
- `sensor.wallpad_fee_current_electricity`
- `sensor.wallpad_fee_current_water`
- `sensor.wallpad_fee_current_heating`
- `sensor.wallpad_fee_current_etc`

It also publishes previous-month and before-previous-month values when present in the captured packets.

## Notes

The wallpad must refresh the fee screen for new packets to appear. The add-on only observes packets and republishes parsed values.

## Optional Active Query

By default, the add-on waits for the wallpad fee screen to refresh. You can enable an experimental active query that sends captured fee-query packet bytes through Mango once per interval.

Options:

- `active_query_enabled`: set to `true` to enable active refresh.
- `active_query_interval_hours`: default `24`.
- `active_query_startup_delay_seconds`: delay before the first query after add-on start.
- `active_query_packets`: comma-separated or newline-separated hex payloads captured from wallpad fee-query requests.

This is read-only in intent, but it still sends a query packet to the apartment server. Keep it disabled unless you have captured and verified the request packet for your wallpad.

If no MQTT entities appear, check:

- The add-on log for SSH or MQTT connection errors.
- Mango can reach the wallpad network.
- The wallpad fee screen was refreshed while the add-on was running.
