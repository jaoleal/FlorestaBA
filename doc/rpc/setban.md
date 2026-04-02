# `setban`

Add or remove an IP address from the ban list.

## Usage

### Synopsis

```
floresta-cli setban <ip> <command> [bantime] [absolute]
```

### Examples

```bash
# Ban an IP for the default duration (24 hours)
floresta-cli setban 192.168.0.1 add

# Ban an IP for 3600 seconds
floresta-cli setban 192.168.0.1 add 3600

# Ban an IP until a specific Unix timestamp
floresta-cli setban 192.168.0.1 add 1800000000 true

# Remove a ban
floresta-cli setban 192.168.0.1 remove
```

## Arguments

- `ip` - (string, required) The IPv4 or IPv6 address to ban or unban.

- `command` - (string, required) Either `"add"` to add a ban or `"remove"` to remove an existing ban.

- `bantime` - (numeric, optional, default=0) When `command` is `"add"`:
  - If `absolute` is `false` (default): duration of the ban in seconds. `0` uses the default of 86400 seconds (24 hours).
  - If `absolute` is `true`: an absolute Unix timestamp indicating when the ban expires.

- `absolute` - (boolean, optional, default=false) If `true`, `bantime` is interpreted as an absolute Unix timestamp instead of a duration.

## Returns

### Ok Response

`null` — the command succeeded.

### Error Response

- `InvalidAddress` — the provided `ip` is not a valid IP address.
- `InvalidSetBanCommand` — `command` is not `"add"` or `"remove"`.
- `Node` — failed to communicate with the node.

## Notes

- Banning an IP immediately disconnects any currently connected peer with that address.
- Expired bans are cleaned up automatically on the next query.
- Use `listbans` to inspect active bans and `clearbans` to remove all of them at once.
