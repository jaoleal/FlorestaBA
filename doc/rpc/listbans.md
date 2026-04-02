# `listbans`

Return all currently active IP address bans.

## Usage

### Synopsis

```
floresta-cli listbans
```

### Examples

```bash
floresta-cli listbans
```

## Arguments

None.

## Returns

### Ok Response

A JSON array of ban entry objects. Each object contains:

- `address` - (string) The banned IP address.
- `ban_created` - (numeric) Unix timestamp when the ban was created.
- `banned_until` - (numeric) Unix timestamp when the ban expires.

Returns an empty array `[]` if there are no active bans.

### Error Response

- `Node` — failed to communicate with the node.

## Notes

- Only non-expired bans are returned. Expired bans are cleaned up automatically.
- Use `setban` to add or remove individual bans, or `clearbans` to remove all bans at once.
