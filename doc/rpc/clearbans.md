# `clearbans`

Remove all active IP address bans.

## Usage

### Synopsis

```
floresta-cli clearbans
```

### Examples

```bash
floresta-cli clearbans
```

## Arguments

None.

## Returns

### Ok Response

`null` — all bans were cleared successfully.

### Error Response

- `Node` — failed to communicate with the node.

## Notes

- This clears every active ban regardless of expiry time or how it was created.
- Use `listbans` to inspect bans before clearing, and `setban` to manage individual bans.
