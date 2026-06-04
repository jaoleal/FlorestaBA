# `submitheader`

Decodes the given hex data as a block header and submits it as a candidate
chain tip if valid.

## Usage

### Synopsis

floresta-cli submitheader <hexdata>

### Examples

```bash
floresta-cli submitheader 0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f...
```

## Arguments

- `hexdata` - (string, required) The 80-byte block header encoded as a 160-character hex string.

## Returns

### Ok Response

`null` on success.

## Notes

- The header's `prev_blockhash` must reference a block already known to the node
- The header is stored as `headers-only` until the full block is validated
- Submitting the same header twice is idempotent
