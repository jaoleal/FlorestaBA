# `invalidateblock`

Permanently marks a block as invalid, as if it violated a consensus rule.

## Usage

### Synopsis

floresta-cli invalidateblock <blockhash>

### Examples

```bash
floresta-cli invalidateblock 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91
```

## Arguments

- `blockhash` - (string, required) The hash of the block to mark as invalid, hex-encoded.

## Returns

### Ok Response

`null` on success.

## Notes

- All descendants of the invalidated block are also marked as invalid
- The chain tip rolls back to the parent of the invalidated block
- Use `reconsiderblock` to reverse the effect of this command
- The genesis block cannot be invalidated
