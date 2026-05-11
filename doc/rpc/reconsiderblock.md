# `reconsiderblock`

Removes the invalid state from a previously invalidated block, undoing the effect of `invalidateblock`. All descendants that were automatically marked invalid are also reconsidered. If the reconsidered chain has more accumulated work than the current best chain, the tip switches back to it.

## Usage

### Synopsis

```bash
floresta-cli reconsiderblock <blockhash>
```

### Examples

```bash
# Reconsider a previously invalidated block
floresta-cli reconsiderblock "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f9a68c5"
```

## Arguments

`blockhash` - (string, required) The hash of the block to reconsider, in hexadecimal format (64 characters).

## Returns

### Ok Response

Returns `null` on success.

### Error Enum `CommandError`

* `JsonRpcError::BlockNotFound` - If the specified block hash is not found in the blockchain or the reconsideration fails.

## Notes

- Only blocks invalidated via `invalidateblock` (user-invalidated) can be reconsidered. Blocks that failed consensus validation cannot be reconsidered.
- Reconsidered blocks are restored to `HeadersOnly` status and require re-validation by the network layer.
- If the reconsidered chain has less work than the current best chain, the blocks are stored as an alternative fork.
- This is the inverse operation of `invalidateblock`.
