# `reconsiderblock`

Removes the invalid state from a previously invalidated block.

## Usage

### Synopsis

floresta-cli reconsiderblock <blockhash>

### Examples

```bash
floresta-cli reconsiderblock 00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91
```

## Arguments

- `blockhash` - (string, required) The hash of the block to reconsider, hex-encoded.

## Returns

### Ok Response

`null` on success.

## Notes

- Only blocks previously invalidated via `invalidateblock` can be reconsidered
- Blocks that failed consensus validation cannot be reconsidered
- Descendants that were marked invalid due to the target block are also restored
- After restoration, chain selection is re-evaluated and a reorg may occur if the reconsidered branch has more cumulative work
