# `getindexinfo`

Returns detailed information about floresta indices on running services.

## Usage

### Synopsis

```bash
floresta-cli getindexinfo <index_name> [verbosity]
```

### Examples

```bash
# Get minimal status of all available indices
floresta-cli getindexinfo

# Get detailed status of the block filter index specifically
floresta-cli getindexinfo blockfilterindex 1
```

## Arguments

- `index_name` (string, optional) Extract only the results for a specific index. If omitted, all available indices are returned. When `index_name` doesnt match an know index, `JsonRpcError::UnkownIndex` is returned.

## Available Indices

- `blockfilterindex` - BIP157/BIP158 compact block filter index.
- `backfillindex` - Validation of historical blocks after a complete assume-utreexo IBD.

## Returns

### Ok Response

Returns a JSON object where each key is an index name and each value is an `IndexState` object that should describe the status and usefull information about internal services on floresta. field describing the lifecycle of that service. All known indices are always present in the response — disabled ones are reported as `deactivated`. Keys are returned in alphabetical order.

Possible states:

| State         | Fields              | Description                                   |
| ------------- | ------------------- | --------------------------------------------- |
| `deactivated` | none                | The index is not enabled in this node config. |
| `to_start`    | none                | Registered but hasn't started processing.     |
| `ongoing`     | `best_block_height` | Actively syncing.                             |
| `done`        | `best_block_height` | Fully synced to the chain tip.                |
| `error`       | `message`           | An error occurred querying the index state.   |

```json
{
  "backfill": {
    "state": "deactivated"
  },
  "block_filter": {
    "state": "ongoing",
    "best_block_height": 450000
  }
}
```

### Error Enum

- `JsonRpcError::Chain` - If there is an error querying the chain height.

## Notes

- This RPC method is modeled after Bitcoin Core's `getindexinfo`. Bitcoin Core tracks indices given the background services that they offer such as `txindex`, `coinstatsindex` and `blockfilterindex`. But for Floresta, the only index they have in common is `blockfilterindex`. To address the same utility and purpose that `getindexinfo` have on Bitcoin Core, Floresta exposes indexes given the current services that the build offers.

- On stock verbosity, currently `0`, the info returned for each index is simplistic and should expose the name of the index, a boolean flag for completition and its height position in the canonical blockchain. Beyond verbosity levels, the index service is free to expose info about itself.

- Indexes arent always present, when theyre deactivate, they will be omitted or have a Deativated state, given the verbosity requested.

- During command execution and response wrapping, the responses are stored in a BTreeMap for deterministic ordering of indexes.
