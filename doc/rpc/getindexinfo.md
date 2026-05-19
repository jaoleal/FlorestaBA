# `getindexinfo`

Returns the status of one or all available indices currently running on the node.

## Usage

### Synopsis

```bash
floresta-cli getindexinfo [<index_name>]
```

### Examples

```bash
# Get status of all available indices
floresta-cli getindexinfo

# Get status of the block filter index specifically
floresta-cli getindexinfo block_filter
```

## Arguments

| Name         | Type   | Required | Description                                                                                       |
| ------------ | ------ | -------- | ------------------------------------------------------------------------------------------------- |
| `index_name` | string | No       | Filter results for an index with a specific name. If omitted, all available indices are returned. |

## Returns

### Ok Response

Returns a JSON object where each key is an index name and each value is an `IndexState` object with a `state` field describing the lifecycle of that service. All known indices are always present in the response — disabled ones are reported as `deactivated`. Keys are returned in alphabetical order.

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

If `index_name` is specified but does not match any known index, an empty object `{}` is returned.

### Error Enum

- `JsonRpcError::Chain` - If there is an error querying the chain height.

## Available Indices

| Name           | Description                                                                                                            | Always present |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- | -------------- |
| `block_filter` | BIP157/BIP158 compact block filter index. Reported as `deactivated` when block filters are disabled (`--no-cfilters`). | Yes            |
| `backfill`     | Historical block validation after assume-utreexo IBD. Reported as `deactivated` when backfill is not enabled.          | Yes            |

## Notes

- This RPC method is modeled after Bitcoin Core's `getindexinfo`. Bitcoin Core tracks different indices (txindex, coinstatsindex, blockfilterindex) that do not apply to Floresta's architecture. Unlike Bitcoin Core, Floresta always reports all known indices — disabled ones appear as `deactivated` rather than being omitted.
- The `block_filter` index is considered synced when the filter height has caught up with the chain tip height. If compact block filters are not enabled, it is reported as `deactivated`.
- The `backfill` index tracks the progress of historical block validation that runs after an assume-utreexo initial sync. It is considered synced once all assumed blocks have been fully validated. If backfill is not enabled, it is reported as `deactivated`.
