# SPDX-License-Identifier: MIT OR Apache-2.0

"""
reconsiderblock.py

Test the `reconsiderblock` RPC on florestad.

We mine blocks via utreexod, sync them to florestad, invalidate a block, then
call `reconsiderblock` to undo the invalidation. We verify that florestad
re-syncs back to the original chain height after the wire layer re-validates
the reconsidered blocks.
"""

import time

import pytest

MINE_BLOCKS = 10
TIMEOUT_SECONDS = 30


def wait_for_sync(log, florestad, utreexod, timeout=TIMEOUT_SECONDS):
    """Poll until florestad and utreexod report the same block count."""
    end = time.time() + timeout
    while time.time() < end:
        florestad_block = florestad.rpc.get_block_count()
        utreexod_block = utreexod.rpc.get_block_count()
        if florestad_block == utreexod_block:
            log.info(f"Nodes are in sync: {florestad_block} blocks")
            return
        time.sleep(1)

    pytest.fail("Florestad did not sync with Utreexod in time")


@pytest.mark.rpc
def test_reconsiderblock(setup_logging, florestad_utreexod):
    """Test that reconsiderblock undoes invalidation and restores the chain."""
    log = setup_logging
    florestad, utreexod = florestad_utreexod

    # Mine 10 blocks on utreexod and sync to florestad
    log.info("Mining %d blocks with utreexod", MINE_BLOCKS)
    utreexod.rpc.generate(MINE_BLOCKS)
    wait_for_sync(log, florestad, utreexod)

    # Verify both nodes are synced
    floresta_info = florestad.rpc.get_blockchain_info()
    utreexo_info = utreexod.rpc.get_blockchain_info()
    assert floresta_info["height"] == utreexo_info["blocks"]
    assert floresta_info["best_block"] == utreexo_info["bestblockhash"]

    # Get the hash of block 5 and its parent (block 4)
    hash_at_5 = florestad.rpc.get_blockhash(5)
    hash_at_4 = florestad.rpc.get_blockhash(4)

    # Invalidate block 5 on florestad
    log.info("Invalidating block at height 5: %s", hash_at_5)
    florestad.rpc.invalidate_block(hash_at_5)

    # Verify florestad's tip rolled back to block 4
    new_info = florestad.rpc.get_blockchain_info()
    assert new_info["height"] == 4
    assert new_info["best_block"] == hash_at_4

    # Now reconsider block 5
    log.info("Reconsidering block at height 5: %s", hash_at_5)
    florestad.rpc.reconsider_block(hash_at_5)

    # After reconsideration, florestad should re-sync back to height 10
    # once the wire layer re-validates the reconsidered blocks
    log.info("Waiting for florestad to re-sync after reconsideration")
    wait_for_sync(log, florestad, utreexod, timeout=120)

    # Verify florestad is back in sync
    floresta_info = florestad.rpc.get_blockchain_info()
    utreexo_info = utreexod.rpc.get_blockchain_info()
    assert floresta_info["height"] == utreexo_info["blocks"]
    assert floresta_info["best_block"] == utreexo_info["bestblockhash"]

    # Verify the accumulators match
    floresta_roots = florestad.rpc.get_roots()
    utreexo_roots = utreexod.rpc.get_utreexo_roots(utreexo_info["bestblockhash"])
    assert floresta_roots == utreexo_roots["roots"]
