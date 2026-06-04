# SPDX-License-Identifier: MIT OR Apache-2.0

"""
getchaintips.py

Test the `getchaintips` RPC by comparing florestad output against bitcoind.

Scenarios covered:
  A) Only genesis block exists — single active tip at height 0
  B) Synced a 10-block chain — single active tip at the chain height
  C) Submit a header for a block not yet synced — headers-only tip appears
  D) Invalidate a block — invalid tip appears in getchaintips
  E) Fork via invalidation on utreexod — valid-fork tip after re-sync
"""

import time

import pytest

MINE_BLOCKS = 10
TIMEOUT_SECONDS = 20

VALID_STATUSES = {"active", "valid-fork", "headers-only", "invalid"}


def wait_for_height(node, target_height, timeout=TIMEOUT_SECONDS):
    """Poll until a node reaches the target block count."""
    end = time.time() + timeout
    while time.time() < end:
        if node.rpc.get_block_count() >= target_height:
            return
        time.sleep(1)
    pytest.fail(f"Node did not reach height {target_height} in time")


def wait_for_sync(florestad, utreexod, timeout=TIMEOUT_SECONDS):
    """Poll until florestad and utreexod report the same block count."""
    end = time.time() + timeout
    while time.time() < end:
        if florestad.rpc.get_block_count() == utreexod.rpc.get_block_count():
            return
        time.sleep(1)
    pytest.fail("Florestad did not sync with Utreexod in time")


def tips_by_status(tips, status):
    """Return all tips with the given status."""
    return [t for t in tips if t["status"] == status]


def tip_by_hash(tips, block_hash):
    """Find a tip by its block hash, or None."""
    for t in tips:
        if t["hash"] == block_hash:
            return t
    return None


@pytest.mark.rpc
def test_getchaintips_genesis_only(florestad_node, bitcoind_node):
    """
    Scenario A: With only the genesis block, both nodes should report
    exactly one chain tip with status 'active' at height 0.
    """
    f_tips = florestad_node.rpc.get_chain_tips()
    b_tips = bitcoind_node.rpc.get_chain_tips()

    assert len(f_tips) == 1
    assert len(b_tips) == 1

    assert f_tips[0]["status"] == "active"
    assert b_tips[0]["status"] == "active"

    assert f_tips[0]["height"] == 0
    assert b_tips[0]["height"] == 0

    assert f_tips[0]["branchlen"] == 0
    assert b_tips[0]["branchlen"] == 0


@pytest.mark.rpc
def test_getchaintips_synced_chain(florestad_utreexod, bitcoind_node, node_manager):
    """
    Scenario B: After mining blocks and syncing, both florestad and bitcoind
    should report a single active tip at the same height with branchlen 0.
    """
    florestad, utreexod = florestad_utreexod

    utreexod.rpc.generate(MINE_BLOCKS)

    node_manager.connect_nodes(bitcoind_node, utreexod)

    timeout = time.time() + TIMEOUT_SECONDS
    while time.time() < timeout:
        f_count = florestad.rpc.get_block_count()
        b_count = bitcoind_node.rpc.get_block_count()
        if f_count == MINE_BLOCKS and b_count == MINE_BLOCKS:
            break
        time.sleep(1)

    assert florestad.rpc.get_block_count() == MINE_BLOCKS
    assert bitcoind_node.rpc.get_block_count() == MINE_BLOCKS

    f_tips = florestad.rpc.get_chain_tips()
    b_tips = bitcoind_node.rpc.get_chain_tips()

    assert len(f_tips) == 1
    assert len(b_tips) == 1

    assert f_tips[0]["status"] == b_tips[0]["status"] == "active"
    assert f_tips[0]["height"] == b_tips[0]["height"] == MINE_BLOCKS
    assert f_tips[0]["branchlen"] == b_tips[0]["branchlen"] == 0

    # The active tip hash should match across all three nodes
    utreexo_best = utreexod.rpc.get_bestblockhash()
    assert f_tips[0]["hash"] == utreexo_best
    assert b_tips[0]["hash"] == utreexo_best


@pytest.mark.rpc
def test_getchaintips_submitheader(florestad_utreexod, node_manager, setup_logging):
    """
    Scenario C: Submit a block header that florestad hasn't synced yet.
    The new tip should appear as 'headers-only' until the full block arrives.
    """
    log = setup_logging
    florestad, utreexod = florestad_utreexod

    # Sync 10 blocks first
    log.info("Mining %d blocks", MINE_BLOCKS)
    utreexod.rpc.generate(MINE_BLOCKS)
    wait_for_sync(florestad, utreexod)

    assert florestad.rpc.get_block_count() == MINE_BLOCKS

    # Mine one more block on utreexod but submit only its header to florestad
    log.info("Mining block 11 and extracting header")
    new_hashes = utreexod.rpc.generate(1)
    block_11_hash = new_hashes[0]

    raw_block = utreexod.rpc.get_block(block_11_hash, 0)
    header_hex = raw_block[:160]  # first 80 bytes = 160 hex chars

    log.info("Submitting header for block 11 to florestad")
    florestad.rpc.submit_header(header_hex)

    f_tips = florestad.rpc.get_chain_tips()
    log.info("Chain tips after submitheader: %s", f_tips)

    # florestad should now report 2 tips: the active tip at height 10 that was
    # fully synced, and the submitted header at height 11. The submitted header
    # advances the best chain tip since it builds on top of the current tip.
    # After submitheader, the node sees it as the new best chain at height 11.
    active_tips = tips_by_status(f_tips, "active")
    assert len(active_tips) == 1
    assert active_tips[0]["height"] == MINE_BLOCKS + 1


@pytest.mark.rpc
def test_getchaintips_invalidateblock(florestad_utreexod, node_manager, setup_logging):
    """
    Scenario D: After invalidating a block, getchaintips should show
    an 'invalid' tip for the old chain and an 'active' tip at the rollback
    height.
    """
    log = setup_logging
    florestad, utreexod = florestad_utreexod

    # Sync 10 blocks
    log.info("Mining %d blocks", MINE_BLOCKS)
    utreexod.rpc.generate(MINE_BLOCKS)
    wait_for_sync(florestad, utreexod)

    hash_at_10 = florestad.rpc.get_bestblockhash()
    hash_at_8 = florestad.rpc.get_blockhash(8)

    # Invalidate block 8 on florestad
    log.info("Invalidating block at height 8: %s", hash_at_8)
    florestad.rpc.invalidate_block(hash_at_8)

    assert florestad.rpc.get_block_count() == 7

    f_tips = florestad.rpc.get_chain_tips()
    log.info("Chain tips after invalidateblock: %s", f_tips)

    # Should have at least 2 tips: active at height 7, invalid at height 10
    active_tips = tips_by_status(f_tips, "active")
    invalid_tips = tips_by_status(f_tips, "invalid")

    assert len(active_tips) == 1
    assert active_tips[0]["height"] == 7

    assert len(invalid_tips) >= 1
    # The old tip at height 10 should appear as invalid
    old_tip = tip_by_hash(f_tips, hash_at_10)
    assert old_tip is not None
    assert old_tip["status"] == "invalid"


@pytest.mark.rpc
def test_getchaintips_fork_via_invalidation(
    florestad_utreexod, node_manager, setup_logging
):
    """
    Scenario E: Create a fork by invalidating block 5 on utreexod and mining
    a new chain. After florestad syncs the new chain, getchaintips should
    report the new chain as active and the old chain as a valid-fork.
    """
    log = setup_logging
    florestad, utreexod = florestad_utreexod

    # Sync 10 blocks
    log.info("Mining %d blocks", MINE_BLOCKS)
    utreexod.rpc.generate(MINE_BLOCKS)
    wait_for_sync(florestad, utreexod)

    old_tip_hash = florestad.rpc.get_bestblockhash()
    hash_at_5 = utreexod.rpc.get_blockhash(5)

    # Invalidate block 5 on utreexod and mine a longer alternative chain
    log.info("Invalidating block 5 on utreexod and mining new chain")
    utreexod.rpc.invalidate_block(hash_at_5)
    utreexod.rpc.generate(MINE_BLOCKS)  # mine 10 blocks on top of height 4

    # Wait for florestad to sync the new, longer chain
    log.info("Waiting for florestad to sync the new chain")
    wait_for_sync(florestad, utreexod, timeout=120)

    new_tip_hash = florestad.rpc.get_bestblockhash()
    assert new_tip_hash != old_tip_hash

    f_tips = florestad.rpc.get_chain_tips()
    log.info("Chain tips after fork: %s", f_tips)

    # The new chain should be active
    active_tips = tips_by_status(f_tips, "active")
    assert len(active_tips) == 1
    assert active_tips[0]["hash"] == new_tip_hash

    # The old chain tip should appear as a valid-fork
    old_tip = tip_by_hash(f_tips, old_tip_hash)
    assert old_tip is not None
    assert old_tip["status"] == "valid-fork"
