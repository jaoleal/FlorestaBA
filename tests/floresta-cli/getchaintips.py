# SPDX-License-Identifier: MIT OR Apache-2.0

"""
getchaintips.py

Test the `getchaintips` RPC by comparing florestad output against bitcoind.

Scenarios covered:
  A) Only genesis block exists — single active tip at height 0
  B) Synced a 10-block chain — single active tip at the chain height
"""

import time

import pytest

MINE_BLOCKS = 10
TIMEOUT_SECONDS = 20

VALID_STATUSES = {"active", "valid-fork", "headers-only", "invalid"}


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
