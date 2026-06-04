# SPDX-License-Identifier: MIT OR Apache-2.0

"""
submitheader.py

Test the `submitheader` RPC on florestad.

We mine a block on bitcoind to obtain a valid header, then start florestad in
isolation and exercise submitheader:
  - reject invalid hex
  - reject truncated (non-80-byte) data
  - accept a valid header and advance the tip to height 1
  - accept a duplicate submission idempotently
"""

import pytest
from requests.exceptions import HTTPError
from test_framework.bitcoin import BlockHeader
from test_framework.node import NodeType


@pytest.mark.rpc
def test_submitheader_errors(node_manager, setup_logging):
    """Test that submitheader rejects invalid inputs."""
    log = setup_logging

    # Create and start bitcoind, mine 1 block, grab its raw header
    bitcoind = node_manager.add_node_default_args(variant=NodeType.BITCOIND)
    node_manager.run_node(bitcoind)

    log.info("Mining 1 block with bitcoind")
    bitcoind.rpc.generate_block(1)

    block_hash = bitcoind.rpc.get_blockhash(1)
    raw_block_hex = bitcoind.rpc.get_block(block_hash, 0)

    # First 160 hex chars = 80-byte block header
    header_hex = raw_block_hex[:160]

    log.info("Stopping bitcoind")
    bitcoind.stop()

    # Start florestad in isolation
    florestad = node_manager.add_node_default_args(variant=NodeType.FLORESTAD)
    node_manager.run_node(florestad)

    info_before = florestad.rpc.get_blockchain_info()
    assert info_before["height"] == 0

    # --- Error case 1: invalid hex ---
    log.info("Submitting invalid hex string")
    with pytest.raises(HTTPError):
        florestad.rpc.submit_header("zzzz_not_hex")

    # --- Error case 2: valid hex but wrong length (not 80 bytes) ---
    log.info("Submitting truncated header (too short)")
    with pytest.raises(HTTPError):
        florestad.rpc.submit_header(header_hex[:80])

    # Tip should not have changed after error cases
    info_after_errors = florestad.rpc.get_blockchain_info()
    assert info_after_errors["height"] == 0


@pytest.mark.rpc
def test_submitheader_valid(node_manager, setup_logging):
    """Test that submitheader accepts a valid header and advances the tip."""
    log = setup_logging

    # Create and start bitcoind, mine 1 block, grab its raw header
    bitcoind = node_manager.add_node_default_args(variant=NodeType.BITCOIND)
    node_manager.run_node(bitcoind)

    log.info("Mining 1 block with bitcoind")
    bitcoind.rpc.generate_block(1)

    block_hash = bitcoind.rpc.get_blockhash(1)
    raw_block_hex = bitcoind.rpc.get_block(block_hash, 0)

    # First 160 hex chars = 80-byte block header
    header_hex = raw_block_hex[:160]

    log.info("Stopping bitcoind")
    bitcoind.stop()

    # Start florestad in isolation
    florestad = node_manager.add_node_default_args(variant=NodeType.FLORESTAD)
    node_manager.run_node(florestad)

    # --- Happy path: valid header ---
    log.info("Submitting valid header for block %s", block_hash)
    florestad.rpc.submit_header(header_hex)

    info_after = florestad.rpc.get_blockchain_info()
    assert info_after["height"] == 1
    assert info_after["best_block"] == block_hash

    # --- Submitting the same header again should succeed (idempotent) ---
    log.info("Submitting the same header again (duplicate)")
    florestad.rpc.submit_header(header_hex)

    info_dup = florestad.rpc.get_blockchain_info()
    assert info_dup["height"] == 1
    assert info_dup["best_block"] == block_hash
