# SPDX-License-Identifier: MIT OR Apache-2.0

"""
gettxout.py

This functional test cli utility to interact with a Floresta node with `gettxout` command.
"""

import pytest
from test_framework.util import compare_fields, wait_until

# How many blocks we mine that Floresta can accept as headers, but never validate.
UNVALIDATED_BLOCKS = 5


# pylint: disable=too-many-locals
@pytest.mark.rpc
def test_get_txout(setup_logging, florestad_bitcoind_utreexod_with_chain, node_manager):
    """
    Test the `gettxout` command for a specific transaction output.
    """
    log = setup_logging
    blocks = 10
    florestad, bitcoind, _ = florestad_bitcoind_utreexod_with_chain(blocks)

    log.info("Waiting for Floresta and Bitcoind to sync with Utreexod...")
    node_manager.wait_for_sync_nodes()

    # `bestblock` and `confirmations` are relative to the chain tip, so both
    # nodes must agree on it for the comparison below to hold. Nothing is
    # mined while the test runs, which keeps that true for the whole loop.
    log.info("Comparing gettxout results between Floresta and Bitcoind...")
    assert (
        florestad.rpc.get_bestblockhash() == bitcoind.rpc.get_bestblockhash()
    ), "Nodes disagree on the chain tip."

    for height in range(2, blocks):
        block_hash = florestad.rpc.get_blockhash(height)
        block = florestad.rpc.get_block(block_hash)
        log.info(f"Comparing gettxout results for {height} block {block_hash}...")

        for tx in block["tx"]:
            txout_floresta = florestad.rpc.get_txout(tx, vout=0, include_mempool=False)

            assert txout_floresta is not None, f"Txout for tx {tx} is None in Floresta."

            txout_bitcoind = bitcoind.rpc.get_txout(tx, vout=0, include_mempool=False)
            assert txout_bitcoind is not None, f"Txout for tx {tx} is None in Bitcoind."

            compare_fields(txout_floresta, txout_bitcoind)


@pytest.mark.rpc
def test_get_txout_counts_from_the_validated_tip(
    setup_logging, florestad_bitcoind_utreexod_with_chain, node_manager
):
    """
    Check that `bestblock` and `confirmations` follow the last validated block.

    An utxo only exists as far as we validated, so both fields must be relative
    to that, the same way Bitcoin Core reports them against its chainstate tip.
    Floresta accepts headers before having the blocks they describe, and it
    needs the utreexo proof shipped with a block to validate it. Dropping the
    only utreexo peer and mining on bitcoind leaves it with headers it can
    never validate, which is the only moment the two tips differ.
    """
    log = setup_logging
    blocks = 20
    florestad, bitcoind, utreexod = florestad_bitcoind_utreexod_with_chain(blocks)

    log.info("Waiting for Floresta and Bitcoind to sync with Utreexod...")
    node_manager.wait_for_sync_nodes()

    height = blocks // 2
    txid = florestad.rpc.get_block(florestad.rpc.get_blockhash(height))["tx"][0]

    log.info("Stopping the only utreexo peer, so nothing else can be validated...")
    utreexod.stop()

    log.info(f"Mining {UNVALIDATED_BLOCKS} blocks Floresta can't get a proof for...")
    bitcoind.rpc.generate_block(UNVALIDATED_BLOCKS)

    headers = blocks + UNVALIDATED_BLOCKS
    wait_until(
        lambda: florestad.rpc.get_blockchain_info()["headers"] == headers,
        error_msg=f"Floresta didn't accept the {UNVALIDATED_BLOCKS} new headers",
    )

    chain_info = florestad.rpc.get_blockchain_info()
    assert (
        chain_info["blocks"] == blocks
    ), "Floresta validated blocks it can't have a proof for."

    log.info(f"Floresta is at header {headers}, but validated only up to {blocks}...")
    txout = florestad.rpc.get_txout(txid, vout=0, include_mempool=False)
    assert txout is not None, f"Txout for tx {txid} is None in Floresta."

    assert txout["bestblock"] == florestad.rpc.get_blockhash(blocks)
    assert txout["confirmations"] == blocks - height + 1
