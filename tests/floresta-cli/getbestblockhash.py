# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Test the floresta's `getbestblockhash` after mining a few block with
utreexod. Then, assert that the command returns the same hash of
`best_block` or `bestblockhash` given in `getblockchaininfo` of floresta
and utreexod, respectively.
"""

import pytest


@pytest.mark.rpc
def test_get_best_block_hash(node_manager, florestad_utreexod):
    """
    Test checks if Floresta can synchronize with the blockchain
    and retrieve the hash of the last block via the getbestblockhash RPC.
    """

    florestad, utreexod = florestad_utreexod

    floresta_best_block = florestad.rpc.get_bestblockhash()
    utreexo_best_block = utreexod.rpc.get_blockchain_info()["bestblockhash"]
    assert floresta_best_block == utreexo_best_block

    utreexod.rpc.generate(10)

    node_manager.wait_for_sync_nodes(is_finished_ibd=False)

    utreexo_chain = utreexod.rpc.get_blockchain_info()
    floresta_best_block = florestad.rpc.get_bestblockhash()

    assert floresta_best_block == utreexo_chain["bestblockhash"]


@pytest.mark.rpc
def test_tip_rpcs_report_the_validated_tip(
    setup_logging, florestad_with_unvalidated_headers
):
    """
    Check that everything reporting "the best block" follows the validated chain.

    Bitcoin Core answers `getbestblockhash`, `getblockcount` and every
    `getblockchaininfo` field but `headers` from its chainstate tip, never from
    a header whose block it couldn't verify.
    """
    log = setup_logging
    florestad, _, blocks, headers = florestad_with_unvalidated_headers()
    validated_hash = florestad.rpc.get_blockhash(blocks)

    log.info(f"Floresta is at header {headers}, but validated only up to {blocks}...")
    assert florestad.rpc.get_bestblockhash() == validated_hash
    assert florestad.rpc.get_block_count() == blocks

    chain_info = florestad.rpc.get_blockchain_info()
    assert chain_info["headers"] == headers
    assert chain_info["blocks"] == blocks
    assert chain_info["bestblockhash"] == validated_hash

    # The block a tip describes and the values derived from it must be the same
    # one, so these come from the validated header rather than from our best.
    validated_header = florestad.rpc.get_blockheader(validated_hash)
    assert chain_info["time"] == validated_header["time"]
    assert chain_info["mediantime"] == validated_header["mediantime"]
    assert chain_info["bits"] == validated_header["bits"]
    assert chain_info["chainwork"] == validated_header["chainwork"]
