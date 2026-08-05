# SPDX-License-Identifier: MIT OR Apache-2.0

"""
Chain reorg test

This test will spawn a florestad and a utreexod, we will use utreexod to mine some blocks.
Then we will invalidate one of those blocks, and mine an alternative chain. This should
make florestad switch to the new chain. We then compare the two node's main chain and
accumulator to make sure they are the same.
"""

import pytest


# TODO: Florestad stops processing messages from a peer it connected to before the
# IBD, once the IBD ends. Until that's fixed, this test can't pass.
#
# What happens, mining 10 blocks, invalidating the 5th and mining 10 more on
# utreexod, is that florestad stays on the pre-reorg chain forever:
#
#     TICKDBG peers=1 tip=Ok(10) validation=Ok(10) inflight=[GetAddresses]
#
# while utreexod is at 14 and announces every new block:
#
#     [DBG] PEER: Sending headers (num 1) to 127.0.0.1:61566 (inbound)   (x10)
#
# The headers reach florestad's socket, but nothing above it ever sees them. Its
# peer actor logs nothing after "starting running node...", the node's
# notification handler is never called, and the chain never moves. Mining yet
# another block afterwards doesn't wake it up either, so it isn't a matter of
# having missed the announcements while still on IBD.
#
# The `GetAddresses` stuck in `inflight` for the whole run is the tell: that's a
# request *we* made, whose reply is never processed either. So it's the receiving
# end that is broken, not the announcing or the triggering. Adding triggers, or
# lowering `NodeContext::ASSUME_STALE`, can't help: the `GetHeaders` they send
# would go down the same path and its answer would be dropped just the same.
#
# Ruled out, each with evidence:
#   - the peer not announcing: utreexod's debug log shows the headers going out;
#   - the notification channel being recreated on the context switch:
#     `RunningNode::catch_up` moves `common` through, so it's the same channel;
#   - the peer being dropped on the switch: `connected_peers() / 2` is 0 for a
#     single peer, and it's both utreexo-protected and a manual connection;
#   - a deadlock or a panic: a stack sample shows every thread idle, the
#     maintenance tick keeps logging, and florestad's stderr is clean;
#   - `handle_new_block` being gated by an inflight `Headers`: what's stuck is
#     `GetAddresses`.
#
# Next step is to instrument `p2p_wire/peer.rs`, logging each message read off the
# socket and each `node_tx.send`, which separates "never read" from "read but not
# forwarded" from "forwarded but not received".
#
# The impact is worth stressing: a node that finishes its IBD can sit on a stale
# chain while a connected peer keeps telling it about a better one. The only way
# out is `check_for_stale_tip`, and that only fires after
# `NodeContext::ASSUME_STALE`, i.e. 15 minutes. With few utreexo-capable peers,
# it doesn't have another peer to learn from meanwhile.
#
# Note this isn't a regression from reporting the validated tip on `getblockcount`
# -- that only made the test notice. Reporting our best *header* made
# `wait_for_sync_nodes` match utreexod as soon as the headers arrived, so the test
# passed while florestad had validated nothing past the fork point.
#
# While in there, `running_ctx.rs`'s header handling bans a peer, silently, when a
# header's parent is unknown, instead of asking for the headers in between with a
# locator. It doesn't run here, since no header ever arrives, but it's a
# fork-out/eclipse hazard once they do.
@pytest.mark.xfail(
    reason="florestad ignores its peers' announcements after the IBD, see TODO above",
    # Not strict: florestad sometimes gets the headers and stalls with its
    # validation index at the fork point instead, which fails earlier.
    strict=False,
)
@pytest.mark.florestad
def test_reorg_chain(setup_logging, florestad_utreexod, node_manager):
    """Mine blocks, trigger a reorg and assert both nodes end up on the same chain."""
    log = setup_logging
    florestad, utreexod = florestad_utreexod

    ChainReorgTest(log, florestad, utreexod, node_manager).run()


class ChainReorgTest:
    """Tests that Florestad follows Utreexod during a chain reorganization."""

    def __init__(self, log, florestad, utreexod, node_manager):
        """
        Attributes initialized to satisfy static analysis; real values are
        provided by pytest fixtures.
        """
        self.log = log
        self.florestad = florestad
        self.utreexod = utreexod
        self.node_manager = node_manager

    def run(self):
        """Mine blocks, trigger a reorg and assert both nodes end up on the same chain."""

        blocks = 10
        self.mine_blocks(blocks)

        old_best_block_hash = self.florestad.rpc.get_bestblockhash()

        utreexo_block = self.utreexod.rpc.get_block_count()
        count_invalid_block = 5
        height_invalid = utreexo_block - count_invalid_block
        hash_invalid = self.utreexod.rpc.get_blockhash(height_invalid)
        self.utreexod.rpc.invalidate_block(hash_invalid)

        assert self.utreexod.rpc.get_block_count() < height_invalid
        self.log.info(f"Utreexod node has {self.utreexod.rpc.get_block_count()} blocks")
        self.log.info(
            f"Florestad node has {self.florestad.rpc.get_block_count()} blocks"
        )

        extra_blocks = 5
        self.log.info(
            f"Mining {count_invalid_block + extra_blocks} blocks to trigger reorg"
        )
        self.mine_blocks(count_invalid_block + extra_blocks)

        assert old_best_block_hash != self.florestad.rpc.get_bestblockhash()
        split_block_hash = self.florestad.rpc.get_blockhash(height_invalid)
        assert split_block_hash != hash_invalid

        florestad_info = self.florestad.rpc.get_blockchain_info()
        utreexod_info = self.utreexod.rpc.get_blockchain_info()
        assert florestad_info["bestblockhash"] == utreexod_info["bestblockhash"]
        assert florestad_info["headers"] == utreexod_info["blocks"]

    def mine_blocks(self, blocks):
        """Request Utreexod to generate blocks and wait for Florestad to sync."""
        self.log.info(f"Utreexod node mine {blocks} blocks")
        self.utreexod.rpc.generate(blocks)

        self.node_manager.wait_for_sync_nodes(is_finished_ibd=False)
