// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unit tests for the block download and processing pipeline.
//!
//! These tests drive the node methods directly, without running its event loop: blocks are
//! received via `request_block_proof` and processed via `process_pending_blocks`, the same
//! sequence the event loop performs.

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use floresta_chain::pruned_utreexo::BlockchainInterface;
    use floresta_chain::pruned_utreexo::UpdatableChainstate;
    use rustreexo::proof::Proof;
    use tokio::sync::oneshot;

    use crate::node::InflightRequests;
    use crate::node::PeerStatus;
    use crate::node_handle::NodeResponse;
    use crate::node_handle::UserRequest;
    use crate::p2p_wire::block_proof::UtreexoProof;
    use crate::p2p_wire::tests::utils::PEER_TEST;
    use crate::p2p_wire::tests::utils::setup_unit_node;
    use crate::p2p_wire::tests::utils::signet_blocks;
    use crate::p2p_wire::tests::utils::signet_headers;

    const NUM_HEADERS: usize = 7;

    fn test_datadir() -> String {
        format!("./tmp-db/{}.blocks_test", rand::random::<u32>())
    }

    #[tokio::test]
    async fn test_valid_blocks_advance_the_tip() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();
        let mut blocks = signet_blocks();

        // Receive and process each block in order, as the node event loop would
        for header in headers.iter().skip(1).take(NUM_HEADERS) {
            let block = blocks.remove(&header.block_hash()).unwrap();

            node.request_block_proof(block, PEER_TEST).unwrap();
            node.process_pending_blocks().unwrap();
        }

        assert_eq!(node.chain.get_validation_index().unwrap(), 7);
        assert!(node.blocks.is_empty());

        // The peer isn't punished
        let peer = node.peers.get(&PEER_TEST).unwrap();
        assert_eq!(peer.state, PeerStatus::Ready);
        assert_eq!(peer.banscore, 0);
    }

    #[tokio::test]
    async fn test_received_block_is_stored_until_processable() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();

        // The block at height 2 can't be processed while block 1 is missing
        let block = signet_blocks().remove(&headers[2].block_hash()).unwrap();
        let block_hash = block.block_hash();

        node.inflight.insert(
            InflightRequests::Blocks(block_hash),
            (PEER_TEST, Instant::now()),
        );

        node.request_block_proof(block, PEER_TEST).unwrap();
        node.process_pending_blocks().unwrap();

        // The inflight request was consumed and the block is stored, ready to be processed
        // once block 1 arrives (coinbase-only blocks don't need utreexo data)
        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::Blocks(block_hash))
        );
        let inflight_block = node.blocks.get(&block_hash).unwrap();
        assert!(inflight_block.aux_data.is_some());
        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::UtreexoProof(block_hash))
        );

        // Nothing was connected
        assert_eq!(node.chain.get_validation_index().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_bogus_proof_for_empty_block_is_ignored() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();
        let blocks = signet_blocks();

        // Connect blocks 1..=6 directly, so the block at height 7 is the next one
        for header in headers.iter().skip(1).take(6) {
            let block = blocks.get(&header.block_hash()).unwrap();
            node.chain
                .connect_block(block, Proof::default(), &[])
                .unwrap();
        }

        let block = blocks.get(&headers[7].block_hash()).unwrap().clone();
        let block_hash = block.block_hash();

        node.request_block_proof(block, PEER_TEST).unwrap();

        // Attach a bogus proof, which targets a deletion but provides no leaf data
        let uproof = UtreexoProof {
            block_hash,
            leaf_data: Vec::new(),
            targets: vec![0],
            proof_hashes: Vec::new(),
        };
        node.attach_proof(uproof, PEER_TEST).unwrap();

        // A coinbase-only block spends nothing, so there are no deletions to authenticate
        // and the proof is entirely ignored: the block still connects and no peer is punished
        node.process_pending_blocks().unwrap();

        assert_eq!(node.chain.get_validation_index().unwrap(), 7);
        assert!(node.blocks.is_empty());
        assert_eq!(node.peers.get(&PEER_TEST).unwrap().state, PeerStatus::Ready);
    }

    #[tokio::test]
    async fn test_user_requested_block_is_replied_and_not_processed() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();

        let block = signet_blocks().remove(&headers[1].block_hash()).unwrap();
        let block_hash = block.block_hash();

        let (tx, rx) = oneshot::channel();
        node.inflight_user_requests.insert(
            UserRequest::Block(block_hash),
            (PEER_TEST, Instant::now(), tx),
        );

        node.request_block_proof(block, PEER_TEST).unwrap();

        // The user gets the block
        let response = rx.await.unwrap();
        match response {
            NodeResponse::Block(Some(b)) => assert_eq!(b.block_hash(), block_hash),
            _ => panic!("expected NodeResponse::Block(Some(_))"),
        }

        // The request is consumed, and the block is neither kept for processing nor
        // has a proof requested for it
        assert!(
            !node
                .inflight_user_requests
                .contains_key(&UserRequest::Block(block_hash))
        );
        assert!(!node.blocks.contains_key(&block_hash));
        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::UtreexoProof(block_hash))
        );

        // The peer isn't punished
        let peer = node.peers.get(&PEER_TEST).unwrap();
        assert_eq!(peer.state, PeerStatus::Ready);
        assert_eq!(peer.banscore, 0);
    }
}
