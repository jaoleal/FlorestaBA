// SPDX-License-Identifier: MIT OR Apache-2.0

//! Unit tests for the block download and processing pipeline.
//!
//! These tests drive the node methods directly, without running its event loop: blocks are
//! received via `request_block_proof` and processed via `process_pending_blocks`, the same
//! sequence the event loop performs.
//!
//! The mutation tests cover both paths a mutated block can take: sync blocks are caught by
//! the structural checks in `connect_block`, while user-requested blocks are caught before
//! being handed to the user, banning the responsible peer in both cases.

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
    use crate::p2p_wire::error::WireError;
    use crate::p2p_wire::tests::utils::PEER_TEST;
    use crate::p2p_wire::tests::utils::mutated_block_h7;
    use crate::p2p_wire::tests::utils::register_test_peer;
    use crate::p2p_wire::tests::utils::setup_unit_node;
    use crate::p2p_wire::tests::utils::signet_blocks;
    use crate::p2p_wire::tests::utils::signet_headers;
    use crate::p2p_wire::tests::utils::witness_mutated_block_h7;

    const NUM_HEADERS: usize = 7;

    /// A backup peer registered by tests that exercise the user request retry
    const PEER_ALT: u32 = 1;

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
    async fn test_mutated_merkle_root_bans_peer_and_allows_retry() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();
        let blocks = signet_blocks();

        // Connect blocks 1..=6 directly, so the mutated block at height 7 is the next one
        for header in headers.iter().skip(1).take(6) {
            let block = blocks.get(&header.block_hash()).unwrap();
            node.chain
                .connect_block(block, Proof::default(), &[])
                .unwrap();
        }

        // The header is valid; only the transaction data is mutated
        let mutated = mutated_block_h7();
        let block_hash = mutated.block_hash();
        assert_eq!(block_hash, headers[7].block_hash());
        assert!(!mutated.check_merkle_root());

        node.request_block_proof(mutated, PEER_TEST).unwrap();
        let err = node.process_pending_blocks().unwrap_err();

        // `connect_block` catches the mutation and the block peer is banned
        assert!(matches!(err, WireError::PeerMisbehaving));
        assert_eq!(
            node.peers.get(&PEER_TEST).unwrap().state,
            PeerStatus::Banned
        );

        // The chain neither connected nor invalidated the block, as the original
        // txdata for this header may be valid
        assert_eq!(node.chain.get_validation_index().unwrap(), 6);
        assert_eq!(node.chain.get_best_block().unwrap().0, 7);

        // The mutated block was dropped, so it can be re-requested from another peer
        assert!(!node.blocks.contains_key(&block_hash));
        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::Blocks(block_hash))
        );
    }

    #[tokio::test]
    async fn test_mutated_witness_commitment_bans_peer_and_allows_retry() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        let headers = signet_headers();
        let blocks = signet_blocks();

        // Connect blocks 1..=6 directly, so the mutated block at height 7 is the next one
        for header in headers.iter().skip(1).take(6) {
            let block = blocks.get(&header.block_hash()).unwrap();
            node.chain
                .connect_block(block, Proof::default(), &[])
                .unwrap();
        }

        // The merkle root matches, so only the witness commitment is invalid
        let mutated = witness_mutated_block_h7();
        let block_hash = mutated.block_hash();
        assert!(mutated.check_merkle_root());
        assert!(!mutated.check_witness_commitment());

        node.request_block_proof(mutated, PEER_TEST).unwrap();
        let err = node.process_pending_blocks().unwrap_err();

        // `connect_block` catches the mutation and the block peer is banned
        assert!(matches!(err, WireError::PeerMisbehaving));
        assert_eq!(
            node.peers.get(&PEER_TEST).unwrap().state,
            PeerStatus::Banned
        );

        // The chain neither connected nor invalidated the block, and the mutated block
        // was dropped, so it can be re-requested from another peer
        assert_eq!(node.chain.get_validation_index().unwrap(), 6);
        assert_eq!(node.chain.get_best_block().unwrap().0, 7);
        assert!(!node.blocks.contains_key(&block_hash));
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

    /// Asserts the outcome of handing a mutated block to an open user request, with a backup
    /// peer available: the sender is banned first, and then the user request is reassigned
    /// and re-sent to the backup peer, without ever touching the sync-path state.
    fn assert_mutated_user_block_retried(mutated: bitcoin::Block) {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);
        register_test_peer(&mut node, PEER_ALT);

        let block_hash = mutated.block_hash();

        let (tx, _rx) = oneshot::channel();
        node.inflight_user_requests.insert(
            UserRequest::Block(block_hash),
            (PEER_TEST, Instant::now(), tx),
        );

        node.request_block_proof(mutated, PEER_TEST).unwrap();

        // The mutated block is never handed to the user: the peer is banned first, so the
        // retry can only pick the backup peer
        assert_eq!(
            node.peers.get(&PEER_TEST).unwrap().state,
            PeerStatus::Banned
        );

        // The user request stays open, now assigned to the backup peer
        let entry = node
            .inflight_user_requests
            .get(&UserRequest::Block(block_hash))
            .unwrap();
        assert_eq!(entry.0, PEER_ALT);

        // The retry is a user request, not a sync-path one, and the block isn't kept
        assert!(
            !node
                .inflight
                .contains_key(&InflightRequests::Blocks(block_hash))
        );
        assert!(!node.blocks.contains_key(&block_hash));
    }

    #[tokio::test]
    async fn test_mutated_user_requested_block_bans_and_retries() {
        assert_mutated_user_block_retried(mutated_block_h7());
    }

    #[tokio::test]
    async fn test_witness_mutated_user_requested_block_bans_and_retries() {
        // The merkle root matches, so only the witness commitment is invalid
        let mutated = witness_mutated_block_h7();
        assert!(mutated.check_merkle_root());
        assert!(!mutated.check_witness_commitment());

        assert_mutated_user_block_retried(mutated);
    }

    #[tokio::test]
    async fn test_duplicate_sibling_user_requested_block_bans_and_retries() {
        // A minimal transaction whose txid is unique per lock time
        let dummy_tx = |lock_time| bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(lock_time),
            input: Vec::new(),
            output: Vec::new(),
        };

        // A fabricated block whose header commits to three transactions
        let txdata: Vec<_> = (0..3).map(dummy_tx).collect();
        let mut mutated = bitcoin::Block {
            header: signet_headers()[7],
            txdata,
        };
        mutated.header.merkle_root = mutated.compute_merkle_root().unwrap();
        let block_hash = mutated.block_hash();

        // CVE-2012-2459: duplicating the last transaction keeps the same merkle root, so the
        // mutated txdata still matches the requested hash for `Block::check_merkle_root`.
        // Only recomputing the block hash from the ground up catches it.
        mutated.txdata.push(mutated.txdata[2].clone());
        assert_eq!(mutated.block_hash(), block_hash);
        assert!(mutated.check_merkle_root());
        assert!(mutated.check_witness_commitment());

        assert_mutated_user_block_retried(mutated);
    }

    #[tokio::test]
    async fn test_mutated_user_requested_block_without_backup_peer_drops_request() {
        let mut node = setup_unit_node(test_datadir(), NUM_HEADERS);

        let mutated = mutated_block_h7();
        let block_hash = mutated.block_hash();

        let (tx, rx) = oneshot::channel();
        node.inflight_user_requests.insert(
            UserRequest::Block(block_hash),
            (PEER_TEST, Instant::now(), tx),
        );

        node.request_block_proof(mutated, PEER_TEST).unwrap();

        // With no other peer to retry with, the request is dropped: the requester gets an
        // error instead of the mutated block, like a user request that finds no peer
        assert_eq!(
            node.peers.get(&PEER_TEST).unwrap().state,
            PeerStatus::Banned
        );
        assert!(node.inflight_user_requests.is_empty());
        assert!(rx.await.is_err());
    }
}
