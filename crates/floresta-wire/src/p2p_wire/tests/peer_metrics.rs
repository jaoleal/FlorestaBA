// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tests for the Prometheus peer gauges written by `update_peer_metrics`.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;

    use bitcoin::Network;
    use bitcoin::p2p::ServiceFlags;
    use floresta_chain::ChainState;
    use floresta_chain::FlatChainStore;
    use floresta_common::Ema;
    use floresta_common::service_flags;
    use floresta_metrics::get_metrics;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tokio::sync::mpsc::unbounded_channel;

    use crate::node::ConnectionKind;
    use crate::node::LocalPeerView;
    use crate::node::NodeRequest;
    use crate::node::PeerStatus;
    use crate::node::UtreexoNode;
    use crate::node::running_ctx::RunningNode;
    use crate::node::sync_ctx::SyncNode;
    use crate::node_context::NodeContext;
    use crate::p2p_wire::peer::Version;
    use crate::p2p_wire::tests::utils::SetupNodeArgs;
    use crate::p2p_wire::tests::utils::setup_node;
    use crate::p2p_wire::transport::TransportProtocol;

    type TestNode<T> = UtreexoNode<Arc<ChainState<FlatChainStore>>, T>;

    fn utreexo_services() -> ServiceFlags {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS | service_flags::UTREEXO.into()
    }

    fn plain_services() -> ServiceFlags {
        ServiceFlags::NETWORK | ServiceFlags::WITNESS
    }

    /// Builds a node with no peers, so every peer is added by `handle_peer_ready` alone.
    fn metrics_node<T: 'static + Default + NodeContext>() -> TestNode<T> {
        let args = SetupNodeArgs::new(
            Vec::new(),
            false,
            Network::Regtest,
            format!("./tmp-db/{}.peer_metrics", rand::random::<u32>()),
            0,
        );

        setup_node::<T>(args)
    }

    /// Registers a peer as `Ready` and returns its request receiver, which the
    /// caller must keep alive: `handle_peer_ready` sends over this channel.
    fn insert_peer<T: 'static + Default + NodeContext>(
        node: &mut TestNode<T>,
        peer_id: u32,
        kind: ConnectionKind,
        services: ServiceFlags,
    ) -> UnboundedReceiver<NodeRequest> {
        let (sender, receiver) = unbounded_channel();

        node.peers.insert(
            peer_id,
            LocalPeerView {
                message_times: Ema::with_half_life_50(),
                state: PeerStatus::Ready,
                channel: sender,
                services,
                user_agent: "/test:0.0.0/".to_string(),
                address: format!("192.0.2.{}:8333", peer_id + 1).parse().unwrap(),
                _last_message: Instant::now(),
                kind,
                height: 0,
                time_offset: 0,
                banscore: 0,
                transport_protocol: TransportProtocol::V2,
            },
        );

        receiver
    }

    fn peer_version(peer_id: u32, kind: ConnectionKind, services: ServiceFlags) -> Version {
        Version {
            user_agent: "/test:0.0.0/".to_string(),
            protocol_version: 70016,
            blocks: 0,
            id: peer_id,
            address_id: peer_id as usize,
            services,
            time_offset: 0,
            kind,
            transport_protocol: TransportProtocol::V2,
        }
    }

    fn peer_count() -> f64 {
        get_metrics().peer_count.get()
    }

    fn utreexo_peer_count() -> f64 {
        get_metrics().utreexo_peer_count.get()
    }

    /// Drives one node context through the peer lifecycle, asserting the gauges
    /// after every transition.
    fn assert_gauges_follow_peers<T: 'static + Default + NodeContext>(context: &str) {
        let mut node = metrics_node::<T>();

        let utreexo_peer = 0;
        let plain_peer = 1;
        let feeler_peer = 2;

        // Keep the receivers alive for the whole scenario, otherwise sending a
        // request to a peer fails and `handle_peer_ready` returns an error.
        let _utreexo_rx = insert_peer(
            &mut node,
            utreexo_peer,
            ConnectionKind::OutboundFullRelay(service_flags::UTREEXO.into()),
            utreexo_services(),
        );
        let _plain_rx = insert_peer(
            &mut node,
            plain_peer,
            ConnectionKind::OutboundFullRelay(ServiceFlags::NETWORK),
            plain_services(),
        );
        let _feeler_rx = insert_peer(
            &mut node,
            feeler_peer,
            ConnectionKind::Feeler,
            utreexo_services(),
        );

        node.handle_peer_ready(
            utreexo_peer,
            peer_version(
                utreexo_peer,
                ConnectionKind::OutboundFullRelay(service_flags::UTREEXO.into()),
                utreexo_services(),
            ),
        )
        .expect("utreexo peer should become ready");

        assert_eq!(
            utreexo_peer_count(),
            1.0,
            "{context}: a ready utreexo peer must be counted"
        );
        assert_eq!(peer_count(), 1.0, "{context}: the peer must be counted");

        // A peer without the utreexo service flag moves `peer_count` only.
        node.handle_peer_ready(
            plain_peer,
            peer_version(
                plain_peer,
                ConnectionKind::OutboundFullRelay(ServiceFlags::NETWORK),
                plain_services(),
            ),
        )
        .expect("non-utreexo peer should become ready");

        assert_eq!(
            utreexo_peer_count(),
            1.0,
            "{context}: a peer without the utreexo flag must not be counted"
        );
        assert_eq!(peer_count(), 2.0, "{context}: both peers must be counted");

        // A feeler is disconnected right after the handshake, so it must never
        // show up in either gauge, even though it advertises utreexo.
        node.handle_peer_ready(
            feeler_peer,
            peer_version(feeler_peer, ConnectionKind::Feeler, utreexo_services()),
        )
        .expect("feeler peer should become ready");

        assert_eq!(
            utreexo_peer_count(),
            1.0,
            "{context}: a feeler must not be counted as a utreexo peer"
        );
        assert_eq!(peer_count(), 2.0, "{context}: a feeler must not be counted");

        node.handle_disconnection(utreexo_peer, utreexo_peer as usize)
            .expect("the utreexo peer should disconnect");

        assert_eq!(
            utreexo_peer_count(),
            0.0,
            "{context}: the gauge must drop when the utreexo peer disconnects"
        );
        assert_eq!(peer_count(), 1.0, "{context}: only one peer is left");

        node.handle_disconnection(plain_peer, plain_peer as usize)
            .expect("the remaining peer should disconnect");

        assert_eq!(utreexo_peer_count(), 0.0, "{context}: no peers are left");
        assert_eq!(peer_count(), 0.0, "{context}: no peers are left");
    }

    #[tokio::test]
    // The metrics registry is a process-wide singleton, so every context is
    // checked in a single test to keep the expected gauge values deterministic.
    async fn utreexo_peer_count_follows_ready_and_disconnected_peers() {
        assert_gauges_follow_peers::<RunningNode>("RunningNode");
        assert_gauges_follow_peers::<SyncNode>("SyncNode");
    }
}
