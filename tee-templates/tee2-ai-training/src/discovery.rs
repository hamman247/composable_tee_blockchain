//! Worker discovery via on-chain registry and gossip protocol.
//!
//! Workers discover the TEE-2 coordinator through two layers:
//! 1. On-chain: query TEERegistry.sol for TEE-2's api_endpoints
//! 2. Gossip: exchange coordinator addresses with known peers

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// A discovered coordinator endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CoordinatorEndpoint {
    /// gRPC or WebSocket address (e.g., "grpc://192.168.1.10:50052").
    pub address: String,
    /// Source of discovery.
    pub source: DiscoverySource,
    /// When this endpoint was last confirmed reachable.
    pub last_verified: Option<u64>,
}

/// How an endpoint was discovered.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoverySource {
    /// Read from on-chain TEERegistry.sol (highest trust).
    OnChain,
    /// Received via gossip from another peer.
    Gossip,
    /// Hardcoded bootstrap endpoint.
    Bootstrap,
    /// Manually configured.
    Manual,
}

/// Watches the on-chain TEERegistry for TEE-2 coordinator endpoints.
pub struct RegistryWatcher {
    /// JSON-RPC endpoint to query the chain.
    rpc_endpoint: String,
    /// TEE-2's on-chain tee_id to look up.
    tee_id_hex: String,
    /// Discovered endpoints.
    endpoints: HashSet<String>,
    /// Last time we polled the registry.
    last_poll: Instant,
    /// Polling interval.
    poll_interval: Duration,
}

impl RegistryWatcher {
    pub fn new(rpc_endpoint: &str, tee_id_hex: &str, poll_interval: Duration) -> Self {
        Self {
            rpc_endpoint: rpc_endpoint.to_string(),
            tee_id_hex: tee_id_hex.to_string(),
            endpoints: HashSet::new(),
            last_poll: Instant::now() - poll_interval, // Trigger immediate first poll
            poll_interval,
        }
    }

    /// Poll the on-chain registry for updated endpoints.
    /// In a real implementation, this would make an eth_call to TEERegistry.getTEE(teeId).
    /// Returns true if endpoints changed.
    pub fn poll(&mut self) -> bool {
        if self.last_poll.elapsed() < self.poll_interval {
            return false;
        }

        self.last_poll = Instant::now();

        // Simulator: In production, this would be:
        // 1. eth_call to TEERegistry.registrations(tee_id)
        // 2. Parse the TeeConfig.api_endpoints array
        // 3. Update self.endpoints
        //
        // For now, endpoints are set manually or via gossip.
        false
    }

    /// Manually set the coordinator endpoint (for simulator mode).
    pub fn set_endpoint(&mut self, addr: &str) {
        self.endpoints.insert(addr.to_string());
    }

    /// Get all known endpoints.
    pub fn endpoints(&self) -> Vec<String> {
        self.endpoints.iter().cloned().collect()
    }
}

/// Lightweight gossip-based endpoint discovery.
/// Workers exchange known coordinator addresses with peers.
pub struct GossipDiscovery {
    /// Known coordinator endpoints.
    known_endpoints: HashSet<String>,
    /// Known peer worker addresses (for gossip).
    known_peers: HashSet<String>,
    /// Bootstrap peers (hardcoded or from config).
    bootstrap_peers: Vec<String>,
}

impl GossipDiscovery {
    pub fn new(bootstrap_peers: Vec<String>) -> Self {
        Self {
            known_endpoints: HashSet::new(),
            known_peers: HashSet::new(),
            bootstrap_peers,
        }
    }

    /// Add a coordinator endpoint learned from gossip.
    pub fn add_endpoint(&mut self, addr: &str) {
        self.known_endpoints.insert(addr.to_string());
    }

    /// Add a peer worker address.
    pub fn add_peer(&mut self, peer: &str) {
        self.known_peers.insert(peer.to_string());
    }

    /// Get all known coordinator endpoints (from gossip + bootstrap).
    pub fn endpoints(&self) -> Vec<String> {
        self.known_endpoints.iter().cloned().collect()
    }

    /// Get peers to gossip with.
    pub fn gossip_targets(&self) -> Vec<String> {
        let mut targets: Vec<String> = self.known_peers.iter().cloned().collect();
        targets.extend(self.bootstrap_peers.iter().cloned());
        targets.dedup();
        targets
    }

    /// Create a gossip message to send to peers.
    pub fn create_gossip_message(&self) -> GossipMessage {
        GossipMessage {
            coordinator_endpoints: self.known_endpoints.iter().cloned().collect(),
            known_peers: self.known_peers.iter().cloned().collect(),
        }
    }

    /// Process a received gossip message.
    pub fn process_gossip(&mut self, msg: &GossipMessage) {
        for ep in &msg.coordinator_endpoints {
            self.known_endpoints.insert(ep.clone());
        }
        for peer in &msg.known_peers {
            self.known_peers.insert(peer.clone());
        }
    }
}

/// Gossip message exchanged between worker peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GossipMessage {
    pub coordinator_endpoints: Vec<String>,
    pub known_peers: Vec<String>,
}

/// Combined discovery service that merges on-chain and gossip sources.
pub struct DiscoveryService {
    pub registry: RegistryWatcher,
    pub gossip: GossipDiscovery,
}

impl DiscoveryService {
    pub fn new(
        rpc_endpoint: &str,
        tee_id_hex: &str,
        bootstrap_peers: Vec<String>,
    ) -> Self {
        Self {
            registry: RegistryWatcher::new(rpc_endpoint, tee_id_hex, Duration::from_secs(60)),
            gossip: GossipDiscovery::new(bootstrap_peers),
        }
    }

    /// Get the best known coordinator endpoint.
    /// Prefers on-chain (most trusted) → gossip → bootstrap.
    pub fn best_endpoint(&mut self) -> Option<String> {
        // Try on-chain first
        self.registry.poll();
        if let Some(ep) = self.registry.endpoints().into_iter().next() {
            return Some(ep);
        }
        // Fall back to gossip
        self.gossip.endpoints().into_iter().next()
    }

    /// Get all known endpoints from all sources.
    pub fn all_endpoints(&mut self) -> Vec<CoordinatorEndpoint> {
        self.registry.poll();
        let mut results = Vec::new();

        for ep in self.registry.endpoints() {
            results.push(CoordinatorEndpoint {
                address: ep,
                source: DiscoverySource::OnChain,
                last_verified: None,
            });
        }
        for ep in self.gossip.endpoints() {
            results.push(CoordinatorEndpoint {
                address: ep,
                source: DiscoverySource::Gossip,
                last_verified: None,
            });
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gossip_exchange() {
        let mut alice = GossipDiscovery::new(vec![]);
        let mut bob = GossipDiscovery::new(vec![]);

        alice.add_endpoint("grpc://coordinator:50052");
        alice.add_peer("bob:30303");

        let msg = alice.create_gossip_message();
        bob.process_gossip(&msg);

        assert!(bob.endpoints().contains(&"grpc://coordinator:50052".to_string()));
    }

    #[test]
    fn test_discovery_service_prefers_onchain() {
        let mut svc = DiscoveryService::new("http://localhost:8545", "0xabcd", vec![]);
        svc.registry.set_endpoint("grpc://onchain:50052");
        svc.gossip.add_endpoint("grpc://gossip:50052");

        let best = svc.best_endpoint().unwrap();
        assert_eq!(best, "grpc://onchain:50052");
    }
}
