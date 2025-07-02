//! Nym Network - P2P networking layer with privacy-preserving communication
//!
//! This module provides:
//! - P2P networking with libp2p
//! - Node discovery and handshake protocols
//! - Message routing with privacy protection
//! - Network synchronization mechanisms
//! - QuID-based authentication for network operations

pub mod error;
pub mod peer;
pub mod protocol;
pub mod discovery;
pub mod routing;
pub mod sync;
pub mod node;
pub mod message;
pub mod p2p_simple;
pub mod integration;

pub use error::{NetworkError, NetworkResult};
pub use peer::{PeerId, PeerInfo, PeerManager};
pub use protocol::{NymProtocol, HandshakeProtocol};
pub use discovery::{NodeDiscovery, DiscoveryConfig};
pub use routing::{MessageRouter, RoutingTable};
pub use sync::{SyncManager, SyncProtocol};
pub use node::{NetworkNode, NodeConfig};
pub use message::{
    NetworkMessage, MessageType, MessagePayload, HandshakePayload, 
    DiscoveryPayload, PeerInfoPayload, PrivacyRoutedPayload, MessageBuilder, MessageHandler
};
pub use p2p_simple::{SimpleP2PNetwork, SimpleP2PConfig, SimpleP2PEvent};
pub use integration::{EnhancedNetworkNode, EnhancedNodeConfig, create_enhanced_config};
