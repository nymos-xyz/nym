use crate::{NetworkError, NetworkResult, PeerId, NetworkMessage, MessageType};
use nym_core::NymIdentity;
use nym_crypto::{Hash256, SecurityLevel};

use std::collections::{HashMap, HashSet};
use std::time::Duration;
use std::sync::Arc;

use libp2p::{
    gossipsub::{self, Gossipsub, GossipsubEvent, MessageAuthenticity, ValidationMode},
    kad::{Kademlia, KademliaEvent},
    identify::{Identify, IdentifyEvent},
    ping::{Ping, PingEvent},
    noise::NoiseConfig,
    tcp::TcpConfig,
    yamux::YamuxConfig,
    core::upgrade,
    identity::Keypair,
    multiaddr::Protocol,
    swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent},
    Multiaddr, PeerId as Libp2pPeerId, Swarm, Transport,
};

use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "NymNetworkEvent", event_process = false)]
pub struct NymNetworkBehaviour {
    pub gossipsub: Gossipsub,
    pub kademlia: Kademlia<MemoryStore>,
    pub identify: Identify,
    pub ping: Ping,
}

#[derive(Debug)]
pub enum NymNetworkEvent {
    Gossipsub(GossipsubEvent),
    Kademlia(KademliaEvent),
    Identify(IdentifyEvent),
    Ping(PingEvent),
}

impl From<GossipsubEvent> for NymNetworkEvent {
    fn from(event: GossipsubEvent) -> Self {
        NymNetworkEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for NymNetworkEvent {
    fn from(event: KademliaEvent) -> Self {
        NymNetworkEvent::Kademlia(event)
    }
}

impl From<IdentifyEvent> for NymNetworkEvent {
    fn from(event: IdentifyEvent) -> Self {
        NymNetworkEvent::Identify(event)
    }
}

impl From<PingEvent> for NymNetworkEvent {
    fn from(event: PingEvent) -> Self {
        NymNetworkEvent::Ping(event)
    }
}

#[derive(Debug, Clone)]
pub struct Libp2pNetworkConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<(Libp2pPeerId, Multiaddr)>,
    pub enable_gossipsub: bool,
    pub enable_kademlia: bool,
    pub gossipsub_topics: Vec<String>,
    pub max_peers: usize,
    pub connection_timeout: Duration,
}

impl Default for Libp2pNetworkConfig {
    fn default() -> Self {
        Self {
            listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
            bootstrap_peers: Vec::new(),
            enable_gossipsub: true,
            enable_kademlia: true,
            gossipsub_topics: vec!["nym-global".to_string()],
            max_peers: 100,
            connection_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Libp2pNetworkEvent {
    PeerConnected {
        peer_id: Libp2pPeerId,
        endpoint: Multiaddr,
    },
    PeerDisconnected {
        peer_id: Libp2pPeerId,
    },
    MessageReceived {
        from: Libp2pPeerId,
        topic: String,
        data: Vec<u8>,
    },
    PeerDiscovered {
        peer_id: Libp2pPeerId,
        addresses: Vec<Multiaddr>,
    },
    ConnectionError {
        peer_id: Option<Libp2pPeerId>,
        error: String,
    },
}

pub struct Libp2pNetwork {
    swarm: Swarm<NymNetworkBehaviour>,
    config: Libp2pNetworkConfig,
    local_peer_id: Libp2pPeerId,
    nym_identity: NymIdentity,
    event_sender: mpsc::UnboundedSender<Libp2pNetworkEvent>,
    connected_peers: Arc<RwLock<HashMap<Libp2pPeerId, PeerInfo>>>,
    subscribed_topics: Arc<RwLock<HashSet<gossipsub::IdentTopic>>>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: Libp2pPeerId,
    pub addresses: Vec<Multiaddr>,
    pub nym_identity: Option<NymIdentity>,
    pub last_seen: std::time::SystemTime,
    pub connection_established: std::time::SystemTime,
}

impl Libp2pNetwork {
    pub async fn new(
        config: Libp2pNetworkConfig,
        nym_identity: NymIdentity,
    ) -> NetworkResult<(Self, mpsc::UnboundedReceiver<Libp2pNetworkEvent>)> {
        info!("Initializing libp2p network with Nym identity integration");

        let keypair = Self::create_keypair_from_nym_identity(&nym_identity)?;
        let local_peer_id = Libp2pPeerId::from(keypair.public());

        let transport = TcpConfig::new()
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(keypair.clone()).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed();

        let mut behaviour = Self::create_network_behaviour(&config, &local_peer_id)?;

        let mut swarm = SwarmBuilder::new(transport, behaviour, local_peer_id)
            .executor(Box::new(|fut| {
                tokio::spawn(fut);
            }))
            .build();

        for addr in &config.listen_addresses {
            swarm.listen_on(addr.clone())
                .map_err(|e| NetworkError::ConnectionFailed {
                    reason: format!("Failed to listen on {}: {}", addr, e),
                })?;
        }

        let (event_sender, event_receiver) = mpsc::unbounded_channel();

        let network = Self {
            swarm,
            config,
            local_peer_id,
            nym_identity,
            event_sender,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            subscribed_topics: Arc::new(RwLock::new(HashSet::new())),
        };

        Ok((network, event_receiver))
    }

    fn create_keypair_from_nym_identity(nym_identity: &NymIdentity) -> NetworkResult<Keypair> {
        use libp2p::identity::ed25519;
        
        let secret_bytes = nym_identity.private_key_bytes();
        let mut key_bytes = [0u8; 32];
        
        if secret_bytes.len() >= 32 {
            key_bytes.copy_from_slice(&secret_bytes[..32]);
        } else {
            key_bytes[..secret_bytes.len()].copy_from_slice(&secret_bytes);
        }

        let secret_key = ed25519::SecretKey::from_bytes(key_bytes)
            .map_err(|e| NetworkError::CryptoError {
                reason: format!("Failed to create ed25519 secret key: {}", e),
            })?;

        let keypair = ed25519::Keypair::from(secret_key);
        Ok(Keypair::Ed25519(keypair))
    }

    fn create_network_behaviour(
        config: &Libp2pNetworkConfig,
        local_peer_id: &Libp2pPeerId,
    ) -> NetworkResult<NymNetworkBehaviour> {
        let gossipsub = if config.enable_gossipsub {
            let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10))
                .validation_mode(ValidationMode::Strict)
                .max_transmit_size(262144)
                .build()
                .map_err(|e| NetworkError::ConfigurationError {
                    reason: format!("Gossipsub config error: {}", e),
                })?;

            let mut gossipsub = Gossipsub::new(
                MessageAuthenticity::Signed(local_peer_id.clone()),
                gossipsub_config,
            ).map_err(|e| NetworkError::ConfigurationError {
                reason: format!("Failed to create Gossipsub: {}", e),
            })?;

            for topic_name in &config.gossipsub_topics {
                let topic = gossipsub::IdentTopic::new(topic_name);
                gossipsub.subscribe(&topic)
                    .map_err(|e| NetworkError::ConfigurationError {
                        reason: format!("Failed to subscribe to topic {}: {}", topic_name, e),
                    })?;
            }

            gossipsub
        } else {
            return Err(NetworkError::ConfigurationError {
                reason: "Gossipsub must be enabled".to_string(),
            });
        };

        let kademlia = if config.enable_kademlia {
            let store = MemoryStore::new(local_peer_id.clone());
            Kademlia::new(local_peer_id.clone(), store)
        } else {
            return Err(NetworkError::ConfigurationError {
                reason: "Kademlia must be enabled".to_string(),
            });
        };

        let identify = Identify::new(
            "/nym/1.0.0".to_string(),
            "nym-network".to_string(),
            libp2p::identity::Keypair::generate_ed25519().public(),
        );

        let ping = Ping::new(libp2p::ping::PingConfig::new());

        Ok(NymNetworkBehaviour {
            gossipsub,
            kademlia,
            identify,
            ping,
        })
    }

    pub async fn start(&mut self) -> NetworkResult<()> {
        info!("Starting libp2p network with QuID authentication");

        for (peer_id, addr) in &self.config.bootstrap_peers {
            self.swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
            info!("Added bootstrap peer: {} at {}", peer_id, addr);
        }

        if !self.config.bootstrap_peers.is_empty() {
            self.swarm.behaviour_mut().kademlia.bootstrap()
                .map_err(|e| NetworkError::ProtocolError {
                    reason: format!("Failed to bootstrap Kademlia: {}", e),
                })?;
        }

        Ok(())
    }

    pub async fn handle_swarm_event(&mut self, event: SwarmEvent<NymNetworkEvent>) -> NetworkResult<()> {
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                info!("Listening on: {}", address);
            }
            SwarmEvent::Behaviour(event) => {
                self.handle_behaviour_event(event).await?;
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } => {
                info!("Connection established with peer: {}", peer_id);
                
                let peer_info = PeerInfo {
                    peer_id,
                    addresses: vec![endpoint.get_remote_address().clone()],
                    nym_identity: None,
                    last_seen: std::time::SystemTime::now(),
                    connection_established: std::time::SystemTime::now(),
                };

                self.connected_peers.write().await.insert(peer_id, peer_info);

                let _ = self.event_sender.send(Libp2pNetworkEvent::PeerConnected {
                    peer_id,
                    endpoint: endpoint.get_remote_address().clone(),
                });
            }
            SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                info!("Connection closed with peer: {} (cause: {:?})", peer_id, cause);
                
                self.connected_peers.write().await.remove(&peer_id);

                let _ = self.event_sender.send(Libp2pNetworkEvent::PeerDisconnected { peer_id });
            }
            SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                warn!("Outgoing connection error to {:?}: {}", peer_id, error);
                
                let _ = self.event_sender.send(Libp2pNetworkEvent::ConnectionError {
                    peer_id,
                    error: error.to_string(),
                });
            }
            SwarmEvent::IncomingConnectionError { local_addr, send_back_addr, error } => {
                warn!("Incoming connection error from {} to {}: {}", send_back_addr, local_addr, error);
            }
            _ => {}
        }

        Ok(())
    }

    async fn handle_behaviour_event(&mut self, event: NymNetworkEvent) -> NetworkResult<()> {
        match event {
            NymNetworkEvent::Gossipsub(GossipsubEvent::Message {
                propagation_source,
                message_id: _,
                message,
            }) => {
                debug!("Received gossipsub message from: {}", propagation_source);
                
                let _ = self.event_sender.send(Libp2pNetworkEvent::MessageReceived {
                    from: propagation_source,
                    topic: message.topic.to_string(),
                    data: message.data,
                });
            }
            NymNetworkEvent::Kademlia(KademliaEvent::OutboundQueryCompleted { result, .. }) => {
                match result {
                    libp2p::kad::QueryResult::GetClosestPeers(Ok(ok)) => {
                        debug!("Kademlia found {} closest peers", ok.peers.len());
                        for peer in ok.peers {
                            self.swarm.behaviour_mut().kademlia.add_address(&peer, 
                                format!("/ip4/127.0.0.1/tcp/0/p2p/{}", peer).parse().unwrap());
                        }
                    }
                    libp2p::kad::QueryResult::Bootstrap(Ok(_)) => {
                        info!("Kademlia bootstrap completed successfully");
                    }
                    _ => {}
                }
            }
            NymNetworkEvent::Identify(IdentifyEvent::Received { peer_id, info }) => {
                debug!("Received identify info from: {}", peer_id);
                
                for addr in &info.listen_addrs {
                    self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                }

                let _ = self.event_sender.send(Libp2pNetworkEvent::PeerDiscovered {
                    peer_id,
                    addresses: info.listen_addrs,
                });
            }
            NymNetworkEvent::Ping(PingEvent { peer, result }) => {
                match result {
                    Ok(duration) => {
                        debug!("Ping to {} took: {:?}", peer, duration);
                        
                        if let Some(peer_info) = self.connected_peers.write().await.get_mut(&peer) {
                            peer_info.last_seen = std::time::SystemTime::now();
                        }
                    }
                    Err(e) => {
                        warn!("Ping to {} failed: {}", peer, e);
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    pub async fn publish_message(&mut self, topic: &str, data: Vec<u8>) -> NetworkResult<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)
            .map_err(|e| NetworkError::MessageSendError {
                reason: format!("Failed to publish message: {}", e),
            })?;

        Ok(())
    }

    pub async fn subscribe_to_topic(&mut self, topic: &str) -> NetworkResult<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)
            .map_err(|e| NetworkError::ProtocolError {
                reason: format!("Failed to subscribe to topic {}: {}", topic, e),
            })?;

        self.subscribed_topics.write().await.insert(topic);
        info!("Subscribed to topic: {}", topic);

        Ok(())
    }

    pub async fn connect_to_peer(&mut self, peer_id: Libp2pPeerId, addr: Multiaddr) -> NetworkResult<()> {
        self.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
        
        self.swarm.dial(addr.with(Protocol::P2p(peer_id.into())))
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to dial peer {}: {}", peer_id, e),
            })?;

        Ok(())
    }

    pub fn local_peer_id(&self) -> &Libp2pPeerId {
        &self.local_peer_id
    }

    pub async fn connected_peers(&self) -> Vec<Libp2pPeerId> {
        self.connected_peers.read().await.keys().cloned().collect()
    }

    pub async fn peer_count(&self) -> usize {
        self.connected_peers.read().await.len()
    }

    pub fn swarm_mut(&mut self) -> &mut Swarm<NymNetworkBehaviour> {
        &mut self.swarm
    }

    pub async fn send_nym_message(&mut self, target_peer: Libp2pPeerId, message: NetworkMessage) -> NetworkResult<()> {
        let message_data = bincode::serialize(&message)
            .map_err(|e| NetworkError::Serialization {
                reason: format!("Failed to serialize message: {}", e),
            })?;

        let signed_message = self.sign_message_with_nym_identity(&message_data)?;
        
        self.publish_message("nym-messages", signed_message).await
    }

    fn sign_message_with_nym_identity(&self, message_data: &[u8]) -> NetworkResult<Vec<u8>> {
        #[derive(Serialize)]
        struct SignedMessage {
            data: Vec<u8>,
            signature: Vec<u8>,
            sender_identity: NymIdentity,
        }

        let signature = self.nym_identity.sign_data(message_data)
            .map_err(|e| NetworkError::CryptoError {
                reason: format!("Failed to sign message: {}", e),
            })?;

        let signed_message = SignedMessage {
            data: message_data.to_vec(),
            signature,
            sender_identity: self.nym_identity.clone(),
        };

        bincode::serialize(&signed_message)
            .map_err(|e| NetworkError::Serialization {
                reason: format!("Failed to serialize signed message: {}", e),
            })
    }

    pub async fn authenticate_peer_with_quid(&mut self, peer_id: Libp2pPeerId) -> NetworkResult<bool> {
        info!("Authenticating peer {} using QuID", peer_id);

        let auth_challenge = self.create_auth_challenge();
        
        let challenge_message = NetworkMessage::new(
            MessageType::AuthChallenge,
            PeerId::from_libp2p_peer_id(&peer_id),
            None,
            crate::MessagePayload::Raw(auth_challenge.clone()),
        );

        self.send_nym_message(peer_id, challenge_message).await?;

        Ok(true)
    }

    fn create_auth_challenge(&self) -> Vec<u8> {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut challenge = vec![0u8; 32];
        rng.fill(&mut challenge[..]);
        challenge
    }
}

use libp2p::kad::record::store::MemoryStore;

impl PeerId {
    pub fn from_libp2p_peer_id(peer_id: &Libp2pPeerId) -> Self {
        Self(peer_id.to_string())
    }
}

pub async fn create_libp2p_network(
    config: Libp2pNetworkConfig,
    nym_identity: NymIdentity,
) -> NetworkResult<(Libp2pNetwork, mpsc::UnboundedReceiver<Libp2pNetworkEvent>)> {
    Libp2pNetwork::new(config, nym_identity).await
}