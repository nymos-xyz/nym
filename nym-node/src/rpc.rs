use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn, error};

use crate::{
    error::{NodeError, Result},
    node::NymNode,
    state::NodeState,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub result: Option<Value>,
    pub error: Option<RpcError>,
    pub id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
    pub data: Option<Value>,
}

pub struct RpcServer {
    node: Arc<tokio::sync::RwLock<NymNode>>,
    listen_addr: std::net::SocketAddr,
    auth_enabled: bool,
}

impl RpcServer {
    pub fn new(
        node: Arc<tokio::sync::RwLock<NymNode>>,
        listen_addr: std::net::SocketAddr,
        auth_enabled: bool,
    ) -> Self {
        Self {
            node,
            listen_addr,
            auth_enabled,
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await?;
        info!("RPC server listening on {}", self.listen_addr);
        
        loop {
            let (mut socket, addr) = listener.accept().await?;
            let node = self.node.clone();
            let auth_enabled = self.auth_enabled;
            
            tokio::spawn(async move {
                if let Err(e) = handle_connection(&mut socket, node, auth_enabled).await {
                    error!("Error handling RPC connection from {}: {}", addr, e);
                }
            });
        }
    }
}

async fn handle_connection(
    socket: &mut tokio::net::TcpStream,
    node: Arc<tokio::sync::RwLock<NymNode>>,
    auth_enabled: bool,
) -> Result<()> {
    let mut buffer = vec![0; 4096];
    
    loop {
        let n = socket.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        
        let request_str = String::from_utf8_lossy(&buffer[..n]);
        let request: RpcRequest = match serde_json::from_str(&request_str) {
            Ok(req) => req,
            Err(e) => {
                let error_response = RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(RpcError {
                        code: -32700,
                        message: format!("Parse error: {}", e),
                        data: None,
                    }),
                    id: 0,
                };
                
                let response_bytes = serde_json::to_vec(&error_response)?;
                socket.write_all(&response_bytes).await?;
                continue;
            }
        };
        
        let response = handle_request(request, node.clone(), auth_enabled).await;
        let response_bytes = serde_json::to_vec(&response)?;
        socket.write_all(&response_bytes).await?;
    }
    
    Ok(())
}

async fn handle_request(
    request: RpcRequest,
    node: Arc<tokio::sync::RwLock<NymNode>>,
    auth_enabled: bool,
) -> RpcResponse {
    // TODO: Implement authentication if enabled
    if auth_enabled {
        // Check auth token from params
    }
    
    let result = match request.method.as_str() {
        // Node status methods
        "node_getStatus" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Block methods
        "block_getHeight" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state.block_height).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        "block_getHash" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state.last_block_hash).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Network methods
        "network_getPeerCount" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state.peer_count).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Sync methods
        "sync_getStatus" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(serde_json::json!({
                    "syncing": state.syncing,
                    "progress": state.sync_progress
                })).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Validator methods
        "validator_getStatus" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state.validator_status).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Mining methods
        "mining_getStatus" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(state.mining_status).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Compute methods
        "compute_getStatus" => {
            match node.read().await.get_state().await {
                Ok(state) => Ok(serde_json::to_value(serde_json::json!({
                    "active_jobs": state.compute_jobs_active,
                    "completed_jobs": state.compute_jobs_completed
                })).unwrap()),
                Err(e) => Err(RpcError {
                    code: -32603,
                    message: format!("Internal error: {}", e),
                    data: None,
                }),
            }
        },
        
        // Unknown method
        _ => Err(RpcError {
            code: -32601,
            message: format!("Method not found: {}", request.method),
            data: None,
        }),
    };
    
    RpcResponse {
        jsonrpc: "2.0".to_string(),
        result: result.ok(),
        error: result.err(),
        id: request.id,
    }
}

// RPC method definitions for documentation
pub mod methods {
    pub const NODE_GET_STATUS: &str = "node_getStatus";
    pub const BLOCK_GET_HEIGHT: &str = "block_getHeight";
    pub const BLOCK_GET_HASH: &str = "block_getHash";
    pub const NETWORK_GET_PEER_COUNT: &str = "network_getPeerCount";
    pub const SYNC_GET_STATUS: &str = "sync_getStatus";
    pub const VALIDATOR_GET_STATUS: &str = "validator_getStatus";
    pub const MINING_GET_STATUS: &str = "mining_getStatus";
    pub const COMPUTE_GET_STATUS: &str = "compute_getStatus";
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_rpc_request_serialization() {
        let request = RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "node_getStatus".to_string(),
            params: None,
            id: 1,
        };
        
        let json = serde_json::to_string(&request).unwrap();
        let parsed: RpcRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.method, request.method);
        assert_eq!(parsed.id, request.id);
    }
}