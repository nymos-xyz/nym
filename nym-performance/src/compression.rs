//! Compression utilities for performance optimization

use crate::{PerformanceError, Result};
use crate::config::{CompressionAlgorithm, NetworkCompressionConfig};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

/// Compression engine for data optimization
pub struct CompressionEngine {
    algorithm: CompressionAlgorithm,
    level: u32,
    min_size: usize,
}

/// Compression result
#[derive(Debug, Clone)]
pub struct CompressionResult {
    pub compressed_data: Vec<u8>,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    pub algorithm_used: CompressionAlgorithm,
}

impl CompressionEngine {
    /// Create a new compression engine
    pub fn new(config: &NetworkCompressionConfig) -> Result<Self> {
        Ok(Self {
            algorithm: config.algorithm,
            level: config.level,
            min_size: config.min_size,
        })
    }

    /// Compress data using the configured algorithm
    pub fn compress(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < self.min_size {
            return Ok(data.to_vec());
        }

        match self.algorithm {
            CompressionAlgorithm::Lz4 => self.compress_lz4(data),
            CompressionAlgorithm::Zstd => self.compress_zstd(data),
            CompressionAlgorithm::Gzip => self.compress_gzip(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }

    /// Decompress data
    pub fn decompress(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.algorithm {
            CompressionAlgorithm::Lz4 => self.decompress_lz4(data),
            CompressionAlgorithm::Zstd => self.decompress_zstd(data),
            CompressionAlgorithm::Gzip => self.decompress_gzip(data),
            CompressionAlgorithm::None => Ok(data.to_vec()),
        }
    }

    /// Compress with detailed result
    pub fn compress_with_result(&self, data: &[u8]) -> Result<CompressionResult> {
        let original_size = data.len();
        let compressed_data = self.compress(data)?;
        let compressed_size = compressed_data.len();
        let compression_ratio = compressed_size as f64 / original_size as f64;

        Ok(CompressionResult {
            compressed_data,
            original_size,
            compressed_size,
            compression_ratio,
            algorithm_used: self.algorithm,
        })
    }

    /// Get compression ratio estimate
    pub fn estimate_compression_ratio(&self, data: &[u8]) -> f64 {
        // Simple heuristic based on data entropy
        let mut histogram = [0u32; 256];
        for &byte in data {
            histogram[byte as usize] += 1;
        }

        let mut entropy = 0.0;
        let len = data.len() as f64;
        for &count in &histogram {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        // Estimate compression ratio based on entropy
        (entropy / 8.0).min(1.0)
    }

    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        compress_prepend_size(data)
            .map_err(|e| PerformanceError::compression(format!("LZ4 compression failed: {}", e)))
    }

    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        decompress_size_prepended(data)
            .map_err(|e| PerformanceError::compression(format!("LZ4 decompression failed: {}", e)))
    }

    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::encode_all(data, self.level as i32)
            .map_err(|e| PerformanceError::compression(format!("ZSTD compression failed: {}", e)))
    }

    fn decompress_zstd(&self, data: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(data)
            .map_err(|e| PerformanceError::compression(format!("ZSTD decompression failed: {}", e)))
    }

    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::new(self.level));
        encoder.write_all(data)
            .map_err(|e| PerformanceError::compression(format!("Gzip write failed: {}", e)))?;
        
        encoder.finish()
            .map_err(|e| PerformanceError::compression(format!("Gzip compression failed: {}", e)))
    }

    fn decompress_gzip(&self, data: &[u8]) -> Result<Vec<u8>> {
        use flate2::read::GzDecoder;
        
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed)
            .map_err(|e| PerformanceError::compression(format!("Gzip decompression failed: {}", e)))?;
        
        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NetworkCompressionConfig;

    #[test]
    fn test_lz4_compression() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
            min_size: 100,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let data = vec![0u8; 1000]; // Compressible data
        
        let compressed = engine.compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        
        let decompressed = engine.decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_zstd_compression() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Zstd,
            level: 3,
            min_size: 100,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let data = b"Hello, world! This is a test string for compression.".repeat(10);
        
        let compressed = engine.compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        
        let decompressed = engine.decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_gzip_compression() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Gzip,
            level: 6,
            min_size: 100,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let data = b"Hello, world! This is a test string for compression.".repeat(10);
        
        let compressed = engine.compress(&data).unwrap();
        assert!(compressed.len() < data.len());
        
        let decompressed = engine.decompress(&compressed).unwrap();
        assert_eq!(data, decompressed);
    }

    #[test]
    fn test_no_compression() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::None,
            level: 0,
            min_size: 100,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let data = b"Hello, world!";
        
        let compressed = engine.compress(data).unwrap();
        assert_eq!(data, compressed.as_slice());
        
        let decompressed = engine.decompress(&compressed).unwrap();
        assert_eq!(data, decompressed.as_slice());
    }

    #[test]
    fn test_min_size_threshold() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
            min_size: 100,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let small_data = b"Small data"; // Less than min_size
        
        let compressed = engine.compress(small_data).unwrap();
        assert_eq!(small_data, compressed.as_slice()); // Should not be compressed
    }

    #[test]
    fn test_compression_result() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
            min_size: 10,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        let data = vec![0u8; 1000];
        
        let result = engine.compress_with_result(&data).unwrap();
        assert_eq!(result.original_size, 1000);
        assert!(result.compressed_size < result.original_size);
        assert!(result.compression_ratio < 1.0);
        assert_eq!(result.algorithm_used, CompressionAlgorithm::Lz4);
    }

    #[test]
    fn test_compression_ratio_estimate() {
        let config = NetworkCompressionConfig {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
            min_size: 10,
        };
        
        let engine = CompressionEngine::new(&config).unwrap();
        
        // Highly compressible data
        let compressible_data = vec![0u8; 1000];
        let ratio1 = engine.estimate_compression_ratio(&compressible_data);
        
        // Less compressible data
        let random_data: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let ratio2 = engine.estimate_compression_ratio(&random_data);
        
        assert!(ratio1 < ratio2); // More compressible should have lower ratio
    }
}