//! Bytecode fingerprinting using TLSH (Trend Micro Locality Sensitive Hash)
//!
//! This module provides functionality to compare EVM bytecode and determine
//! if two contracts are from the same protocol family.

use thiserror::Error;
use tlsh2::{TlshDefault, TlshDefaultBuilder};

/// Similarity classification based on TLSH diff score
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Similarity {
    /// Identical bytecode (diff = 0)
    Identical,
    /// Same contract, different immutables (diff 1-30)
    SameContract,
    /// Same protocol family or fork (diff 31-100)
    SameFamily,
    /// Possibly related (diff 101-150)
    PossiblyRelated,
    /// Different protocols (diff > 150)
    Different,
}

impl Similarity {
    /// Create from TLSH diff score
    pub fn from_diff(diff: i32) -> Self {
        match diff {
            0 => Self::Identical,
            1..=30 => Self::SameContract,
            31..=100 => Self::SameFamily,
            101..=150 => Self::PossiblyRelated,
            _ => Self::Different,
        }
    }

    /// Check if contracts are from the same protocol family
    pub fn is_same_family(&self) -> bool {
        matches!(
            self,
            Self::Identical | Self::SameContract | Self::SameFamily
        )
    }
}

/// Errors that can occur during fingerprinting
#[derive(Debug, Error)]
pub enum FingerprintError {
    #[error("bytecode too small for TLSH (need at least 50 bytes, got {0})")]
    BytecodeTooSmall(usize),

    #[error("invalid bytecode")]
    InvalidBytecode,
}

/// Bytecode fingerprint for comparison
pub struct Fingerprint {
    tlsh: TlshDefault,
    original_size: usize,
    normalized_size: usize,
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fingerprint")
            .field("hash", &self.hash_hex())
            .field("original_size", &self.original_size)
            .field("normalized_size", &self.normalized_size)
            .finish()
    }
}

impl Fingerprint {
    /// Create a fingerprint from raw bytecode
    pub fn from_bytecode(bytecode: &[u8]) -> Result<Self, FingerprintError> {
        if bytecode.len() < 50 {
            return Err(FingerprintError::BytecodeTooSmall(bytecode.len()));
        }

        let stripped = strip_metadata(bytecode);
        let normalized = normalize_push_data(stripped);

        let mut builder = TlshDefaultBuilder::new();
        builder.update(&normalized);

        let tlsh = builder.build().ok_or(FingerprintError::InvalidBytecode)?;

        Ok(Self {
            tlsh,
            original_size: bytecode.len(),
            normalized_size: normalized.len(),
        })
    }

    /// Get the TLSH hash as hex string
    pub fn hash_hex(&self) -> String {
        hex::encode(self.tlsh.hash())
    }

    /// Get the raw TLSH hash bytes
    pub fn hash(&self) -> [u8; 72] {
        self.tlsh.hash()
    }

    /// Original bytecode size
    pub fn original_size(&self) -> usize {
        self.original_size
    }

    /// Normalized bytecode size (after stripping metadata)
    pub fn normalized_size(&self) -> usize {
        self.normalized_size
    }

    /// Compare with another fingerprint, returns diff score
    /// Lower score = more similar (0 = identical)
    pub fn diff(&self, other: &Self) -> i32 {
        self.tlsh.diff(&other.tlsh, true)
    }

    /// Compare and return similarity classification
    pub fn similarity(&self, other: &Self) -> Similarity {
        Similarity::from_diff(self.diff(other))
    }
}

/// Strip CBOR metadata from bytecode (starts with 0xa264 or 0xa165)
fn strip_metadata(bytecode: &[u8]) -> &[u8] {
    // CBOR metadata markers for different solc versions
    const MARKERS: [[u8; 2]; 2] = [
        [0xa2, 0x64], // solc >= 0.6.0
        [0xa1, 0x65], // older solc
    ];

    for marker in MARKERS {
        if let Some(pos) = bytecode.windows(2).rposition(|w| w == marker) {
            return &bytecode[..pos];
        }
    }
    bytecode
}

/// Normalize bytecode by zeroing out PUSH data (immutables, addresses, etc.)
fn normalize_push_data(bytecode: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(bytecode.len());
    let mut i = 0;

    while i < bytecode.len() {
        let op = bytecode[i];
        result.push(op);
        i += 1;

        // PUSH1 (0x60) to PUSH32 (0x7f)
        if (0x60..=0x7f).contains(&op) {
            let push_size = (op - 0x5f) as usize;
            // Replace pushed data with zeros to ignore immutables/addresses
            let zeros_to_add = push_size.min(bytecode.len().saturating_sub(i));
            result.extend(std::iter::repeat(0u8).take(zeros_to_add));
            i += push_size;
        }
    }

    result
}

/// Check if bytecode is an EIP-1167 minimal proxy
pub fn is_eip1167_proxy(bytecode: &[u8]) -> bool {
    // EIP-1167 pattern: 363d3d373d3d3d363d73<address>5af43d82803e903d91602b57fd5bf3
    bytecode.len() == 45
        && bytecode.starts_with(&[0x36, 0x3d, 0x3d, 0x37, 0x3d, 0x3d, 0x3d, 0x36, 0x3d, 0x73])
}

/// Extract implementation address from EIP-1167 proxy bytecode
pub fn extract_eip1167_impl(bytecode: &[u8]) -> Option<[u8; 20]> {
    if !is_eip1167_proxy(bytecode) {
        return None;
    }

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytecode[10..30]);
    Some(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_metadata() {
        // Bytecode ending with 0xa264... metadata
        let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0xa2, 0x64, 0x69, 0x70];
        let stripped = strip_metadata(&bytecode);
        assert_eq!(stripped, &[0x60, 0x80, 0x60, 0x40]);
    }

    #[test]
    fn test_normalize_push_data() {
        // PUSH1 0x80, PUSH1 0x40
        let bytecode = vec![0x60, 0x80, 0x60, 0x40];
        let normalized = normalize_push_data(&bytecode);
        // Push values should be zeroed
        assert_eq!(normalized, vec![0x60, 0x00, 0x60, 0x00]);
    }

    #[test]
    fn test_is_eip1167_proxy() {
        let proxy = hex::decode(
            "363d3d373d3d3d363d7395885af5492195f0754be71ad1545fe81364e5315af43d82803e903d91602b57fd5bf3"
        ).unwrap();
        assert!(is_eip1167_proxy(&proxy));

        let not_proxy = vec![0x60, 0x80, 0x60, 0x40];
        assert!(!is_eip1167_proxy(&not_proxy));
    }

    #[test]
    fn test_extract_eip1167_impl() {
        let proxy = hex::decode(
            "363d3d373d3d3d363d7395885af5492195f0754be71ad1545fe81364e5315af43d82803e903d91602b57fd5bf3"
        ).unwrap();

        let impl_addr = extract_eip1167_impl(&proxy).unwrap();
        assert_eq!(
            hex::encode(impl_addr),
            "95885af5492195f0754be71ad1545fe81364e531"
        );
    }

    #[test]
    fn test_similarity_from_diff() {
        assert_eq!(Similarity::from_diff(0), Similarity::Identical);
        assert_eq!(Similarity::from_diff(15), Similarity::SameContract);
        assert_eq!(Similarity::from_diff(50), Similarity::SameFamily);
        assert_eq!(Similarity::from_diff(120), Similarity::PossiblyRelated);
        assert_eq!(Similarity::from_diff(200), Similarity::Different);
    }
}
