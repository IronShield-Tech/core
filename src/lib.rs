//! # Core functionality for the IronShield proof-of-work system.
//! 
//! This module contains shared code that can be used in both
//! the server-side (Cloudflare Workers) and client-side (WASM) implementations

use hex;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};

const MAX_ATTEMPTS:   u64 = 10_000_000;
const CHUNK_SIZE:   usize = 10_000;
const YIELD_INTERVAL: u64 = 1000;

/// Find a solution for the given challenge and difficulty level
pub fn find_solution(challenge: &str, difficulty: usize) -> Result<(u64, String), String> {
    let target_prefix = "0".repeat(difficulty);

    for nonce in 0..MAX_ATTEMPTS {
        let hash = calculate_hash(challenge, nonce);

        if hash.starts_with(&target_prefix) {
            return Ok((nonce, hash));
        }

        // Occasionally yield to avoid blocking UI
        if nonce % YIELD_INTERVAL == 0 {
            // In real implementation, we'd use js_sys::Promise here
        }
    }

    Err("Could not find solution within attempt limit".into())
}


/// Find a solution using parallel processing
#[cfg(feature = "parallel")]
pub fn find_solution_parallel(
    challenge: &str,
    difficulty: usize,
    num_threads: usize,
) -> Result<(u64, String), String> {
    let target_prefix = "0".repeat(difficulty);

    let result = (0..MAX_ATTEMPTS)
        .step_by(num_threads)
        .collect::<Vec<u64>>()
        .par_chunks(CHUNK_SIZE)
        .find_map_any(|chunk| {
            chunk.iter().find_map(|&start_nonce| {
                (0..num_threads).find_map(|thread_offset| {
                    let nonce = start_nonce + thread_offset as u64;
                    let hash = calculate_hash(challenge, nonce);

                    if hash.starts_with(&target_prefix) {
                        Some((nonce, hash))
                    } else {
                        None
                    }
                })
            })
        });

    result.ok_or_else(|| "Could not find solution within attempt limit".into())
}


/// Calculate the hash for a given challenge and nonce
pub fn calculate_hash(challenge: &str, nonce: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", challenge, nonce).as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a solution for the given challenge and difficulty level
pub fn verify_solution(challenge: &str, nonce_str: &str, difficulty: usize) -> bool {
    nonce_str
        .parse::<u64>()
        .map(|nonce| {
            let hash = calculate_hash(challenge, nonce);
            hash.starts_with(&"0".repeat(difficulty))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_calculation() {
        let hash = calculate_hash("test_challenge", 12345);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_verification() {
        let challenge = "test_challenge";
        let difficulty = 1;

        let (nonce, _) = find_solution(challenge, difficulty).unwrap();

        assert!(verify_solution(challenge, &nonce.to_string(), difficulty));
        assert!(!verify_solution(challenge, "999999", difficulty));
    }
}