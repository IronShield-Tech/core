use sha2::{Sha256, Digest};
use hex;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Core functionality for the IronShield proof-of-work system
/// This module contains shared code that can be used in both
/// the server-side (Cloudflare Workers) and client-side (WASM) implementations

/// Find a solution for the given challenge and difficulty level
pub fn find_solution(challenge: &str, difficulty: usize) -> Result<(u64, String), String> {
    let target_prefix: String = "0".repeat(difficulty);
    let max_attempts: u64 = 10000000;
    
    for nonce in 0..max_attempts {
        let data_to_hash: String = format!("{}:{}", challenge, nonce);
        let mut hasher = Sha256::new();
        hasher.update(data_to_hash.as_bytes());
        let hash_bytes = hasher.finalize();
        let hash: String = hex::encode(hash_bytes);
        
        if hash.starts_with(&target_prefix) {
            return Ok((nonce, hash));
        }
        
        // Occasionally yield to avoid blocking UI
        if nonce % 1000 == 0 {
            // In real implementation, we'd use js_sys::Promise here
            // but for simplicity we'll just continue
        }
    }
    
    Err("Could not find solution within attempt limit".into())
}

/// Find a solution for the given challenge and difficulty level using parallel processing
#[cfg(feature = "parallel")]
pub fn find_solution_parallel(challenge: &str, difficulty: usize, num_threads: usize) -> Result<(u64, String), String> {
    let target_prefix = "0".repeat(difficulty);
    let max_attempts = 10000000;
    let chunk_size = 10000;
    
    // Create a range of nonces to check, divided into chunks
    let result = (0..max_attempts)
        .step_by(num_threads)
        .collect::<Vec<u64>>()
        .par_chunks(chunk_size)
        .map(|chunk| {
            // Process each chunk in parallel
            for &start_nonce in chunk {
                // Each thread checks a different set of nonces based on its offset
                for thread_offset in 0..num_threads {
                    let nonce = start_nonce + thread_offset as u64;
                    let hash = calculate_hash(challenge, nonce);
                    
                    if hash.starts_with(&target_prefix) {
                        return Some((nonce, hash));
                    }
                }
            }
            None
        })
        .find_any(|result| result.is_some())
        .flatten();
    
    match result {
        Some((nonce, hash)) => Ok((nonce, hash)),
        None => Err("Could not find solution within attempt limit".into())
    }
}

/// Calculate the hash for a given challenge and nonce
pub fn calculate_hash(challenge: &str, nonce: u64) -> String {
    let data_to_hash: String = format!("{}:{}", challenge, nonce);
    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash_bytes = hasher.finalize();
    hex::encode(hash_bytes)
}

/// Verify a solution for the given challenge and difficulty level
pub fn verify_solution(challenge: &str, nonce_str: &str, difficulty: usize) -> bool {
    match nonce_str.parse::<u64>() {
        Ok(nonce) => {
            let target_prefix: String = "0".repeat(difficulty);
            let hash = calculate_hash(challenge, nonce);
            hash.starts_with(&target_prefix)
        },
        Err(_) => false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_calculation() {
        let challenge: &str = "test_challenge";
        let nonce: u64 = 12345;
        let hash: String = calculate_hash(challenge, nonce);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_verification() {
        let challenge: &str = "test_challenge";
        let difficulty: usize = 1; // Use low difficulty for quick test
        
        // Find a valid solution
        let (nonce, _) = find_solution(challenge, difficulty).unwrap();
        
        // Verify it works
        assert!(verify_solution(challenge, &nonce.to_string(), difficulty));
        
        // Verify invalid solution fails
        assert!(!verify_solution(challenge, "999999", difficulty));
    }
} 