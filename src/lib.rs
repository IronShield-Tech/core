use sha2::{Sha256, Digest};
use hex;

/// Core functionality for the IronShield proof-of-work system
/// This module contains shared code that can be used in both
/// the server-side (Cloudflare Workers) and client-side (WASM) implementations

/// Find a solution for the given challenge and difficulty level
pub fn find_solution(challenge: &str, difficulty: usize) -> Result<(u64, String), String> {
    let target_prefix = "0".repeat(difficulty);
    let max_attempts = 10000000;
    
    for nonce in 0..max_attempts {
        let data_to_hash = format!("{}:{}", challenge, nonce);
        let mut hasher = Sha256::new();
        hasher.update(data_to_hash.as_bytes());
        let hash_bytes = hasher.finalize();
        let hash = hex::encode(hash_bytes);
        
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

/// Calculate the hash for a given challenge and nonce
pub fn calculate_hash(challenge: &str, nonce: u64) -> String {
    let data_to_hash = format!("{}:{}", challenge, nonce);
    let mut hasher = Sha256::new();
    hasher.update(data_to_hash.as_bytes());
    let hash_bytes = hasher.finalize();
    hex::encode(hash_bytes)
}

/// Verify a solution for the given challenge and difficulty level
pub fn verify_solution(challenge: &str, nonce_str: &str, difficulty: usize) -> bool {
    match nonce_str.parse::<u64>() {
        Ok(nonce) => {
            let target_prefix = "0".repeat(difficulty);
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
        let challenge = "test_challenge";
        let nonce = 12345;
        let hash = calculate_hash(challenge, nonce);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_verification() {
        let challenge = "test_challenge";
        let difficulty = 1; // Use low difficulty for quick test
        
        // Find a valid solution
        let (nonce, _) = find_solution(challenge, difficulty).unwrap();
        
        // Verify it works
        assert!(verify_solution(challenge, &nonce.to_string(), difficulty));
        
        // Verify invalid solution fails
        assert!(!verify_solution(challenge, "999999", difficulty));
    }
} 