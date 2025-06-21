//! Verification functions for IronShield proof-of-work solutions.
//! 
//! This module contains functions for verifying that proposed solutions
//! satisfy the proof-of-work requirements for both legacy string-based
//! challenges and the new IronShieldChallenge struct-based challenges.

use hex;
use sha2::{Digest, Sha256};
use ironshield_types::*;

/// Verify that a given nonce produces a valid solution for the challenge.
///
/// # Arguments
/// * `challenge` - The original challenge string.
/// * `nonce_str` - The proposed nonce as a string (will be parsed to u64).
/// * `difficulty` - Required number of leading zeros in the hash.
///
/// # Returns
/// * `true` - If the nonce produces a hash meeting the difficulty requirement
/// * `false` - If nonce is invalid, hash doesn't meet the requirement, or parsing fails.
///
/// # Safety
/// This function handles invalid nonce strings gracefully by returning false.
pub fn verify_solution(challenge: &str, nonce_str: &str, difficulty: usize) -> bool {
    nonce_str
        .parse::<u64>()
        .map(|nonce| {
            let hash = calculate_hash(challenge, nonce);
            hash.starts_with(&"0".repeat(difficulty))
        })
        .unwrap_or(false)
}

/// Calculate the SHA-256 hash for a given challenge and nonce combination.
///
/// The input format is "challenge:nonce" (e.g., "hello_world:12345").
///
/// # Arguments
/// * `challenge` - The challenge string.
/// * `nonce` - The nonce value to try.
///
/// # Returns
/// * Hexadecimal string representation of the SHA-256 hash (64 chars long).
fn calculate_hash(challenge: &str, nonce: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", challenge, nonce).as_bytes());
    hex::encode(hasher.finalize())
}

/// Verify that a solution is valid for a given IronShieldChallenge.
/// 
/// This function uses the same optimized hashing approach as find_solution_single_threaded
/// to ensure consistency and performance.
/// 
/// # Arguments
/// * `challenge` - The original IronShieldChallenge
/// * `nonce` - The proposed solution nonce
/// 
/// # Returns
/// * `true` if the nonce produces a hash less than the challenge_param
/// * `false` if the nonce is invalid or doesn't meet the requirement
pub fn verify_ironshield_solution(challenge: &IronShieldChallenge, nonce: i64) -> bool {
    // Parse the random_nonce from hex string to bytes
    let random_nonce_bytes = match hex::decode(&challenge.random_nonce) {
        Ok(bytes) => bytes,
        Err(_) => return false, // Invalid hex string
    };
    
    // Convert nonce to little-endian bytes
    let nonce_bytes: [u8; 8] = nonce.to_le_bytes();
    
    // Use the same optimized hashing approach as the main function
    let mut hasher = Sha256::new();
    hasher.update(&random_nonce_bytes);  // First part of the input
    hasher.update(&nonce_bytes);         // Second part of the input
    let hash_result = hasher.finalize();
    
    // Convert hash to [u8; 32] for comparison
    let hash_bytes: [u8; 32] = hash_result.into();
    
    // Compare with the challenge parameter
    hash_bytes < challenge.challenge_param
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::solve::find_solution;

    #[test]
    fn test_verification() {
        let challenge = "test_challenge";
        let difficulty = 1;

        let (nonce, _) = find_solution(challenge, difficulty).unwrap();

        assert!(verify_solution(challenge, &nonce.to_string(), difficulty));
        assert!(!verify_solution(challenge, "999999", difficulty));
    }

    #[test]
    fn test_verify_solution_invalid_nonce() {
        let challenge = "test_challenge";
        let difficulty = 1;

        // Test with invalid nonce string
        assert!(!verify_solution(challenge, "not_a_number", difficulty));
        assert!(!verify_solution(challenge, "", difficulty));
        assert!(!verify_solution(challenge, "-1", difficulty)); // negative numbers should fail parsing to u64
    }

    #[test]
    fn test_verify_ironshield_solution() {
        // Create a challenge with reasonable threshold
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
            "cafe1234".to_string(),
            1000000,
            "test_website".to_string(),
            [0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], // Medium threshold
            [0x00; 32],
            [0x22; 64],
        );
        
        // Find a solution using the solver
        let result = crate::solve::find_solution_single_threaded(&challenge);
        assert!(result.is_ok(), "Should find solution for reasonable challenge");
        
        let response = result.unwrap();
        
        // Verify using our verification function
        assert!(verify_ironshield_solution(&challenge, response.solution), 
                "Verification function should confirm the solution is valid");
                
        // Verify that an obviously wrong nonce fails (much larger value)
        assert!(!verify_ironshield_solution(&challenge, response.solution + 1000000), 
                "Obviously wrong nonce should fail verification");
                
        // Test with invalid hex in the challenge
        let bad_challenge: IronShieldChallenge = IronShieldChallenge::new(
            "invalid_hex_zzzz".to_string(), // Invalid hex
            1000000,
            "test_website".to_string(),
            [0x80; 32],
            [0x00; 32],
            [0x22; 64],
        );
        assert!(!verify_ironshield_solution(&bad_challenge, 12345), 
                "Challenge with invalid hex should fail verification");
    }

    #[test]
    fn test_verify_ironshield_solution_edge_cases() {
        // Test with very easy challenge (all 0xFF)
        let easy_challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Very easy
            [0x00; 32],
            [0x11; 64],
        );
        
        // Almost any nonce should work for this challenge
        assert!(verify_ironshield_solution(&easy_challenge, 0));
        assert!(verify_ironshield_solution(&easy_challenge, 1));
        assert!(verify_ironshield_solution(&easy_challenge, 12345));
        
        // Test with impossible challenge (all 0x00)
        let impossible_challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x00; 32], // Impossible
            [0x00; 32],
            [0x11; 64],
        );
        
        // No nonce should work for this challenge
        assert!(!verify_ironshield_solution(&impossible_challenge, 0));
        assert!(!verify_ironshield_solution(&impossible_challenge, 1));
        assert!(!verify_ironshield_solution(&impossible_challenge, 12345));
    }
} 