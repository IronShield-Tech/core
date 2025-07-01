//! Verification functions for IronShield proof-of-work solutions.
//! 
//! This module contains functions for verifying that proposed solutions
//! satisfy the proof-of-work requirements for both legacy string-based
//! challenges and the new IronShieldChallenge struct-based challenges.

use hex;
use sha2::{Digest, Sha256};
use ironshield_types::*;



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


    #[test]
    fn test_verify_ironshield_solution() {
        // Create a challenge with reasonable threshold
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
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
    }

    #[test]
    fn test_verify_ironshield_solution_edge_cases() {
        // Test with very easy challenge (all 0xFF)
        let easy_challenge = IronShieldChallenge::new(
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