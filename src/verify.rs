//! Verification functions for IronShield proof-of-work solutions.
//!
//! This module contains functions for verifying that proposed solutions
//! satisfy the proof-of-work requirements for both legacy string-based
//! challenges and the new IronShieldChallenge struct-based challenges.

use hex;
use sha2::{Digest, Sha256};
use ironshield_types::*;

/// Verify that an IronShieldChallengeResponse contains a valid solution.
///
/// This function uses the same optimized hashing approach as find_solution_single_threaded
/// to ensure consistency and performance. It extracts the challenge and solution from
/// the response and verifies that the solution is valid for the challenge.
///
/// # Arguments
/// * `response` - The IronShieldChallengeResponse containing both the challenge and solution
///
/// # Returns
/// * `true` if the solution produces a hash less than the challenge_param
/// * `false` if the solution is invalid or doesn't meet the requirement
///
/// # Example
/// ```
/// use ironshield_core::{find_solution_single_threaded, verify_ironshield_solution, IronShieldChallenge, SigningKey};
///
/// let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
/// let challenge = IronShieldChallenge::new(
///     "test_website".to_string(),
///     1, // Easy difficulty
///     dummy_key,
///     [0x00; 32],
/// );
///
/// let response = find_solution_single_threaded(&challenge, None).unwrap();
/// assert!(verify_ironshield_solution(&response));
/// ```
pub fn verify_ironshield_solution(response: &IronShieldChallengeResponse) -> bool {
    let challenge: &IronShieldChallenge = &response.solved_challenge;
    let nonce: i64 = response.solution;

    // Parse the random_nonce from hex string to bytes
    let random_nonce_bytes: Vec<u8> = match hex::decode(&challenge.random_nonce) {
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
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
            "test_website".to_string(),
            2, // Medium threshold
            dummy_key,
            [0x00; 32],
        );

        // Find a solution using the solver
        let result = crate::solve::find_solution_single_threaded(&challenge, None);
        assert!(result.is_ok(), "Should find solution for reasonable challenge");

        let response = result.unwrap();

        // Verify using our verification function
        assert!(verify_ironshield_solution(&response),
                "Verification function should confirm the solution is valid");
    }

    #[test]
    fn test_verify_ironshield_solution_edge_cases() {
        // Test with very easy challenge (all 0xFF)
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let easy_challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Very easy
            dummy_key.clone(),
            [0x00; 32],
        );

        // Create responses with different nonces - almost any nonce should work for this challenge
        let response1 = IronShieldChallengeResponse::new(easy_challenge.clone(), 0);
        let response2 = IronShieldChallengeResponse::new(easy_challenge.clone(), 1);
        let response3 = IronShieldChallengeResponse::new(easy_challenge.clone(), 12345);

        assert!(verify_ironshield_solution(&response1));
        assert!(verify_ironshield_solution(&response2));
        assert!(verify_ironshield_solution(&response3));

        // Test with impossible challenge (all 0x00)
        let impossible_challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            u64::MAX, // Impossible
            dummy_key,
            [0x00; 32],
        );

        // Create responses - no nonce should work for this challenge
        let impossible_response1 = IronShieldChallengeResponse::new(impossible_challenge.clone(), 0);
        let impossible_response2 = IronShieldChallengeResponse::new(impossible_challenge.clone(), 1);
        let impossible_response3 = IronShieldChallengeResponse::new(impossible_challenge, 12345);

        assert!(!verify_ironshield_solution(&impossible_response1));
        assert!(!verify_ironshield_solution(&impossible_response2));
        assert!(!verify_ironshield_solution(&impossible_response3));
    }
}