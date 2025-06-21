//! Proof-of-work solving functions for IronShield challenges.
//! 
//! This module contains functions for finding valid nonces that satisfy
//! the proof-of-work requirements for both legacy string-based challenges
//! and the new IronShieldChallenge struct-based challenges.

use hex;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use ironshield_types::*;

const MAX_ATTEMPTS: u64 = 10_000_000; // Maximum number of nonce values to try before giving up.
#[cfg(feature = "parallel")]
const CHUNK_SIZE: usize = 10_000; // Number of nonce values processed in each parallel chunk.
const MAX_ATTEMPTS_SINGLE_THREADED: i64 = 100_000_000; // Maximum number of nonce values to try in the new algorithm before giving up.

/// Find a solution for the given challenge and difficulty level
/// using sequential search.
/// 
/// This function searches for a nonce value that, when combined 
/// with the challenge string and hashed with SHA-256, produces a hash
/// starting with the required number of leading zeros.
/// 
/// # Arguments
/// * `challenge` - The challenge string to hash (typically server-provided).
/// * `difficulty` - Number of leading zeros required in the hash (higher = more difficult).
///
/// # Returns
/// * `Ok((nonce, hash))` - The successful nonce value and resulting hash.
/// * `Err(message)` - Error if no solution is found within `MAX_ATTEMPTS`.
///
/// # Performance
/// Sequential search is suitable for single-threaded environments like WASM.
pub fn find_solution(challenge: &str, difficulty: usize) -> Result<(u64, String), String> {
    let target_prefix = "0".repeat(difficulty);

    for nonce in 0..MAX_ATTEMPTS {
        let hash = calculate_hash(challenge, nonce);

        if hash.starts_with(&target_prefix) {
            return Ok((nonce, hash));
        }
    }

    Err("Could not find solution within attempt limit".into())
}

/// Find a solution using parallel processing
/// 
/// Something Ethan is working on. 
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
pub fn calculate_hash(challenge: &str, nonce: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", challenge, nonce).as_bytes());
    hex::encode(hasher.finalize())
}

/// Find a solution for the given IronShieldChallenge using single-threaded computation.
/// 
/// This function implements a proof-of-work algorithm that finds a nonce value such that
/// when concatenated with the challenge's random_nonce and hashed with SHA-256, the 
/// resulting hash (interpreted as a [u8; 32]) is numerically less than the challenge_param.
/// 
/// The algorithm:
/// 1. Takes the random_nonce from the challenge (as bytes)
/// 2. Iterates through nonce values (starting from 0)
/// 3. For each nonce: hashes random_nonce_bytes + nonce_bytes using multiple hasher updates
/// 4. Compares the hash [u8; 32] with challenge_param [u8; 32] using byte-wise comparison
/// 5. Returns the first nonce where hash < challenge_param
/// 
/// 
/// # Arguments
/// * `challenge` - The IronShieldChallenge struct containing random_nonce and challenge_param
/// 
/// # Returns
/// * `Ok(IronShieldChallengeResponse)` - Contains the successful nonce and signature
/// * `Err(String)` - Error message if no solution found within MAX_ATTEMPTS_SINGLE_THREADED
/// 
/// # Example
/// The challenge contains:
/// - random_nonce: "abc123def456" (hex string)
/// - challenge_param: [0x00, 0x00, 0xFF, ...] (target threshold)
/// 
/// The function will find nonce N such that:
/// SHA256(hex::decode("abc123def456") + N.to_le_bytes()) < challenge_param
pub fn find_solution_single_threaded(
    challenge: &IronShieldChallenge,
) -> Result<IronShieldChallengeResponse, String> {
    
    // Parse the random_nonce from hex string to bytes
    let random_nonce_bytes: Vec<u8> = hex::decode(&challenge.random_nonce)
        .map_err(|e: hex::FromHexError| format!("Failed to decode random_nonce hex: {}", e))?;
    
    // Get the target threshold from challenge_param
    let target_threshold: &[u8; 32] = &challenge.challenge_param;
    
    // Iterate through possible nonce values
    for nonce in 0..MAX_ATTEMPTS_SINGLE_THREADED {
        // Convert nonce to little-endian bytes (8 bytes for i64)
        let nonce_bytes: [u8; 8] = nonce.to_le_bytes();
        
        // Calculate the hash of the random_nonce and nonce
        let mut hasher = Sha256::new();
        hasher.update(&random_nonce_bytes);  // First part of the input
        hasher.update(&nonce_bytes);         // Second part of the input
        let hash_result = hasher.finalize();
        
        // Convert hash and use byte-wise comparison with the target threshold
        let hash_bytes: [u8; 32] = hash_result.into();
        if hash_bytes < *target_threshold {
            // Found a valid solution!
            return Ok(IronShieldChallengeResponse::new(
                challenge.challenge_signature, // Copy the challenge signature
                nonce, // The successful nonce value
            ));
        }
    }
    
    // No solution found within the attempt limit
    Err(format!("Could not find solution within {} attempts", MAX_ATTEMPTS_SINGLE_THREADED))
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
    fn test_find_solution() {
        let challenge = "test_challenge";
        let difficulty = 1;

        let result = find_solution(challenge, difficulty);
        assert!(result.is_ok(), "Should find solution for easy challenge");

        let (nonce, hash) = result.unwrap();
        assert!(hash.starts_with("0"), "Hash should start with at least one zero");
        
        // Verify the solution by recalculating the hash
        let verified_hash = calculate_hash(challenge, nonce);
        assert_eq!(hash, verified_hash, "Hash should be reproducible");
    }

    #[test]
    fn test_find_solution_single_threaded_easy() {
        // Create a challenge with very high threshold (easy to solve)
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Maximum possible value - should find solution quickly
            [0x00; 32],
            [0x11; 64],
        );
        
        let result = find_solution_single_threaded(&challenge);
        assert!(result.is_ok(), "Should find solution for easy challenge");
        
        let response = result.unwrap();
        assert_eq!(response.challenge_signature, [0x11; 64]);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    #[test]
    fn test_find_solution_single_threaded_invalid_hex() {
        // Create a challenge with invalid hex string
        let challenge = IronShieldChallenge::new(
            "not_valid_hex!".to_string(), // Invalid hex
            1000000,
            "test_website".to_string(),
            [0xFF; 32],
            [0x00; 32],
            [0x11; 64],
        );
        
        let result = find_solution_single_threaded(&challenge);
        assert!(result.is_err(), "Should fail for invalid hex");
        
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Failed to decode random_nonce hex"), "Should contain hex decode error");
    }

    #[test]
    fn test_performance_optimization_correctness() {
        // This test ensures that our optimization produces the same results
        // as the original Vec-based approach would have
        
        let random_nonce = "deadbeefcafe1234";
        let random_nonce_bytes = hex::decode(random_nonce).unwrap();
        let nonce: i64 = 12345;
        let nonce_bytes = nonce.to_le_bytes();
        
        // Method 1: Optimized approach (multiple hasher updates)
        let mut hasher1 = Sha256::new();
        hasher1.update(&random_nonce_bytes);
        hasher1.update(&nonce_bytes);
        let hash1: [u8; 32] = hasher1.finalize().into();
        
        // Method 2: Traditional approach (Vec concatenation) - for comparison
        let mut input_data = Vec::with_capacity(random_nonce_bytes.len() + 8);
        input_data.extend_from_slice(&random_nonce_bytes);
        input_data.extend_from_slice(&nonce_bytes);
        let mut hasher2 = Sha256::new();
        hasher2.update(&input_data);
        let hash2: [u8; 32] = hasher2.finalize().into();
        
        // Both methods should produce identical results
        assert_eq!(hash1, hash2, "Optimized and traditional methods should produce identical hashes");
    }
} 