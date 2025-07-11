//! Proof-of-work solving functions for IronShield challenges.
//! 
//! This module contains functions for finding valid nonces that satisfy
//! the proof-of-work requirements for both legacy string-based challenges
//! and the new IronShieldChallenge struct-based challenges.

use hex;
#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
use sha2::{Digest, Sha256};
use ironshield_types::*;

// Legacy constants removed - use single_threaded and multi_threaded functions instead
const MAX_ATTEMPTS_SINGLE_THREADED: i64 = 100_000_000; // Maximum number of nonce values to try in the new algorithm before giving up.

// Optimized constants for multi-threaded PoW - thread-stride approach
#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
const MAX_ATTEMPTS_MULTI_THREADED: i64 = 1_000_000_000; // Higher limit for parallel execution

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
                challenge.clone(), // Pass the complete challenge
                nonce, // The successful nonce value
            ));
        }
    }
    
    // No solution found within the attempt limit
    Err(format!("Could not find solution within {} attempts", MAX_ATTEMPTS_SINGLE_THREADED))
}

/// Find a solution for the given IronShieldChallenge using optimized multi-threaded computation.
/// 
/// This function implements a highly optimized proof-of-work algorithm using a thread-stride
/// approach coordinated at the JavaScript worker level for maximum reliability and performance.
/// 
/// ## Algorithm:
/// 1. Pre-computes the random_nonce bytes once to avoid repeated hex decoding
/// 2. Uses JavaScript worker coordination with start_offset/stride for thread-stride distribution
/// 3. Each worker simulates one thread of the optimal thread-stride pattern
/// 4. Provides perfect load balancing without WASM threading complications
/// 5. Returns immediately when a solution is found
/// 
/// ## Optimization Strategy:
/// - **Perfect Load Balancing**: Thread-stride ensures equal work distribution
/// - **Zero Coordination Overhead**: No complex synchronization needed
/// - **WASM Reliability**: Avoids problematic WASM threading entirely
/// - **Cache Efficiency**: Workers access sequential nonce ranges
/// - **JavaScript Worker Control**: Parallelization handled reliably at JS level
/// 
/// ## Performance Characteristics:
/// - **Single-core performance**: Identical to single-threaded when no coordination
/// - **Multi-worker scaling**: Near-linear scaling up to available CPU cores
/// - **Memory usage**: Minimal per-worker overhead
/// - **WASM compatibility**: 100% reliable, no threading issues
/// 
/// # Arguments
/// * `challenge` - The IronShieldChallenge struct containing random_nonce and challenge_param
/// * `num_threads` - Ignored (for compatibility only)
/// * `start_offset` - Starting nonce for this worker's search range (JavaScript coordination)
/// * `stride` - Nonce increment step for thread-stride pattern (JavaScript coordination)
/// 
/// # Returns
/// * `Ok(IronShieldChallengeResponse)` - Contains the successful nonce and signature
/// * `Err(String)` - Error message if no solution found within MAX_ATTEMPTS_MULTI_THREADED
/// 
/// # Example
/// ```rust
/// use ironshield_core::{IronShieldChallenge, find_solution_multi_threaded, SigningKey};
/// 
/// # fn example() -> Result<(), String> {
/// let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
/// let challenge = IronShieldChallenge::new(
///     "website".to_string(), 
///     1,  // difficulty
///     dummy_key,
///     [0x00; 32],  // public_key
/// );
/// 
/// // JavaScript worker coordination mode
/// let response = find_solution_multi_threaded(&challenge, None, Some(0), Some(8), None)?;
/// println!("Found solution: {}", response.solution);
/// # Ok(())
/// # }
/// ```
#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
pub fn find_solution_multi_threaded(
    challenge: &IronShieldChallenge,
    _num_threads: Option<usize>,
    start_offset: Option<usize>,
    stride: Option<usize>,
    progress_callback: Option<&dyn Fn(u64)>,
) -> Result<IronShieldChallengeResponse, String> {
    
    // Pre-parse the random_nonce from hex string to bytes once
    let random_nonce_bytes: Vec<u8> = hex::decode(&challenge.random_nonce)
        .map_err(|e: hex::FromHexError| format!("Failed to decode random_nonce hex: {}", e))?;
    
    // Get the target threshold reference
    let target_threshold: &[u8; 32] = &challenge.challenge_param;
    
    // Handle JavaScript worker coordination mode
    if let (Some(start), Some(step)) = (start_offset, stride) {
        // JavaScript worker coordination: simulate one thread of a multi-threaded system
        let mut nonce = start as i64;
        let mut attempts_counter: u64 = 0;
        while nonce < MAX_ATTEMPTS_MULTI_THREADED {
            // Convert nonce to little-endian bytes (8 bytes for i64)
            let nonce_bytes: [u8; 8] = nonce.to_le_bytes();
            
            // Calculate the hash of the random_nonce and nonce
            let mut hasher = Sha256::new();
            hasher.update(&random_nonce_bytes);
            hasher.update(&nonce_bytes);
            let hash_result = hasher.finalize();
            
            // Convert hash to [u8; 32] and use byte-wise comparison
            let hash_bytes: [u8; 32] = hash_result.into();
            if hash_bytes < *target_threshold {
                // Found a valid solution!
                return Ok(IronShieldChallengeResponse::new(
                    challenge.clone(),
                    nonce,
                ));
            }
            
            // Progress reporting
            attempts_counter += 1;
            if attempts_counter == 200_000 {
                if let Some(callback) = progress_callback {
                    callback(attempts_counter);
                }
                attempts_counter = 0; // Reset counter
            }

            // Move to next nonce using stride pattern
            nonce += step as i64;
        }
        
        // No solution found within attempt limit
        return Err(format!("Could not find solution within {} attempts using JavaScript worker coordination", MAX_ATTEMPTS_MULTI_THREADED));
    }
    
    // Fallback to single-threaded mode when no coordination parameters provided
    // This ensures compatibility when called without worker coordination
    let mut nonce = 0i64;
    let mut attempts_counter: u64 = 0;
    while nonce < MAX_ATTEMPTS_MULTI_THREADED {
        // Convert nonce to little-endian bytes (8 bytes for i64)
        let nonce_bytes: [u8; 8] = nonce.to_le_bytes();
        
        // Calculate the hash of the random_nonce and nonce
        let mut hasher = Sha256::new();
        hasher.update(&random_nonce_bytes);
        hasher.update(&nonce_bytes);
        let hash_result = hasher.finalize();
        
        // Convert hash to [u8; 32] and use byte-wise comparison with the target threshold
        let hash_bytes: [u8; 32] = hash_result.into();
        if hash_bytes < *target_threshold {
            // Found a valid solution!
            return Ok(IronShieldChallengeResponse::new(
                challenge.clone(),
                nonce,
            ));
        }
        
        // Progress reporting
        attempts_counter += 1;
        if attempts_counter == 200_000 {
            if let Some(callback) = progress_callback {
                callback(attempts_counter);
            }
            attempts_counter = 0; // Reset counter
        }

        // Move to next nonce
        nonce += 1;
    }
    
    // No solution found within the attempt limit
    Err(format!("Could not find solution within {} attempts using single-threaded fallback", MAX_ATTEMPTS_MULTI_THREADED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_solution_single_threaded_easy() {
        // Create a challenge with very high threshold (easy to solve)
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easiest difficulty
            dummy_key,
            [0x00; 32],
        );
        
        let result = find_solution_single_threaded(&challenge);
        assert!(result.is_ok(), "Should find solution for easy challenge");
        
        let response = result.unwrap();
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
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

    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_find_solution_multi_threaded_easy() {
        // Create a challenge with very high threshold (easy to solve)
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easiest difficulty
            dummy_key,
            [0x00; 32],
        );
        
        let result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for easy challenge");
        
        let response = result.unwrap();
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
        
        // Verify the solution using the verification function
        assert!(crate::verify::verify_ironshield_solution(&response),
                "Multi-threaded solution should pass verification");
    }
    
    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_find_solution_multi_threaded_vs_single_threaded() {
        // Test that multi-threaded and single-threaded versions find valid solutions
        // for the same challenge (solutions may differ due to search order)
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1000, // Medium difficulty
            dummy_key,
            [0x00; 32],
        );
        
        // Solve with single-threaded version
        let single_result = find_solution_single_threaded(&challenge);
        assert!(single_result.is_ok(), "Single-threaded should find solution");
        
        // Solve with multi-threaded version
        let multi_result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(multi_result.is_ok(), "Multi-threaded should find solution");
        
        let single_response = single_result.unwrap();
        let multi_response = multi_result.unwrap();
        
        // Both solutions should be valid (but may be different nonces)
        assert!(crate::verify::verify_ironshield_solution(&single_response),
                "Single-threaded solution should be valid");
        assert!(crate::verify::verify_ironshield_solution(&multi_response),
                "Multi-threaded solution should be valid");
        
        // Both should have the same challenge signature
        assert_eq!(single_response.solved_challenge.challenge_signature, multi_response.solved_challenge.challenge_signature);
    }
    
    #[test]
    #[cfg(feature = "parallel")]
    fn test_find_solution_multi_threaded_deterministic_correctness() {
        // Test that the multi-threaded function produces correct results
        // by testing with a known challenge where we can predict the solution range
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            2, // ~50% probability per hash
            dummy_key,
            [0x00; 32],
        );
        
        // Should find a solution relatively quickly with 50% probability per attempt
        let result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for medium difficulty challenge");
        
        let response = result.unwrap();
        
        // Manually verify the solution using the same algorithm
        let random_nonce_bytes = hex::decode(&challenge.random_nonce).unwrap();
        let nonce_bytes = response.solution.to_le_bytes();
        let mut hasher = Sha256::new();
        hasher.update(&random_nonce_bytes);
        hasher.update(&nonce_bytes);
        let hash_bytes: [u8; 32] = hasher.finalize().into();
        
        assert!(hash_bytes < challenge.challenge_param, 
                "Solution should satisfy the challenge requirement");
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature, 
                "Response should preserve challenge signature");
    }
} 