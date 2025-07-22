//! Proof-of-work solving functions for IronShield challenges.
//!
//! This module contains functions for finding valid nonces that satisfy
//! the proof-of-work requirements for IronShieldChallenge struct-based challenges.

use hex;
use sha2::{Digest, Sha256};

use ironshield_types::*;

const  PROGRESS_REPORTING_INTERVAL: u64 = 200_000;
const MAX_ATTEMPTS_SINGLE_THREADED: i64 = 100_000_000;
#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
const  MAX_ATTEMPTS_MULTI_THREADED: i64 = 1_000_000_000; // Higher limit for parallel execution

/// Configuration parameters for proof-of-work challenges.
///
/// # Arguments
/// * `max_attempts`:                number of nonces to try
///                                  before terminating (giving
///                                  up).
/// * `progress_reporting_interval`: The interval for every
///                                  progress report callback
///                                  (in attempts).
pub struct PoWConfig {
    pub max_attempts:                i64,
    pub progress_reporting_interval: u64,
}

impl Default for PoWConfig {
    fn default() -> Self {
        Self { // Single threaded default.
            max_attempts:                MAX_ATTEMPTS_SINGLE_THREADED,
            progress_reporting_interval: PROGRESS_REPORTING_INTERVAL,
        }
    }
}

impl PoWConfig {
    pub fn single_threaded() -> Self {
        Self::default()
    }

    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    pub fn multi_threaded() -> Self {
        Self {
            max_attempts:                MAX_ATTEMPTS_MULTI_THREADED,
            progress_reporting_interval: PROGRESS_REPORTING_INTERVAL,
        }
    }

    /// Create a custom configuration with specified
    /// parameters.
    ///
    /// # Arguments
    /// * `max_attempts`:                number of nonces to try
    ///                                  before terminating (giving
    ///                                  up).
    /// * `progress_reporting_interval`: The interval for every
    ///                                  progress report callback
    ///                                  (in attempts).
    pub fn custom(
        max_attempts:                i64,
        progress_reporting_interval: u64
    ) -> Self {
        Self {
            max_attempts,
            progress_reporting_interval,
        }
    }
}

/// Find a solution for the given IronShieldChallenge using single-threaded computation.
///
/// This function implements a proof-of-work algorithm that finds a nonce value such that
/// when concatenated with the challenge's random_nonce and hashed with SHA-256, the
/// resulting hash (interpreted as a `[u8; 32]`) is numerically less than the challenge_param.
///
/// The algorithm:
/// 1. Takes the random_nonce from the challenge (as bytes)
/// 2. Iterates through nonce values (starting from 0)
/// 3. For each nonce: hashes random_nonce_bytes + nonce_bytes using multiple hasher updates
/// 4. Compares the hash `[u8; 32]` with challenge_param `[u8; 32]` using byte-wise comparison
/// 5. Returns the first nonce where hash < challenge_param
///
/// # Arguments
/// * `challenge`: The IronShieldChallenge struct containing random_nonce and challenge_param
///
/// # Returns
/// * `Result<IronShieldChallengeResponse, String>`: `Ok(IronShieldChallengeResponse)`
///                                                  that contains the successful nonce,
///                                                  or an error (`Err(String)`) message
///                                                  if no solution is found within
///                                                  `config.max_attempts`.
pub fn find_solution_single_threaded(
    challenge: &IronShieldChallenge,
    config:    Option<PoWConfig>,
) -> Result<IronShieldChallengeResponse, String> {
    let config = config.unwrap_or_else(PoWConfig::single_threaded);

    let random_nonce_bytes: Vec<u8> = hex::decode(&challenge.random_nonce)
        .map_err(|e: hex::FromHexError| format!("Failed to decode random_nonce hex: {}", e))?;

    let target_threshold: &[u8; 32] = &challenge.challenge_param;

    for nonce in 0..config.max_attempts {
        let nonce_bytes: [u8; 8] = nonce.to_le_bytes();
        let mut hasher = Sha256::new();

        hasher.update(&random_nonce_bytes);             // First part of the input.
        hasher.update(&nonce_bytes);                    // Second part of the input.
        let hash_result = hasher.finalize();

        let hash_bytes: [u8; 32] = hash_result.into();
        if hash_bytes < *target_threshold {             // Upon finding a valid solution:
            return Ok(IronShieldChallengeResponse::new(
                challenge.clone(),                      // Pass the complete challenge,
                nonce,                                  // Along with the successful nonce.
            ));
        }
    }

    Err(format!("Could not find solution within {} attempts", config.max_attempts))
}

/// Find a solution for the given IronShieldChallenge using optimized
/// multithreaded computation.
///
/// Implements thread-stride approach delegated to multiple threads
/// (e.g. Web Workers or Tokio tasks) for maximum performance.
/// The lack of chunking of nonces between threads dramatically increases
/// performance since threads don't have to constantly communicate and
/// distribute work. Each thread is mathematically guaranteed to not check
/// overlapping nonces with other threads.
///
/// ## Algorithm:
/// 1. Pre-computes the random_nonce bytes once to avoid repeated hex decoding
/// 2. Assigns each thread a start_offset and stride
/// 3. Each thread performs the single-threaded algorithm with a stride and offset
/// 4. Returns immediately when a solution is found
///
/// # Arguments
/// * `challenge`:    The IronShieldChallenge struct containing random_nonce and challenge_param
/// * `num_threads`:  Ignored (for compatibility only)
/// * `start_offset`: Starting nonce for this worker's search range (JavaScript coordination)
/// * `stride`:       Nonce increment step for thread-stride pattern (JavaScript coordination)
///
/// # Returns
/// * `Result<IronShieldChallengeResponse, String>`: `Ok(IronShieldChallengeResponse)`
///                                                  that contains the successful nonce,
///                                                  or an error (`Err(String)`) message
///                                                  if no solution is found within
///                                                  `config.max_attempts`.
///
/// # Example
/// ```
/// use ironshield_core::{
///     IronShieldChallenge,
///     find_solution_multi_threaded,
///     SigningKey
/// };
///
/// # fn example() -> Result<(), String> {
///     let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
///     let challenge = IronShieldChallenge::new(
///         "website".to_string(),
///         1,           // difficulty
///         dummy_key,
///         [0x00; 32],  // public_key
///      );
///
///     // JavaScript worker coordination mode
///     let response = find_solution_multi_threaded(&challenge, None, Some(0), Some(8), None)?;
///     println!("Found solution: {}", response.solution);
/// #   Ok(())
/// # }
/// ```
#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
pub fn find_solution_multi_threaded(
    challenge:         &IronShieldChallenge,
    config:            Option<PoWConfig>,
    start_offset:      Option<usize>,
    stride:            Option<usize>,
    progress_callback: Option<&dyn Fn(u64)>,
) -> Result<IronShieldChallengeResponse, String> {
    let config = config.unwrap_or_else(PoWConfig::multi_threaded);

    let random_nonce_bytes: Vec<u8> = hex::decode(&challenge.random_nonce)
        .map_err(|e: hex::FromHexError| format!("Failed to decode random_nonce hex: {}", e))?;

    let target_threshold: &[u8; 32] = &challenge.challenge_param;

    // Set the start nonce and nonce increment based on the start_offset and stride.
    let (start_nonce, nonce_increment) =
        if let (Some(start), Some(step)) = (start_offset, stride) {
            (start as i64, step as i64)
        } else {
            (0i64, 1i64) // Single-threaded fallback
        };

    execute_proof_of_work(
        &random_nonce_bytes,
        target_threshold,
        start_nonce,
        nonce_increment,
        &config,
        progress_callback,
        challenge,
    ).map_err(|_| {
        format!("Could not find solution within {} attempts", config.max_attempts)
    })
}

/// Proof-of-work function that handles both worker coordination
/// and single-threaded fallback modes.
///
/// # Arguments
/// * `random_nonce_bytes`: Pre-decoded hex bytes from `challenge.random_nonce`.
/// * `target_threshold`:   Reference to `challenge.challenge_param` for
///                         comparison.
/// * `start_nonce`:        Starting nonce value (0 for single-threaded,
///                         offset for worker coordination).
/// * `nonce_increment`:    How much to increment nonce each iteration
///                         (1 for single-threaded, stride for workers).
/// * `config`:             `PoWConfig` containing `max_attempts` and
///                         `progress_reporting_interval`.
/// * `progress_callback`:  Optional callback for progress reporting.
/// * `challenge`:          Original challenge for constructing the
///                         response.
///
/// # Returns
/// * `Result<IronShieldChallengeResponse, String>`: `Ok(IronShieldChallengeResponse)`
///                                                  that contains the successful nonce,
///                                                  or an error (`Err(String)`) message
///                                                  if no solution is found within
///                                                  `config.max_attempts`.
fn execute_proof_of_work(
    random_nonce_bytes: &[u8],
    target_threshold:   &[u8; 32],
    start_nonce:        i64,
    nonce_increment:    i64,
    config:             &PoWConfig,
    progress_callback:  Option<&dyn Fn(u64)>,
    challenge:          &IronShieldChallenge,
) -> Result<IronShieldChallengeResponse, String> {
    let mut      nonce_bytes: [u8; 8] = start_nonce.to_le_bytes();
    let     increment_amount: u64 = nonce_increment as u64;
    let mut            nonce: i64 = start_nonce;
    let mut attempts_counter: u64 = 0;

    // Pre-compute the hash of the random nonce
    let mut base_hasher: Sha256 = Sha256::new();
    base_hasher.update(random_nonce_bytes);

    while nonce < config.max_attempts {
        // Hash the random nonce and nonce bytes
        let mut hasher = base_hasher.clone();
        hasher.update(&nonce_bytes);
        let hash_result = hasher.finalize();

        // Upon finding a valid solution convert bytes back to i64 and return the solution
        if hash_result.as_slice() < target_threshold {
            let final_nonce: i64 = le_bytes_to_i64(&nonce_bytes);
            return Ok(IronShieldChallengeResponse::new(
                challenge.clone(),
                final_nonce,
            ));
        }

        // Increment the attempts counter and report progress if a callback is provided
        attempts_counter += 1;
        if attempts_counter == config.progress_reporting_interval {
            if let Some(callback) = progress_callback {
                callback(attempts_counter);
            }
            attempts_counter = 0;
        }

        // Increment nonce byte directly, avoid i64 conversion.
        increment_le_bytes(&mut nonce_bytes, increment_amount);
        nonce += nonce_increment;
    }

    Err(format!("Could not find solution within {} attempts", config.max_attempts))
}

/// Increment little-endian bytes by a specified amount.
///
/// Avoids the overhead of converting to/from i64 in the hot loop.
///
/// # Arguments
/// * `bytes`:     Mutable reference to the 8-byte little-endian
///                array to increment.
/// * `increment`: The amount to add (must be positive).
#[inline]
fn increment_le_bytes(bytes: &mut [u8; 8], increment: u64) {
    let mut carry: u64 = increment;
    for byte in bytes.iter_mut() {
        if carry == 0 {
            break;
        }
        let sum: u64 = *byte as u64 + carry;
        *byte   = sum as u8;
        carry   = sum >> 8;
    }
}

#[inline]
fn le_bytes_to_i64(bytes: &[u8; 8]) -> i64 {
    i64::from_le_bytes(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_increment_le_bytes() {
        let mut bytes = [0u8; 8];
        increment_le_bytes(&mut bytes, 1);
        assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 0]);

        let mut bytes = [0u8; 8];
        increment_le_bytes(&mut bytes, 256);
        assert_eq!(bytes, [0, 1, 0, 0, 0, 0, 0, 0]);

        let mut bytes = [255u8; 8];
        increment_le_bytes(&mut bytes, 1);
        assert_eq!(bytes, [0, 0, 0, 0, 0, 0, 0, 0]); // Wraps around.

        let mut bytes = [0u8; 8];
        increment_le_bytes(&mut bytes, 8); // Common stride for 8 threads.
        assert_eq!(bytes, [8, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_le_bytes_to_i64_roundtrip() {
        // Test that we can convert i64 -> bytes -> i64 without loss.
        let original_values = [0i64, 1, 255, 256, 65535, 65536, 16777215, 16777216];

        for &original in &original_values {
            let bytes = original.to_le_bytes();
            let recovered = le_bytes_to_i64(&bytes);
            assert_eq!(original, recovered, "Roundtrip failed for value {}", original);
        }
    }

    #[test]
    fn test_find_solution_single_threaded_easy() {
        // Create a challenge with very high threshold (easy to solve).
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easiest difficulty.
            dummy_key,
            [0x00; 32],
        );

        let result = find_solution_single_threaded(&challenge, None);
        assert!(result.is_ok(), "Should find solution for easy challenge");

        let response = result.unwrap();
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    #[test]
    fn test_find_solution_single_threaded_custom_config() {
        // Test with custom configuration.
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easiest difficulty.
            dummy_key,
            [0x00; 32],
        );

        let config = PoWConfig::custom(10_000, 1_000);
        let result = find_solution_single_threaded(&challenge, Some(config));
        assert!(result.is_ok(), "Should find solution with custom config");
    }


    #[test]
    fn test_performance_optimization_correctness() {
        // This test ensures that our optimization produces the same results
        // as the original Vec-based approach would have.

        let random_nonce = "deadbeefcafe1234";
        let random_nonce_bytes = hex::decode(random_nonce).unwrap();
        let nonce: i64 = 12345;
        let nonce_bytes = nonce.to_le_bytes();

        // Method 1: Optimized approach (multiple hasher updates).
        let mut hasher1 = Sha256::new();
        hasher1.update(&random_nonce_bytes);
        hasher1.update(&nonce_bytes);
        let hash1: [u8; 32] = hasher1.finalize().into();

        // Method 2: Traditional approach (Vec concatenation) - for comparison.
        let mut input_data = Vec::with_capacity(random_nonce_bytes.len() + 8);
        input_data.extend_from_slice(&random_nonce_bytes);
        input_data.extend_from_slice(&nonce_bytes);
        let mut hasher2 = Sha256::new();
        hasher2.update(&input_data);
        let hash2: [u8; 32] = hasher2.finalize().into();

        // Both methods should produce identical results.
        assert_eq!(hash1, hash2, "Optimized and traditional methods should produce identical hashes");
    }

    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_find_solution_multi_threaded_easy() {
        // Create a challenge with very high threshold (easy to solve).
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easiest difficulty.
            dummy_key,
            [0x00; 32],
        );

        let result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for easy challenge");

        let response = result.unwrap();
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");

        // Verify the solution using the verification function.
        assert!(crate::verify::verify_ironshield_solution(&response),
                "Multi-threaded solution should pass verification");
    }

    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_find_solution_multi_threaded_vs_single_threaded() {
        // Test that multithreaded and single-threaded versions find valid solutions
        // for the same challenge (solutions may differ due to search order).
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1000, // Medium difficulty.
            dummy_key,
            [0x00; 32],
        );

        // Solve with single-threaded version.
        let single_result = find_solution_single_threaded(&challenge, None);
        assert!(single_result.is_ok(), "Single-threaded should find solution");

        // Solve with multithreaded version.
        let multi_result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(multi_result.is_ok(), "Multi-threaded should find solution");

        let single_response = single_result.unwrap();
        let multi_response = multi_result.unwrap();

        // Both solutions should be valid (but may be different nonces).
        assert!(crate::verify::verify_ironshield_solution(&single_response),
                "Single-threaded solution should be valid");
        assert!(crate::verify::verify_ironshield_solution(&multi_response),
                "Multi-threaded solution should be valid");

        // Both should have the same challenge signature.
        assert_eq!(single_response.solved_challenge.challenge_signature, multi_response.solved_challenge.challenge_signature);
    }

    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_find_solution_multi_threaded_deterministic_correctness() {
        // Test that the multithreaded function produces correct results
        // by testing with a known challenge where we can predict the solution range.
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            2, // ~50% probability per hash.
            dummy_key,
            [0x00; 32],
        );

        // Should find a solution relatively quickly with 50% probability per attempt.
        let result = find_solution_multi_threaded(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for medium difficulty challenge");

        let response = result.unwrap();

        // Manually verify the solution using the same algorithm.
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

    #[test]
    fn test_execute_proof_of_work_single_threaded_mode() {
        // Test the internal function with single-threaded parameters.
        let random_nonce_bytes = hex::decode("deadbeef").unwrap();
        let target_threshold = [0xFF; 32]; // Very easy threshold.
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test".to_string(),
            1,
            dummy_key,
            target_threshold,
        );

        let result = execute_proof_of_work(
            &random_nonce_bytes,
            &target_threshold,
            0, // start_nonce
            1, // nonce_increment
            &PoWConfig::default(), // conf
            None, // progress_callback
            &challenge,
        );

        assert!(result.is_ok(), "Should find solution with easy threshold");
    }

    #[test]
    fn test_execute_proof_of_work_worker_coordination_mode() {
        // Test the internal function with worker coordination parameters.
        let random_nonce_bytes = hex::decode("deadbeef").unwrap();
        let target_threshold = [0xFF; 32]; // Very easy threshold.
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test".to_string(),
            1,
            dummy_key,
            target_threshold,
        );

        let result = execute_proof_of_work(
            &random_nonce_bytes,
            &target_threshold,
            5,  // start_nonce (worker offset)
            8,  // nonce_increment (worker stride)
            &PoWConfig::default(), // conf
            None, // progress_callback
            &challenge,
        );

        assert!(result.is_ok(), "Should find solution with worker coordination parameters");
    }
}