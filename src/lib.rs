//! # Core functionality for the IronShield proof-of-work system.
//!
//! This module contains shared code that can be used in both
//! the server-side (Cloudflare Workers) and client-side (WASM) implementations

pub use ironshield_types::*; // Re-export types from ironshield-types

mod solve;
mod verify;

#[cfg(any(feature = "wasm", rust_analyzer))]
pub mod js;

// Re-export public functions from modules
pub use solve::PoWConfig;
pub use solve::find_solution;
pub use verify::verify_ironshield_solution;

#[cfg(any(feature = "wasm", rust_analyzer))]
pub use js::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ironshield_challenge_creation() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Very high threshold - should be easy to find solution
            dummy_key,
            [0x00; 32],
        );
        assert_eq!(challenge.website_id, "test_website");
        assert_ne!(challenge.challenge_param, [0u8; 32]);
    }

    #[test]
    fn test_serde_serialization() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1000,
            dummy_key,
            [0x34; 32],
        );

        // Test serialization
        let serialized = serde_json::to_string(&challenge).unwrap();
        assert!(!serialized.is_empty());

        // Test deserialization
        let deserialized: IronShieldChallenge = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.challenge_param, challenge.challenge_param);
        assert_eq!(deserialized.public_key, challenge.public_key);
        assert_eq!(deserialized.challenge_signature, challenge.challenge_signature);
    }

    #[test]
    fn test_recommended_attempts() {
        // Test the new recommended_attempts function
        assert_eq!(IronShieldChallenge::recommended_attempts(1000), 2000);
        assert_eq!(IronShieldChallenge::recommended_attempts(50000), 100000);
        assert_eq!(IronShieldChallenge::recommended_attempts(0), 0);

        // Test overflow protection
        assert_eq!(IronShieldChallenge::recommended_attempts(u64::MAX), u64::MAX);
    }

    #[test]
    fn test_difficulty_to_challenge_param() {
        // Test that our difficulty conversion works correctly

        // Very easy case
        let challenge_param = IronShieldChallenge::difficulty_to_challenge_param(1);
        assert_eq!(challenge_param, [0xFF; 32]);

        // Test zero difficulty panics
        let result = std::panic::catch_unwind(|| {
            IronShieldChallenge::difficulty_to_challenge_param(0);
        });
        assert!(result.is_err(), "Zero difficulty should panic");

        // Test some practical values produce valid outputs
        let challenge_param_256 = IronShieldChallenge::difficulty_to_challenge_param(256);
        assert_ne!(challenge_param_256, [0; 32]);
        assert_ne!(challenge_param_256, [0xFF; 32]);

        let challenge_param_1024 = IronShieldChallenge::difficulty_to_challenge_param(1024);
        assert_ne!(challenge_param_1024, [0; 32]);
        assert_ne!(challenge_param_1024, [0xFF; 32]);

        // Test very high difficulty - this produces a very small target, not all zeros
        let challenge_param_max = IronShieldChallenge::difficulty_to_challenge_param(u64::MAX);
        // For max difficulty, the target should be very small but not necessarily all zeros
        // since the function uses bit manipulation logic
        assert_ne!(challenge_param_max, [0xFF; 32], "Maximum difficulty should not produce all FFs");

        // Test that the function produces consistent results
        let challenge_param_test = IronShieldChallenge::difficulty_to_challenge_param(1000);
        let challenge_param_test2 = IronShieldChallenge::difficulty_to_challenge_param(1000);
        assert_eq!(challenge_param_test, challenge_param_test2, "Function should be deterministic");
    }

    // Integration test that verifies the solve and verify modules work together
    #[test]
    fn test_solve_verify_integration() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Easy difficulty
            dummy_key,
            [0x00; 32],
        );

        // Solve the challenge
        let result = find_solution(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for integration test");

        let response = result.unwrap();

        // Verify the solution using the IronShield verification
        assert!(verify_ironshield_solution(&response),
                "IronShield verification should confirm the solution is valid");

        // Verify response structure
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    // Integration test for the new IronShield algorithm
    #[test]
    fn test_ironshield_solve_verify_integration() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        // Use the same parameters as the working test in solve.rs
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Very easy difficulty - should find solution quickly
            dummy_key,
            [0x00; 32],
        );

        // Solve the challenge
        let result = find_solution(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for IronShield integration test");

        let response = result.unwrap();

        // Verify the solution
        assert!(verify_ironshield_solution(&response),
                "IronShield verification should confirm the solution is valid");

        // Verify response structure
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    // Integration test for the multi-threaded IronShield algorithm
    #[test]

    fn test_ironshield_multi_threaded_solve_verify_integration() {
        let dummy_key = SigningKey::from_bytes(&[0u8; 32]);
        // Use the same parameters as the working test in solve.rs
        let challenge = IronShieldChallenge::new(
            "test_website".to_string(),
            1, // Very easy difficulty - should find solution quickly
            dummy_key,
            [0x00; 32],
        );

        // Solve the challenge using multi-threaded version
        let result = find_solution(&challenge, None, None, None, None);
        assert!(result.is_ok(), "Should find solution for IronShield multi-threaded integration test");

        let response = result.unwrap();

        // Verify the solution
        assert!(verify_ironshield_solution(&response),
                "IronShield multi-threaded verification should confirm the solution is valid");

        // Verify response structure
        assert_eq!(response.solved_challenge.challenge_signature, challenge.challenge_signature);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }
}