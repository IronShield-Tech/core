//! # Core functionality for the IronShield proof-of-work system.
//! 
//! This module contains shared code that can be used in both
//! the server-side (Cloudflare Workers) and client-side (WASM) implementations

pub use ironshield_types::*; // Re-export types from ironshield-types

mod solve;
mod verify;

// Re-export public functions from modules
pub use solve::find_solution_single_threaded;

#[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
pub use solve::find_solution_multi_threaded;

pub use verify::verify_ironshield_solution;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_ironshield_challenge_creation() {
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Very high threshold - should be easy to find solution
            [0x00; 32],
            [0x00; 64],
        );
        
        assert_eq!(challenge.random_nonce, "deadbeef");
        assert_eq!(challenge.created_time, 1000000);
        assert_eq!(challenge.expiration_time, 1030000); // +30 seconds
        assert_eq!(challenge.website_id, "test_website");
        assert_eq!(challenge.challenge_param, [0xFF; 32]);
    }

    #[test]
    fn test_ironshield_challenge_expiration() {
        let past_time = Utc::now().timestamp_millis() - 60000; // 1 minute ago
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            past_time,
            "test_website".to_string(),
            [0xFF; 32],
            [0x00; 32],
            [0x00; 64],
        );
        
        assert!(challenge.is_expired(), "Challenge created in the past should be expired");
        assert!(challenge.time_until_expiration() < 0, "Time until expiration should be negative");
    }

    #[test]
    fn test_serde_serialization() {
        let challenge: IronShieldChallenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0x12; 32],
            [0x34; 32],
            [0x56; 64],
        );
        
        // Test serialization
        let serialized = serde_json::to_string(&challenge).unwrap();
        assert!(!serialized.is_empty());
        
        // Test deserialization
        let deserialized: IronShieldChallenge = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.random_nonce, challenge.random_nonce);
        assert_eq!(deserialized.challenge_param, challenge.challenge_param);
        assert_eq!(deserialized.public_key, challenge.public_key);
        assert_eq!(deserialized.challenge_signature, challenge.challenge_signature);
    }

    #[test]
    fn test_recommended_attempts() {
        // Test the new recommended_attempts function
        assert_eq!(IronShieldChallenge::recommended_attempts(1000), 3000);
        assert_eq!(IronShieldChallenge::recommended_attempts(50000), 150000);
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
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(),
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Easy difficulty
            [0x00; 32],
            [0x11; 64],
        );

        // Solve the challenge
        let result = find_solution_single_threaded(&challenge);
        assert!(result.is_ok(), "Should find solution for integration test");

        let response = result.unwrap();
        
        // Verify the solution using the IronShield verification
        assert!(verify_ironshield_solution(&challenge, response.solution),
                "IronShield verification should confirm the solution is valid");
        
        // Verify response structure
        assert_eq!(response.challenge_signature, [0x11; 64]);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    // Integration test for the new IronShield algorithm
    #[test]
    fn test_ironshield_solve_verify_integration() {
        // Use the same parameters as the working test in solve.rs
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(), // Same as the working test
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Very easy difficulty - should find solution quickly
            [0x00; 32],
            [0x33; 64],
        );

        // Solve the challenge
        let result = find_solution_single_threaded(&challenge);
        assert!(result.is_ok(), "Should find solution for IronShield integration test");

        let response = result.unwrap();
        
        // Verify the solution
        assert!(verify_ironshield_solution(&challenge, response.solution),
                "IronShield verification should confirm the solution is valid");
        
        // Verify response structure
        assert_eq!(response.challenge_signature, [0x33; 64]);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }

    // Integration test for the multi-threaded IronShield algorithm
    #[test]
    #[cfg(all(feature = "parallel", not(feature = "no-parallel")))]
    fn test_ironshield_multi_threaded_solve_verify_integration() {
        // Use the same parameters as the working test in solve.rs
        let challenge = IronShieldChallenge::new(
            "deadbeef".to_string(), // Same as the working test
            1000000,
            "test_website".to_string(),
            [0xFF; 32], // Very easy difficulty - should find solution quickly
            [0x00; 32],
            [0x77; 64],
        );

        // Solve the challenge using multi-threaded version
        let result = find_solution_multi_threaded(&challenge, None, None, None);
        assert!(result.is_ok(), "Should find solution for IronShield multi-threaded integration test");

        let response = result.unwrap();
        
        // Verify the solution
        assert!(verify_ironshield_solution(&challenge, response.solution),
                "IronShield multi-threaded verification should confirm the solution is valid");
        
        // Verify response structure
        assert_eq!(response.challenge_signature, [0x77; 64]);
        assert!(response.solution >= 0, "Solution should be non-negative");
    }
}