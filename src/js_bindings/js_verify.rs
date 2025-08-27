// Suppress warnings from wasm-bindgen internals during ABI transition
#![allow(wasm_c_abi)]

#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

use crate::*;

/// Verifies an IronShield proof-of-work solution without recomputing.
///
/// # Arguments
/// * `challenge_json`: JSON string containing the original IronShieldChallenge.
/// * `solution_nonce`: Proposed solution nonce as i64.
///
/// # Returns
/// `Result<bool, JsValue>`: `true` if the solution is valid, `false` otherwise.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub fn verify_ironshield_solution(challenge_json: &str, solution_nonce: i64) -> Result<bool, JsValue> {
    // Parse the challenge from JSON
    let challenge: IronShieldChallenge = serde_json::from_str(challenge_json)
        .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Error parsing challenge JSON for verification: {}", e)))?;

    // Create a challenge response for verification
    let response: IronShieldChallengeResponse = IronShieldChallengeResponse::new(challenge, solution_nonce);

    // Verify the solution using the new API
    let is_valid: bool = crate::verify_ironshield_solution(&response);
    Ok(is_valid)
}