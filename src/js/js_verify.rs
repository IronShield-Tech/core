#[cfg(any(feature = "wasm", rust_analyzer))]
use wasm_bindgen::prelude::*;

#[cfg(any(feature = "wasm", rust_analyzer))]
use crate::*;

/// Verifies an IronShield proof-of-work challenge response solution in JSON format.
///
/// # Arguments
/// * `challenge_response_json`: JSON string containing the IronShieldChallengeResponse.
///
/// # Returns
/// `Result<bool, JsValue>`: `true` if the solution is valid, `false` otherwise.
#[cfg(any(feature = "wasm", rust_analyzer))]
#[wasm_bindgen]
pub fn verify_ironshield_solution(challenge_response_json: &str) -> Result<bool, JsValue> {
    // Parse the challenge response from JSON
    let response: IronShieldChallengeResponse = serde_json::from_str(challenge_response_json)
        .map_err(|e: serde_json::Error| JsValue::from_str(&format!("Error parsing challenge response JSON for verification: {}", e)))?;

    // Verify the solution
    let is_valid: bool = verify::verify_ironshield_solution(&response);
    Ok(is_valid)
}